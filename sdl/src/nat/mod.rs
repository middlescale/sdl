use anyhow::{anyhow, Context};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use rand::prelude::SliceRandom;
use rand::Rng;

use crate::transport::socket::LocalInterface;
use crate::transport::udp_channel::UdpChannel;
use crate::util::StopManager;
#[cfg(feature = "upnp")]
use crate::util::UPnP;

pub mod punch;
pub mod punch_workers;
mod stun;
pub(crate) use stun::looks_like_stun_response;

use crate::nat::punch::{NatInfo, NatType, PunchModel};

struct PendingStunRequest {
    transaction_id: u128,
    server_addr: SocketAddr,
    expires_at: Instant,
}

pub fn local_ipv4_() -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

pub fn local_ipv4() -> Option<Ipv4Addr> {
    match local_ipv4_() {
        Ok(ipv4) => Some(ipv4),
        Err(e) => {
            log::warn!("获取ipv4失败：{:?}", e);
            None
        }
    }
}

pub fn local_ipv6_() -> io::Result<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0")?;
    socket.connect("[2001:4860:4860:0000:0000:0000:0000:8888]:80")?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(_) => Ok(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(ip) => Ok(ip),
    }
}

pub fn local_ipv6() -> Option<Ipv6Addr> {
    match local_ipv6_() {
        Ok(ipv6) => {
            if is_ipv6_global(&ipv6) {
                return Some(ipv6);
            }
        }
        Err(e) => {
            log::warn!("获取ipv6失败：{:?}", e);
        }
    }
    None
}

pub const fn is_ipv4_global(ipv4: &Ipv4Addr) -> bool {
    !(ipv4.octets()[0] == 0 // "This network"
        || ipv4.is_private()
        || ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0b1100_0000 == 0b0100_0000)//ipv4.is_shared()
        || ipv4.is_loopback()
        || ipv4.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        // .9 and .10 are documented as globally reachable so they're excluded
        || (
        ipv4.octets()[0] == 192 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 0
            && ipv4.octets()[3] != 9 && ipv4.octets()[3] != 10
    )
        || ipv4.is_documentation()
        || ipv4.octets()[0] == 198 && (ipv4.octets()[1] & 0xfe) == 18//ipv4.is_benchmarking()
        || ipv4.octets()[0] & 240 == 240 && !ipv4.is_broadcast()//ipv4.is_reserved()
        || ipv4.is_broadcast())
}

pub const fn is_ipv6_global(ipv6addr: &Ipv6Addr) -> bool {
    !(ipv6addr.is_unspecified()
        || ipv6addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ipv6addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ipv6addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ipv6addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ipv6addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
        && !(
        // Port Control Protocol Anycast (`2001:1::1`)
        u128::from_be_bytes(ipv6addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
            // Traversal Using Relays around NAT Anycast (`2001:1::2`)
            || u128::from_be_bytes(ipv6addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
            // AMT (`2001:3::/32`)
            || matches!(ipv6addr.segments(), [0x2001, 3, _, _, _, _, _, _])
            // AS112-v6 (`2001:4:112::/48`)
            || matches!(ipv6addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
            // ORCHIDv2 (`2001:20::/28`)
            || matches!(ipv6addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
    ))
        || (ipv6addr.segments()[0] == 0x2001) && (ipv6addr.segments()[1] == 0xdb8)//ipv6addr.is_documentation()
        || (ipv6addr.segments()[0] & 0xfe00) == 0xfc00//ipv6addr.is_unique_local()
        || (ipv6addr.segments()[0] & 0xffc0) == 0xfe80) //ipv6addr.is_unicast_link_local())
}

#[derive(Clone)]
pub struct NatTest {
    stun_server: Vec<String>,
    default_interface: LocalInterface,
    udp_channel: UdpChannel,
    info: Arc<Mutex<NatInfo>>,
    time: Arc<AtomicCell<Instant>>,
    pending_stun_requests: Arc<Mutex<Vec<PendingStunRequest>>>,
    udp_ports: Vec<u16>,
    #[cfg(feature = "upnp")]
    upnp: UPnP,
    pub(crate) update_local_ipv4: bool,
}

impl NatTest {
    pub fn new(
        stun_server: Vec<String>,
        default_interface: LocalInterface,
        udp_channel: UdpChannel,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        udp_ports: Vec<u16>,
        update_local_ipv4: bool,
        punch_model: PunchModel,
    ) -> NatTest {
        let ports = vec![0; udp_ports.len()];
        let nat_info = NatInfo::new(
            Vec::new(),
            ports,
            Vec::new(),
            0,
            local_ipv4,
            ipv6,
            udp_ports.clone(),
            NatType::Cone,
            punch_model,
        );
        let info = Arc::new(Mutex::new(nat_info));
        #[cfg(feature = "upnp")]
        let upnp = UPnP::default();
        #[cfg(feature = "upnp")]
        for port in &udp_ports {
            upnp.add_udp_port(*port);
        }
        let instant = Instant::now();
        NatTest {
            stun_server,
            default_interface,
            udp_channel,
            info,
            time: Arc::new(AtomicCell::new(
                instant
                    .checked_sub(Duration::from_secs(100))
                    .unwrap_or(instant),
            )),
            pending_stun_requests: Arc::new(Mutex::new(Vec::with_capacity(4))),
            udp_ports,
            #[cfg(feature = "upnp")]
            upnp,
            update_local_ipv4,
        }
    }
    pub fn can_update(&self) -> bool {
        let last = self.time.load();
        last.elapsed() > Duration::from_secs(10)
            && self.time.compare_exchange(last, Instant::now()).is_ok()
    }
    pub fn start_refresh_task(&self, stop_manager: StopManager) -> anyhow::Result<()> {
        let nat_test = self.clone();
        let (stop_sender, stop_receiver) = std::sync::mpsc::channel::<()>();
        let worker = stop_manager.add_listener("natRefresh".into(), move || {
            let _ = stop_sender.send(());
        })?;
        thread::Builder::new()
            .name("natRefresh".into())
            .spawn(move || {
                refresh_nat_type0(nat_test.clone());
                loop {
                    if stop_receiver
                        .recv_timeout(Duration::from_secs(60 * 10))
                        .is_ok()
                    {
                        break;
                    }
                    refresh_nat_type0(nat_test.clone());
                }
                drop(worker);
            })?;
        Ok(())
    }

    pub fn nat_info(&self) -> NatInfo {
        self.info.lock().clone()
    }
    pub fn has_public_udp_endpoints(&self) -> bool {
        let guard = self.info.lock();
        !guard.public_udp_endpoints.is_empty()
    }
    pub fn public_addr_retry_delay(&self) -> Duration {
        let guard = self.info.lock();
        if !guard.public_udp_endpoints.is_empty() {
            if guard.nat_type == NatType::Symmetric {
                Duration::from_secs(600)
            } else {
                Duration::from_secs(19)
            }
        } else {
            Duration::from_secs(3)
        }
    }
    pub fn request_public_addr(&self) -> anyhow::Result<()> {
        let (data, addr, transaction_id) = self.send_data()?;
        self.track_pending_stun_request(transaction_id, addr);
        self.udp_channel.send_to(&data, addr)?;
        Ok(())
    }
    pub fn is_local_udp(&self, ipv4: Ipv4Addr, port: u16) -> bool {
        for x in &self.udp_ports {
            if x == &port {
                let guard = self.info.lock();
                if let Some(ip) = guard.local_ipv4 {
                    if ipv4 == ip {
                        return true;
                    }
                }
                break;
            }
        }
        false
    }
    pub fn is_local_address(&self, is_tcp: bool, addr: SocketAddr) -> bool {
        if is_tcp {
            return false;
        }
        let port = addr.port();
        let check_ip = || {
            let guard = self.info.lock();
            match addr.ip() {
                IpAddr::V4(ipv4) => {
                    if let Some(ip) = guard.local_ipv4 {
                        if ipv4 == ip {
                            return true;
                        }
                    }
                }
                IpAddr::V6(ipv6) => {
                    if let Some(ip) = guard.ipv6 {
                        if ipv6 == ip {
                            return true;
                        }
                    }
                }
            }
            false
        };
        for x in &self.udp_ports {
            if x == &port {
                return check_ip();
            }
        }
        false
    }
    pub fn update_addr(&self, ip: Ipv4Addr, port: u16) -> bool {
        let mut guard = self.info.lock();
        guard.update_addr(ip, port)
    }
    pub fn re_test(
        &self,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        default_interface: &LocalInterface,
    ) -> anyhow::Result<NatInfo> {
        let mut stun_server = self.stun_server.clone();
        if stun_server.len() > 5 {
            stun_server.shuffle(&mut rand::thread_rng());
            stun_server.truncate(5);
            log::info!("stun_server truncate {:?}", stun_server);
        }
        let (nat_type, public_udp_endpoints, port_range) =
            stun::stun_test_nat(stun_server, default_interface)?;
        if public_udp_endpoints.is_empty() {
            Err(anyhow!("public_udp_endpoints.is_empty"))?
        }
        let mut guard = self.info.lock();
        guard.nat_type = nat_type;
        guard.public_udp_endpoints = public_udp_endpoints.clone();
        guard.public_ips = public_udp_endpoints
            .iter()
            .filter_map(|addr| match addr {
                SocketAddr::V4(addr) => Some(*addr.ip()),
                SocketAddr::V6(_) => None,
            })
            .collect();
        guard.public_ports = public_udp_endpoints.iter().map(SocketAddr::port).collect();
        guard.public_port_range = port_range;
        if local_ipv4.is_some() {
            guard.local_ipv4 = local_ipv4;
        }
        guard.ipv6 = ipv6;

        Ok(guard.clone())
    }
    #[cfg(feature = "upnp")]
    pub fn reset_upnp(&self) {
        let local_ipv4 = self.info.lock().local_ipv4.clone();
        if let Some(local_ipv4) = local_ipv4 {
            self.upnp.reset(local_ipv4)
        }
    }
    pub fn send_data(&self) -> anyhow::Result<(Vec<u8>, SocketAddr, u128)> {
        let len = self.stun_server.len();
        let stun_server = if len == 1 {
            &self.stun_server[0]
        } else {
            let index = rand::thread_rng().gen_range(0..self.stun_server.len());
            &self.stun_server[index]
        };
        let addr = stun_server
            .to_socket_addrs()?
            .next()
            .with_context(|| format!("stun error {:?}", stun_server))?;
        let (data, transaction_id) = stun::send_stun_request();
        Ok((data, addr, transaction_id))
    }
    pub fn recv_data(&self, source_addr: SocketAddr, buf: &[u8]) -> anyhow::Result<bool> {
        if stun::looks_like_stun_response(buf) {
            if let Some((transaction_id, addr)) = stun::recv_stun_response(buf) {
                if !self.take_pending_stun_request(transaction_id, source_addr) {
                    return Ok(true);
                }
                if let Err(e) = self.recv_data_(source_addr, addr) {
                    log::warn!("{:?}", e);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub fn has_pending_stun_server_addr(&self, source_addr: SocketAddr) -> bool {
        let now = Instant::now();
        let mut pending = self.pending_stun_requests.lock();
        pending.retain(|item| item.expires_at > now);
        pending.iter().any(|item| item.server_addr == source_addr)
    }
    fn track_pending_stun_request(&self, transaction_id: u128, server_addr: SocketAddr) {
        let now = Instant::now();
        let mut pending = self.pending_stun_requests.lock();
        pending.retain(|item| item.expires_at > now);
        pending.push(PendingStunRequest {
            transaction_id,
            server_addr,
            expires_at: now + Duration::from_secs(5),
        });
        if pending.len() > 8 {
            let drop_count = pending.len() - 8;
            pending.drain(..drop_count);
        }
    }
    fn take_pending_stun_request(&self, transaction_id: u128, source_addr: SocketAddr) -> bool {
        let now = Instant::now();
        let mut pending = self.pending_stun_requests.lock();
        pending.retain(|item| item.expires_at > now);
        if let Some(index) = pending.iter().position(|item| {
            item.transaction_id == transaction_id && item.server_addr == source_addr
        }) {
            pending.swap_remove(index);
            true
        } else {
            false
        }
    }
    fn recv_data_(&self, source_addr: SocketAddr, addr: SocketAddr) -> anyhow::Result<()> {
        if let SocketAddr::V4(addr) = addr {
            let mut check_fail = true;
            let source_ip = match source_addr.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(ip) => {
                    if let Some(ip) = ip.to_ipv4() {
                        ip
                    } else {
                        return Ok(());
                    }
                }
            };
            'a: for stun_server in &self.stun_server {
                for x in stun_server.to_socket_addrs()? {
                    if source_addr.port() == x.port() {
                        if let IpAddr::V4(ip) = x.ip() {
                            if ip == source_ip {
                                check_fail = false;
                                break 'a;
                            }
                        };
                    }
                }
            }
            if !check_fail {
                if is_ipv4_global(addr.ip()) {
                    if self.update_addr(*addr.ip(), addr.port()) {
                        log::info!("回应地址{:?},来源stun {:?}", addr, source_addr)
                    }
                }
            }
        }
        Ok(())
    }
}

fn refresh_nat_type0(nat_test: NatTest) {
    thread::Builder::new()
        .name("natTest".into())
        .spawn(move || {
            if nat_test.can_update() {
                let local_ipv4 = if nat_test.update_local_ipv4 {
                    local_ipv4()
                } else {
                    None
                };
                let local_ipv6 = local_ipv6();
                match nat_test.re_test(local_ipv4, local_ipv6, &nat_test.default_interface) {
                    Ok(nat_info) => {
                        log::info!("当前nat信息:{:?}", nat_info);
                    }
                    Err(e) => {
                        log::warn!("nat re_test {:?}", e);
                    }
                };
                #[cfg(feature = "upnp")]
                nat_test.reset_upnp();
                log::info!("刷新nat结束")
            }
        })
        .expect("natTest");
}
