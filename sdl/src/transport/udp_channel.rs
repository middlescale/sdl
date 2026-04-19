use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use crate::core::Config;
use crate::data_plane::route::RouteKey;
use crate::data_plane::stats::DataPlaneStats;
use crate::nat::looks_like_stun_response;
use crate::protocol::{BUFFER_SIZE, MAX_TTL, Protocol, Version, HEAD_LEN};
use crate::transport::connect_protocol::ConnectProtocol;
use crate::util::StopManager;

const NOTIFY: Token = Token(0);
static SHORT_UDP_INGRESS_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static SHORT_UDP_INGRESS_DROP_LOG_LIMITER: OnceLock<crate::util::limit::ConcurrentRateLimiter> =
    OnceLock::new();
static INVALID_UDP_INGRESS_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static INVALID_UDP_INGRESS_DROP_LOG_LIMITER: OnceLock<crate::util::limit::ConcurrentRateLimiter> =
    OnceLock::new();

fn log_sampled_udp_ingress_drop(
    counter: &AtomicU64,
    limiter: &'static OnceLock<crate::util::limit::ConcurrentRateLimiter>,
    message: impl FnOnce(u64) -> String,
) {
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if limiter
        .get_or_init(|| crate::util::limit::ConcurrentRateLimiter::new(1, 1))
        .try_acquire()
    {
        let sampled = counter.swap(0, Ordering::Relaxed);
        let total = sampled.max(count);
        log::debug!("{}", message(total));
    }
}

fn looks_like_sdl_udp_packet(buf: &[u8]) -> bool {
    if buf.len() < HEAD_LEN {
        return false;
    }
    if !matches!(Version::from(buf[0] & 0x0F), Version::V2 | Version::V3) {
        return false;
    }
    if !matches!(
        Protocol::from(buf[1]),
        Protocol::Service
            | Protocol::Error
            | Protocol::Control
            | Protocol::IpTurn
            | Protocol::OtherTurn
    ) {
        return false;
    }
    let ttl = buf[3] & MAX_TTL;
    let origin_ttl = buf[3] >> 4;
    ttl != 0 && origin_ttl >= ttl
}

fn should_accept_udp_ingress_frame(buf: &[u8]) -> bool {
    looks_like_stun_response(buf) || looks_like_sdl_udp_packet(buf)
}

#[derive(Clone)]
pub struct UdpChannel {
    driver: UdpSocketDriver,
    stats: DataPlaneStats,
}

#[derive(Clone)]
pub(crate) struct UdpSocketDriver {
    socket: Arc<UdpSocket>,
    dual_stack: bool,
}

impl UdpChannel {
    pub fn bind(config: &Config, stats: DataPlaneStats) -> anyhow::Result<Self> {
        let port = config
            .ports
            .as_ref()
            .and_then(|ports| ports.first().copied())
            .unwrap_or(0);
        let driver = UdpSocketDriver::bind(port, &config.local_interface)?;
        Ok(Self { driver, stats })
    }

    pub fn local_udp_port(&self) -> io::Result<u16> {
        Ok(self.driver.local_addr()?.port())
    }

    pub fn supports_ipv6(&self) -> bool {
        self.driver.supports_ipv6()
    }

    pub fn up_traffic_total(&self) -> u64 {
        self.stats.up_traffic_total()
    }

    pub fn up_traffic_all(&self) -> Option<(u64, std::collections::HashMap<usize, u64>)> {
        self.stats.up_traffic_all()
    }

    pub fn up_traffic_history(
        &self,
    ) -> Option<(u64, std::collections::HashMap<usize, (u64, Vec<usize>)>)> {
        self.stats.up_traffic_history()
    }

    pub fn down_traffic_total(&self) -> u64 {
        self.stats.down_traffic_total()
    }

    pub fn down_traffic_all(&self) -> Option<(u64, std::collections::HashMap<usize, u64>)> {
        self.stats.down_traffic_all()
    }

    pub fn down_traffic_history(
        &self,
    ) -> Option<(u64, std::collections::HashMap<usize, (u64, Vec<usize>)>)> {
        self.stats.down_traffic_history()
    }

    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.driver.send_to(buf, addr)?;
        self.record_up_traffic(buf.len());
        Ok(())
    }

    pub fn send_by_key(&self, buf: &[u8], route_key: RouteKey) -> io::Result<()> {
        if !route_key.protocol().is_udp() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not udp route: {:?}", route_key.protocol()),
            ));
        }
        self.send_to(buf, route_key.addr)
    }

    pub fn start<H>(&self, stop_manager: StopManager, recv_handler: H) -> anyhow::Result<()>
    where
        H: Fn(&mut [u8], &mut [u8], RouteKey) + Clone + Send + Sync + 'static,
    {
        let channel = self.clone();
        self.driver
            .start_named(stop_manager, "mainUdp", recv_handler, move |len| {
                channel.record_down_traffic(len);
            })
    }

    fn record_up_traffic(&self, len: usize) {
        self.stats.record_up(0, len);
    }

    fn record_down_traffic(&self, len: usize) {
        self.stats.record_down(0, len);
    }
}

impl UdpSocketDriver {
    pub(crate) fn bind(
        port: u16,
        default_interface: &crate::transport::socket::LocalInterface,
    ) -> anyhow::Result<Self> {
        let (socket, dual_stack) = match bind_dual_stack_udp(port, default_interface) {
            Ok(socket) => (socket, true),
            Err(e) => {
                log::warn!("bind dual-stack udp failed: {:?}", e);
                (bind_ipv4_udp(port, default_interface)?, false)
            }
        };
        Ok(Self {
            socket: Arc::new(socket),
            dual_stack,
        })
    }

    pub(crate) fn bind_unspecified_for_remote(remote_addr: SocketAddr) -> anyhow::Result<Self> {
        let bind_addr = match remote_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_addr)?;
        Ok(Self {
            socket: Arc::new(socket),
            dual_stack: false,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) fn supports_ipv6(&self) -> bool {
        self.dual_stack
    }

    pub(crate) fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        let addr = normalize_send_addr(self.dual_stack, addr);
        self.socket.send_to(buf, addr)?;
        Ok(())
    }

    pub(crate) fn start_named<H, D>(
        &self,
        stop_manager: StopManager,
        worker_name: &str,
        recv_handler: H,
        down_traffic_hook: D,
    ) -> anyhow::Result<()>
    where
        H: Fn(&mut [u8], &mut [u8], RouteKey) + Clone + Send + Sync + 'static,
        D: Fn(usize) + Clone + Send + Sync + 'static,
    {
        listen(
            self.clone(),
            stop_manager,
            worker_name,
            recv_handler,
            down_traffic_hook,
        )
    }
}

fn bind_dual_stack_udp(
    port: u16,
    default_interface: &crate::transport::socket::LocalInterface,
) -> anyhow::Result<UdpSocket> {
    let addr_v6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let socket = crate::transport::socket::bind_udp_ops(addr_v6, false, default_interface)?;
    if let Err(e) = socket.set_recv_buffer_size(2 * 1024 * 1024) {
        log::warn!("set_recv_buffer_size {:?}", e);
    }
    Ok(socket.into())
}

fn bind_ipv4_udp(
    port: u16,
    default_interface: &crate::transport::socket::LocalInterface,
) -> anyhow::Result<UdpSocket> {
    let addr_v4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let socket = crate::transport::socket::bind_udp(addr_v4, default_interface)?;
    if let Err(e) = socket.set_recv_buffer_size(2 * 1024 * 1024) {
        log::warn!("set_recv_buffer_size {:?}", e);
    }
    Ok(socket.into())
}

fn listen<H, D>(
    driver: UdpSocketDriver,
    stop_manager: StopManager,
    worker_name: &str,
    recv_handler: H,
    down_traffic_hook: D,
) -> anyhow::Result<()>
where
    H: Fn(&mut [u8], &mut [u8], RouteKey) + Clone + Send + Sync + 'static,
    D: Fn(usize) + Clone + Send + Sync + 'static,
{
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), NOTIFY)?);
    let wake = waker.clone();
    let worker_name = worker_name.to_string();
    let worker = stop_manager.add_listener(worker_name.clone(), move || {
        if let Err(e) = wake.wake() {
            log::error!("{:?}", e);
        }
    })?;
    thread::Builder::new().name(worker_name).spawn(move || {
        if let Err(e) = listen_loop(driver, poll, recv_handler, down_traffic_hook) {
            log::error!("{:?}", e);
        }
        drop(waker);
        worker.stop_all();
    })?;
    Ok(())
}

fn listen_loop<H, D>(
    driver: UdpSocketDriver,
    mut poll: Poll,
    recv_handler: H,
    down_traffic_hook: D,
) -> io::Result<()>
where
    H: Fn(&mut [u8], &mut [u8], RouteKey) + Clone + Send + Sync + 'static,
    D: Fn(usize) + Clone + Send + Sync + 'static,
{
    let mut buf = [0; BUFFER_SIZE];
    let udp_socket = driver.socket.try_clone()?;
    udp_socket.set_nonblocking(true)?;
    let mut udp = MioUdpSocket::from_std(udp_socket);
    poll.registry()
        .register(&mut udp, Token(1), Interest::READABLE)?;

    let mut events = Events::with_capacity(2);
    let mut extend = [0; BUFFER_SIZE];
    loop {
        if let Err(e) = poll.poll(&mut events, None) {
            crate::ignore_io_interrupted(e)?;
            continue;
        }
        for event in events.iter() {
            match event.token() {
                NOTIFY => return Ok(()),
                Token(1) => {}
                token => {
                    log::error!("invalid udp token {:?}", token);
                    continue;
                }
            }
            loop {
                match udp.recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        let buf = &mut buf[..len];
                        if !should_accept_udp_ingress_frame(buf) {
                            let addr = normalize_recv_addr(addr);
                            if len < HEAD_LEN {
                                log_sampled_udp_ingress_drop(
                                    &SHORT_UDP_INGRESS_DROP_COUNT,
                                    &SHORT_UDP_INGRESS_DROP_LOG_LIMITER,
                                    |count| {
                                        format!(
                                            "dropping too-short udp ingress frames (sample addr={}, len={}, count={})",
                                            addr, len, count
                                        )
                                    },
                                );
                            } else {
                                let head = &buf[..HEAD_LEN];
                                log_sampled_udp_ingress_drop(
                                    &INVALID_UDP_INGRESS_DROP_COUNT,
                                    &INVALID_UDP_INGRESS_DROP_LOG_LIMITER,
                                    |count| {
                                        format!(
                                            "dropping invalid udp ingress frames (sample addr={}, head={:?}, count={})",
                                            addr, head, count
                                        )
                                    },
                                );
                            }
                            continue;
                        }
                        down_traffic_hook(len);
                        recv_handler(
                            buf,
                            &mut extend,
                            RouteKey::new(ConnectProtocol::UDP, normalize_recv_addr(addr)),
                        )
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        log::error!("main_udp_listen={:?}", e);
                    }
                }
            }
        }
    }
}

pub(crate) fn normalize_send_addr(dual_stack: bool, addr: SocketAddr) -> SocketAddr {
    if dual_stack {
        if let SocketAddr::V4(addr_v4) = addr {
            return SocketAddr::V6(std::net::SocketAddrV6::new(
                addr_v4.ip().to_ipv6_mapped(),
                addr_v4.port(),
                0,
                0,
            ));
        }
    }
    addr
}

pub(crate) fn normalize_recv_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(addr_v6) => {
            if let Some(ipv4) = addr_v6.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(ipv4), addr_v6.port())
            } else {
                SocketAddr::V6(addr_v6)
            }
        }
        SocketAddr::V4(_) => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        looks_like_sdl_udp_packet, normalize_recv_addr, normalize_send_addr,
        should_accept_udp_ingress_frame, UdpChannel, UdpSocketDriver,
    };
    use crate::data_plane::route::RouteKey;
    use crate::data_plane::stats::DataPlaneStats;
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
    use std::sync::Arc;
    use std::time::Duration;

    fn test_channel(socket: UdpSocket, dual_stack: bool, enable_traffic: bool) -> UdpChannel {
        UdpChannel {
            driver: UdpSocketDriver {
                socket: Arc::new(socket),
                dual_stack,
            },
            stats: DataPlaneStats::new(enable_traffic),
        }
    }

    #[test]
    fn normalize_send_addr_maps_ipv4_when_dual_stack() {
        let channel = test_channel(UdpSocket::bind("127.0.0.1:0").unwrap(), true, false);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3000));

        let normalized = normalize_send_addr(channel.driver.dual_stack, addr);

        assert_eq!(
            normalized,
            SocketAddr::V6(SocketAddrV6::new(
                Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
                3000,
                0,
                0,
            ))
        );
    }

    #[test]
    fn normalize_recv_addr_restores_ipv4_from_mapped_ipv6() {
        let channel = test_channel(UdpSocket::bind("127.0.0.1:0").unwrap(), true, false);
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped(),
            4000,
            0,
            0,
        ));

        let normalized = normalize_recv_addr(mapped);

        assert_eq!(
            normalized,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 4000))
        );
    }

    #[test]
    fn send_to_uses_single_socket_and_records_up_traffic() {
        let sender = test_channel(UdpSocket::bind("127.0.0.1:0").unwrap(), false, true);
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let payload = b"hello-udp";
        sender
            .send_to(payload, receiver.local_addr().unwrap())
            .unwrap();

        let mut buf = [0_u8; 64];
        let (len, from) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], payload);
        assert_eq!(from, sender.driver.socket.local_addr().unwrap());
        assert_eq!(sender.up_traffic_total(), payload.len() as u64);
        assert_eq!(
            sender.up_traffic_all(),
            Some((
                payload.len() as u64,
                std::collections::HashMap::from([(0_usize, payload.len() as u64)]),
            ))
        );
    }

    #[test]
    fn send_by_key_rejects_non_udp_route() {
        let channel = test_channel(UdpSocket::bind("127.0.0.1:0").unwrap(), false, false);
        let route_key = RouteKey::new(
            ConnectProtocol::QUIC,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3000, 0, 0)),
        );

        let err = channel.send_by_key(b"nope", route_key).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn record_down_traffic_uses_single_channel_slot() {
        let channel = test_channel(UdpSocket::bind("127.0.0.1:0").unwrap(), false, true);

        channel.record_down_traffic(7);
        channel.record_down_traffic(5);

        assert_eq!(channel.down_traffic_total(), 12);
        assert_eq!(
            channel.down_traffic_all(),
            Some((12, std::collections::HashMap::from([(0_usize, 12_u64)])))
        );
    }

    #[test]
    fn accept_udp_ingress_frame_accepts_stun_response_shape() {
        let buf = [
            0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11,
        ];

        assert!(should_accept_udp_ingress_frame(&buf));
    }

    #[test]
    fn looks_like_sdl_udp_packet_accepts_valid_head() {
        let mut buf = [0_u8; 12];
        buf[0] = 3;
        buf[1] = 1;
        buf[3] = 0x11;

        assert!(looks_like_sdl_udp_packet(&buf));
    }

    #[test]
    fn looks_like_sdl_udp_packet_rejects_unknown_version() {
        let mut buf = [0_u8; 12];
        buf[0] = 1;
        buf[1] = 1;
        buf[3] = 0x11;

        assert!(!looks_like_sdl_udp_packet(&buf));
    }

    #[test]
    fn looks_like_sdl_udp_packet_rejects_unknown_protocol() {
        let mut buf = [0_u8; 12];
        buf[0] = 3;
        buf[1] = 99;
        buf[3] = 0x11;

        assert!(!looks_like_sdl_udp_packet(&buf));
    }

    #[test]
    fn looks_like_sdl_udp_packet_rejects_invalid_ttl_shape() {
        let mut buf = [0_u8; 12];
        buf[0] = 3;
        buf[1] = 1;
        buf[3] = 0x01;

        assert!(!looks_like_sdl_udp_packet(&buf));
    }
}
