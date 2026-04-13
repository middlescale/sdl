use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::{Div, Mul};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use rand::prelude::SliceRandom;
use rand::Rng;

use crate::data_plane::route_manager::RouteManager;
use crate::handle::CurrentDeviceInfo;
use crate::nat::{is_ipv4_global, NatTest};
use crate::proto::message::{PunchNatModel, PunchNatType};
use crate::transport::udp_channel::UdpChannel;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum PunchModel {
    All,
    IPv4,
    IPv6,
    IPv4Udp,
    IPv6Udp,
}

impl PunchModel {
    pub fn use_udp(&self) -> bool {
        true
    }
    pub fn use_ipv6(&self) -> bool {
        self == &PunchModel::All || self == &PunchModel::IPv6 || self == &PunchModel::IPv6Udp
    }
    pub fn use_ipv4(&self) -> bool {
        self == &PunchModel::All || self == &PunchModel::IPv4 || self == &PunchModel::IPv4Udp
    }
}

impl FromStr for PunchModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "ipv4" => Ok(PunchModel::IPv4),
            "ipv6" => Ok(PunchModel::IPv6),
            "ipv4-udp" => Ok(PunchModel::IPv4Udp),
            "ipv6-udp" => Ok(PunchModel::IPv6Udp),
            "all" => Ok(PunchModel::All),
            _ => Err(format!(
                "not match '{}', enum: ipv4/ipv4-udp/ipv6/ipv6-udp/all",
                s
            )),
        }
    }
}

impl Default for PunchModel {
    fn default() -> Self {
        PunchModel::All
    }
}
impl From<PunchModel> for PunchNatModel {
    fn from(value: PunchModel) -> Self {
        match value {
            PunchModel::All => PunchNatModel::All,
            PunchModel::IPv4 => PunchNatModel::IPv4,
            PunchModel::IPv6 => PunchNatModel::IPv6,
            PunchModel::IPv4Udp => PunchNatModel::IPv4Udp,
            PunchModel::IPv6Udp => PunchNatModel::IPv6Udp,
        }
    }
}

impl Into<PunchModel> for PunchNatModel {
    fn into(self) -> PunchModel {
        match self {
            PunchNatModel::All => PunchModel::All,
            PunchNatModel::IPv4 => PunchModel::IPv4,
            PunchNatModel::IPv6 => PunchModel::IPv6,
            PunchNatModel::IPv4Udp => PunchModel::IPv4Udp,
            PunchNatModel::IPv6Udp => PunchModel::IPv6Udp,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NatInfo {
    public_ips: Vec<Ipv4Addr>,
    public_ports: Vec<u16>,
    public_udp_endpoints: Vec<SocketAddr>,
    public_port_range: u16,
    nat_type: NatType,
    local_ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    udp_ports: Vec<u16>,
    punch_model: PunchModel,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum NatType {
    Symmetric,
    Cone,
}

impl NatType {
    pub fn is_cone(&self) -> bool {
        self == &NatType::Cone
    }
}
impl From<NatType> for PunchNatType {
    fn from(value: NatType) -> Self {
        match value {
            NatType::Symmetric => PunchNatType::Symmetric,
            NatType::Cone => PunchNatType::Cone,
        }
    }
}

impl Into<NatType> for PunchNatType {
    fn into(self) -> NatType {
        match self {
            PunchNatType::Symmetric => NatType::Symmetric,
            PunchNatType::Cone => NatType::Cone,
        }
    }
}

impl NatInfo {
    pub fn new(
        mut public_ips: Vec<Ipv4Addr>,
        public_ports: Vec<u16>,
        mut public_udp_endpoints: Vec<SocketAddr>,
        public_port_range: u16,
        mut local_ipv4: Option<Ipv4Addr>,
        mut ipv6: Option<Ipv6Addr>,
        udp_ports: Vec<u16>,
        mut nat_type: NatType,
        punch_model: PunchModel,
    ) -> Self {
        public_ips.retain(|ip| {
            !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
        });
        if public_ips.len() > 1 {
            nat_type = NatType::Symmetric;
        }
        public_udp_endpoints.retain(|addr| match addr {
            SocketAddr::V4(addr) => is_ipv4_global(addr.ip()) && addr.port() != 0,
            SocketAddr::V6(addr) => {
                !addr.ip().is_multicast()
                    && !addr.ip().is_unspecified()
                    && !addr.ip().is_loopback()
                    && addr.port() != 0
            }
        });
        for addr in &public_udp_endpoints {
            match addr {
                SocketAddr::V4(addr) => {
                    if !public_ips.contains(addr.ip()) {
                        public_ips.push(*addr.ip());
                    }
                }
                SocketAddr::V6(addr) => {
                    if ipv6.is_none() {
                        ipv6 = Some(*addr.ip());
                    }
                }
            }
        }
        if let Some(ip) = local_ipv4 {
            if ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() || ip.is_loopback() {
                local_ipv4 = None
            }
        }
        if let Some(ip) = ipv6 {
            if ip.is_multicast() || ip.is_unspecified() || ip.is_loopback() {
                ipv6 = None
            }
        }
        Self {
            public_ips,
            public_ports,
            public_udp_endpoints,
            public_port_range,
            local_ipv4,
            ipv6,
            udp_ports,
            nat_type,
            punch_model,
        }
    }
    pub fn update_addr(&mut self, ip: Ipv4Addr, port: u16) -> bool {
        let mut updated = false;
        if port != 0 {
            if let Some(public_port) = self.public_ports.get_mut(0) {
                if *public_port != port {
                    updated = true;
                    log::info!("端口变化={}:{}", ip, port)
                }
                *public_port = port;
            }
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            if !self.public_udp_endpoints.contains(&addr) {
                self.public_udp_endpoints.push(addr);
                updated = true;
            }
        }
        if is_ipv4_global(&ip) {
            if !self.public_ips.contains(&ip) {
                self.public_ips.push(ip);
                updated = true;
                log::info!("ip变化={},{:?}", ip, self.public_ips)
            }
        }
        updated
    }
    pub fn local_ipv4(&self) -> Option<Ipv4Addr> {
        self.local_ipv4
    }
    pub fn public_ips(&self) -> &[Ipv4Addr] {
        &self.public_ips
    }
    pub fn public_ports(&self) -> &[u16] {
        &self.public_ports
    }
    pub fn public_udp_endpoints(&self) -> &[SocketAddr] {
        &self.public_udp_endpoints
    }
    pub fn public_port_range(&self) -> u16 {
        self.public_port_range
    }
    pub fn nat_type(&self) -> NatType {
        self.nat_type
    }
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }
    pub fn udp_ports(&self) -> &[u16] {
        &self.udp_ports
    }
    pub fn punch_model(&self) -> PunchModel {
        self.punch_model
    }
    pub(crate) fn replace_probe_result(
        &mut self,
        nat_type: NatType,
        public_udp_endpoints: Vec<SocketAddr>,
        public_port_range: u16,
        local_ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) {
        self.nat_type = nat_type;
        self.public_ips = public_udp_endpoints
            .iter()
            .filter_map(|addr| match addr {
                SocketAddr::V4(addr) => Some(*addr.ip()),
                SocketAddr::V6(_) => None,
            })
            .collect();
        self.public_ports = public_udp_endpoints.iter().map(SocketAddr::port).collect();
        self.public_udp_endpoints = public_udp_endpoints;
        self.public_port_range = public_port_range;
        self.local_ipv4 = local_ipv4;
        self.ipv6 = ipv6;
    }
    pub fn local_udp_ipv4addr(&self) -> Option<SocketAddr> {
        let port = *self.udp_ports.first()?;
        if let Some(local_ipv4) = self.local_ipv4 {
            Some(SocketAddr::V4(SocketAddrV4::new(local_ipv4, port)))
        } else {
            None
        }
    }
    pub fn local_udp_ipv6addr(&self) -> Option<SocketAddr> {
        let port = *self.udp_ports.first()?;
        if let Some(ipv6) = self.ipv6 {
            Some(SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0)))
        } else {
            None
        }
    }
    pub fn local_udp_endpoints(&self) -> Vec<SocketAddr> {
        let mut endpoints = Vec::with_capacity(self.udp_ports.len() * 2);
        for port in &self.udp_ports {
            if *port == 0 {
                continue;
            }
            if let Some(local_ipv4) = self.local_ipv4 {
                endpoints.push(SocketAddr::V4(SocketAddrV4::new(local_ipv4, *port)));
            }
            if let Some(ipv6) = self.ipv6 {
                endpoints.push(SocketAddr::V6(SocketAddrV6::new(ipv6, *port, 0, 0)));
            }
        }
        endpoints
    }

    pub fn matches_candidate_endpoint(&self, endpoint: SocketAddr) -> bool {
        if self.public_udp_endpoints.contains(&endpoint) {
            return true;
        }
        match endpoint {
            SocketAddr::V4(addr) => {
                if self
                    .local_ipv4
                    .map(|ip| ip == *addr.ip() && self.udp_ports.contains(&addr.port()))
                    .unwrap_or(false)
                {
                    return true;
                }
                if self.public_udp_endpoints.is_empty() {
                    if self.public_ips.contains(addr.ip())
                        && self.public_ports.contains(&addr.port())
                    {
                        return true;
                    }
                    if self.nat_type == NatType::Symmetric
                        && self.public_ips.contains(addr.ip())
                        && self.public_port_range > 0
                    {
                        if let Some(base_port) = self.public_ports.first().copied() {
                            let min_port = base_port.saturating_sub(self.public_port_range);
                            let max_port = base_port.saturating_add(self.public_port_range);
                            if addr.port() >= min_port && addr.port() <= max_port {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            SocketAddr::V6(addr) => self
                .ipv6
                .map(|ip| ip == *addr.ip() && self.udp_ports.contains(&addr.port()))
                .unwrap_or(false),
        }
    }
}

#[derive(Clone)]
pub struct Punch {
    udp_channel: UdpChannel,
    route_manager: RouteManager,
    port_vec: Vec<u16>,
    port_index: HashMap<Ipv4Addr, usize>,
    punch_model: PunchModel,
    nat_test: NatTest,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
}

impl Punch {
    pub fn new(
        udp_channel: UdpChannel,
        route_manager: RouteManager,
        punch_model: PunchModel,
        nat_test: NatTest,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ) -> Self {
        let mut port_vec: Vec<u16> = (1..65535).collect();
        port_vec.push(65535);
        let mut rng = rand::thread_rng();
        port_vec.shuffle(&mut rng);
        Punch {
            udp_channel,
            route_manager,
            port_vec,
            port_index: HashMap::new(),
            punch_model,
            nat_test,
            current_device,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NatInfo, NatType, PunchModel};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn nat_info_matches_explicit_candidate_endpoint() {
        let endpoint = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 4000));
        let nat_info = NatInfo::new(
            vec![Ipv4Addr::new(198, 51, 100, 10)],
            vec![4000],
            vec![endpoint],
            0,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            None,
            vec![4000],
            NatType::Cone,
            PunchModel::IPv4Udp,
        );

        assert!(nat_info.matches_candidate_endpoint(endpoint));
        assert!(
            !nat_info.matches_candidate_endpoint(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(198, 51, 100, 11),
                4000,
            )))
        );
    }

    #[test]
    fn nat_info_matches_symmetric_port_range_when_explicit_endpoints_absent() {
        let nat_info = NatInfo::new(
            vec![Ipv4Addr::new(198, 51, 100, 10)],
            vec![5000],
            Vec::new(),
            20,
            None,
            None,
            vec![5000],
            NatType::Symmetric,
            PunchModel::IPv4Udp,
        );

        assert!(
            nat_info.matches_candidate_endpoint(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(198, 51, 100, 10),
                5010,
            )))
        );
        assert!(
            !nat_info.matches_candidate_endpoint(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(198, 51, 100, 10),
                6000,
            )))
        );
    }
}

impl Punch {
    pub fn punch(
        &mut self,
        buf: &[u8],
        id: Ipv4Addr,
        mut nat_info: NatInfo,
        count: usize,
    ) -> io::Result<()> {
        if self.route_manager.has_enough_direct_paths(&id) {
            log::info!("已打洞成功,无需打洞:{:?}", id);
            return Ok(());
        }
        let device_info = self.current_device.load();

        nat_info
            .public_ips
            .retain(|ip| is_ipv4_global(ip) && device_info.not_in_network(*ip));
        nat_info.public_ports.retain(|port| *port != 0);
        nat_info.udp_ports.retain(|port| *port != 0);

        nat_info.local_ipv4 = nat_info
            .local_ipv4
            .filter(|ip| device_info.not_in_network(*ip));
        if !self.punch_model.use_udp() || !nat_info.punch_model.use_udp() {
            return Ok(());
        }
        if self.punch_model.use_ipv6() && nat_info.punch_model.use_ipv6() {
            if let Some(ipv6_addr) = nat_info.local_udp_ipv6addr() {
                if !self.nat_test.is_local_address(false, ipv6_addr) {
                    let rs = self.udp_channel.send_to_addr(buf, ipv6_addr);
                    log::info!("发送到ipv6地址:{:?},rs={:?} {}", ipv6_addr, rs, id);
                }
            }
        }
        let has_explicit_public_endpoints = !nat_info.public_udp_endpoints.is_empty();
        for addr in &nat_info.public_udp_endpoints {
            if !self.nat_test.is_local_address(false, *addr) {
                let _ = self.udp_channel.send_to_addr(buf, *addr);
                thread::sleep(Duration::from_millis(3));
            }
        }
        if !self.punch_model.use_ipv4() || !nat_info.punch_model.use_ipv4() {
            return Ok(());
        }
        if let Some(ipv4_addr) = nat_info.local_udp_ipv4addr() {
            if !self.nat_test.is_local_address(false, ipv4_addr) {
                let _ = self.udp_channel.send_to_addr(buf, ipv4_addr);
            }
        }
        if !has_explicit_public_endpoints {
            // 可能是开放了端口的，需要打洞
            for port in &nat_info.udp_ports {
                if *port == 0 {
                    continue;
                }
                for ip in &nat_info.public_ips {
                    if ip.is_unspecified() {
                        continue;
                    }
                    let addr = SocketAddrV4::new(*ip, *port);
                    let _ = self.udp_channel.send_to_addr(buf, addr.into());
                    thread::sleep(Duration::from_millis(3));
                }
            }
        }

        match nat_info.nat_type {
            NatType::Symmetric => {
                // 假设对方绑定n个端口，通过NAT对外映射出n个 公网ip:公网端口，自己随机尝试k次的情况下
                // 猜中的概率 p = 1-((65535-n)/65535)*((65535-n-1)/(65535-1))*...*((65535-n-k+1)/(65535-k+1))
                // n取76，k取600，猜中的概率就超过50%了
                // 前提 自己是锥形网络，否则猜中了也通信不了

                //预测范围内最多发送max_k1个包
                let max_k1 = 60;
                //全局最多发送max_k2个包
                let mut max_k2: usize = rand::thread_rng().gen_range(600..800);
                if count > 2 {
                    //递减探测规模
                    max_k2 = max_k2.mul(2).div(count).max(max_k1 as usize);
                }
                let port = nat_info.public_ports.get(0).map(|e| *e).unwrap_or(0);
                if nat_info.public_port_range < max_k1 * 3 {
                    //端口变化不大时，在预测的范围内随机发送
                    let min_port = if port > nat_info.public_port_range {
                        port - nat_info.public_port_range
                    } else {
                        1
                    };
                    let (max_port, overflow) = port.overflowing_add(nat_info.public_port_range);
                    let max_port = if overflow { 65535 } else { max_port };
                    let k = if max_port - min_port + 1 > max_k1 {
                        max_k1 as usize
                    } else {
                        (max_port - min_port + 1) as usize
                    };
                    let mut nums: Vec<u16> = (min_port..=max_port).collect();
                    nums.shuffle(&mut rand::thread_rng());
                    self.punch_symmetric(&nums[..k], buf, &nat_info.public_ips, max_k1 as usize)?;
                }
                let start = *self.port_index.entry(id.clone()).or_insert(0);
                let mut end = start + max_k2;
                if end > self.port_vec.len() {
                    end = self.port_vec.len();
                }
                let mut index = start
                    + self.punch_symmetric(
                        &self.port_vec[start..end],
                        buf,
                        &nat_info.public_ips,
                        max_k2,
                    )?;
                if index >= self.port_vec.len() {
                    index = 0
                }
                self.port_index.insert(id, index);
            }
            NatType::Cone => {
                let is_cone = self.nat_test.nat_info().nat_type.is_cone();
                for port in nat_info
                    .public_ports
                    .iter()
                    .copied()
                    .filter(|port| *port != 0)
                {
                    for ip in &nat_info.public_ips {
                        if ip.is_unspecified() {
                            continue;
                        }
                        let addr = SocketAddr::V4(SocketAddrV4::new(*ip, port));
                        self.udp_channel.send_to_addr(buf, addr)?;
                        thread::sleep(Duration::from_millis(2));
                    }
                    if !is_cone {
                        // 单端口模型下，对称侧只需要从当前绑定端口发送一遍
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn punch_symmetric(
        &self,
        ports: &[u16],
        buf: &[u8],
        ips: &Vec<Ipv4Addr>,
        max: usize,
    ) -> io::Result<usize> {
        let mut count = 0;
        for (index, port) in ports.iter().enumerate() {
            for pub_ip in ips {
                count += 1;
                if count == max {
                    return Ok(index);
                }
                let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, *port));
                self.udp_channel.send_to_addr(buf, addr)?;
                thread::sleep(Duration::from_millis(3));
            }
        }
        Ok(ports.len())
    }
}
