use crossbeam_utils::atomic::AtomicCell;
use std::net::Ipv4Addr;

pub mod callback;
mod extension;
pub mod recv_data;
pub mod registrar;
#[cfg(feature = "integrated_tun")]
pub mod tun_tap;

const SELF_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 2);

/// Shared peer-device table, protected by a Mutex.
/// `epoch` increments every time the server pushes a new device list so stale updates can be
/// detected and dropped.
#[derive(Debug, Default)]
pub struct PeerState {
    pub epoch: u16,
    pub devices: std::collections::HashMap<Ipv4Addr, PeerDeviceInfo>,
}
pub(crate) const CONTROL_VIP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 1);

pub fn now_time() -> u64 {
    let now = std::time::SystemTime::now();
    if let Ok(timestamp) = now.duration_since(std::time::UNIX_EPOCH) {
        timestamp.as_secs() * 1000 + u64::from(timestamp.subsec_millis())
    } else {
        0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDeviceInfo {
    pub virtual_ip: Ipv4Addr,
    pub name: String,
    pub status: PeerDeviceStatus,
    pub device_id: String,
    pub device_pub_key: Vec<u8>,
}

impl PeerDeviceInfo {
    pub fn new(
        virtual_ip: Ipv4Addr,
        name: String,
        status: u8,
        device_id: String,
        device_pub_key: Vec<u8>,
    ) -> Self {
        Self {
            virtual_ip,
            name,
            status: PeerDeviceStatus::from(status),
            device_id,
            device_pub_key,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PeerDeviceStatus {
    Online,
    Offline,
}

impl PeerDeviceStatus {
    pub fn is_online(&self) -> bool {
        self == &PeerDeviceStatus::Online
    }
    pub fn is_offline(&self) -> bool {
        self == &PeerDeviceStatus::Offline
    }
}

impl Into<u8> for PeerDeviceStatus {
    fn into(self) -> u8 {
        match self {
            PeerDeviceStatus::Online => 0,
            PeerDeviceStatus::Offline => 1,
        }
    }
}

impl From<u8> for PeerDeviceStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PeerDeviceStatus::Online,
            _ => PeerDeviceStatus::Offline,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConnectStatus {
    Connecting,
    Connected,
}

impl ConnectStatus {
    pub fn online(&self) -> bool {
        self == &ConnectStatus::Connected
    }
    pub fn offline(&self) -> bool {
        self == &ConnectStatus::Connecting
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CurrentDeviceInfo {
    //本机虚拟IP
    pub virtual_ip: Ipv4Addr,
    //子网掩码
    pub virtual_netmask: Ipv4Addr,
    //虚拟网关
    pub virtual_gateway: Ipv4Addr,
    //网络地址
    pub virtual_network: Ipv4Addr,
    //直接广播地址
    pub broadcast_ip: Ipv4Addr,
    //连接状态
    pub status: ConnectStatus,
}

impl CurrentDeviceInfo {
    pub fn new(virtual_ip: Ipv4Addr, virtual_netmask: Ipv4Addr, virtual_gateway: Ipv4Addr) -> Self {
        let broadcast_ip = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_gateway.octets());
        let broadcast_ip = Ipv4Addr::from(broadcast_ip);
        let virtual_network = u32::from_be_bytes(virtual_netmask.octets())
            & u32::from_be_bytes(virtual_gateway.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        Self {
            virtual_ip,
            virtual_netmask,
            virtual_gateway,
            virtual_network,
            broadcast_ip,
            status: ConnectStatus::Connecting,
        }
    }
    pub fn new0() -> Self {
        Self {
            virtual_ip: Ipv4Addr::UNSPECIFIED,
            virtual_gateway: Ipv4Addr::UNSPECIFIED,
            virtual_netmask: Ipv4Addr::UNSPECIFIED,
            virtual_network: Ipv4Addr::UNSPECIFIED,
            broadcast_ip: Ipv4Addr::UNSPECIFIED,
            status: ConnectStatus::Connecting,
        }
    }
    pub fn update(
        &mut self,
        virtual_ip: Ipv4Addr,
        virtual_netmask: Ipv4Addr,
        virtual_gateway: Ipv4Addr,
    ) {
        let broadcast_ip = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_ip.octets());
        let broadcast_ip = Ipv4Addr::from(broadcast_ip);
        let virtual_network =
            u32::from_be_bytes(virtual_netmask.octets()) & u32::from_be_bytes(virtual_ip.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        self.virtual_ip = virtual_ip;
        self.virtual_netmask = virtual_netmask;
        self.virtual_gateway = virtual_gateway;
        self.broadcast_ip = broadcast_ip;
        self.virtual_network = virtual_network;
    }
    #[inline]
    pub fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }
    #[inline]
    pub fn virtual_gateway(&self) -> Ipv4Addr {
        self.virtual_gateway
    }
    #[inline]
    pub fn is_gateway_vip(&self, ip: &Ipv4Addr) -> bool {
        &self.virtual_gateway == ip
    }
    #[inline]
    pub fn is_control_vip(&self, ip: &Ipv4Addr) -> bool {
        ip == &CONTROL_VIP
    }
    #[inline]
    pub fn not_in_network(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & u32::from(self.virtual_netmask) != u32::from(self.virtual_network)
    }
}
pub fn change_status(
    current_device: &AtomicCell<CurrentDeviceInfo>,
    connect_status: ConnectStatus,
) -> CurrentDeviceInfo {
    loop {
        let cur = current_device.load();
        let mut new_info = cur;
        new_info.status = connect_status;
        if current_device.compare_exchange(cur, new_info).is_ok() {
            return new_info;
        }
    }
}
