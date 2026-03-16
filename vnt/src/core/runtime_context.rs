use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

use crate::channel::punch::NatInfo;
use crate::cipher::Cipher;
use crate::control::ControlSession;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::maintain::PunchCoordinator;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::nat::NatTest;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::tun_create_helper::TunDeviceHelper;

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub name: String,
    pub token: String,
    pub ip: Option<Ipv4Addr>,
    pub client_secret_hash: Option<[u8; 16]>,
    pub server_secret: bool,
    pub device_id: String,
    pub device_pub_key: Vec<u8>,
    pub device_pub_key_alg: String,
    pub server_addr: String,
    pub name_servers: Vec<String>,
    pub mtu: u32,
    #[cfg(feature = "integrated_tun")]
    #[cfg(target_os = "windows")]
    pub tap: bool,
    #[cfg(feature = "integrated_tun")]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
    pub default_interface: crate::channel::socket::LocalInterface,
    pub auth_user_id: Option<String>,
    pub auth_group: Option<String>,
    pub auth_ticket: Option<String>,
    pub auth_only: bool,
}

#[derive(Clone)]
pub struct VntRuntime {
    pub config: RuntimeConfig,
    pub current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    pub nat_test: NatTest,
    pub device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    pub peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
    pub external_route: ExternalRoute,
    pub out_external_route: AllowExternalRoute,
    pub client_cipher: Cipher,
    pub control_session: ControlSession,
    pub gateway_sessions: GatewaySessions,
    pub punch_coordinator: PunchCoordinator,
    #[cfg(feature = "ip_proxy")]
    #[cfg(feature = "integrated_tun")]
    pub ip_proxy_map: Option<IpProxyMap>,
    #[cfg(feature = "integrated_tun")]
    pub tun_device_helper: TunDeviceHelper,
}
