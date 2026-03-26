use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[cfg(feature = "integrated_tun")]
use anyhow::anyhow;
use crossbeam_utils::atomic::AtomicCell;
use ed25519_dalek::SigningKey;
use parking_lot::{Mutex, RwLock};

use crate::cipher::CipherModel;
use crate::control::ControlSession;
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::stats::DataPlaneStats;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::punch::NatInfo;
use crate::nat::punch_workers::PunchCoordinator;
use crate::nat::NatTest;
use crate::transport::udp_channel::UdpChannel;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::create_device;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::tun_create_helper::TunDeviceHelper;
use crate::util::PeerCryptoManager;
#[cfg(feature = "integrated_tun")]
use crate::{DeviceConfig, VntCallback};

#[derive(Clone, Debug, Default)]
pub struct AuthRequestConfig {
    pub user_id: Option<String>,
    pub group: Option<String>,
    pub ticket: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub name: String,
    pub token: String,
    pub ip: Option<Ipv4Addr>,
    pub cipher_model: CipherModel,
    pub device_id: String,
    pub device_pub_key: Vec<u8>,
    pub server_addr: String,
    pub name_servers: Vec<String>,
    pub mtu: u32,
    #[cfg(feature = "integrated_tun")]
    #[cfg(target_os = "windows")]
    pub tap: bool,
    #[cfg(feature = "integrated_tun")]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
    pub default_interface: crate::transport::socket::LocalInterface,
    pub auth_request: Arc<RwLock<AuthRequestConfig>>,
}

#[derive(Clone)]
pub struct VntRuntime {
    pub config: RuntimeConfig,
    pub current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    pub device_signing_key: Arc<SigningKey>,
    pub peer_crypto: Arc<PeerCryptoManager>,
    pub nat_test: NatTest,
    pub peer_state: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    pub peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
    pub external_route: ExternalRoute,
    pub out_external_route: AllowExternalRoute,
    pub control_session: ControlSession,
    pub gateway_sessions: GatewaySessions,
    pub route_manager: RouteManager,
    pub data_plane_stats: DataPlaneStats,
    pub udp_channel: UdpChannel,
    pub data_channel: DataChannel,
    pub punch_coordinator: PunchCoordinator,
    #[cfg(feature = "integrated_tun")]
    pub suspended: Arc<AtomicCell<bool>>,
    #[cfg(feature = "integrated_tun")]
    pub tun_lifecycle: Arc<Mutex<()>>,
    #[cfg(feature = "integrated_tun")]
    pub tun_device_helper: TunDeviceHelper,
}

impl VntRuntime {
    pub fn route_manager(&self) -> RouteManager {
        self.route_manager.clone()
    }

    pub fn peer_info(&self, ip: &Ipv4Addr) -> Option<PeerDeviceInfo> {
        self.peer_state.lock().1.get(ip).cloned()
    }

    #[cfg(feature = "integrated_tun")]
    pub fn is_suspended(&self) -> bool {
        self.suspended.load()
    }

    #[cfg(feature = "integrated_tun")]
    pub fn suspend(&self) {
        let _guard = self.tun_lifecycle.lock();
        self.suspended.store(true);
        self.tun_device_helper.stop();
    }

    #[cfg(feature = "integrated_tun")]
    pub fn resume<Call: VntCallback>(&self, callback: &Call) -> anyhow::Result<()> {
        let _guard = self.tun_lifecycle.lock();
        self.suspended.store(false);
        self.rebuild_tun_locked(callback)
    }

    #[cfg(feature = "integrated_tun")]
    pub fn sync_tun_with_current_device<Call: VntCallback>(
        &self,
        callback: &Call,
    ) -> anyhow::Result<()> {
        let _guard = self.tun_lifecycle.lock();
        if self.suspended.load() {
            self.tun_device_helper.stop();
            return Ok(());
        }
        self.rebuild_tun_locked(callback)
    }

    #[cfg(feature = "integrated_tun")]
    fn rebuild_tun_locked<Call: VntCallback>(&self, callback: &Call) -> anyhow::Result<()> {
        let current_device = self.current_device.load();
        if current_device.virtual_ip.is_unspecified()
            || current_device.virtual_gateway.is_unspecified()
            || current_device.virtual_netmask.is_unspecified()
        {
            return Ok(());
        }
        self.tun_device_helper.stop();
        let device_config = DeviceConfig::new(
            #[cfg(target_os = "windows")]
            self.config.tap,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            self.config.device_name.clone(),
            self.config.mtu,
            current_device.virtual_ip,
            current_device.virtual_netmask,
            current_device.virtual_gateway,
            current_device.virtual_network,
            self.external_route.to_route(),
        );
        let device = create_device(device_config, callback).map_err(|e| anyhow!("{}", e))?;
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        {
            let tun_info = crate::handle::callback::DeviceInfo::new(
                device.name().unwrap_or("unknown".into()),
                "".into(),
            );
            callback.create_tun(tun_info);
        }
        self.tun_device_helper.start(device)?;
        Ok(())
    }
}
