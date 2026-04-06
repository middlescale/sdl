use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
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
use crate::{DeviceConfig, SdlCallback};
use crate::{DnsProfile, ErrorInfo, ErrorType};

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

#[derive(Clone, Debug)]
pub struct PendingDnsQuery {
    pub client_ip: Ipv4Addr,
    pub dns_server_ip: Ipv4Addr,
    pub client_port: u16,
    pub created_at_ms: u64,
}

#[derive(Clone)]
pub struct SdlRuntime {
    pub config: RuntimeConfig,
    pub dns_profile: Arc<RwLock<Option<DnsProfile>>>,
    pub dns_query_seq: Arc<AtomicU64>,
    pub pending_dns_queries: Arc<Mutex<HashMap<u64, PendingDnsQuery>>>,
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
    #[cfg(all(feature = "integrated_tun", target_os = "linux"))]
    pub applied_dns_interface: Arc<Mutex<Option<String>>>,
}

impl SdlRuntime {
    pub fn route_manager(&self) -> RouteManager {
        self.route_manager.clone()
    }

    pub fn peer_info(&self, ip: &Ipv4Addr) -> Option<PeerDeviceInfo> {
        self.peer_state.lock().1.get(ip).cloned()
    }

    pub fn replace_dns_profile(&self, profile: Option<DnsProfile>) -> bool {
        let mut guard = self.dns_profile.write();
        if *guard == profile {
            return false;
        }
        *guard = profile;
        true
    }

    pub fn is_dns_service_ip(&self, ip: Ipv4Addr) -> bool {
        self.dns_profile
            .read()
            .as_ref()
            .map(|profile| {
                profile.servers.iter().any(|server| {
                    server
                        .parse::<Ipv4Addr>()
                        .map(|candidate| candidate == ip)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    pub fn remember_dns_query(
        &self,
        client_ip: Ipv4Addr,
        dns_server_ip: Ipv4Addr,
        client_port: u16,
    ) -> u64 {
        let request_id = self
            .dns_query_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let now_ms = crate::handle::now_time() as u64;
        let mut pending = self.pending_dns_queries.lock();
        pending.retain(|_, query| now_ms.saturating_sub(query.created_at_ms) < 30_000);
        pending.insert(
            request_id,
            PendingDnsQuery {
                client_ip,
                dns_server_ip,
                client_port,
                created_at_ms: now_ms,
            },
        );
        request_id
    }

    pub fn forget_dns_query(&self, request_id: u64) {
        self.pending_dns_queries.lock().remove(&request_id);
    }

    pub fn take_dns_query(&self, request_id: u64) -> Option<PendingDnsQuery> {
        self.pending_dns_queries.lock().remove(&request_id)
    }

    #[cfg(feature = "integrated_tun")]
    pub fn is_suspended(&self) -> bool {
        self.suspended.load()
    }

    #[cfg(feature = "integrated_tun")]
    pub fn suspend(&self) {
        let _guard = self.tun_lifecycle.lock();
        self.suspended.store(true);
        self.clear_applied_dns_profile();
        self.tun_device_helper.stop();
    }

    #[cfg(feature = "integrated_tun")]
    pub fn resume<Call: SdlCallback>(&self, callback: &Call) -> anyhow::Result<()> {
        let _guard = self.tun_lifecycle.lock();
        self.suspended.store(false);
        self.rebuild_tun_locked(callback)
    }

    #[cfg(feature = "integrated_tun")]
    pub fn sync_tun_with_current_device<Call: SdlCallback>(
        &self,
        callback: &Call,
    ) -> anyhow::Result<()> {
        let _guard = self.tun_lifecycle.lock();
        if self.suspended.load() {
            self.clear_applied_dns_profile();
            self.tun_device_helper.stop();
            return Ok(());
        }
        self.rebuild_tun_locked(callback)
    }

    #[cfg(feature = "integrated_tun")]
    fn rebuild_tun_locked<Call: SdlCallback>(&self, callback: &Call) -> anyhow::Result<()> {
        let current_device = self.current_device.load();
        if current_device.virtual_ip.is_unspecified()
            || current_device.virtual_gateway.is_unspecified()
            || current_device.virtual_netmask.is_unspecified()
        {
            return Ok(());
        }
        self.clear_applied_dns_profile();
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
        #[cfg(target_os = "linux")]
        let tun_name = device.name().unwrap_or_else(|_| "sdl-tun".to_string());
        self.tun_device_helper.start(device)?;
        #[cfg(target_os = "linux")]
        self.apply_dns_profile(&tun_name, callback);
        Ok(())
    }

    #[cfg(feature = "integrated_tun")]
    fn clear_applied_dns_profile(&self) {
        #[cfg(target_os = "linux")]
        {
            if let Some(interface_name) = self.applied_dns_interface.lock().take() {
                if let Err(err) = crate::util::linux_dns::revert_split_dns(&interface_name) {
                    log::warn!(
                        "failed to revert split DNS for interface {}: {:?}",
                        interface_name,
                        err
                    );
                }
            }
        }
    }

    #[cfg(all(feature = "integrated_tun", target_os = "linux"))]
    fn apply_dns_profile<Call: SdlCallback>(&self, interface_name: &str, callback: &Call) {
        let profile = self.dns_profile.read().clone();
        let Some(profile) = profile else {
            return;
        };
        if profile.servers.is_empty() || profile.match_domains.is_empty() {
            return;
        }
        match crate::util::linux_dns::apply_split_dns(interface_name, &profile) {
            Ok(()) => {
                *self.applied_dns_interface.lock() = Some(interface_name.to_string());
            }
            Err(err) => {
                log::warn!(
                    "failed to apply split DNS for interface {}: {:?}",
                    interface_name,
                    err
                );
                callback.error(ErrorInfo::new_msg(
                    ErrorType::Warn,
                    format!("split DNS apply failed on {}: {:?}", interface_name, err),
                ));
            }
        }
    }

    #[cfg(all(feature = "integrated_tun", target_os = "linux"))]
    pub fn revert_dns_on_shutdown(&self) {
        self.clear_applied_dns_profile();
    }
}
