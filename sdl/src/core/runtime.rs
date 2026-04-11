use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

#[cfg(feature = "integrated_tun")]
use anyhow::anyhow;
use crossbeam_utils::atomic::AtomicCell;
use ed25519_dalek::SigningKey;
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Map, Value};

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
use crate::util::{DebugWatch, PeerCryptoManager};
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

pub struct PendingRenameRequest {
    pub responder: mpsc::Sender<Result<RenameRequestOutcome, String>>,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenameRequestOutcome {
    Applied(String),
    PendingApproval,
}

#[derive(Clone)]
pub struct SdlRuntime {
    pub config: RuntimeConfig,
    pub dns_profile: Arc<RwLock<Option<DnsProfile>>>,
    pub dns_query_seq: Arc<AtomicU64>,
    pub pending_dns_queries: Arc<Mutex<HashMap<u64, PendingDnsQuery>>>,
    pub rename_request_seq: Arc<AtomicU64>,
    pub pending_rename_requests: Arc<Mutex<HashMap<u64, PendingRenameRequest>>>,
    pub current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    pub device_signing_key: Arc<SigningKey>,
    pub peer_crypto: Arc<PeerCryptoManager>,
    pub debug_watch: DebugWatch,
    pub nat_test: NatTest,
    pub peer_state: Arc<Mutex<crate::handle::PeerState>>,
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
    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "macos", target_os = "windows")
    ))]
    pub applied_dns_domains: Arc<Mutex<Vec<String>>>,
}

impl SdlRuntime {
    pub fn route_manager(&self) -> RouteManager {
        self.route_manager.clone()
    }

    pub fn peer_info(&self, ip: &Ipv4Addr) -> Option<PeerDeviceInfo> {
        self.peer_state.lock().devices.get(ip).cloned()
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

    pub fn remember_rename_request(
        &self,
        responder: mpsc::Sender<Result<RenameRequestOutcome, String>>,
    ) -> u64 {
        let request_id = self
            .rename_request_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let now_ms = crate::handle::now_time() as u64;
        let mut pending = self.pending_rename_requests.lock();
        pending.retain(|_, request| now_ms.saturating_sub(request.created_at_ms) < 30_000);
        pending.insert(
            request_id,
            PendingRenameRequest {
                responder,
                created_at_ms: now_ms,
            },
        );
        request_id
    }

    pub fn forget_rename_request(&self, request_id: u64) {
        self.pending_rename_requests.lock().remove(&request_id);
    }

    pub fn complete_rename_request(
        &self,
        request_id: u64,
        result: Result<RenameRequestOutcome, String>,
    ) -> bool {
        let Some(request) = self.pending_rename_requests.lock().remove(&request_id) else {
            return false;
        };
        let _ = request.responder.send(result);
        true
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
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let tun_name = device.name().unwrap_or_else(|_| "sdl-tun".to_string());
        self.tun_device_helper.start(device)?;
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
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
        #[cfg(target_os = "macos")]
        {
            let mut applied_domains = self.applied_dns_domains.lock();
            let domains = std::mem::take(&mut *applied_domains);
            drop(applied_domains);
            if let Err(err) = crate::util::macos_dns::revert_split_dns(&domains) {
                log::warn!(
                    "failed to revert split DNS domains {:?}: {:?}",
                    domains,
                    err
                );
            }
        }
        #[cfg(target_os = "windows")]
        {
            let mut applied_domains = self.applied_dns_domains.lock();
            let domains = std::mem::take(&mut *applied_domains);
            drop(applied_domains);
            if let Err(err) = crate::util::windows_dns::revert_split_dns(&domains) {
                log::warn!(
                    "failed to revert split DNS domains {:?}: {:?}",
                    domains,
                    err
                );
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

    #[cfg(all(feature = "integrated_tun", target_os = "macos"))]
    fn apply_dns_profile<Call: SdlCallback>(&self, interface_name: &str, callback: &Call) {
        let profile = self.dns_profile.read().clone();
        let Some(profile) = profile else {
            return;
        };
        if profile.servers.is_empty() || profile.match_domains.is_empty() {
            return;
        }
        match crate::util::macos_dns::apply_split_dns(interface_name, &profile) {
            Ok(domains) => {
                *self.applied_dns_domains.lock() = domains;
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

    #[cfg(all(feature = "integrated_tun", target_os = "windows"))]
    fn apply_dns_profile<Call: SdlCallback>(&self, interface_name: &str, callback: &Call) {
        let profile = self.dns_profile.read().clone();
        let Some(profile) = profile else {
            return;
        };
        if profile.servers.is_empty() || profile.match_domains.is_empty() {
            return;
        }
        match crate::util::windows_dns::apply_split_dns(interface_name, &profile) {
            Ok(domains) => {
                *self.applied_dns_domains.lock() = domains;
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

    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    pub fn revert_dns_on_shutdown(&self) {
        self.clear_applied_dns_profile();
    }

    pub fn debug_snapshot_json(&self, sections: &[String]) -> anyhow::Result<String> {
        let include_all = sections.is_empty() || sections.iter().any(|section| section == "all");
        let wants = |name: &str| include_all || sections.iter().any(|section| section == name);
        let current_device = self.current_device.load();
        let mut root = Map::new();
        root.insert(
            "collected_at_unix_ms".into(),
            json!(crate::handle::now_time() as i64),
        );
        root.insert(
            "selected_sections".into(),
            json!(if include_all {
                vec!["all".to_string()]
            } else {
                sections.to_vec()
            }),
        );

        if wants("runtime") {
            let dns_profile = self.dns_profile.read().clone();
            let auth_request = self.config.auth_request.read().clone();
            root.insert(
                "runtime".into(),
                json!({
                    "name": self.config.name,
                    "device_id": self.config.device_id,
                    "server_addr": self.config.server_addr,
                    "mtu": self.config.mtu,
                    "virtual_ip": current_device.virtual_ip.to_string(),
                    "virtual_gateway": current_device.virtual_gateway.to_string(),
                    "virtual_netmask": current_device.virtual_netmask.to_string(),
                    "virtual_network": current_device.virtual_network.to_string(),
                    "broadcast_ip": current_device.broadcast_ip.to_string(),
                    "control_server": self.control_session.server_addr().to_string(),
                    "connect_status": format!("{:?}", current_device.status),
                    "use_channel_type": format!("{:?}", self.route_manager.use_channel_type()),
                    "dns_profile": dns_profile.as_ref().map(|profile| json!({
                        "servers": profile.servers,
                        "match_domains": profile.match_domains,
                    })).unwrap_or(Value::Null),
                    "auth_request": {
                        "user_id": auth_request.user_id,
                        "group": auth_request.group,
                        "ticket_present": auth_request.ticket.as_ref().map(|ticket| !ticket.is_empty()).unwrap_or(false),
                    },
                }),
            );
        }

        if wants("gateway") {
            let summary = self.gateway_sessions.session_summary();
            let grant = self.gateway_sessions.current_grant_snapshot();
            root.insert(
                "gateway".into(),
                json!({
                    "configured": summary.configured,
                    "authenticated": summary.authenticated,
                    "endpoint": summary.endpoint.map(|endpoint| endpoint.to_string()),
                    "channel_name": summary.channel_name,
                    "reauth_required": summary.reauth_required,
                    "grant": grant.as_ref().map(|grant| json!({
                        "session_id": grant.session_id,
                        "policy_rev": grant.policy_rev,
                        "ticket_expire_unix_ms": grant.ticket_expire_unix_ms,
                    })).unwrap_or(Value::Null),
                }),
            );
        }

        if wants("nat") {
            let nat_info = self.nat_test.nat_info();
            root.insert(
                "nat".into(),
                json!({
                    "nat_type": format!("{:?}", nat_info.nat_type),
                    "punch_model": format!("{:?}", nat_info.punch_model),
                    "public_ips": nat_info.public_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "public_ports": nat_info.public_ports,
                    "public_port_range": nat_info.public_port_range,
                    "public_udp_endpoints": nat_info.public_udp_endpoints.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "udp_ports": nat_info.udp_ports,
                    "local_udp_endpoints": nat_info.local_udp_endpoints().iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "local_ipv4": nat_info.local_ipv4.map(|ip| ip.to_string()),
                    "ipv6": nat_info.ipv6.map(|ip| ip.to_string()),
                }),
            );
        }

        if wants("peers") {
            let (peer_epoch, mut peer_items) = {
                let peer_state = self.peer_state.lock();
                let peers = peer_state
                    .devices
                    .values()
                    .map(|peer| {
                        json!({
                            "virtual_ip": peer.virtual_ip.to_string(),
                            "name": peer.name,
                            "status": format!("{:?}", peer.status),
                            "device_id": peer.device_id,
                            "device_pub_key_len": peer.device_pub_key.len(),
                            "online_kx_pub_len": peer.online_kx_pub.len(),
                        })
                    })
                    .collect::<Vec<_>>();
                (peer_state.epoch, peers)
            };
            peer_items.sort_by(|a, b| a["virtual_ip"].as_str().cmp(&b["virtual_ip"].as_str()));
            let mut peer_nat_items = self
                .peer_nat_info_map
                .read()
                .iter()
                .map(|(peer_ip, info)| {
                    json!({
                        "peer_ip": peer_ip.to_string(),
                        "nat_type": format!("{:?}", info.nat_type),
                        "public_ips": info.public_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "public_ports": info.public_ports,
                    })
                })
                .collect::<Vec<_>>();
            peer_nat_items.sort_by(|a, b| a["peer_ip"].as_str().cmp(&b["peer_ip"].as_str()));
            let (current_cipher_count, previous_cipher_count, grace_active) =
                self.peer_crypto.debug_counts();
            root.insert(
                "peers".into(),
                json!({
                    "epoch": peer_epoch,
                    "peer_count": peer_items.len(),
                    "peer_nat_count": peer_nat_items.len(),
                    "current_cipher_count": current_cipher_count,
                    "previous_cipher_count": previous_cipher_count,
                    "cipher_grace_active": grace_active,
                    "items": peer_items,
                    "nat_items": peer_nat_items,
                }),
            );
        }

        if wants("routes") {
            let mut route_items = self
                .route_manager
                .snapshot_route_states(current_device.virtual_gateway)
                .into_iter()
                .flat_map(|(_, states)| states)
                .map(|state| {
                    json!({
                        "peer_ip": state.peer_ip.to_string(),
                        "kind": format!("{:?}", state.kind),
                        "transport": format!("{:?}", state.transport),
                        "addr": state.addr.to_string(),
                        "metric": state.metric,
                        "rt": state.rt,
                    })
                })
                .collect::<Vec<_>>();
            route_items.sort_by(|a, b| {
                a["peer_ip"]
                    .as_str()
                    .cmp(&b["peer_ip"].as_str())
                    .then_with(|| a["addr"].as_str().cmp(&b["addr"].as_str()))
            });
            root.insert(
                "routes".into(),
                json!({
                    "count": route_items.len(),
                    "items": route_items,
                }),
            );
        }

        if wants("traffic") {
            root.insert(
                "traffic".into(),
                json!({
                    "up_total": self.data_plane_stats.up_traffic_total(),
                    "up_channels": self.data_plane_stats.up_traffic_all().map(|(_, channels)| channels),
                    "down_total": self.data_plane_stats.down_traffic_total(),
                    "down_channels": self.data_plane_stats.down_traffic_all().map(|(_, channels)| channels),
                }),
            );
        }

        serde_json::to_string_pretty(&Value::Object(root)).map_err(Into::into)
    }
}
