use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

#[cfg(feature = "integrated_tun")]
use anyhow::anyhow;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Map, Value};

use crate::cipher::CipherModel;
use crate::control::ControlSession;
use crate::core::PeerInfo;
use crate::core::{ExitNodeRoute, PeerIdentity};
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route::RouteKey;
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::stats::DataPlaneStats;
use crate::handle::CurrentDeviceInfo;
use crate::nat::punch::NatInfo;
use crate::nat::punch_workers::PunchCoordinator;
use crate::nat::NatTest;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::transport::udp_channel::UdpChannel;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::create_device;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::tun_create_helper::TunDeviceHelper;
use crate::util::DebugWatch;
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
pub struct SdlContextConfig {
    pub name: String,
    pub token: String,
    pub ip: Option<Ipv4Addr>,
    pub cipher_model: CipherModel,
    pub device_id: String,
    pub device_pub_key: Vec<u8>,
    pub server_addr: String,
    pub mtu: u32,
    #[cfg(feature = "integrated_tun")]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
    pub default_interface: crate::transport::socket::LocalInterface,
}

#[derive(Clone, Debug)]
pub struct PendingDnsQuery {
    pub client_ip: Ipv4Addr,
    pub dns_server_ip: Ipv4Addr,
    pub client_port: u16,
}

impl PendingDnsQuery {
    pub fn new(client_ip: Ipv4Addr, dns_server_ip: Ipv4Addr, client_port: u16) -> Self {
        Self {
            client_ip,
            dns_server_ip,
            client_port,
        }
    }
}

pub struct PendingRenameRequest {
    pub responder: mpsc::Sender<Result<RenameRequestOutcome, String>>,
}

pub(crate) const PENDING_REQUEST_TTL_MS: u64 = 30_000;

struct PendingEntry<T> {
    value: T,
    created_at_ms: u64,
}

pub(crate) struct PendingRequestTable<T> {
    seq: AtomicU64,
    table: Mutex<HashMap<u64, PendingEntry<T>>>,
    ttl_ms: u64,
}

impl<T> PendingRequestTable<T> {
    pub(crate) fn new(ttl_ms: u64) -> Self {
        Self {
            seq: AtomicU64::new(0),
            table: Mutex::new(HashMap::new()),
            ttl_ms,
        }
    }

    pub(crate) fn remember(&self, value: T) -> u64 {
        let request_id = self.seq.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let now_ms = crate::handle::now_time() as u64;
        let mut pending = self.table.lock();
        pending.retain(|_, entry| now_ms.saturating_sub(entry.created_at_ms) < self.ttl_ms);
        pending.insert(
            request_id,
            PendingEntry {
                value,
                created_at_ms: now_ms,
            },
        );
        request_id
    }

    pub(crate) fn forget(&self, request_id: u64) {
        self.table.lock().remove(&request_id);
    }

    pub(crate) fn take(&self, request_id: u64) -> Option<T> {
        self.table
            .lock()
            .remove(&request_id)
            .map(|entry| entry.value)
    }

    pub(crate) fn clear(&self) {
        self.table.lock().clear();
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExitNodeLocalState {
    pub enabled: bool,
    pub local_ready: bool,
    pub egress_interface: Option<String>,
    pub selected_device_id: Option<String>,
    pub selected_identity: Option<PeerIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenameRequestOutcome {
    Applied(String),
    RestartRequired(String),
}

#[derive(Clone)]
pub(crate) struct PeerSubsystem {
    pub(crate) table: Arc<RwLock<crate::core::PeerTable>>,
    pub(crate) nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
    pub(crate) crypto: Arc<PeerCryptoManager>,
    pub(crate) probe_tracker: Arc<crate::util::PeerProbeTracker>,
}

impl PeerSubsystem {
    pub(crate) fn reset_for_auth_pending(&self) {
        {
            let mut peer_table = self.table.write();
            peer_table.bump_epoch();
            peer_table.clear_devices();
        }
        self.nat_info_map.write().clear();
        self.crypto.clear_all();
    }

    pub(crate) fn nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.nat_info_map.read().get(ip).cloned()
    }

    pub(crate) fn list(&self) -> Vec<PeerInfo> {
        self.table
            .read()
            .cloned_devices()
            .into_values()
            .collect::<Vec<_>>()
    }

    pub(crate) fn info(&self, ip: &Ipv4Addr) -> Option<PeerInfo> {
        self.table.read().get(ip).cloned()
    }

    pub(crate) fn identity_for_device_id(&self, device_id: &str) -> Option<PeerIdentity> {
        self.table
            .read()
            .values()
            .find(|peer| peer.device_id == device_id)
            .map(|peer| peer.identity())
    }

    pub(crate) fn identity_for_vip(&self, ip: &Ipv4Addr) -> Option<PeerIdentity> {
        self.table.read().identity_for_vip(ip)
    }

    pub(crate) fn epoch(&self) -> u16 {
        self.table.read().epoch()
    }

    pub(crate) fn reset_epoch(&self) {
        self.table.write().reset_epoch();
    }

    pub(crate) fn replace_devices_if_fresh(
        &self,
        epoch: u16,
        next_devices: HashMap<Ipv4Addr, PeerInfo>,
    ) -> Result<HashMap<Ipv4Addr, PeerInfo>, u16> {
        self.table
            .write()
            .replace_devices_if_fresh(epoch, next_devices)
    }

    pub(crate) fn usable_exit_node_vip(&self, identity: &PeerIdentity) -> Option<Ipv4Addr> {
        let peer_table = self.table.read();
        peer_table.vip_for_identity(identity).and_then(|peer_ip| {
            peer_table
                .get(&peer_ip)
                .filter(|peer| peer.exit_node_usable && peer.status.is_online())
                .map(|_| peer_ip)
        })
    }
}

#[derive(Clone)]
pub(crate) struct GatewaySubsystem {
    pub(crate) sessions: GatewaySessions,
    pub(crate) grant_policy_rev: Arc<AtomicU64>,
}

impl GatewaySubsystem {
    pub(crate) fn reset_for_auth_pending(&self) {
        self.sessions.clear_gateway_grant();
        self.grant_policy_rev.store(0, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub(crate) struct DnsSubsystem {
    pub(crate) profile: Arc<RwLock<Option<DnsProfile>>>,
    pub(crate) pending_queries: Arc<PendingRequestTable<PendingDnsQuery>>,
    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    pub(crate) last_interface: Arc<Mutex<Option<String>>>,
    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    pub(crate) applied_interface: Arc<Mutex<Option<String>>>,
    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    pub(crate) applied_profile: Arc<Mutex<Option<DnsProfile>>>,
}

impl DnsSubsystem {
    pub(crate) fn reset_for_auth_pending(&self) {
        self.pending_queries.clear();
    }

    pub(crate) fn replace_profile(&self, profile: Option<DnsProfile>) -> bool {
        let mut guard = self.profile.write();
        if *guard == profile {
            return false;
        }
        *guard = profile;
        true
    }

    pub(crate) fn service_ipv4s(&self) -> Vec<Ipv4Addr> {
        self.profile
            .read()
            .as_ref()
            .map(|profile| {
                profile
                    .servers
                    .iter()
                    .filter_map(|server| server.parse::<Ipv4Addr>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn is_service_ip(&self, ip: Ipv4Addr) -> bool {
        self.service_ipv4s()
            .into_iter()
            .any(|candidate| candidate == ip)
    }

    pub(crate) fn remember_query(
        &self,
        client_ip: Ipv4Addr,
        dns_server_ip: Ipv4Addr,
        client_port: u16,
    ) -> u64 {
        self.pending_queries
            .remember(PendingDnsQuery::new(client_ip, dns_server_ip, client_port))
    }

    pub(crate) fn forget_query(&self, request_id: u64) {
        self.pending_queries.forget(request_id);
    }

    pub(crate) fn take_query(&self, request_id: u64) -> Option<PendingDnsQuery> {
        self.pending_queries.take(request_id)
    }

    pub(crate) fn primary_service_ip(&self) -> Option<Ipv4Addr> {
        self.service_ipv4s().into_iter().next()
    }
}

#[derive(Clone)]
pub(crate) struct ExitNodeSubsystem {
    pub(crate) state: Arc<RwLock<ExitNodeLocalState>>,
    pub(crate) route: ExitNodeRoute,
}

impl ExitNodeSubsystem {
    pub(crate) fn reset_for_auth_pending(&self) {
        self.route.set_default_next_hop(None);
        *self.state.write() = ExitNodeLocalState::default();
    }

    pub(crate) fn snapshot(&self) -> ExitNodeLocalState {
        self.state.read().clone()
    }

    pub(crate) fn local_ready(&self) -> bool {
        let state = self.state.read();
        state.enabled && state.local_ready
    }

    pub(crate) fn replace_state(&self, state: ExitNodeLocalState) -> Option<bool> {
        let should_report_status = {
            let previous = self.state.read();
            previous.enabled != state.enabled || previous.local_ready != state.local_ready
        };
        {
            let mut guard = self.state.write();
            if *guard == state {
                return None;
            }
            *guard = state;
        }
        Some(should_report_status)
    }
}

#[cfg(feature = "integrated_tun")]
#[derive(Clone)]
pub(crate) struct TunSubsystem {
    pub(crate) suspended: Arc<AtomicCell<bool>>,
    pub(crate) lifecycle: Arc<Mutex<()>>,
    pub(crate) device_helper: TunDeviceHelper,
}

// `SdlContext` is intentionally shallow-cloneable: subsystem fields either wrap
// `Arc` state or local handles whose `Clone` implementations share inner state.
// Keep new fields on that model; this type is cloned into callbacks and workers.
#[derive(Clone)]
pub struct SdlContext {
    pub(crate) config: SdlContextConfig,
    pub(crate) auth_request: Arc<RwLock<AuthRequestConfig>>,
    pub(crate) peers: PeerSubsystem,
    pub(crate) gateway: GatewaySubsystem,
    pub(crate) dns: DnsSubsystem,
    pub(crate) exit_node: ExitNodeSubsystem,
    pub(crate) pending_rename_requests: Arc<PendingRequestTable<PendingRenameRequest>>,
    pub(crate) current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    pub(crate) debug_watch: DebugWatch,
    pub(crate) nat_test: NatTest,
    pub(crate) control_session: ControlSession,
    pub(crate) route_manager: RouteManager,
    pub(crate) data_plane_stats: DataPlaneStats,
    pub(crate) udp_channel: UdpChannel,
    pub(crate) punch_coordinator: PunchCoordinator,
    #[cfg(feature = "integrated_tun")]
    pub(crate) tun: TunSubsystem,
}

impl SdlContext {
    pub fn block_data_plane_for_auth_pending(&self) {
        self.peers.reset_for_auth_pending();
        self.route_manager.clear_all_paths();
        self.gateway.reset_for_auth_pending();
        self.dns.reset_for_auth_pending();
        self.pending_rename_requests.clear();
        self.exit_node.reset_for_auth_pending();
    }

    pub(crate) fn apply_selected_exit_node_route(&self) {
        let state = self.exit_node.state.read().clone();
        let Some(selected_identity) = state.selected_identity else {
            self.exit_node.route.set_default_next_hop(None);
            return;
        };
        let selected_peer_ip = self.peers.usable_exit_node_vip(&selected_identity);
        self.exit_node.route.set_default_next_hop(selected_peer_ip);
        if selected_peer_ip.is_none() {
            log::warn!(
                "selected exit node is not currently usable: {}",
                state
                    .selected_device_id
                    .unwrap_or_else(|| selected_identity.fingerprint_hex())
            );
        }
    }

    pub fn route_manager(&self) -> RouteManager {
        self.route_manager.clone()
    }

    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.current_device.load()
    }

    pub fn current_device_handle(&self) -> Arc<AtomicCell<CurrentDeviceInfo>> {
        self.current_device.clone()
    }

    pub fn connection_status(&self) -> crate::handle::ConnectStatus {
        self.current_device().status
    }

    pub fn change_connection_status(
        &self,
        connect_status: crate::handle::ConnectStatus,
    ) -> CurrentDeviceInfo {
        crate::handle::change_status(&self.current_device, connect_status)
    }

    pub fn virtual_gateway(&self) -> Ipv4Addr {
        self.current_device().virtual_gateway
    }

    pub fn is_gateway_vip(&self, ip: &Ipv4Addr) -> bool {
        self.current_device().is_gateway_vip(ip)
    }

    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.peers.nat_info(ip)
    }

    pub fn peer_list(&self) -> Vec<PeerInfo> {
        self.peers.list()
    }

    pub fn peer_info(&self, ip: &Ipv4Addr) -> Option<PeerInfo> {
        self.peers.info(ip)
    }

    pub fn peer_identity_for_device_id(&self, device_id: &str) -> Option<PeerIdentity> {
        self.peers.identity_for_device_id(device_id)
    }

    pub fn peer_identity_for_vip(&self, ip: &Ipv4Addr) -> Option<PeerIdentity> {
        self.peers.identity_for_vip(ip)
    }

    pub fn peer_epoch(&self) -> u16 {
        self.peers.epoch()
    }

    pub fn reset_peer_epoch(&self) {
        self.peers.reset_epoch();
    }

    pub fn replace_peer_devices(
        &self,
        epoch: u16,
        next_devices: HashMap<Ipv4Addr, PeerInfo>,
    ) -> Result<HashMap<Ipv4Addr, PeerInfo>, u16> {
        self.peers.replace_devices_if_fresh(epoch, next_devices)
    }

    pub fn exit_node_state(&self) -> ExitNodeLocalState {
        self.exit_node.snapshot()
    }

    pub fn exit_node_local_ready(&self) -> bool {
        self.exit_node.local_ready()
    }

    pub fn set_exit_node_state(&self, state: ExitNodeLocalState) -> bool {
        let Some(should_report_status) = self.exit_node.replace_state(state) else {
            return false;
        };
        self.apply_selected_exit_node_route();
        should_report_status
    }

    pub fn is_known_udp_source(&self, addr: std::net::SocketAddr) -> bool {
        self.control_session.is_control_addr(addr)
            || self.gateway.sessions.is_gateway_addr(addr)
            || self.nat_test.has_pending_stun_server_addr(addr)
            || self
                .route_manager
                .has_direct_route_key(&RouteKey::new(ConnectProtocol::UDP, addr))
    }

    pub fn replace_dns_profile(&self, profile: Option<DnsProfile>) -> bool {
        self.dns.replace_profile(profile)
    }

    pub fn is_dns_service_ip(&self, ip: Ipv4Addr) -> bool {
        self.dns.is_service_ip(ip)
    }

    pub fn remember_dns_query(
        &self,
        client_ip: Ipv4Addr,
        dns_server_ip: Ipv4Addr,
        client_port: u16,
    ) -> u64 {
        self.dns
            .remember_query(client_ip, dns_server_ip, client_port)
    }

    pub fn forget_dns_query(&self, request_id: u64) {
        self.dns.forget_query(request_id);
    }

    pub fn take_dns_query(&self, request_id: u64) -> Option<PendingDnsQuery> {
        self.dns.take_query(request_id)
    }

    pub fn primary_dns_service_ip(&self) -> Option<Ipv4Addr> {
        self.dns.primary_service_ip()
    }

    pub fn remember_rename_request(
        &self,
        responder: mpsc::Sender<Result<RenameRequestOutcome, String>>,
    ) -> u64 {
        self.pending_rename_requests
            .remember(PendingRenameRequest { responder })
    }

    pub fn forget_rename_request(&self, request_id: u64) {
        self.pending_rename_requests.forget(request_id);
    }

    pub fn complete_rename_request(
        &self,
        request_id: u64,
        result: Result<RenameRequestOutcome, String>,
    ) -> bool {
        let Some(request) = self.pending_rename_requests.take(request_id) else {
            return false;
        };
        let _ = request.responder.send(result);
        true
    }

    #[cfg(feature = "integrated_tun")]
    pub fn is_suspended(&self) -> bool {
        self.tun.suspended.load()
    }

    #[cfg(feature = "integrated_tun")]
    pub fn suspend(&self) {
        let _guard = self.tun.lifecycle.lock();
        self.tun.suspended.store(true);
        self.clear_applied_dns_profile();
        self.tun.device_helper.stop();
    }

    #[cfg(feature = "integrated_tun")]
    pub fn resume<Call: SdlCallback>(&self, callback: &Call) -> anyhow::Result<()> {
        let _guard = self.tun.lifecycle.lock();
        self.tun.suspended.store(false);
        self.rebuild_tun_locked(callback)
    }

    #[cfg(feature = "integrated_tun")]
    pub fn sync_tun_with_current_device<Call: SdlCallback>(
        &self,
        callback: &Call,
    ) -> anyhow::Result<()> {
        let _guard = self.tun.lifecycle.lock();
        if self.tun.suspended.load() {
            self.clear_applied_dns_profile();
            self.tun.device_helper.stop();
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
        self.tun.device_helper.stop();
        let device_config = DeviceConfig::new(
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            self.config.device_name.clone(),
            self.config.mtu,
            current_device.virtual_ip,
            current_device.virtual_netmask,
            current_device.virtual_gateway,
            current_device.virtual_network,
        );
        let device = create_device(device_config, callback).map_err(|e| anyhow!("{}", e))?;
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let tun_name = device.name().unwrap_or_else(|_| "sdl-tun".to_string());
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        self.apply_dns_profile(&tun_name, callback);
        self.tun.device_helper.start(device)?;
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        {
            let tun_info = crate::handle::callback::DeviceInfo::new(tun_name, "".into());
            callback.create_tun(tun_info);
        }
        Ok(())
    }

    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    fn clear_applied_dns_profile(&self) {
        let _ = self.dns.last_interface.lock().take();
        let interface_name = self.dns.applied_interface.lock().take();
        let applied_profile = self.dns.applied_profile.lock().take();
        if interface_name.is_none() && applied_profile.is_none() {
            return;
        }
        if let Err(err) = crate::net::dns::platform::revert_split_dns(
            interface_name.as_deref(),
            applied_profile.as_ref(),
        ) {
            log::warn!(
                "failed to revert split DNS interface={:?} profile={:?}: {:?}",
                interface_name,
                applied_profile,
                err
            );
        }
    }

    #[cfg(all(
        feature = "integrated_tun",
        not(any(target_os = "windows", target_os = "linux", target_os = "macos"))
    ))]
    fn clear_applied_dns_profile(&self) {}

    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    fn apply_dns_profile<Call: SdlCallback>(&self, interface_name: &str, callback: &Call) {
        let profile = self.dns.profile.read().clone();
        let Some(profile) = profile else {
            return;
        };
        if profile.servers.is_empty() || profile.match_domains.is_empty() {
            return;
        }
        *self.dns.last_interface.lock() = Some(interface_name.to_string());
        let previous_profile = self.dns.applied_profile.lock().clone();
        match crate::net::dns::platform::apply_split_dns(
            interface_name,
            previous_profile.as_ref(),
            &profile,
        ) {
            Ok(_) => {
                *self.dns.applied_interface.lock() = Some(interface_name.to_string());
                *self.dns.applied_profile.lock() = Some(profile);
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

    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    pub fn force_apply_dns_profile<Call: SdlCallback>(&self, callback: &Call) {
        let interface_name = self
            .dns
            .applied_interface
            .lock()
            .clone()
            .or_else(|| self.dns.last_interface.lock().clone());
        if let Some(interface_name) = interface_name {
            self.apply_dns_profile(&interface_name, callback);
        }
    }

    #[cfg(all(
        feature = "integrated_tun",
        not(any(target_os = "windows", target_os = "linux", target_os = "macos"))
    ))]
    pub fn force_apply_dns_profile<Call: SdlCallback>(&self, _callback: &Call) {}

    pub fn debug_snapshot_json(&self, sections: &[String]) -> anyhow::Result<String> {
        let include_all = sections.is_empty() || sections.iter().any(|section| section == "all");
        let wants = |name: &str| include_all || sections.iter().any(|section| section == name);
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
            root.insert("runtime".into(), self.snapshot_runtime());
        }

        if wants("gateway") {
            root.insert("gateway".into(), self.snapshot_gateway());
        }

        if wants("nat") {
            root.insert("nat".into(), self.snapshot_nat());
        }

        if wants("peers") {
            root.insert("peers".into(), self.snapshot_peers());
        }

        if wants("routes") {
            root.insert("routes".into(), self.snapshot_routes(self.current_device()));
        }

        if wants("traffic") {
            root.insert("traffic".into(), self.snapshot_traffic());
        }

        serde_json::to_string_pretty(&Value::Object(root)).map_err(Into::into)
    }

    fn snapshot_runtime(&self) -> Value {
        let current_device = self.current_device();
        let dns_profile = self.dns.profile.read().clone();
        let auth_request = self.auth_request.read().clone();
        json!({
            "name": self.config.name,
            "device_id": self.config.device_id,
            "sdl_version": crate::SDL_VERSION,
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
            "system": debug_system_info_json(),
            "build": debug_build_info_json(),
            "auth_request": {
                "user_id": auth_request.user_id,
                "group": auth_request.group,
                "ticket_present": auth_request.ticket.as_ref().map(|ticket| !ticket.is_empty()).unwrap_or(false),
            },
        })
    }

    fn snapshot_gateway(&self) -> Value {
        let summary = self.gateway.sessions.session_summary();
        let grant = self.gateway.sessions.current_grant_snapshot();
        json!({
            "configured": summary.configured,
            "authenticated": summary.authenticated,
            "endpoint": summary.endpoint.map(|endpoint| endpoint.to_string()),
            "channel_name": summary.channel_name,
            "grant_state": summary.grant_state.as_str(),
            "lease_expire_unix_ms": summary.lease_expire_unix_ms,
            "grace_expire_unix_ms": summary.grace_expire_unix_ms,
            "reauth_required": summary.reauth_required,
            "grant": grant.as_ref().map(|grant| json!({
                "session_id": grant.session_id,
                "policy_rev": grant.policy_rev,
                "soft_refresh_after_unix_ms": grant.soft_refresh_after_unix_ms,
                "hard_expire_unix_ms": grant.hard_expire_unix_ms,
                "ticket_expire_unix_ms": grant.ticket_expire_unix_ms,
            })).unwrap_or(Value::Null),
        })
    }

    fn snapshot_nat(&self) -> Value {
        let nat_info = self.nat_test.nat_info();
        json!({
            "nat_type": format!("{:?}", nat_info.nat_type),
            "punch_model": format!("{:?}", nat_info.punch_model),
            "public_ips": nat_info.public_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "public_ports": nat_info.public_ports,
            "public_port_range": nat_info.public_port_range,
            "public_udp_endpoints": nat_info.public_udp_endpoints.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "local_udp_ports": nat_info.local_udp_ports,
            "local_udp_endpoints": nat_info.local_udp_endpoints().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "local_ipv4": nat_info.local_ipv4.map(|ip| ip.to_string()),
            "ipv6": nat_info.ipv6.map(|ip| ip.to_string()),
        })
    }

    fn snapshot_peers(&self) -> Value {
        let (peer_epoch, mut peer_items) = {
            let peer_table = self.peers.table.read();
            let peers = peer_table
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
            (peer_table.epoch(), peers)
        };
        peer_items.sort_by(|a, b| a["virtual_ip"].as_str().cmp(&b["virtual_ip"].as_str()));

        let mut peer_nat_items = self
            .peers.nat_info_map
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
            self.peers.crypto.debug_counts();
        json!({
            "epoch": peer_epoch,
            "peer_count": peer_items.len(),
            "peer_nat_count": peer_nat_items.len(),
            "current_cipher_count": current_cipher_count,
            "previous_cipher_count": previous_cipher_count,
            "cipher_grace_active": grace_active,
            "items": peer_items,
            "nat_items": peer_nat_items,
        })
    }

    fn snapshot_routes(&self, current_device: CurrentDeviceInfo) -> Value {
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
        json!({
            "count": route_items.len(),
            "items": route_items,
        })
    }

    fn snapshot_traffic(&self) -> Value {
        json!({
            "up_total": self.data_plane_stats.up_traffic_total(),
            "up_channels": self.data_plane_stats.up_traffic_all().map(|(_, channels)| channels),
            "down_total": self.data_plane_stats.down_traffic_total(),
            "down_channels": self.data_plane_stats.down_traffic_all().map(|(_, channels)| channels),
        })
    }
}

fn debug_system_info_json() -> Value {
    json!({
        "hostname": gethostname::gethostname().to_string_lossy().into_owned(),
        "os": env::consts::OS,
        "arch": env::consts::ARCH,
        "family": env::consts::FAMILY,
        "target_env": option_env!("CARGO_CFG_TARGET_ENV"),
        "target_vendor": option_env!("CARGO_CFG_TARGET_VENDOR"),
        "process_id": std::process::id(),
        "current_dir": env::current_dir().ok().map(|path| path.display().to_string()),
        "current_exe": env::current_exe().ok().map(|path| path.display().to_string()),
    })
}

fn debug_build_info_json() -> Value {
    json!({
        "package_name": env!("CARGO_PKG_NAME"),
        "package_version": env!("CARGO_PKG_VERSION"),
        "debug_assertions": cfg!(debug_assertions),
        "features": {
            "integrated_tun": cfg!(feature = "integrated_tun"),
            "quic": cfg!(feature = "quic"),
            "port_mapping": cfg!(feature = "port_mapping"),
            "upnp": cfg!(feature = "upnp"),
            "lz4_compress": cfg!(feature = "lz4_compress"),
            "zstd_compress": cfg!(feature = "zstd_compress"),
            "aes_gcm": cfg!(feature = "aes_gcm"),
            "aes_cbc": cfg!(feature = "aes_cbc"),
            "aes_ecb": cfg!(feature = "aes_ecb"),
            "sm4_cbc": cfg!(feature = "sm4_cbc"),
            "chacha20_poly1305": cfg!(feature = "chacha20_poly1305"),
        },
    })
}
