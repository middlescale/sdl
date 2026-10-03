use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::anyhow;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

mod debug;

use crate::control::ControlSession;
use crate::core::PeerInfo;
use crate::core::{ExitNodeRoute, PeerIdentity};
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route::RouteKey;
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::route_state::RouteKind;
use crate::data_plane::runtime::{is_definitive_p2p_path_error, DataPlaneRuntime, PayloadPath};
use crate::data_plane::stats::DataPlaneStats;
use crate::handle::CurrentDeviceInfo;
use crate::nat::punch::NatInfo;
use crate::nat::NatTest;
use crate::protocol::NetPacket;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::tun_device::create_device;
use crate::tun_device::{TunSubsystem, TunTransition};
use crate::util::DebugWatch;
use crate::{DeviceConfig, SdlCallback};
use crate::{DnsProfile, ErrorInfo, ErrorType};

#[derive(Clone, Debug, Default)]
pub(crate) struct AuthRequestConfig {
    pub user_id: Option<String>,
    pub group: Option<String>,
    pub ticket: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfig {
    pub name: String,
    pub token: String,
    pub ip: Option<Ipv4Addr>,
    pub device_id: String,
    pub device_pub_key: Vec<u8>,
    pub server_addr: String,
    pub mtu: u32,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingDnsQuery {
    pub client_ip: Ipv4Addr,
    pub dns_server_ip: Ipv4Addr,
    pub client_port: u16,
}

impl PendingDnsQuery {
    pub(crate) fn new(client_ip: Ipv4Addr, dns_server_ip: Ipv4Addr, client_port: u16) -> Self {
        Self {
            client_ip,
            dns_server_ip,
            client_port,
        }
    }
}

pub(crate) struct PendingRenameRequest {
    pub(crate) responder: mpsc::Sender<Result<RenameRequestOutcome, String>>,
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

    pub(crate) fn contains(&self, ip: &Ipv4Addr) -> bool {
        self.table.read().get(ip).is_some()
    }

    pub(crate) fn preferred_channel_mode(
        &self,
        ip: &Ipv4Addr,
    ) -> Option<crate::proto::message::ChannelMode> {
        self.table
            .read()
            .get(ip)
            .map(|peer| peer.preferred_channel_mode)
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

    pub(crate) fn vip_for_identity(&self, identity: &PeerIdentity) -> Option<Ipv4Addr> {
        self.table.read().vip_for_identity(identity)
    }
}

#[derive(Clone)]
pub(crate) struct DnsSubsystem {
    pub(crate) profile: Arc<RwLock<Option<DnsProfile>>>,
    pub(crate) pending_queries: Arc<PendingRequestTable<PendingDnsQuery>>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub(crate) last_interface: Arc<Mutex<Option<String>>>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub(crate) applied_interface: Arc<Mutex<Option<String>>>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
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

// State owned by the local node.  These components primarily hold observable
// runtime state; their APIs may update that state but do not own background
// transport lifecycle.
#[derive(Clone)]
pub(crate) struct SdlNodeState {
    pub(crate) auth_request: Arc<RwLock<AuthRequestConfig>>,
    pub(crate) peers: PeerSubsystem,
    pub(crate) gateway_grant_policy_rev: Arc<AtomicU64>,
    pub(crate) dns: DnsSubsystem,
    pub(crate) exit_node: ExitNodeSubsystem,
    // Runtime state, independent of the CLI's presentation state.  It makes
    // auth-pending data-plane teardown idempotent and marks the next control
    // snapshot as an auth-recovery snapshot.
    pub(crate) auth_pending_block_applied: Arc<AtomicBool>,
    pub(crate) pending_rename_requests: Arc<PendingRequestTable<PendingRenameRequest>>,
    pub(crate) current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    pub(crate) data_plane_stats: DataPlaneStats,
    pub(crate) debug_watch: DebugWatch,
    pub(crate) tun: TunSubsystem,
}

// `SdlRuntime` is intentionally shallow-cloneable: node state and active
// runtime components either wrap `Arc` state or local handles whose `Clone`
// implementations share inner state. Keep new fields on that model; this type
// is cloned into callbacks and workers.
#[derive(Clone)]
pub(crate) struct SdlRuntime {
    pub(crate) config: Arc<RuntimeConfig>,
    pub(crate) state: SdlNodeState,
    pub(crate) data_plane: DataPlaneRuntime,
    pub(crate) control_session: ControlSession,
    pub(crate) nat_test: NatTest,
}

impl SdlRuntime {
    // These expose subsystem boundaries without restoring the old facade of
    // one forwarding method per subsystem operation.  Callers that use a
    // subsystem repeatedly should bind the returned reference locally.
    pub(crate) fn peers(&self) -> &PeerSubsystem {
        &self.state.peers
    }

    pub(crate) fn routes(&self) -> &RouteManager {
        &self.data_plane.route_manager
    }

    pub(crate) fn control_session(&self) -> &ControlSession {
        &self.control_session
    }

    pub(crate) fn set_gateway_selection(&self, endpoint: Option<SocketAddr>) -> anyhow::Result<()> {
        self.data_plane
            .gateway_sessions
            .set_manual_endpoint(endpoint)
    }

    pub(crate) fn is_dns_service_ip(&self, vip: Ipv4Addr) -> bool {
        self.state.dns.is_service_ip(vip)
    }

    pub(crate) fn send_to_peer<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
        vip: &Ipv4Addr,
    ) -> io::Result<RouteKind> {
        let is_gateway_vip = self.state.current_device.load().is_gateway_vip(vip);
        let peer_channel_mode = self.state.peers.preferred_channel_mode(vip);
        let route_plan =
            self.data_plane
                .prepare_peer_payload_route(vip, is_gateway_vip, peer_channel_mode);
        if route_plan.direct_recovery_requested {
            // The first payload keeps the normal relay fallback while control
            // coordinates a direct route in the background.
            self.control_session.request_direct_recovery_for(*vip);
        }
        match route_plan.path {
            Some(PayloadPath::P2pUdp(route_key)) => {
                match self.data_plane.send_p2p(packet, route_key) {
                    Ok(()) => Ok(RouteKind::P2p),
                    Err(err) if !is_definitive_p2p_path_error(&err) => {
                        log::debug!(
                            "p2p send failed for {}, preserving route {:?}: {:?}",
                            vip,
                            route_key,
                            err
                        );
                        Err(err)
                    }
                    Err(err) => {
                        self.data_plane.mark_p2p_path_failed(vip, route_key);
                        if !route_plan.allows_gateway_relay {
                            log::warn!(
                            "p2p send failed for {}, removed route {:?}, relay fallback unavailable: {:?}",
                            vip,
                            route_key,
                            err
                        );
                            return Err(err);
                        }
                        log::warn!(
                        "p2p send failed for {}, removed route {:?}, falling back to relay: {:?}",
                        vip,
                        route_key,
                        err
                    );
                        self.send_peer_relay(*vip, packet)?;
                        Ok(RouteKind::GatewayRelay)
                    }
                }
            }
            Some(PayloadPath::GatewayRelay) => {
                self.send_peer_relay(*vip, packet)?;
                Ok(RouteKind::GatewayRelay)
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("peer route not found: {vip}"),
            )),
        }
    }

    fn send_peer_relay<B: AsRef<[u8]>>(
        &self,
        vip: Ipv4Addr,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        let peer_identity = self.state.peers.identity_for_vip(&vip);
        self.data_plane.send_peer_relay(
            vip,
            peer_identity.as_ref(),
            self.state.peers.crypto.as_ref(),
            packet,
        )
    }

    pub(crate) fn proxy_dns_query(
        &self,
        client_ip: Ipv4Addr,
        dns_server_ip: Ipv4Addr,
        client_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        let request_id = self
            .state
            .dns
            .remember_query(client_ip, dns_server_ip, client_port);
        let query_payload =
            match crate::net::dns::tunnel::build_dns_query_payload(request_id, payload) {
                Ok(payload) => payload,
                Err(err) => {
                    self.state.dns.forget_query(request_id);
                    return Err(err);
                }
            };
        if let Err(err) = self.control_session.send_service_payload(
            crate::protocol::service_packet::Protocol::DnsQueryRequest,
            &query_payload,
        ) {
            self.state.dns.forget_query(request_id);
            return Err(io::Error::other(err));
        }
        Ok(())
    }

    pub(crate) fn block_data_plane_for_auth_pending(&self) {
        if self
            .state
            .auth_pending_block_applied
            .swap(true, Ordering::AcqRel)
        {
            return;
        }
        self.state.peers.reset_for_auth_pending();
        self.routes().clear_all_paths();
        self.data_plane.gateway_sessions.clear_gateway_grant();
        self.state
            .gateway_grant_policy_rev
            .store(0, Ordering::Relaxed);
        self.state.dns.reset_for_auth_pending();
        self.state.pending_rename_requests.clear();
        self.state.exit_node.reset_for_auth_pending();
    }

    // The caller must hold ServerPacketHandler::device_list_update_lock and
    // invoke this immediately before applying a control device-list snapshot.
    // A long auth-pending retry loop can otherwise move the local epoch ahead
    // of a restarted control server's epoch.
    pub(crate) fn reset_peer_epoch_for_auth_pending_recovery(&self) -> bool {
        if !self
            .state
            .auth_pending_block_applied
            .load(Ordering::Acquire)
        {
            return false;
        }
        self.state.peers.reset_epoch();
        true
    }

    // Clear only after a successful RegistrationResponse has committed its
    // authoritative snapshot.  A later auth failure must tear down once too.
    pub(crate) fn finish_auth_pending_recovery(&self) {
        self.state
            .auth_pending_block_applied
            .store(false, Ordering::Release);
    }

    pub(crate) fn apply_selected_exit_node_route(&self) {
        let state = self.state.exit_node.state.read().clone();
        let Some(selected_identity) = state.selected_identity else {
            self.state.exit_node.route.set_default_next_hop(None);
            return;
        };
        let selected_peer_ip = self.state.peers.usable_exit_node_vip(&selected_identity);
        self.state
            .exit_node
            .route
            .set_default_next_hop(selected_peer_ip);
        if selected_peer_ip.is_none() {
            log::warn!(
                "selected exit node is not currently usable: {}",
                selected_identity.fingerprint_hex()
            );
        }
    }

    pub(crate) fn set_exit_node_state(&self, state: ExitNodeLocalState) -> bool {
        let Some(should_report_status) = self.state.exit_node.replace_state(state) else {
            return false;
        };
        self.apply_selected_exit_node_route();
        should_report_status
    }

    pub(crate) fn is_known_udp_source(&self, addr: std::net::SocketAddr) -> bool {
        self.control_session.is_control_addr(addr)
            || self.data_plane.gateway_sessions.is_gateway_addr(addr)
            || self.nat_test.has_pending_stun_server_addr(addr)
            || self
                .data_plane
                .route_manager
                .has_direct_route_key(&RouteKey::new(ConnectProtocol::UDP, addr))
    }

    pub(crate) fn is_suspended(&self) -> bool {
        self.state.tun.is_suspended()
    }

    pub(crate) fn suspend(&self) {
        let mut tun = self.state.tun.transition();
        tun.set_suspended(true);
        self.clear_applied_dns_profile();
        tun.stop_device();
    }

    pub(crate) fn resume<Call: SdlCallback>(&self, callback: &Call) -> anyhow::Result<()> {
        let mut tun = self.state.tun.transition();
        tun.set_suspended(false);
        self.rebuild_tun_locked(&mut tun, callback)
    }

    pub(crate) fn sync_tun_with_current_device<Call: SdlCallback>(
        &self,
        callback: &Call,
    ) -> anyhow::Result<()> {
        let mut tun = self.state.tun.transition();
        if tun.is_suspended() {
            self.clear_applied_dns_profile();
            tun.stop_device();
            return Ok(());
        }
        self.rebuild_tun_locked(&mut tun, callback)
    }

    fn rebuild_tun_locked<Call: SdlCallback>(
        &self,
        tun: &mut TunTransition<'_>,
        callback: &Call,
    ) -> anyhow::Result<()> {
        let current_device = self.state.current_device.load();
        if current_device.virtual_ip.is_unspecified()
            || current_device.virtual_gateway.is_unspecified()
            || current_device.virtual_netmask.is_unspecified()
        {
            return Ok(());
        }
        self.clear_applied_dns_profile();
        tun.stop_device();
        let device_config = DeviceConfig::new(
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            self.config.device_name.clone(),
            self.config.mtu,
            current_device.virtual_ip,
            current_device.virtual_netmask,
            current_device.virtual_gateway,
            current_device.virtual_network,
        );
        let device = create_device(device_config).map_err(|e| anyhow!("{}", e))?;
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        let tun_name = device.name().unwrap_or_else(|_| "sdl-tun".to_string());
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        self.apply_dns_profile(&tun_name, callback);
        tun.start_device(device)?;
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        {
            let tun_info = crate::handle::callback::DeviceInfo::new(tun_name, "".into());
            callback.create_tun(tun_info);
        }
        Ok(())
    }

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    fn clear_applied_dns_profile(&self) {
        let _ = self.state.dns.last_interface.lock().take();
        let interface_name = self.state.dns.applied_interface.lock().take();
        let applied_profile = self.state.dns.applied_profile.lock().take();
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

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    fn clear_applied_dns_profile(&self) {}

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    fn apply_dns_profile<Call: SdlCallback>(&self, interface_name: &str, callback: &Call) {
        let profile = self.state.dns.profile.read().clone();
        let Some(profile) = profile else {
            return;
        };
        if profile.servers.is_empty() || profile.match_domains.is_empty() {
            return;
        }
        *self.state.dns.last_interface.lock() = Some(interface_name.to_string());
        let previous_profile = self.state.dns.applied_profile.lock().clone();
        match crate::net::dns::platform::apply_split_dns(
            interface_name,
            previous_profile.as_ref(),
            &profile,
        ) {
            Ok(_) => {
                *self.state.dns.applied_interface.lock() = Some(interface_name.to_string());
                *self.state.dns.applied_profile.lock() = Some(profile);
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

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub(crate) fn revert_dns_on_shutdown(&self) {
        self.clear_applied_dns_profile();
    }

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub(crate) fn force_apply_dns_profile<Call: SdlCallback>(&self, callback: &Call) {
        let interface_name = self
            .state
            .dns
            .applied_interface
            .lock()
            .clone()
            .or_else(|| self.state.dns.last_interface.lock().clone());
        if let Some(interface_name) = interface_name {
            self.apply_dns_profile(&interface_name, callback);
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    pub(crate) fn force_apply_dns_profile<Call: SdlCallback>(&self, _callback: &Call) {}
}
