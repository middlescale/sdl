use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use http::Uri;
use parking_lot::Mutex;
use protobuf::Message;
use rand::RngCore;

use crate::core::PeerIdentity;
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route::RouteKey;
use crate::data_plane::stats::DataPlaneStats;
use crate::handle::{now_time, CurrentDeviceInfo};
use crate::proto::message::{
    GatewayAccessGrant, GatewayChannelKind, GatewayConnectAck, GatewayConnectHello,
};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};
use crate::transport::gateway_udp_channel::GatewayUdpChannel;
use crate::transport::http2_channel::Http2Channel;
use crate::transport::quic_channel::{PacketCallback, QuicChannel};
use crate::util::{DebugWatch, StopManager};

const GATEWAY_SWITCH_BETTER_RT_MS: i64 = 15;
const GATEWAY_SWITCH_COOLDOWN_MS: i64 = 10_000;
const GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS: u64 = 10;
const GATEWAY_GRANT_SOFT_REFRESH_LEAD_MS: i64 = 120_000;
const GATEWAY_UDP_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const UDP_GATEWAY_HELLOS_BEFORE_REBUILD: u32 = 3;
const UDP_GATEWAY_REBUILD_BASE_DELAY_MS: i64 = 5_000;
const UDP_GATEWAY_REBUILD_MAX_DELAY_MS: i64 = 60_000;
const PEER_INGRESS_GATEWAY_TTL: Duration = Duration::from_secs(60);
const GATEWAY_PROBE_INTERVAL_MS: i64 = 10_000;
const GATEWAY_PROBE_UNREACHABLE_AFTER: u32 = 3;
const PEER_RELAY_PROBE_INTERVAL_MS: i64 = 30_000;
static GATEWAY_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GatewayGrantPhase {
    #[default]
    Missing,
    Active,
    RefreshDue,
    Grace,
    Expired,
}

impl GatewayGrantPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Active => "active",
            Self::RefreshDue => "refresh-due",
            Self::Grace => "grace",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GatewayGrantState {
    Active,
    #[default]
    NeedsRefresh,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GatewayRelayHealth {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Unreachable,
}

impl GatewayRelayHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unreachable => "unreachable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayErrorKind {
    AuthRejected,
    SendFailed,
    ProbeUnreachable,
}

impl GatewayErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthRejected => "auth-rejected",
            Self::SendFailed => "send-failed",
            Self::ProbeUnreachable => "probe-unreachable",
        }
    }
}

impl GatewayGrantState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::NeedsRefresh => "needs-refresh",
        }
    }
}

#[derive(Clone, Default)]
struct GatewaySessionState {
    gateway_id: String,
    ticket: Vec<u8>,
    session_id: u64,
    policy_rev: u64,
    soft_refresh_after_unix_ms: i64,
    hard_expire_unix_ms: i64,
    ticket_expire_unix_ms: i64,
    device_id: String,
    channel_name: String,
    authenticated: bool,
    last_hello_unix_ms: i64,
    keepalive_secs: u32,
    lease_expire_unix_ms: i64,
    grace_expire_unix_ms: i64,
    lease_secs_hint: u32,
    grace_secs_hint: u32,
    reauth_required: bool,
    last_gateway_error: Option<String>,
    last_gateway_error_kind: Option<GatewayErrorKind>,
    last_gateway_error_unix_ms: i64,
    consecutive_gateway_errors: u32,
    last_rtt_ms: Option<i64>,
    consecutive_send_failures: u32,
    unanswered_hello_count: u32,
    udp_rebuild_requested: bool,
    gateway_virtual_ip: Option<Ipv4Addr>,
    last_probe_sent_unix_ms: i64,
    last_probe_reply_unix_ms: i64,
    last_probe_rtt_ms: Option<i64>,
    probe_epoch: u16,
    consecutive_probe_failures: u32,
    // Stream gateway authentication is bound to one transport connection on
    // the gateway. Never reuse an ACK after that connection has been replaced.
    authenticated_transport_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayTickOutcome {
    Idle,
    RebuildUdp,
}

#[derive(Clone, Copy, Debug, Default)]
struct UdpGatewayRebuildBackoff {
    attempts: u32,
    retry_after_unix_ms: i64,
}

#[derive(Clone)]
pub struct GatewaySession {
    endpoint: SocketAddr,
    state: Arc<Mutex<GatewaySessionState>>,
    channel: GatewayTransport,
    started: Arc<AtomicCell<bool>>,
    active: Arc<AtomicCell<bool>>,
    udp_stop_handle: Arc<Mutex<Option<UdpStopHandle>>>,
    debug_watch: DebugWatch,
    stats: DataPlaneStats,
}

struct UdpStopHandle {
    stop_sender: Option<mpsc::Sender<()>>,
    stopped_receiver: mpsc::Receiver<()>,
    runtime_active: Arc<AtomicCell<bool>>,
}

impl UdpStopHandle {
    fn stop(&mut self, timeout: Duration) -> bool {
        if let Some(stop_sender) = self.stop_sender.take() {
            let _ = stop_sender.send(());
        }
        self.stopped_receiver.recv_timeout(timeout).is_ok()
    }
}

#[derive(Clone)]
enum GatewayTransport {
    Quic(QuicChannel),
    Https(Http2Channel),
    Udp(GatewayUdpChannel),
}

impl GatewaySession {
    fn default_soft_refresh_after_unix_ms(hard_expire_unix_ms: i64) -> i64 {
        if hard_expire_unix_ms <= 0 {
            return 0;
        }
        if hard_expire_unix_ms <= GATEWAY_GRANT_SOFT_REFRESH_LEAD_MS {
            return hard_expire_unix_ms;
        }
        hard_expire_unix_ms - GATEWAY_GRANT_SOFT_REFRESH_LEAD_MS
    }

    fn hard_expire_unix_ms(guard: &GatewaySessionState) -> i64 {
        guard.hard_expire_unix_ms.max(guard.ticket_expire_unix_ms)
    }

    fn soft_refresh_after_unix_ms(guard: &GatewaySessionState) -> i64 {
        if guard.soft_refresh_after_unix_ms > 0 {
            guard.soft_refresh_after_unix_ms
        } else {
            Self::default_soft_refresh_after_unix_ms(Self::hard_expire_unix_ms(guard))
        }
    }

    fn grant_phase(guard: &GatewaySessionState, now_ms: i64) -> GatewayGrantPhase {
        let hard_expire_unix_ms = Self::hard_expire_unix_ms(guard);
        if guard.ticket.is_empty() || hard_expire_unix_ms <= 0 {
            return GatewayGrantPhase::Missing;
        }
        if now_ms > hard_expire_unix_ms {
            return GatewayGrantPhase::Expired;
        }
        if guard.authenticated
            && guard.lease_expire_unix_ms > 0
            && now_ms > guard.lease_expire_unix_ms
            && now_ms <= guard.grace_expire_unix_ms
        {
            return GatewayGrantPhase::Grace;
        }
        if now_ms >= Self::soft_refresh_after_unix_ms(guard) {
            return GatewayGrantPhase::RefreshDue;
        }
        GatewayGrantPhase::Active
    }

    fn grant_state(phase: GatewayGrantPhase) -> GatewayGrantState {
        match phase {
            GatewayGrantPhase::Active => GatewayGrantState::Active,
            GatewayGrantPhase::RefreshDue
            | GatewayGrantPhase::Grace
            | GatewayGrantPhase::Missing
            | GatewayGrantPhase::Expired => GatewayGrantState::NeedsRefresh,
        }
    }

    fn is_available(guard: &GatewaySessionState, now_ms: i64) -> bool {
        let expire_unix_ms = guard
            .grace_expire_unix_ms
            .max(guard.lease_expire_unix_ms)
            .max(Self::hard_expire_unix_ms(guard));
        guard.authenticated && now_ms <= expire_unix_ms
    }

    fn new_quic(endpoint: SocketAddr, debug_watch: DebugWatch, stats: DataPlaneStats) -> Self {
        Self {
            endpoint,
            state: Arc::new(Mutex::new(GatewaySessionState::default())),
            channel: GatewayTransport::Quic(QuicChannel::new(endpoint, endpoint.ip().to_string())),
            started: Arc::new(AtomicCell::new(false)),
            active: Arc::new(AtomicCell::new(false)),
            udp_stop_handle: Arc::new(Mutex::new(None)),
            debug_watch,
            stats,
        }
    }

    fn new_udp(
        endpoint: SocketAddr,
        grant: &GatewayAccessGrant,
        channel_meta: &crate::proto::message::GatewayChannel,
        debug_watch: DebugWatch,
        stats: DataPlaneStats,
    ) -> anyhow::Result<Self> {
        let gateway_udp_public_key: [u8; 32] = channel_meta
            .udp_public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("gateway udp public key must be 32 bytes"))?;
        Ok(Self {
            endpoint,
            state: Arc::new(Mutex::new(GatewaySessionState::default())),
            channel: GatewayTransport::Udp(GatewayUdpChannel::new(
                endpoint,
                gateway_udp_public_key,
                channel_meta.udp_key_id.clone(),
                grant.session_id,
            )?),
            started: Arc::new(AtomicCell::new(false)),
            active: Arc::new(AtomicCell::new(false)),
            udp_stop_handle: Arc::new(Mutex::new(None)),
            debug_watch,
            stats,
        })
    }

    fn new_https(
        endpoint: SocketAddr,
        request_uri: String,
        server_name: String,
        debug_watch: DebugWatch,
        stats: DataPlaneStats,
    ) -> Self {
        Self {
            endpoint,
            state: Arc::new(Mutex::new(GatewaySessionState::default())),
            channel: GatewayTransport::Https(Http2Channel::new(endpoint, request_uri, server_name)),
            started: Arc::new(AtomicCell::new(false)),
            active: Arc::new(AtomicCell::new(false)),
            udp_stop_handle: Arc::new(Mutex::new(None)),
            debug_watch,
            stats,
        }
    }

    fn start(&self, stop_manager: &StopManager, on_packet: &PacketCallback) -> anyhow::Result<()> {
        if self.started.swap(true) {
            return Ok(());
        }
        let runtime_id = GATEWAY_RUNTIME_ID.fetch_add(1, Ordering::Relaxed);
        let worker_name = format!(
            "gateway-{}-{runtime_id}",
            sanitize_worker_name(self.endpoint)
        );
        let endpoint = self.endpoint;
        let stats = self.stats.clone();
        let on_packet = on_packet.clone();
        let session_active = self.active.clone();
        match &self.channel {
            GatewayTransport::Quic(channel) => channel.start_named(
                stop_manager.clone(),
                &worker_name,
                move |packet: Vec<u8>, route_key| {
                    if !session_active.load() {
                        return;
                    }
                    stats.record_transport_down(endpoint.ip(), packet.len());
                    on_packet(packet, route_key);
                },
            ),
            GatewayTransport::Https(channel) => {
                let session_active = self.active.clone();
                channel.start_named(
                    stop_manager.clone(),
                    &worker_name,
                    move |packet: Vec<u8>, route_key| {
                        if !session_active.load() {
                            return;
                        }
                        stats.record_transport_down(endpoint.ip(), packet.len());
                        on_packet(packet, route_key);
                    },
                )
            }
            GatewayTransport::Udp(channel) => {
                let runtime_active = Arc::new(AtomicCell::new(true));
                let callback_runtime_active = runtime_active.clone();
                let session_active = self.active.clone();
                let callback: PacketCallback = Arc::new(move |packet: Vec<u8>, route_key| {
                    if !session_active.load() || !callback_runtime_active.load() {
                        return;
                    }
                    stats.record_transport_down(endpoint.ip(), packet.len());
                    on_packet(packet, route_key);
                });
                self.start_udp(
                    stop_manager,
                    &worker_name,
                    channel,
                    callback,
                    runtime_active,
                )
            }
        }
    }

    fn start_udp(
        &self,
        stop_manager: &StopManager,
        worker_name: &str,
        channel: &GatewayUdpChannel,
        callback: PacketCallback,
        runtime_active: Arc<AtomicCell<bool>>,
    ) -> anyhow::Result<()> {
        let mut udp_stop_handle = self.udp_stop_handle.lock();
        let session_stop_manager = StopManager::new(|| {});
        let (stop_sender, stop_receiver) = mpsc::channel::<()>();
        let parent_stop_sender = stop_sender.clone();
        let parent_worker = stop_manager.add_listener(worker_name.to_string(), move || {
            let _ = parent_stop_sender.send(());
        })?;
        let child_stop_manager = session_stop_manager.clone();
        let (stopped_sender, stopped_receiver) = mpsc::channel::<()>();
        let bridge_thread_name = format!("{worker_name}-stop");
        if let Err(err) = thread::Builder::new()
            .name(bridge_thread_name)
            .spawn(move || {
                let _ = stop_receiver.recv();
                child_stop_manager.stop();
                child_stop_manager.wait();
                drop(parent_worker);
                let _ = stopped_sender.send(());
            })
        {
            runtime_active.store(false);
            self.started.store(false);
            return Err(err.into());
        }
        if let Err(err) = channel.start_named(session_stop_manager, worker_name, callback) {
            runtime_active.store(false);
            let mut stop_handle = UdpStopHandle {
                stop_sender: Some(stop_sender),
                stopped_receiver,
                runtime_active: runtime_active.clone(),
            };
            let _ = stop_handle.stop(GATEWAY_UDP_STOP_TIMEOUT);
            self.started.store(false);
            return Err(err);
        }
        *udp_stop_handle = Some(UdpStopHandle {
            stop_sender: Some(stop_sender),
            stopped_receiver,
            runtime_active,
        });
        Ok(())
    }

    fn is_udp(&self) -> bool {
        matches!(&self.channel, GatewayTransport::Udp(_))
    }

    fn matches_kind(&self, kind: GatewayChannelKind) -> bool {
        matches!(
            (&self.channel, kind),
            (
                GatewayTransport::Udp(_),
                GatewayChannelKind::GATEWAY_CHANNEL_UDP
            ) | (
                GatewayTransport::Quic(_),
                GatewayChannelKind::GATEWAY_CHANNEL_QUIC
            ) | (
                GatewayTransport::Https(_),
                GatewayChannelKind::GATEWAY_CHANNEL_HTTPS
            )
        )
    }

    fn reactivate(&self) {
        self.active.store(true);
    }

    fn retire(&self) {
        self.active.store(false);
        let mut state = self.state.lock();
        state.authenticated = false;
        state.ticket.clear();
        state.hard_expire_unix_ms = 0;
        state.ticket_expire_unix_ms = 0;
        state.lease_expire_unix_ms = 0;
        state.grace_expire_unix_ms = 0;
    }

    fn stop_udp_runtime(&self) -> bool {
        let mut guard = self.udp_stop_handle.lock();
        if let Some(stop_handle) = guard.as_ref() {
            stop_handle.runtime_active.store(false);
        }
        let stopped = guard
            .as_mut()
            .map(|stop_handle| stop_handle.stop(GATEWAY_UDP_STOP_TIMEOUT))
            .unwrap_or(true);
        guard.take();
        self.started.store(false);
        stopped
    }

    fn recreate_udp(&self) -> anyhow::Result<Self> {
        let GatewayTransport::Udp(channel) = &self.channel else {
            return Err(anyhow::anyhow!(
                "cannot recreate non-UDP gateway session {}",
                self.endpoint
            ));
        };
        let mut state = self.state.lock().clone();
        state.authenticated = false;
        state.last_hello_unix_ms = 0;
        state.keepalive_secs = 0;
        state.lease_expire_unix_ms = 0;
        state.grace_expire_unix_ms = 0;
        state.last_rtt_ms = None;
        state.consecutive_send_failures = 0;
        state.unanswered_hello_count = 0;
        state.udp_rebuild_requested = false;
        Ok(Self {
            endpoint: self.endpoint,
            state: Arc::new(Mutex::new(state)),
            channel: GatewayTransport::Udp(channel.recreate()?),
            started: Arc::new(AtomicCell::new(false)),
            active: Arc::new(AtomicCell::new(false)),
            udp_stop_handle: Arc::new(Mutex::new(None)),
            debug_watch: self.debug_watch.clone(),
            stats: self.stats.clone(),
        })
    }

    fn update_grant(&self, grant: &GatewayAccessGrant, device_id: String) -> anyhow::Result<()> {
        let mut guard = self.state.lock();
        let auth_changed = guard.session_id != grant.session_id || guard.ticket != grant.ticket;
        guard.gateway_id = grant.gateway_id.clone();
        guard.ticket = grant.ticket.clone();
        guard.session_id = grant.session_id;
        guard.policy_rev = grant.policy_rev;
        guard.hard_expire_unix_ms = grant.hard_expire_unix_ms.max(grant.ticket_expire_unix_ms);
        guard.soft_refresh_after_unix_ms = if grant.soft_refresh_after_unix_ms > 0 {
            grant.soft_refresh_after_unix_ms
        } else {
            Self::default_soft_refresh_after_unix_ms(guard.hard_expire_unix_ms)
        };
        guard.ticket_expire_unix_ms = guard.hard_expire_unix_ms;
        guard.device_id = device_id;
        guard.channel_name = match &self.channel {
            GatewayTransport::Quic(_) => "quic".to_string(),
            GatewayTransport::Https(_) => "https".to_string(),
            GatewayTransport::Udp(_) => "udp".to_string(),
        };
        if auth_changed {
            guard.authenticated = false;
            guard.last_hello_unix_ms = 0;
            guard.keepalive_secs = 0;
            guard.lease_expire_unix_ms = 0;
            guard.grace_expire_unix_ms = 0;
            guard.reauth_required = false;
            Self::clear_gateway_error(&mut guard);
            guard.last_rtt_ms = None;
            guard.consecutive_send_failures = 0;
            guard.unanswered_hello_count = 0;
            guard.udp_rebuild_requested = false;
        }
        guard.lease_secs_hint = grant.lease_secs;
        guard.grace_secs_hint = grant.grace_secs;
        let http2_idle_timeout = gateway_http2_idle_timeout(guard.keepalive_secs);
        drop(guard);
        match &self.channel {
            GatewayTransport::Quic(channel) => {
                let selected_channel = grant.gateway_channel.as_ref().filter(|channel_meta| {
                    channel_meta.kind.enum_value_or_default()
                        == GatewayChannelKind::GATEWAY_CHANNEL_QUIC
                        && parse_transport_endpoint(&channel_meta.addr)
                            .map(|addr| addr == self.endpoint)
                            .unwrap_or(false)
                });
                let server_name = selected_channel
                    .map(|channel_meta| channel_meta.server_name.clone())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| self.endpoint.ip().to_string());
                let transport_changed = channel.update_server_name(server_name)
                    | channel.update_server_addr(self.endpoint);
                if transport_changed {
                    self.invalidate_stream_authentication();
                }
            }
            GatewayTransport::Https(channel) => {
                let selected_channel = grant.gateway_channel.as_ref().filter(|channel_meta| {
                    channel_meta.kind.enum_value_or_default()
                        == GatewayChannelKind::GATEWAY_CHANNEL_HTTPS
                        && parse_https_transport_target(&channel_meta.addr)
                            .map(|target| target.endpoint == self.endpoint)
                            .unwrap_or(false)
                });
                let parsed_target = selected_channel
                    .and_then(|channel_meta| parse_https_transport_target(&channel_meta.addr).ok());
                let server_name = selected_channel
                    .map(|channel_meta| channel_meta.server_name.clone())
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        parsed_target
                            .as_ref()
                            .map(|target| target.server_name.clone())
                    })
                    .unwrap_or_else(|| self.endpoint.ip().to_string());
                let request_uri = parsed_target
                    .map(|target| target.request_uri)
                    .unwrap_or_else(|| format!("https://{}/gateway", self.endpoint));
                let transport_changed = channel.update_server_addr(self.endpoint)
                    | channel.update_server_name(server_name)
                    | channel.update_request_uri(request_uri);
                channel.update_idle_timeout(http2_idle_timeout);
                if transport_changed {
                    self.invalidate_stream_authentication();
                }
            }
            GatewayTransport::Udp(channel) => {
                let channel_meta = grant
                    .gateway_channel
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("gateway channel is missing"))?;
                let gateway_udp_public_key: [u8; 32] = channel_meta
                    .udp_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("gateway udp public key must be 32 bytes"))?;
                channel.update_server_addr(self.endpoint);
                channel.update_gateway_udp_auth(
                    gateway_udp_public_key,
                    channel_meta.udp_key_id.clone(),
                    grant.session_id,
                )?;
            }
        }
        Ok(())
    }

    fn grant_snapshot(&self) -> GatewayGrantSnapshot {
        let guard = self.state.lock();
        GatewayGrantSnapshot {
            session_id: guard.session_id,
            policy_rev: guard.policy_rev,
            soft_refresh_after_unix_ms: Self::soft_refresh_after_unix_ms(&guard),
            hard_expire_unix_ms: Self::hard_expire_unix_ms(&guard),
            ticket_expire_unix_ms: Self::hard_expire_unix_ms(&guard),
        }
    }

    fn summary(&self) -> GatewaySessionSummary {
        self.reconcile_stream_authentication();
        let guard = self.state.lock();
        let now_ms = now_time() as i64;
        let grant_phase = Self::grant_phase(&guard, now_ms);
        GatewaySessionSummary {
            configured: true,
            authenticated: Self::is_available(&guard, now_ms),
            endpoint: Some(self.endpoint),
            gateway_id: guard.gateway_id.clone(),
            channel_name: guard.channel_name.clone(),
            grant_state: Self::grant_state(grant_phase),
            soft_refresh_after_unix_ms: Self::soft_refresh_after_unix_ms(&guard),
            hard_expire_unix_ms: Self::hard_expire_unix_ms(&guard),
            lease_expire_unix_ms: guard.lease_expire_unix_ms,
            grace_expire_unix_ms: guard.grace_expire_unix_ms,
            reauth_required: guard.reauth_required,
            last_gateway_error: guard.last_gateway_error.clone(),
            last_gateway_error_kind: guard.last_gateway_error_kind,
            last_gateway_error_unix_ms: guard.last_gateway_error_unix_ms,
            consecutive_gateway_errors: guard.consecutive_gateway_errors,
            rt_ms: guard.last_rtt_ms,
            active: false,
            grant_phase,
            consecutive_send_failures: guard.consecutive_send_failures,
            relay_health: Self::relay_health(&guard, now_ms),
            last_probe_unix_ms: guard.last_probe_reply_unix_ms,
            last_probe_rtt_ms: guard.last_probe_rtt_ms,
            consecutive_probe_failures: guard.consecutive_probe_failures,
            relay_send_failures_total: self.stats.gateway_send_failures_total(),
        }
    }

    fn relay_health(guard: &GatewaySessionState, now_ms: i64) -> GatewayRelayHealth {
        if !Self::is_available(guard, now_ms) {
            return GatewayRelayHealth::Unknown;
        }
        if guard.consecutive_probe_failures >= GATEWAY_PROBE_UNREACHABLE_AFTER {
            return GatewayRelayHealth::Unreachable;
        }
        if guard.last_probe_reply_unix_ms <= 0 {
            return GatewayRelayHealth::Degraded;
        }
        GatewayRelayHealth::Healthy
    }

    fn is_relay_available(&self) -> bool {
        if !self.active.load() {
            return false;
        }
        self.reconcile_stream_authentication();
        let guard = self.state.lock();
        Self::is_available(&guard, now_time() as i64)
    }

    fn matches_addr(&self, addr: SocketAddr) -> bool {
        self.endpoint == addr
    }

    fn tick(&self, current_device: &CurrentDeviceInfo) -> anyhow::Result<GatewayTickOutcome> {
        self.reconcile_stream_authentication();
        if self.take_udp_rebuild_request() {
            return Ok(GatewayTickOutcome::RebuildUdp);
        }
        if current_device.virtual_ip == Ipv4Addr::UNSPECIFIED {
            return Ok(GatewayTickOutcome::Idle);
        }
        if let Some(packet) = self.maybe_build_connect_hello(current_device)? {
            log::debug!(
                "sending gateway connect hello endpoint={}, source={}, gateway={}",
                self.endpoint,
                current_device.virtual_ip,
                current_device.virtual_gateway
            );
            self.debug_watch.emit(
                "gateway",
                "connect_hello",
                serde_json::json!({
                    "endpoint": self.endpoint.to_string(),
                    "source": current_device.virtual_ip.to_string(),
                    "gateway": current_device.virtual_gateway.to_string(),
                }),
            );
            if let Err(e) = self.send_packet(&packet) {
                if self.record_send_failure(e.kind()) {
                    return Ok(GatewayTickOutcome::RebuildUdp);
                }
                return Err(e.into());
            }
            self.record_send_success();
            if self.record_unanswered_hello() {
                return Ok(GatewayTickOutcome::RebuildUdp);
            }
        }
        if let Some(packet) = self.maybe_build_gateway_probe(current_device)? {
            if let Err(err) = self.send_packet(&packet) {
                self.record_send_failure(err.kind());
                return Err(err.into());
            }
            self.record_send_success();
        }
        Ok(GatewayTickOutcome::Idle)
    }

    fn send_relay<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        self.reconcile_stream_authentication();
        {
            let guard = self.state.lock();
            let now_ms = now_time() as i64;
            let expire_unix_ms = guard
                .grace_expire_unix_ms
                .max(guard.lease_expire_unix_ms)
                .max(guard.ticket_expire_unix_ms);
            if !Self::is_available(&guard, now_ms) {
                log::debug!(
                    "gateway relay unavailable endpoint={}, authenticated={}, now_ms={}, expire_unix_ms={}, session_id={}",
                    self.endpoint,
                    guard.authenticated,
                    now_ms,
                    expire_unix_ms,
                    guard.session_id
                );
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "gateway relay is not authenticated",
                ));
            }
        }
        if let Err(e) = self.send_packet(packet) {
            self.stats.record_gateway_send_failure();
            self.record_send_failure(e.kind());
            return Err(e);
        }
        self.record_send_success();
        self.stats
            .record_transport_up(self.endpoint.ip(), packet.buffer().as_ref().len());
        Ok(())
    }

    fn record_send_failure(&self, kind: io::ErrorKind) -> bool {
        let mut guard = self.state.lock();
        Self::record_gateway_error(
            &mut guard,
            GatewayErrorKind::SendFailed,
            format!("send_failed:{}", gateway_send_error_code(kind)),
            now_time() as i64,
        );
        guard.consecutive_send_failures += 1;
        let udp_transport_error = self.is_udp()
            && matches!(
                kind,
                io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::NotConnected
            );
        if udp_transport_error {
            guard.udp_rebuild_requested = true;
        }
        if guard.consecutive_send_failures >= 3 {
            guard.authenticated = false;
        }
        guard.udp_rebuild_requested
    }

    fn record_send_success(&self) {
        let mut guard = self.state.lock();
        guard.consecutive_send_failures = 0;
        if guard.last_gateway_error_kind == Some(GatewayErrorKind::SendFailed) {
            Self::clear_gateway_error(&mut guard);
        }
    }

    fn record_gateway_error(
        guard: &mut GatewaySessionState,
        kind: GatewayErrorKind,
        error: String,
        now_ms: i64,
    ) {
        if guard.last_gateway_error_kind == Some(kind)
            && guard.last_gateway_error.as_deref() == Some(error.as_str())
        {
            guard.consecutive_gateway_errors = guard.consecutive_gateway_errors.saturating_add(1);
        } else {
            guard.consecutive_gateway_errors = 1;
        }
        guard.last_gateway_error = Some(error);
        guard.last_gateway_error_kind = Some(kind);
        guard.last_gateway_error_unix_ms = now_ms;
    }

    fn clear_gateway_error(guard: &mut GatewaySessionState) {
        guard.last_gateway_error = None;
        guard.last_gateway_error_kind = None;
        guard.last_gateway_error_unix_ms = 0;
        guard.consecutive_gateway_errors = 0;
    }

    fn record_unanswered_hello(&self) -> bool {
        if !self.is_udp() {
            return false;
        }
        let mut guard = self.state.lock();
        if guard.authenticated {
            guard.unanswered_hello_count = 0;
            return false;
        }
        guard.unanswered_hello_count += 1;
        if guard.unanswered_hello_count >= UDP_GATEWAY_HELLOS_BEFORE_REBUILD {
            guard.udp_rebuild_requested = true;
        }
        guard.udp_rebuild_requested
    }

    fn take_udp_rebuild_request(&self) -> bool {
        if !self.is_udp() {
            return false;
        }
        let mut guard = self.state.lock();
        let requested = guard.udp_rebuild_requested;
        guard.udp_rebuild_requested = false;
        requested
    }

    fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        if !self.active.load() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "gateway session is retired",
            ));
        }
        match &self.channel {
            GatewayTransport::Quic(channel) => channel.send_packet(packet),
            GatewayTransport::Https(channel) => channel.send_packet(packet),
            GatewayTransport::Udp(channel) => {
                let runtime_active = self
                    .udp_stop_handle
                    .lock()
                    .as_ref()
                    .map(|stop_handle| stop_handle.runtime_active.load())
                    .unwrap_or(false);
                if !runtime_active {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "udp gateway session is inactive",
                    ));
                }
                channel.send_packet(packet)
            }
        }
    }

    fn handle_connect_ack(&self, ack: &GatewayConnectAck) {
        let mut guard = self.state.lock();
        if guard.session_id != ack.session_id {
            log::debug!(
                "ignoring gateway connect ack for endpoint={} due to session mismatch local={} remote={}",
                self.endpoint,
                guard.session_id,
                ack.session_id
            );
            return;
        }
        guard.authenticated = ack.ok;
        guard.authenticated_transport_generation = match &self.channel {
            GatewayTransport::Https(channel) if ack.ok => channel.connection_generation(),
            GatewayTransport::Quic(channel) if ack.ok => channel.connection_generation(),
            _ => 0,
        };
        guard.consecutive_send_failures = 0;
        guard.unanswered_hello_count = 0;
        guard.udp_rebuild_requested = false;
        if ack.ok {
            Self::clear_gateway_error(&mut guard);
            let now_ms = now_time() as i64;
            if guard.last_hello_unix_ms > 0 && now_ms >= guard.last_hello_unix_ms {
                guard.last_rtt_ms = Some((now_ms - guard.last_hello_unix_ms).max(1));
            }
            guard.keepalive_secs = ack.keepalive_secs;
            guard.lease_expire_unix_ms = if ack.lease_expire_unix_ms > 0 {
                ack.lease_expire_unix_ms
            } else {
                now_ms + i64::from(guard.lease_secs_hint.max(ack.keepalive_secs.max(3))) * 1_000
            };
            guard.grace_expire_unix_ms = if ack.grace_expire_unix_ms > 0 {
                ack.grace_expire_unix_ms
            } else {
                guard.lease_expire_unix_ms + i64::from(guard.grace_secs_hint) * 1_000
            };
            guard.reauth_required = ack.reauth_required;
            if let GatewayTransport::Https(channel) = &self.channel {
                channel.update_idle_timeout(gateway_http2_idle_timeout(ack.keepalive_secs));
            }
            log::info!(
                "gateway relay authenticated, session={}, endpoint={}, keepalive_secs={}, lease_expire={}, grace_expire={}, reauth_required={}",
                ack.session_id,
                self.endpoint,
                ack.keepalive_secs,
                ack.lease_expire_unix_ms,
                ack.grace_expire_unix_ms,
                ack.reauth_required
            );
            self.debug_watch.emit(
                "gateway",
                "authenticated",
                serde_json::json!({
                    "session_id": ack.session_id,
                    "endpoint": self.endpoint.to_string(),
                    "keepalive_secs": ack.keepalive_secs,
                    "lease_expire_unix_ms": ack.lease_expire_unix_ms,
                    "grace_expire_unix_ms": ack.grace_expire_unix_ms,
                    "reauth_required": ack.reauth_required,
                }),
            );
        } else {
            let now_ms = now_time() as i64;
            guard.keepalive_secs = 0;
            guard.lease_expire_unix_ms = 0;
            guard.grace_expire_unix_ms = 0;
            guard.reauth_required = ack.reauth_required;
            let error = if ack.reason.is_empty() {
                "gateway_rejected".to_string()
            } else {
                ack.reason.clone()
            };
            Self::record_gateway_error(&mut guard, GatewayErrorKind::AuthRejected, error, now_ms);
            guard.last_rtt_ms = None;
            if let GatewayTransport::Https(channel) = &self.channel {
                channel.update_idle_timeout(gateway_http2_idle_timeout(0));
            }
            log::warn!(
                "gateway relay auth rejected, session={}, endpoint={}, reason={}, reauth_required={}",
                ack.session_id,
                self.endpoint,
                ack.reason,
                ack.reauth_required
            );
            self.debug_watch.emit(
                "gateway",
                "auth_rejected",
                serde_json::json!({
                    "session_id": ack.session_id,
                    "endpoint": self.endpoint.to_string(),
                    "reason": ack.reason,
                    "reauth_required": ack.reauth_required,
                }),
            );
        }
    }

    fn invalidate_stream_authentication(&self) {
        let mut guard = self.state.lock();
        guard.authenticated = false;
        guard.authenticated_transport_generation = 0;
        guard.last_hello_unix_ms = 0;
        guard.last_rtt_ms = None;
        guard.consecutive_send_failures = 0;
        guard.unanswered_hello_count = 0;
    }

    fn reconcile_stream_authentication(&self) {
        let generation = match &self.channel {
            GatewayTransport::Https(channel) => channel.connection_generation(),
            GatewayTransport::Quic(channel) => channel.connection_generation(),
            GatewayTransport::Udp(_) => return,
        };
        let mut guard = self.state.lock();
        if guard.authenticated
            && (generation == 0 || generation != guard.authenticated_transport_generation)
        {
            guard.authenticated = false;
            guard.authenticated_transport_generation = 0;
            guard.last_hello_unix_ms = 0;
            guard.last_rtt_ms = None;
            guard.consecutive_send_failures = 0;
            guard.unanswered_hello_count = 0;
        }
    }

    fn maybe_build_gateway_probe(
        &self,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<Option<NetPacket<Vec<u8>>>> {
        let mut guard = self.state.lock();
        let now_ms = now_time() as i64;
        if !Self::is_available(&guard, now_ms)
            || now_ms - guard.last_probe_sent_unix_ms < GATEWAY_PROBE_INTERVAL_MS
        {
            return Ok(None);
        }
        if guard.last_probe_sent_unix_ms > guard.last_probe_reply_unix_ms {
            guard.consecutive_probe_failures = guard.consecutive_probe_failures.saturating_add(1);
            if guard.consecutive_probe_failures >= GATEWAY_PROBE_UNREACHABLE_AFTER {
                Self::record_gateway_error(
                    &mut guard,
                    GatewayErrorKind::ProbeUnreachable,
                    "probe_unreachable".to_string(),
                    now_ms,
                );
            }
        }
        guard.last_probe_sent_unix_ms = now_ms;
        guard.gateway_virtual_ip = Some(current_device.virtual_gateway);
        guard.probe_epoch = guard.probe_epoch.wrapping_add(1).max(1);
        let mut packet = NetPacket::new(vec![0u8; 12 + 4])?;
        packet.set_default_version();
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
        packet.set_initial_ttl(MAX_TTL);
        packet.set_source(current_device.virtual_ip);
        packet.set_destination(current_device.virtual_gateway);
        let mut ping = PingPacket::new(packet.payload_mut())?;
        ping.set_time(now_time() as u16);
        ping.set_epoch(guard.probe_epoch);
        Ok(Some(packet))
    }

    fn handle_gateway_probe_pong(&self, source: Ipv4Addr, route_key: RouteKey, epoch: u16) -> bool {
        if !self.matches_addr(route_key.addr) {
            return false;
        }
        let mut guard = self.state.lock();
        if Some(source) != guard.gateway_virtual_ip || epoch != guard.probe_epoch {
            return false;
        }
        let now_ms = now_time() as i64;
        guard.last_probe_reply_unix_ms = now_ms;
        guard.last_probe_rtt_ms = Some((now_ms - guard.last_probe_sent_unix_ms).max(1));
        guard.consecutive_probe_failures = 0;
        if guard.last_gateway_error_kind == Some(GatewayErrorKind::ProbeUnreachable) {
            Self::clear_gateway_error(&mut guard);
        }
        true
    }

    fn maybe_build_connect_hello(
        &self,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<Option<NetPacket<Vec<u8>>>> {
        let mut guard = self.state.lock();
        let now_ms = now_time() as i64;
        let ticket_available = now_ms <= guard.ticket_expire_unix_ms && !guard.ticket.is_empty();
        if !ticket_available && now_ms > guard.grace_expire_unix_ms {
            return Ok(None);
        }
        if guard.authenticated
            && guard.lease_expire_unix_ms > 0
            && now_ms > guard.lease_expire_unix_ms
        {
            guard.authenticated = false;
        }
        let interval_ms = if guard.authenticated {
            u64::from(guard.keepalive_secs.max(3)) * 1_000
        } else {
            3_000
        } as i64;
        if now_ms - guard.last_hello_unix_ms < interval_ms {
            return Ok(None);
        }
        if !guard.authenticated {
            if let GatewayTransport::Udp(channel) = &self.channel {
                channel.mark_bootstrap_pending();
            }
        }
        guard.last_hello_unix_ms = now_ms;
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let hello = GatewayConnectHello {
            device_id: guard.device_id.clone(),
            virtual_ip: u32::from(current_device.virtual_ip),
            session_id: guard.session_id,
            ticket: guard.ticket.clone(),
            nonce,
            client_time_unix_ms: now_ms,
            reauth: guard.reauth_required || !ticket_available,
            ..Default::default()
        };
        let payload = hello.write_to_bytes()?;
        let mut packet = NetPacket::new(vec![0u8; 12 + payload.len()])?;
        packet.set_default_version();
        packet.set_source(current_device.virtual_ip);
        packet.set_destination(current_device.virtual_gateway);
        packet.set_protocol(Protocol::Service);
        packet.set_transport_protocol(service_packet::Protocol::GatewayConnectHello.into());
        packet.set_initial_ttl(MAX_TTL);
        packet.set_payload(&payload)?;
        log::debug!(
            "built gateway connect hello endpoint={}, device_id={}, session_id={}, reauth={}, ticket_available={}",
            self.endpoint,
            guard.device_id,
            guard.session_id,
            guard.reauth_required || !ticket_available,
            ticket_available
        );
        Ok(Some(packet))
    }
}

#[derive(Clone)]
pub struct GatewayGrantSnapshot {
    pub session_id: u64,
    pub policy_rev: u64,
    pub soft_refresh_after_unix_ms: i64,
    pub hard_expire_unix_ms: i64,
    pub ticket_expire_unix_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct GatewaySessionSummary {
    pub configured: bool,
    pub authenticated: bool,
    pub endpoint: Option<SocketAddr>,
    pub gateway_id: String,
    pub channel_name: String,
    pub grant_state: GatewayGrantState,
    pub soft_refresh_after_unix_ms: i64,
    pub hard_expire_unix_ms: i64,
    pub lease_expire_unix_ms: i64,
    pub grace_expire_unix_ms: i64,
    pub reauth_required: bool,
    pub last_gateway_error: Option<String>,
    pub last_gateway_error_kind: Option<GatewayErrorKind>,
    pub last_gateway_error_unix_ms: i64,
    pub consecutive_gateway_errors: u32,
    pub rt_ms: Option<i64>,
    pub active: bool,
    pub grant_phase: GatewayGrantPhase,
    pub consecutive_send_failures: u32,
    pub relay_health: GatewayRelayHealth,
    pub last_probe_unix_ms: i64,
    pub last_probe_rtt_ms: Option<i64>,
    pub consecutive_probe_failures: u32,
    pub relay_send_failures_total: u64,
}

#[derive(Default)]
struct GatewaySelectionState {
    manual_endpoint: Option<SocketAddr>,
    selected_endpoint: Option<SocketAddr>,
    last_switch_unix_ms: i64,
}

#[derive(Clone, Copy, Debug)]
struct PeerIngressGateway {
    endpoint: SocketAddr,
    expires_at: Instant,
}

#[derive(Clone, Copy, Default)]
struct PeerRelayProbe {
    epoch: u16,
    last_sent_unix_ms: i64,
    last_reply_unix_ms: i64,
    consecutive_failures: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PeerRelayHealthSummary {
    pub last_relay_receive_unix_ms: i64,
    pub last_probe_unix_ms: i64,
    pub consecutive_probe_failures: u32,
}

#[derive(Clone)]
pub struct GatewaySessions {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    runtime: Arc<OnceLock<(StopManager, PacketCallback)>>,
    sessions: Arc<Mutex<HashMap<SocketAddr, GatewaySession>>>,
    dormant_stream_sessions: Arc<Mutex<HashMap<SocketAddr, GatewaySession>>>,
    selection: Arc<Mutex<GatewaySelectionState>>,
    peer_ingress_gateways: Arc<Mutex<HashMap<PeerIdentity, PeerIngressGateway>>>,
    peer_relay_probes: Arc<Mutex<HashMap<Ipv4Addr, PeerRelayProbe>>>,
    peer_relay_receives: Arc<Mutex<HashMap<Ipv4Addr, i64>>>,
    udp_rebuild_backoff: Arc<Mutex<HashMap<SocketAddr, UdpGatewayRebuildBackoff>>>,
    refresh_requested_at_ms: Arc<AtomicCell<i64>>,
    worker_started: Arc<AtomicCell<bool>>,
    debug_watch: DebugWatch,
    stats: DataPlaneStats,
}

impl GatewaySessions {
    pub fn new(
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        debug_watch: DebugWatch,
        stats: DataPlaneStats,
    ) -> Self {
        Self {
            current_device,
            runtime: Arc::new(OnceLock::new()),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            dormant_stream_sessions: Arc::new(Mutex::new(HashMap::new())),
            selection: Arc::new(Mutex::new(GatewaySelectionState::default())),
            peer_ingress_gateways: Arc::new(Mutex::new(HashMap::new())),
            peer_relay_probes: Arc::new(Mutex::new(HashMap::new())),
            peer_relay_receives: Arc::new(Mutex::new(HashMap::new())),
            udp_rebuild_backoff: Arc::new(Mutex::new(HashMap::new())),
            refresh_requested_at_ms: Arc::new(AtomicCell::new(0)),
            worker_started: Arc::new(AtomicCell::new(false)),
            debug_watch,
            stats,
        }
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        let _ = self
            .runtime
            .set((stop_manager.clone(), Arc::new(on_packet)));
        let (stop_manager, on_packet) = self.runtime.get().unwrap();
        for session in self.sessions.lock().values() {
            session.start(stop_manager, on_packet)?;
        }
        if self.worker_started.swap(true) {
            return Ok(());
        }
        let (stop_sender, stop_receiver) = mpsc::channel::<()>();
        let worker = stop_manager.add_listener("gatewaySessions".into(), move || {
            let _ = stop_sender.send(());
        })?;
        let sessions = self.clone();
        thread::Builder::new()
            .name("gatewaySessions".into())
            .spawn(move || {
                sessions.run(stop_receiver);
                drop(worker);
            })?;
        Ok(())
    }

    fn run(&self, stop_receiver: mpsc::Receiver<()>) {
        loop {
            if stop_receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                break;
            }
            self.trigger_connect_now();
        }
    }

    pub fn trigger_connect_now(&self) {
        let current_device = self.current_device.load();
        let sessions: Vec<GatewaySession> = self.sessions.lock().values().cloned().collect();
        for session in sessions {
            match session.tick(&current_device) {
                Ok(GatewayTickOutcome::Idle) => {}
                Ok(GatewayTickOutcome::RebuildUdp) => self.rebuild_udp_session(session.endpoint),
                Err(e) => {
                    log::debug!(
                        "gateway session tick failed endpoint={}: {:?}",
                        session.endpoint,
                        e
                    );
                }
            }
        }
    }

    /// Recreates UDP gateway sockets after the local underlay changed. Stream
    /// transports keep their self-healing connections and are not rebuilt.
    pub fn rebuild_udp_sessions_after_underlay_change(&self) {
        self.udp_rebuild_backoff.lock().clear();
        let endpoints = self
            .sessions
            .lock()
            .values()
            .filter(|session| session.is_udp())
            .map(|session| session.endpoint)
            .collect::<Vec<_>>();
        for endpoint in endpoints {
            self.rebuild_udp_session(endpoint);
        }
        self.trigger_connect_now();
    }

    fn rebuild_udp_session(&self, endpoint: SocketAddr) {
        let old = {
            let mut sessions = self.sessions.lock();
            let Some(session) = sessions.get(&endpoint) else {
                return;
            };
            if !session.is_udp() {
                return;
            }
            if !self.try_begin_udp_rebuild(endpoint) {
                return;
            }
            log::warn!("rebuilding UDP gateway session endpoint={}", endpoint);
            sessions
                .remove(&endpoint)
                .expect("gateway session disappeared")
        };
        let replacement = match old.recreate_udp() {
            Ok(session) => session,
            Err(err) => {
                log::warn!(
                    "recreate UDP gateway session failed endpoint={}: {err:#}",
                    endpoint
                );
                return;
            }
        };
        old.retire();
        if !old.stop_udp_runtime() {
            log::warn!(
                "UDP gateway runtime stop timed out before rebuild; detaching endpoint={}",
                endpoint
            );
        }
        if let Some((stop_manager, on_packet)) = self.runtime.get() {
            if let Err(err) = replacement.start(stop_manager, on_packet) {
                log::warn!(
                    "restart UDP gateway session failed endpoint={}: {err:#}",
                    endpoint
                );
            }
        }
        replacement.reactivate();
        let mut sessions = self.sessions.lock();
        if sessions.contains_key(&endpoint) {
            log::debug!(
                "skip stale UDP gateway replacement because a newer session exists endpoint={}",
                endpoint
            );
            replacement.retire();
            let _ = replacement.stop_udp_runtime();
            return;
        }
        sessions.insert(endpoint, replacement);
    }

    fn try_begin_udp_rebuild(&self, endpoint: SocketAddr) -> bool {
        let now_ms = now_time() as i64;
        let mut backoff = self.udp_rebuild_backoff.lock();
        let state = backoff.entry(endpoint).or_default();
        if now_ms < state.retry_after_unix_ms {
            return false;
        }
        let exponent = state.attempts.min(4);
        let delay_ms = UDP_GATEWAY_REBUILD_BASE_DELAY_MS
            .saturating_mul(1_i64 << exponent)
            .min(UDP_GATEWAY_REBUILD_MAX_DELAY_MS);
        state.attempts = state.attempts.saturating_add(1);
        state.retry_after_unix_ms = now_ms.saturating_add(delay_ms);
        true
    }

    pub fn set_gateway_grant(
        &self,
        grant: &GatewayAccessGrant,
        virtual_ip: Ipv4Addr,
        device_id: String,
    ) {
        self.set_gateway_grants(std::slice::from_ref(grant), virtual_ip, device_id);
    }

    pub fn set_gateway_grants(
        &self,
        grants: &[GatewayAccessGrant],
        virtual_ip: Ipv4Addr,
        device_id: String,
    ) {
        let mut parsed: Vec<(GatewayAccessGrant, ResolvedGatewayChannel)> = Vec::new();
        let mut desired = HashSet::new();
        for grant in grants {
            if let Some(channel) = grant.gateway_channel.as_ref() {
                let kind = match channel.kind.enum_value() {
                    Ok(
                        kind @ (GatewayChannelKind::GATEWAY_CHANNEL_UDP
                        | GatewayChannelKind::GATEWAY_CHANNEL_QUIC
                        | GatewayChannelKind::GATEWAY_CHANNEL_HTTPS),
                    ) => kind,
                    Ok(GatewayChannelKind::GATEWAY_CHANNEL_UNKNOWN) => {
                        log::warn!(
                            "ignore gateway channel with unspecified kind gateway_id={} addr={}",
                            grant.gateway_id,
                            channel.addr
                        );
                        continue;
                    }
                    Err(value) => {
                        log::warn!(
                            "ignore gateway channel with unknown kind gateway_id={} kind={} addr={}",
                            grant.gateway_id,
                            value,
                            channel.addr
                        );
                        continue;
                    }
                };
                if kind == GatewayChannelKind::GATEWAY_CHANNEL_UDP
                    && (channel.udp_public_key.len() != 32 || channel.udp_key_id.is_empty())
                {
                    log::warn!(
                        "ignore UDP gateway channel with invalid key metadata gateway_id={} addr={}",
                        grant.gateway_id,
                        channel.addr
                    );
                    continue;
                }
                match resolve_gateway_channel(channel) {
                    Ok(channel) if desired.insert(channel.endpoint) => {
                        parsed.push((grant.clone(), channel));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!(
                            "ignore invalid gateway channel gateway_id={} kind={:?} addr={}: {:?}",
                            grant.gateway_id,
                            kind,
                            channel.addr,
                            e
                        );
                    }
                }
            }
        }
        if parsed.is_empty() {
            self.clear_gateway_grant();
            log::info!(
                "gateway relay disabled for virtual ip {virtual_ip}: no supported gateway channel"
            );
            return;
        }
        self.refresh_requested_at_ms.store(0);
        log::info!(
            "gateway grants applied for virtual ip {} with endpoints {:?}, gateways={:?}",
            virtual_ip,
            parsed
                .iter()
                .map(|(_, channel)| channel.endpoint)
                .collect::<Vec<_>>(),
            parsed
                .iter()
                .map(|(grant, _)| grant.gateway_id.clone())
                .collect::<Vec<_>>()
        );
        let mut guard = self.sessions.lock();
        let removed_endpoints: Vec<SocketAddr> = guard
            .keys()
            .filter(|endpoint| !desired.contains(endpoint))
            .copied()
            .collect();
        let mut dormant = self.dormant_stream_sessions.lock();
        for endpoint in removed_endpoints {
            self.udp_rebuild_backoff.lock().remove(&endpoint);
            let Some(session) = guard.remove(&endpoint) else {
                continue;
            };
            session.retire();
            if session.is_udp() {
                if !session.stop_udp_runtime() {
                    log::warn!(
                        "udp gateway session stop timed out; detaching endpoint={}",
                        endpoint
                    );
                }
            } else {
                dormant.insert(endpoint, session);
            }
        }
        for (grant, resolved_channel) in parsed {
            let endpoint = resolved_channel.endpoint;
            let session = if let Some(existing) = guard.get(&endpoint).cloned() {
                if !existing.matches_kind(resolved_channel.kind) {
                    log::warn!(
                        "ignore gateway channel kind change for active endpoint={} requested_kind={:?}",
                        endpoint,
                        resolved_channel.kind
                    );
                    continue;
                }
                existing
            } else if let Some(existing) = dormant.remove(&endpoint) {
                if existing.matches_kind(resolved_channel.kind) {
                    guard.insert(endpoint, existing.clone());
                    existing
                } else {
                    log::warn!(
                        "ignore gateway channel kind change for dormant endpoint={} requested_kind={:?}",
                        endpoint,
                        resolved_channel.kind
                    );
                    dormant.insert(endpoint, existing);
                    continue;
                }
            } else {
                let created = match resolved_channel.kind {
                    GatewayChannelKind::GATEWAY_CHANNEL_UDP => {
                        match GatewaySession::new_udp(
                            endpoint,
                            &grant,
                            grant
                                .gateway_channel
                                .as_ref()
                                .expect("parsed gateway channel"),
                            self.debug_watch.clone(),
                            self.stats.clone(),
                        ) {
                            Ok(session) => session,
                            Err(e) => {
                                log::warn!(
                                    "create udp gateway session failed {}: {:?}",
                                    endpoint,
                                    e
                                );
                                continue;
                            }
                        }
                    }
                    GatewayChannelKind::GATEWAY_CHANNEL_HTTPS => GatewaySession::new_https(
                        endpoint,
                        resolved_channel
                            .request_uri
                            .clone()
                            .unwrap_or_else(|| format!("https://{}/gateway", endpoint)),
                        resolved_channel.server_name.clone(),
                        self.debug_watch.clone(),
                        self.stats.clone(),
                    ),
                    _ => GatewaySession::new_quic(
                        endpoint,
                        self.debug_watch.clone(),
                        self.stats.clone(),
                    ),
                };
                guard.insert(endpoint, created.clone());
                created
            };
            if let Err(e) = session.update_grant(&grant, device_id.clone()) {
                log::warn!("update gateway session failed {}: {:?}", endpoint, e);
                session.retire();
                if session.is_udp() && !session.stop_udp_runtime() {
                    log::warn!(
                        "udp gateway session stop timed out after grant update failure; detaching endpoint={}",
                        endpoint
                    );
                }
                guard.remove(&endpoint);
                continue;
            }
            if let Some((stop_manager, on_packet)) = self.runtime.get() {
                if let Err(e) = session.start(stop_manager, on_packet) {
                    log::warn!("start gateway session failed {}: {:?}", endpoint, e);
                    session.retire();
                    if session.is_udp() && !session.stop_udp_runtime() {
                        log::warn!(
                            "udp gateway session stop timed out after start failure; detaching endpoint={}",
                            endpoint
                        );
                    }
                    guard.remove(&endpoint);
                    continue;
                }
            }
            session.reactivate();
        }
        self.reset_selection_if_missing(&guard);
        drop(guard);
        self.peer_ingress_gateways
            .lock()
            .retain(|_, ingress| desired.contains(&ingress.endpoint));
        self.trigger_connect_now();
    }

    pub fn clear_gateway_grant(&self) {
        let mut sessions = self.sessions.lock();
        let mut dormant = self.dormant_stream_sessions.lock();
        self.udp_rebuild_backoff.lock().clear();
        for (endpoint, session) in sessions.drain() {
            session.retire();
            if session.is_udp() {
                if !session.stop_udp_runtime() {
                    log::warn!(
                        "udp gateway session stop timed out while clearing grants; detaching endpoint={}",
                        endpoint
                    );
                }
            } else {
                dormant.insert(endpoint, session);
            }
        }
        drop(dormant);
        drop(sessions);
        *self.selection.lock() = GatewaySelectionState::default();
        self.peer_ingress_gateways.lock().clear();
        self.refresh_requested_at_ms.store(0);
    }

    pub fn set_manual_endpoint(&self, endpoint: Option<SocketAddr>) -> anyhow::Result<()> {
        let sessions = self.sessions.lock();
        if let Some(endpoint) = endpoint {
            if !sessions.contains_key(&endpoint) {
                anyhow::bail!("gateway endpoint {endpoint} not found");
            }
        }
        let mut selection = self.selection.lock();
        selection.manual_endpoint = endpoint;
        selection.selected_endpoint = endpoint;
        selection.last_switch_unix_ms = now_time() as i64;
        Ok(())
    }

    pub fn current_grant_snapshot(&self) -> Option<GatewayGrantSnapshot> {
        self.sessions
            .lock()
            .values()
            .map(GatewaySession::grant_snapshot)
            .max_by_key(|snapshot| {
                snapshot
                    .hard_expire_unix_ms
                    .max(snapshot.ticket_expire_unix_ms)
            })
    }

    pub fn session_summary(&self) -> GatewaySessionSummary {
        let guard = self.sessions.lock();
        let active = self.choose_active_endpoint_locked(&guard);
        active
            .and_then(|endpoint| guard.get(&endpoint))
            .map(|session| {
                let mut summary = session.summary();
                summary.active = true;
                summary
            })
            .or_else(|| {
                guard
                    .values()
                    .map(GatewaySession::summary)
                    .max_by_key(gateway_summary_sort_key)
            })
            .unwrap_or_default()
    }

    pub fn session_summaries(&self) -> Vec<GatewaySessionSummary> {
        let guard = self.sessions.lock();
        let active = self.choose_active_endpoint_locked(&guard);
        let mut summaries: Vec<GatewaySessionSummary> = guard
            .iter()
            .map(|(endpoint, session)| {
                let mut summary = session.summary();
                summary.active = Some(*endpoint) == active;
                summary
            })
            .collect();
        summaries.sort_by_key(|summary| {
            (
                summary.endpoint != active,
                !summary.authenticated,
                summary.rt_ms.unwrap_or(i64::MAX),
                summary.gateway_id.clone(),
                summary.channel_name.clone(),
            )
        });
        summaries
    }

    pub fn mark_refresh_requested(&self) {
        self.refresh_requested_at_ms.store(now_time() as i64);
    }

    pub fn last_refresh_requested_at_ms(&self) -> i64 {
        self.refresh_requested_at_ms.load()
    }

    pub fn is_gateway_addr(&self, addr: SocketAddr) -> bool {
        self.sessions
            .lock()
            .values()
            .any(|session| session.matches_addr(addr))
    }

    /// Records the gateway that most recently delivered relay traffic for a peer.
    ///
    /// This is only a relay fallback hint. Measured P2P routes remain preferred by
    /// `DataChannel`, and the hint expires so a peer can move to another gateway.
    pub fn remember_peer_ingress_gateway(&self, peer: PeerIdentity, endpoint: SocketAddr) {
        if !self.sessions.lock().contains_key(&endpoint) {
            return;
        }
        self.peer_ingress_gateways.lock().insert(
            peer,
            PeerIngressGateway {
                endpoint,
                expires_at: Instant::now() + PEER_INGRESS_GATEWAY_TTL,
            },
        );
    }

    pub fn retain_peer_ingress_gateways(&self, active_peers: &HashSet<PeerIdentity>) {
        self.peer_ingress_gateways.lock().retain(|peer, ingress| {
            active_peers.contains(peer) && ingress.expires_at > Instant::now()
        });
    }

    fn peer_ingress_gateway(&self, peer: &PeerIdentity) -> Option<SocketAddr> {
        let mut ingress_gateways = self.peer_ingress_gateways.lock();
        let ingress = ingress_gateways.get(peer).copied()?;
        if ingress.expires_at <= Instant::now() {
            ingress_gateways.remove(peer);
            return None;
        }
        Some(ingress.endpoint)
    }

    fn relay_session_at(&self, endpoint: SocketAddr) -> Option<GatewaySession> {
        let session = self.sessions.lock().get(&endpoint).cloned()?;
        session.is_relay_available().then_some(session)
    }

    fn peer_ingress_session(&self, peer: &PeerIdentity) -> Option<GatewaySession> {
        self.peer_ingress_gateway(peer)
            .and_then(|endpoint| self.relay_session_at(endpoint))
    }

    pub fn send_relay_to<B: AsRef<[u8]>>(
        &self,
        endpoint: SocketAddr,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        let session = self
            .sessions
            .lock()
            .get(&endpoint)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "requested gateway session is unavailable",
                )
            })?;
        session.send_relay(packet)
    }

    /// Sends a reply through the gateway that delivered the request when it is
    /// still usable; otherwise falls back to normal active-gateway selection.
    ///
    /// A send failure from a usable preferred session is returned directly. Retrying
    /// through another gateway at that point could duplicate a packet already handed
    /// to the transport.
    pub fn send_relay_to_or_active<B: AsRef<[u8]>>(
        &self,
        endpoint: SocketAddr,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(session) = self.relay_session_at(endpoint) {
            return session.send_relay(packet);
        }
        self.send_relay(packet)
    }

    pub fn send_relay_for_peer<B: AsRef<[u8]>>(
        &self,
        peer: Option<&PeerIdentity>,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(session) = peer.and_then(|peer| self.peer_ingress_session(peer)) {
            return session.send_relay(packet);
        }
        self.send_relay(packet)
    }

    pub fn send_relay<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        let guard = self.sessions.lock();
        let active = self.choose_active_endpoint_locked(&guard);
        let manual_endpoint = self.selection.lock().manual_endpoint;
        if let Some(endpoint) = manual_endpoint {
            let Some(session) = guard.get(&endpoint).cloned() else {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "selected gateway session is unavailable",
                ));
            };
            drop(guard);
            return session.send_relay(packet);
        }
        let mut sessions: Vec<GatewaySession> = guard.values().cloned().collect();
        drop(guard);
        sessions.sort_by_key(|session| gateway_session_order_key(session, active));
        let mut last_err = None;
        for session in sessions {
            match session.send_relay(packet) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                    log::debug!(
                        "gateway relay send skipped endpoint={}: {}",
                        session.endpoint,
                        e
                    );
                    last_err = Some(e);
                }
                Err(e) => {
                    log::warn!(
                        "gateway relay send failed endpoint={}: {:?}",
                        session.endpoint,
                        e
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no available gateway session")
        }))
    }

    pub fn handle_connect_ack(&self, from: SocketAddr, ack: &GatewayConnectAck) {
        if let Some(session) = self.sessions.lock().get(&from).cloned() {
            session.handle_connect_ack(ack);
            if ack.ok {
                self.udp_rebuild_backoff.lock().remove(&from);
            }
        } else {
            log::debug!(
                "received gateway connect ack from unknown endpoint={} session_id={} ok={} reason={}",
                from,
                ack.session_id,
                ack.ok,
                ack.reason
            );
        }
    }

    pub fn handle_gateway_probe_pong(
        &self,
        source: Ipv4Addr,
        route_key: RouteKey,
        epoch: u16,
    ) -> bool {
        self.sessions
            .lock()
            .get(&route_key.addr)
            .map(|session| session.handle_gateway_probe_pong(source, route_key, epoch))
            .unwrap_or(false)
    }

    pub fn maybe_send_peer_relay_probe(
        &self,
        peer_ip: Ipv4Addr,
        peer_identity: Option<&PeerIdentity>,
        peer_crypto: &PeerCryptoManager,
    ) {
        let Some(peer_identity) = peer_identity else {
            return;
        };
        let now_ms = now_time() as i64;
        let epoch = {
            let mut probes = self.peer_relay_probes.lock();
            let probe = probes.entry(peer_ip).or_default();
            if now_ms - probe.last_sent_unix_ms < PEER_RELAY_PROBE_INTERVAL_MS {
                return;
            }
            if probe.last_sent_unix_ms > probe.last_reply_unix_ms {
                probe.consecutive_failures = probe.consecutive_failures.saturating_add(1);
            }
            probe.last_sent_unix_ms = now_ms;
            probe.epoch = probe.epoch.wrapping_add(1).max(1);
            probe.epoch
        };
        let Some(cipher) = peer_crypto.current_cipher(peer_identity).ok() else {
            return;
        };
        let current = self.current_device.load();
        let mut packet = match NetPacket::new_encrypt(vec![0u8; 12 + 4 + ENCRYPTION_RESERVED]) {
            Ok(packet) => packet,
            Err(err) => {
                log::debug!(
                    "failed to create relay peer probe for {}: {:?}",
                    peer_ip,
                    err
                );
                return;
            }
        };
        packet.set_default_version();
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
        packet.set_initial_ttl(MAX_TTL);
        packet.set_source(current.virtual_ip);
        packet.set_destination(peer_ip);
        if let Ok(mut ping) = PingPacket::new(packet.payload_mut()) {
            ping.set_time(now_time() as u16);
            ping.set_epoch(epoch);
        } else {
            return;
        }
        if let Err(err) = cipher.encrypt_ipv4(&mut packet) {
            log::debug!(
                "failed to encrypt relay peer probe for {}: {:?}",
                peer_ip,
                err
            );
            return;
        }
        if let Err(err) = self.send_relay_for_peer(Some(peer_identity), &packet) {
            log::debug!("failed to send relay peer probe for {}: {:?}", peer_ip, err);
        }
    }

    pub fn handle_peer_relay_probe_pong(
        &self,
        peer_ip: Ipv4Addr,
        route_key: RouteKey,
        epoch: u16,
    ) -> bool {
        if !self.is_gateway_addr(route_key.addr) {
            return false;
        }
        let mut probes = self.peer_relay_probes.lock();
        let Some(probe) = probes.get_mut(&peer_ip) else {
            return false;
        };
        if probe.epoch != epoch {
            return false;
        }
        probe.last_reply_unix_ms = now_time() as i64;
        probe.consecutive_failures = 0;
        true
    }

    pub fn observe_peer_relay_receive(&self, peer_ip: Ipv4Addr, route_key: RouteKey) {
        if self.is_gateway_addr(route_key.addr) {
            self.peer_relay_receives
                .lock()
                .insert(peer_ip, now_time() as i64);
        }
    }

    pub fn peer_relay_health_summary(&self, peer_ip: Ipv4Addr) -> PeerRelayHealthSummary {
        let probe = self
            .peer_relay_probes
            .lock()
            .get(&peer_ip)
            .copied()
            .unwrap_or_default();
        PeerRelayHealthSummary {
            last_relay_receive_unix_ms: self
                .peer_relay_receives
                .lock()
                .get(&peer_ip)
                .copied()
                .unwrap_or_default(),
            last_probe_unix_ms: probe.last_reply_unix_ms,
            consecutive_probe_failures: probe.consecutive_failures,
        }
    }

    fn reset_selection_if_missing(&self, sessions: &HashMap<SocketAddr, GatewaySession>) {
        let mut selection = self.selection.lock();
        if selection
            .manual_endpoint
            .is_some_and(|endpoint| !sessions.contains_key(&endpoint))
        {
            selection.manual_endpoint = None;
        }
        if selection
            .selected_endpoint
            .is_some_and(|endpoint| !sessions.contains_key(&endpoint))
        {
            selection.selected_endpoint = None;
            selection.last_switch_unix_ms = 0;
        }
    }

    fn choose_active_endpoint_locked(
        &self,
        sessions: &HashMap<SocketAddr, GatewaySession>,
    ) -> Option<SocketAddr> {
        let now_ms = now_time() as i64;
        let mut selection = self.selection.lock();
        if let Some(endpoint) = selection.manual_endpoint {
            if sessions.contains_key(&endpoint) {
                selection.selected_endpoint = Some(endpoint);
                return Some(endpoint);
            }
            selection.manual_endpoint = None;
        }
        let best = sessions
            .iter()
            .map(|(endpoint, session)| (*endpoint, session.summary()))
            .max_by_key(|(_, summary)| gateway_summary_sort_key(summary));
        let current = selection.selected_endpoint.and_then(|endpoint| {
            sessions
                .get(&endpoint)
                .map(|session| (endpoint, session.summary()))
        });
        let chosen = match (current, best) {
            (Some((current_endpoint, current_summary)), Some((best_endpoint, best_summary))) => {
                if current_endpoint == best_endpoint {
                    current_endpoint
                } else if !current_summary.authenticated {
                    best_endpoint
                } else if best_summary.authenticated
                    && gateway_summary_is_clearly_better(&best_summary, &current_summary)
                    && now_ms - selection.last_switch_unix_ms >= GATEWAY_SWITCH_COOLDOWN_MS
                {
                    best_endpoint
                } else {
                    current_endpoint
                }
            }
            (Some((current_endpoint, current_summary)), None) => {
                if current_summary.configured {
                    current_endpoint
                } else {
                    return None;
                }
            }
            (None, Some((best_endpoint, _))) => best_endpoint,
            (None, None) => return None,
        };
        if selection.selected_endpoint != Some(chosen) {
            selection.selected_endpoint = Some(chosen);
            selection.last_switch_unix_ms = now_ms;
        }
        Some(chosen)
    }
}

impl Default for GatewaySessions {
    fn default() -> Self {
        Self::new(
            Arc::new(AtomicCell::new(CurrentDeviceInfo::new0())),
            DebugWatch::default(),
            DataPlaneStats::new(true),
        )
    }
}

fn parse_transport_endpoint(addr: &str) -> anyhow::Result<SocketAddr> {
    let normalized = addr
        .strip_prefix("quic://")
        .or_else(|| addr.strip_prefix("udp://"))
        .unwrap_or(addr)
        .trim()
        .to_string();
    if let Ok(socket_addr) = SocketAddr::from_str(&normalized) {
        return Ok(socket_addr);
    }
    normalized
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no socket address resolved for {normalized}"))
}

#[derive(Clone)]
struct ResolvedGatewayChannel {
    endpoint: SocketAddr,
    kind: GatewayChannelKind,
    server_name: String,
    request_uri: Option<String>,
}

#[derive(Debug)]
struct HttpsTransportTarget {
    endpoint: SocketAddr,
    server_name: String,
    request_uri: String,
}

fn resolve_gateway_channel(
    channel: &crate::proto::message::GatewayChannel,
) -> anyhow::Result<ResolvedGatewayChannel> {
    let kind = channel
        .kind
        .enum_value()
        .map_err(|value| anyhow::anyhow!("unknown gateway channel kind {value}"))?;
    if kind == GatewayChannelKind::GATEWAY_CHANNEL_UNKNOWN {
        anyhow::bail!("gateway channel kind is unspecified");
    }
    match kind {
        GatewayChannelKind::GATEWAY_CHANNEL_HTTPS => {
            let target = parse_https_transport_target(&channel.addr)?;
            Ok(ResolvedGatewayChannel {
                endpoint: target.endpoint,
                kind,
                server_name: if channel.server_name.is_empty() {
                    target.server_name
                } else {
                    channel.server_name.clone()
                },
                request_uri: Some(target.request_uri),
            })
        }
        _ => {
            let endpoint = parse_transport_endpoint(&channel.addr)?;
            Ok(ResolvedGatewayChannel {
                endpoint,
                kind,
                server_name: if channel.server_name.is_empty() {
                    endpoint.ip().to_string()
                } else {
                    channel.server_name.clone()
                },
                request_uri: None,
            })
        }
    }
}

fn parse_https_transport_target(addr: &str) -> anyhow::Result<HttpsTransportTarget> {
    let uri: Uri = addr.trim().parse()?;
    if uri.scheme_str() != Some("https") {
        anyhow::bail!("gateway https addr must use https://");
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("gateway https addr missing host: {addr}"))?;
    let port = uri.port_u16().unwrap_or(443);
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let endpoint = authority
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no socket address resolved for {authority}"))?;
    let path = match uri.path_and_query().map(|value| value.as_str()) {
        Some("/") | None => "/gateway".to_string(),
        Some(path) if path.is_empty() => "/gateway".to_string(),
        Some("/gateway") => "/gateway".to_string(),
        Some(path) => {
            anyhow::bail!("gateway https addr path must be /gateway or empty, got {path}")
        }
    };
    Ok(HttpsTransportTarget {
        endpoint,
        server_name: host.to_string(),
        request_uri: format!("https://{}{}", authority, path),
    })
}

fn sanitize_worker_name(addr: SocketAddr) -> String {
    addr.to_string()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn gateway_summary_sort_key(
    summary: &GatewaySessionSummary,
) -> (
    bool,
    u8,
    std::cmp::Reverse<i64>,
    bool,
    std::cmp::Reverse<String>,
) {
    (
        summary.authenticated,
        gateway_grant_phase_rank(summary.grant_phase),
        std::cmp::Reverse(summary.rt_ms.unwrap_or(i64::MAX)),
        !summary.reauth_required,
        std::cmp::Reverse(summary.gateway_id.clone()),
    )
}

fn gateway_summary_is_clearly_better(
    challenger: &GatewaySessionSummary,
    current: &GatewaySessionSummary,
) -> bool {
    match (challenger.rt_ms, current.rt_ms) {
        (Some(challenger_rt), Some(current_rt)) => {
            current_rt - challenger_rt >= GATEWAY_SWITCH_BETTER_RT_MS
        }
        (Some(_), None) => true,
        _ => false,
    }
}

fn gateway_session_order_key(
    session: &GatewaySession,
    active: Option<SocketAddr>,
) -> (bool, bool, std::cmp::Reverse<u8>, i64, String) {
    let summary = session.summary();
    (
        Some(session.endpoint) != active,
        !summary.authenticated,
        std::cmp::Reverse(gateway_grant_phase_rank(summary.grant_phase)),
        summary.rt_ms.unwrap_or(i64::MAX),
        summary.gateway_id,
    )
}

fn gateway_grant_phase_rank(phase: GatewayGrantPhase) -> u8 {
    match phase {
        GatewayGrantPhase::Active => 4,
        GatewayGrantPhase::RefreshDue => 3,
        GatewayGrantPhase::Grace => 2,
        GatewayGrantPhase::Missing => 1,
        GatewayGrantPhase::Expired => 0,
    }
}

fn gateway_send_error_code(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::AddrNotAvailable => "addr_not_available",
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::NotConnected => "not_connected",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::WouldBlock => "would_block",
        _ => "io_error",
    }
}

fn gateway_http2_idle_timeout(keepalive_secs: u32) -> Duration {
    let keepalive_secs = u64::from(keepalive_secs.max(3));
    Duration::from_secs((keepalive_secs * 2).max(GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS))
}

#[cfg(test)]
mod tests {
    use super::{
        gateway_http2_idle_timeout, gateway_session_order_key, now_time,
        parse_https_transport_target, parse_transport_endpoint, resolve_gateway_channel,
        GatewayGrantPhase, GatewayGrantState, GatewaySession, GatewaySessionState, GatewaySessions,
        GatewayTransport, UdpStopHandle, UDP_GATEWAY_HELLOS_BEFORE_REBUILD,
    };
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crossbeam_utils::atomic::AtomicCell;
    use protobuf::EnumOrUnknown;

    use crate::core::PeerIdentity;
    use crate::data_plane::stats::DataPlaneStats;
    use crate::handle::CurrentDeviceInfo;
    use crate::proto::message::{
        GatewayAccessGrant, GatewayChannel, GatewayChannelKind, GatewayConnectAck,
    };
    use crate::protocol::NetPacket;
    use crate::util::StopManager;

    #[test]
    fn parse_transport_endpoint_accepts_socket_addr() {
        let endpoint = parse_transport_endpoint("quic://127.0.0.1:29900").unwrap();
        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.port(), 29900);
    }

    #[test]
    fn parse_transport_endpoint_accepts_udp_scheme() {
        let endpoint = parse_transport_endpoint("udp://127.0.0.1:29901").unwrap();
        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.port(), 29901);
    }

    #[test]
    fn parse_transport_endpoint_resolves_hostname() {
        let endpoint = parse_transport_endpoint("quic://localhost:29900").unwrap();
        assert_eq!(endpoint.port(), 29900);
        assert!(endpoint.ip().is_loopback());
    }

    #[test]
    fn parse_https_transport_target_defaults_gateway_path() {
        let target = parse_https_transport_target("https://127.0.0.1:443").unwrap();
        assert_eq!(target.endpoint.port(), 443);
        assert_eq!(target.request_uri, "https://127.0.0.1:443/gateway");
    }

    #[test]
    fn parse_https_transport_target_rejects_non_gateway_path() {
        let err = parse_https_transport_target("https://127.0.0.1:443/custom").unwrap_err();
        assert!(
            err.to_string()
                .contains("gateway https addr path must be /gateway or empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_gateway_channel_kind_is_rejected() {
        let channel = GatewayChannel {
            kind: EnumOrUnknown::from_i32(99),
            addr: "quic://127.0.0.1:29900".into(),
            ..Default::default()
        };

        let err = resolve_gateway_channel(&channel)
            .err()
            .expect("unknown channel kind");
        assert!(err.to_string().contains("unknown gateway channel kind 99"));
    }

    #[test]
    fn gateway_http2_idle_timeout_uses_minimum_before_ack() {
        assert_eq!(
            gateway_http2_idle_timeout(0),
            Duration::from_secs(super::GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS)
        );
    }

    #[test]
    fn gateway_http2_idle_timeout_tracks_keepalive_window() {
        assert_eq!(gateway_http2_idle_timeout(7), Duration::from_secs(14));
    }

    #[test]
    fn grant_phase_distinguishes_active_refresh_due_grace_and_expired() {
        let mut state = GatewaySessionState {
            ticket: vec![1, 2, 3],
            soft_refresh_after_unix_ms: 100,
            hard_expire_unix_ms: 200,
            ticket_expire_unix_ms: 200,
            ..Default::default()
        };
        assert_eq!(
            GatewaySession::grant_phase(&state, 99),
            GatewayGrantPhase::Active
        );
        assert_eq!(
            GatewaySession::grant_phase(&state, 100),
            GatewayGrantPhase::RefreshDue
        );

        state.authenticated = true;
        state.lease_expire_unix_ms = 120;
        state.grace_expire_unix_ms = 150;
        assert_eq!(
            GatewaySession::grant_phase(&state, 130),
            GatewayGrantPhase::Grace
        );
        assert_eq!(
            GatewaySession::grant_phase(&state, 201),
            GatewayGrantPhase::Expired
        );
    }

    #[test]
    fn grant_state_collapse_keeps_only_active_and_needs_refresh() {
        assert_eq!(
            GatewaySession::grant_state(GatewayGrantPhase::Active),
            GatewayGrantState::Active
        );
        assert_eq!(
            GatewaySession::grant_state(GatewayGrantPhase::RefreshDue),
            GatewayGrantState::NeedsRefresh
        );
        assert_eq!(
            GatewaySession::grant_state(GatewayGrantPhase::Grace),
            GatewayGrantState::NeedsRefresh
        );
        assert_eq!(
            GatewaySession::grant_state(GatewayGrantPhase::Missing),
            GatewayGrantState::NeedsRefresh
        );
        assert_eq!(
            GatewaySession::grant_state(GatewayGrantPhase::Expired),
            GatewayGrantState::NeedsRefresh
        );
    }

    #[test]
    fn authenticated_gateway_probe_health_becomes_unreachable_after_threshold() {
        let mut state = GatewaySessionState {
            authenticated: true,
            ticket: vec![1],
            ticket_expire_unix_ms: i64::MAX,
            lease_expire_unix_ms: i64::MAX,
            grace_expire_unix_ms: i64::MAX,
            ..Default::default()
        };
        assert_eq!(
            GatewaySession::relay_health(&state, 1),
            super::GatewayRelayHealth::Degraded
        );
        state.consecutive_probe_failures = super::GATEWAY_PROBE_UNREACHABLE_AFTER;
        assert_eq!(
            GatewaySession::relay_health(&state, 1),
            super::GatewayRelayHealth::Unreachable
        );
        state.last_probe_reply_unix_ms = 1;
        state.consecutive_probe_failures = 0;
        assert_eq!(
            GatewaySession::relay_health(&state, 1),
            super::GatewayRelayHealth::Healthy
        );
    }

    #[test]
    fn fallback_soft_refresh_after_clamps_invalid_early_expiry() {
        assert_eq!(GatewaySession::default_soft_refresh_after_unix_ms(0), 0);
        assert_eq!(
            GatewaySession::default_soft_refresh_after_unix_ms(1_000),
            1_000
        );
        assert_eq!(
            GatewaySession::default_soft_refresh_after_unix_ms(500_000),
            380_000
        );
    }

    #[test]
    fn gateway_session_order_key_prefers_active_grants() {
        let sessions = GatewaySessions::default();
        let now_ms = now_time() as i64;
        sessions.set_gateway_grants(
            &[
                GatewayAccessGrant {
                    gateway_id: "gw-active".into(),
                    ticket: vec![1, 2, 3],
                    session_id: 1,
                    policy_rev: 1,
                    soft_refresh_after_unix_ms: now_ms + 30_000,
                    hard_expire_unix_ms: now_ms + 60_000,
                    ticket_expire_unix_ms: now_ms + 60_000,
                    gateway_channel: Some(GatewayChannel {
                        kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_QUIC),
                        addr: "quic://127.0.0.1:29910".into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
                GatewayAccessGrant {
                    gateway_id: "gw-expired".into(),
                    ticket: vec![4, 5, 6],
                    session_id: 2,
                    policy_rev: 1,
                    soft_refresh_after_unix_ms: now_ms - 60_000,
                    hard_expire_unix_ms: now_ms - 1,
                    ticket_expire_unix_ms: now_ms - 1,
                    gateway_channel: Some(GatewayChannel {
                        kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_QUIC),
                        addr: "quic://127.0.0.1:29911".into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
            ],
            Ipv4Addr::new(10, 0, 0, 1),
            "device-1".into(),
        );

        let guard = sessions.sessions.lock();
        let active = guard
            .get(&"127.0.0.1:29910".parse().unwrap())
            .expect("active session")
            .clone();
        let expired = guard
            .get(&"127.0.0.1:29911".parse().unwrap())
            .expect("expired session")
            .clone();
        drop(guard);

        assert!(
            gateway_session_order_key(&active, None) < gateway_session_order_key(&expired, None)
        );
    }

    #[test]
    fn mark_refresh_requested_keeps_existing_ticket_expiry() {
        let sessions = GatewaySessions::default();
        let soft_refresh_after_unix_ms = 9_000;
        let hard_expire_unix_ms = 12_345;
        let ticket_expire_unix_ms = 12_345;
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-1".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms,
                hard_expire_unix_ms,
                ticket_expire_unix_ms,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_QUIC),
                    addr: "quic://127.0.0.1:29900".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        sessions.mark_refresh_requested();

        let snapshot = sessions.current_grant_snapshot().expect("grant snapshot");
        assert_eq!(
            snapshot.soft_refresh_after_unix_ms,
            soft_refresh_after_unix_ms
        );
        assert_eq!(snapshot.hard_expire_unix_ms, hard_expire_unix_ms);
        assert_eq!(snapshot.ticket_expire_unix_ms, ticket_expire_unix_ms);
        assert!(sessions.last_refresh_requested_at_ms() > 0);
    }

    #[test]
    fn replaying_same_gateway_grant_keeps_authenticated_session_state() {
        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29900".parse().unwrap();
        let mut grant = GatewayAccessGrant {
            gateway_id: "gw-1".into(),
            ticket: vec![1, 2, 3],
            session_id: 7,
            policy_rev: 8,
            soft_refresh_after_unix_ms: 9_000,
            hard_expire_unix_ms: 12_345,
            ticket_expire_unix_ms: 12_345,
            lease_secs: 30,
            grace_secs: 60,
            gateway_channel: Some(GatewayChannel {
                kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_QUIC),
                addr: "quic://127.0.0.1:29900".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        sessions.set_gateway_grants(
            &[grant.clone()],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        let session = sessions
            .sessions
            .lock()
            .get(&endpoint)
            .expect("gateway session")
            .clone();
        {
            let mut state = session.state.lock();
            state.authenticated = true;
            state.keepalive_secs = 9;
            state.lease_expire_unix_ms = 11_111;
            state.grace_expire_unix_ms = 22_222;
            state.reauth_required = true;
            state.last_rtt_ms = Some(7);
        }

        grant.policy_rev = 9;
        grant.soft_refresh_after_unix_ms = 10_000;
        grant.hard_expire_unix_ms = 20_000;
        grant.ticket_expire_unix_ms = 20_000;
        grant.lease_secs = 45;
        grant.grace_secs = 90;
        session
            .update_grant(&grant, "device-1".into())
            .expect("update unchanged gateway grant");

        let state = session.state.lock();
        assert!(state.authenticated);
        assert_eq!(state.keepalive_secs, 9);
        assert_eq!(state.lease_expire_unix_ms, 11_111);
        assert_eq!(state.grace_expire_unix_ms, 22_222);
        assert!(state.reauth_required);
        assert_eq!(state.last_rtt_ms, Some(7));
        assert_eq!(state.policy_rev, 9);
        assert_eq!(state.soft_refresh_after_unix_ms, 10_000);
        assert_eq!(state.hard_expire_unix_ms, 20_000);
        assert_eq!(state.ticket_expire_unix_ms, 20_000);
        assert_eq!(state.lease_secs_hint, 45);
        assert_eq!(state.grace_secs_hint, 90);
    }

    #[test]
    fn stale_quic_authentication_is_not_relay_routable() {
        let session = GatewaySession::new_quic(
            "127.0.0.1:29900".parse().unwrap(),
            super::DebugWatch::default(),
            DataPlaneStats::new(true),
        );
        session.active.store(true);
        {
            let mut state = session.state.lock();
            state.authenticated = true;
            state.authenticated_transport_generation = 1;
            state.hard_expire_unix_ms = now_time() as i64 + 60_000;
        }

        assert!(!session.is_relay_available());
        assert!(!session.state.lock().authenticated);
    }

    #[test]
    fn unauthenticated_udp_connect_hello_reenables_bootstrap() {
        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29901".parse().unwrap();
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-udp".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: 9_000,
                hard_expire_unix_ms: now_time() as i64 + 60_000,
                ticket_expire_unix_ms: now_time() as i64 + 60_000,
                lease_secs: 30,
                grace_secs: 60,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: "udp://127.0.0.1:29901".into(),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: "key-1".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        let session = sessions
            .sessions
            .lock()
            .get(&endpoint)
            .expect("gateway session")
            .clone();
        let channel = match &session.channel {
            GatewayTransport::Udp(channel) => channel.clone(),
            _ => panic!("expected udp gateway transport"),
        };
        {
            let mut state = session.state.lock();
            state.authenticated = false;
            state.last_hello_unix_ms = 0;
        }
        channel.set_bootstrap_pending_for_test(false);

        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        let packet = session
            .maybe_build_connect_hello(&current_device)
            .expect("build connect hello");

        assert!(packet.is_some());
        assert!(channel.bootstrap_pending_for_test());
    }

    #[test]
    fn udp_transport_error_requests_session_rebuild() {
        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29901".parse().unwrap();
        let now_ms = now_time() as i64;
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-udp".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: now_ms + 9_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: "udp://127.0.0.1:29901".into(),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: "key-1".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let session = sessions.sessions.lock().get(&endpoint).unwrap().clone();

        assert!(session.record_send_failure(io::ErrorKind::NetworkUnreachable));
        assert!(session.take_udp_rebuild_request());
        assert!(!session.take_udp_rebuild_request());
    }

    #[test]
    fn requested_udp_rebuild_replaces_the_running_session() {
        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29901".parse().unwrap();
        let now_ms = now_time() as i64;
        let stop_manager = StopManager::new(|| {});
        sessions
            .start(stop_manager.clone(), |_, _| {})
            .expect("start gateway sessions");
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-udp".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: now_ms + 9_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: "udp://127.0.0.1:29901".into(),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: "key-1".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let old = sessions.sessions.lock().get(&endpoint).unwrap().clone();
        assert!(old.record_send_failure(io::ErrorKind::AddrNotAvailable));

        sessions.trigger_connect_now();

        let replacement = sessions.sessions.lock().get(&endpoint).unwrap().clone();
        assert!(!Arc::ptr_eq(&old.state, &replacement.state));
        assert!(old.udp_stop_handle.lock().is_none());
        assert!(replacement.started.load());
        stop_manager.stop();
        assert!(stop_manager.wait_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn unanswered_udp_hellos_request_session_rebuild() {
        let session = GatewaySession::new_udp(
            "127.0.0.1:29901".parse().unwrap(),
            &GatewayAccessGrant {
                session_id: 7,
                ..Default::default()
            },
            &GatewayChannel {
                udp_public_key: [7; 32].to_vec(),
                udp_key_id: "key-1".into(),
                ..Default::default()
            },
            Default::default(),
            DataPlaneStats::new(true),
        )
        .unwrap();

        for _ in 0..UDP_GATEWAY_HELLOS_BEFORE_REBUILD - 1 {
            assert!(!session.record_unanswered_hello());
        }
        assert!(session.record_unanswered_hello());
        assert!(session.take_udp_rebuild_request());
    }

    #[test]
    fn successful_gateway_ack_clears_udp_rebuild_backoff() {
        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29901".parse().unwrap();
        let now_ms = now_time() as i64;
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-udp".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: now_ms + 9_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: "udp://127.0.0.1:29901".into(),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: "key-1".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        assert!(sessions.try_begin_udp_rebuild(endpoint));
        assert!(sessions.udp_rebuild_backoff.lock().contains_key(&endpoint));

        sessions.handle_connect_ack(
            endpoint,
            &GatewayConnectAck {
                session_id: 7,
                ok: true,
                ..Default::default()
            },
        );

        assert!(!sessions.udp_rebuild_backoff.lock().contains_key(&endpoint));
    }

    #[test]
    fn rejected_gateway_ack_records_error_until_a_successful_ack() {
        let session = GatewaySession::new_quic(
            "127.0.0.1:29900".parse().unwrap(),
            Default::default(),
            DataPlaneStats::new(true),
        );
        session.state.lock().session_id = 7;

        session.handle_connect_ack(&GatewayConnectAck {
            session_id: 7,
            ok: false,
            reason: "ticket_client_clock_skew".to_string(),
            ..Default::default()
        });
        {
            let state = session.state.lock();
            assert_eq!(
                state.last_gateway_error.as_deref(),
                Some("ticket_client_clock_skew")
            );
            assert_eq!(
                state.last_gateway_error_kind,
                Some(super::GatewayErrorKind::AuthRejected)
            );
            assert!(state.last_gateway_error_unix_ms > 0);
            assert_eq!(state.consecutive_gateway_errors, 1);
        }

        session.handle_connect_ack(&GatewayConnectAck {
            session_id: 7,
            ok: true,
            ..Default::default()
        });
        let state = session.state.lock();
        assert!(state.last_gateway_error.is_none());
        assert_eq!(state.last_gateway_error_kind, None);
        assert_eq!(state.last_gateway_error_unix_ms, 0);
        assert_eq!(state.consecutive_gateway_errors, 0);
    }

    #[test]
    fn gateway_send_failure_is_exposed_as_a_gateway_error() {
        let session = GatewaySession::new_quic(
            "127.0.0.1:29900".parse().unwrap(),
            Default::default(),
            DataPlaneStats::new(true),
        );

        session.record_send_failure(io::ErrorKind::NetworkUnreachable);
        {
            let state = session.state.lock();
            assert_eq!(
                state.last_gateway_error.as_deref(),
                Some("send_failed:network_unreachable")
            );
            assert_eq!(
                state.last_gateway_error_kind,
                Some(super::GatewayErrorKind::SendFailed)
            );
        }

        session.record_send_success();
        assert!(session.state.lock().last_gateway_error.is_none());
    }

    #[test]
    fn retired_https_session_rejects_outbound_packets() {
        let session = GatewaySession::new_https(
            "127.0.0.1:443".parse().unwrap(),
            "https://127.0.0.1:443/gateway".into(),
            "127.0.0.1".into(),
            Default::default(),
            crate::data_plane::stats::DataPlaneStats::new(true),
        );
        let packet = NetPacket::new(vec![0u8; 12]).expect("packet");

        session.retire();

        let err = session
            .send_packet(&packet)
            .expect_err("retired HTTPS send");
        assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);
    }

    #[test]
    fn inactive_udp_session_rejects_outbound_packets() {
        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29901".parse().unwrap();
        let now_ms = now_time() as i64;
        let stop_manager = StopManager::new(|| {});
        sessions
            .start(stop_manager.clone(), |_, _| {})
            .expect("start gateway sessions");
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-udp".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: now_ms + 9_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                lease_secs: 30,
                grace_secs: 60,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: "udp://127.0.0.1:29901".into(),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: "key-1".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let session = sessions
            .sessions
            .lock()
            .get(&endpoint)
            .expect("gateway session")
            .clone();
        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        let packet = session
            .maybe_build_connect_hello(&current_device)
            .expect("build connect hello")
            .expect("connect hello");

        session
            .udp_stop_handle
            .lock()
            .as_ref()
            .expect("udp runtime")
            .runtime_active
            .store(false);
        let err = session.send_packet(&packet).expect_err("inactive UDP send");
        assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);
        stop_manager.stop();
        assert!(stop_manager.wait_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn expired_udp_lease_drops_auth_and_reenables_bootstrap() {
        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29901".parse().unwrap();
        let now_ms = now_time() as i64;
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-udp".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: now_ms + 9_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                lease_secs: 30,
                grace_secs: 60,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: "udp://127.0.0.1:29901".into(),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: "key-1".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        let session = sessions
            .sessions
            .lock()
            .get(&endpoint)
            .expect("gateway session")
            .clone();
        let channel = match &session.channel {
            GatewayTransport::Udp(channel) => channel.clone(),
            _ => panic!("expected udp gateway transport"),
        };
        {
            let mut state = session.state.lock();
            state.authenticated = true;
            state.keepalive_secs = 15;
            state.lease_expire_unix_ms = now_ms - 1;
            state.last_hello_unix_ms = now_ms - 4_000;
        }
        channel.set_bootstrap_pending_for_test(false);

        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        let packet = session
            .maybe_build_connect_hello(&current_device)
            .expect("build connect hello");

        assert!(packet.is_some());
        assert!(channel.bootstrap_pending_for_test());
        assert!(!session.state.lock().authenticated);
    }

    #[test]
    fn udp_runtime_gates_are_independent() {
        let old_gate = Arc::new(AtomicCell::new(true));
        let new_gate = Arc::new(AtomicCell::new(true));

        old_gate.store(false);

        assert!(!old_gate.load());
        assert!(new_gate.load());
    }

    #[test]
    fn udp_stop_timeout_preserves_handle_until_listener_exits() {
        let (stop_sender, stop_receiver) = std::sync::mpsc::channel();
        let (stopped_sender, stopped_receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            stop_receiver.recv().expect("stop request");
            std::thread::sleep(Duration::from_millis(50));
            stopped_sender.send(()).expect("stopped notification");
        });
        let mut handle = UdpStopHandle {
            stop_sender: Some(stop_sender),
            stopped_receiver,
            runtime_active: Arc::new(AtomicCell::new(true)),
        };

        assert!(!handle.stop(Duration::from_millis(5)));
        assert!(handle.stop_sender.is_none());
        assert!(handle.stop(Duration::from_secs(1)));
        worker.join().expect("stop worker");
    }

    #[test]
    fn failed_stream_gateway_start_is_not_routable() {
        let cases = [
            (
                GatewayChannelKind::GATEWAY_CHANNEL_QUIC,
                "quic://127.0.0.1:29951",
                "127.0.0.1:29951",
            ),
            (
                GatewayChannelKind::GATEWAY_CHANNEL_HTTPS,
                "https://127.0.0.1:445/gateway",
                "127.0.0.1:445",
            ),
        ];

        for (kind, addr, endpoint) in cases {
            let sessions = GatewaySessions::default();
            let stop_manager = StopManager::new(|| {});
            sessions
                .start(stop_manager.clone(), |_, _| {})
                .expect("start gateway sessions");
            stop_manager.stop();
            assert!(stop_manager.wait_timeout(Duration::from_secs(2)));

            let now_ms = now_time() as i64;
            sessions.set_gateway_grants(
                &[GatewayAccessGrant {
                    gateway_id: format!("gw-{kind:?}"),
                    ticket: vec![1, 2, 3],
                    session_id: 7,
                    policy_rev: 8,
                    soft_refresh_after_unix_ms: now_ms + 30_000,
                    hard_expire_unix_ms: now_ms + 60_000,
                    ticket_expire_unix_ms: now_ms + 60_000,
                    lease_secs: 30,
                    grace_secs: 60,
                    gateway_channel: Some(GatewayChannel {
                        kind: EnumOrUnknown::new(kind),
                        addr: addr.into(),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                }],
                Ipv4Addr::new(10, 26, 0, 3),
                "device-1".into(),
            );

            let endpoint = endpoint.parse().unwrap();
            assert!(!sessions.sessions.lock().contains_key(&endpoint));
            assert!(!sessions
                .dormant_stream_sessions
                .lock()
                .contains_key(&endpoint));
        }
    }

    #[test]
    fn stream_gateway_session_is_reused_after_clear_and_readd() {
        let cases = [
            (
                GatewayChannelKind::GATEWAY_CHANNEL_QUIC,
                "quic://127.0.0.1:29941",
                "127.0.0.1:29941",
            ),
            (
                GatewayChannelKind::GATEWAY_CHANNEL_HTTPS,
                "https://127.0.0.1:444/gateway",
                "127.0.0.1:444",
            ),
        ];

        for (kind, addr, endpoint) in cases {
            let sessions = GatewaySessions::default();
            let now_ms = now_time() as i64;
            let grant = GatewayAccessGrant {
                gateway_id: format!("gw-{kind:?}"),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: now_ms + 30_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                lease_secs: 30,
                grace_secs: 60,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(kind),
                    addr: addr.into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            };
            let endpoint = endpoint.parse().unwrap();

            sessions.set_gateway_grants(
                &[grant.clone()],
                Ipv4Addr::new(10, 26, 0, 3),
                "device-1".into(),
            );
            let original = sessions
                .sessions
                .lock()
                .get(&endpoint)
                .expect("original stream session")
                .clone();

            sessions.clear_gateway_grant();
            assert!(!original.active.load());
            assert!(sessions.sessions.lock().is_empty());
            assert!(sessions
                .dormant_stream_sessions
                .lock()
                .contains_key(&endpoint));

            sessions.set_gateway_grants(&[grant], Ipv4Addr::new(10, 26, 0, 3), "device-1".into());
            let reused = sessions
                .sessions
                .lock()
                .get(&endpoint)
                .expect("reused stream session")
                .clone();

            assert!(Arc::ptr_eq(&original.active, &reused.active));
            assert!(Arc::ptr_eq(&original.state, &reused.state));
            assert!(reused.active.load());
            assert!(!sessions
                .dormant_stream_sessions
                .lock()
                .contains_key(&endpoint));
        }
    }

    #[test]
    fn gateway_kind_change_for_same_endpoint_is_rejected() {
        fn stream_grant(
            gateway_id: &str,
            kind: GatewayChannelKind,
            addr: &str,
        ) -> GatewayAccessGrant {
            let now_ms = now_time() as i64;
            GatewayAccessGrant {
                gateway_id: gateway_id.into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms: now_ms + 30_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                lease_secs: 30,
                grace_secs: 60,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(kind),
                    addr: addr.into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }

        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29961".parse().unwrap();
        let quic_grant = stream_grant(
            "gw-quic",
            GatewayChannelKind::GATEWAY_CHANNEL_QUIC,
            "quic://127.0.0.1:29961",
        );
        let https_grant = stream_grant(
            "gw-https",
            GatewayChannelKind::GATEWAY_CHANNEL_HTTPS,
            "https://127.0.0.1:29961/gateway",
        );

        sessions.set_gateway_grants(
            &[quic_grant],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let original = sessions
            .sessions
            .lock()
            .get(&endpoint)
            .expect("original QUIC session")
            .clone();

        sessions.set_gateway_grants(
            &[https_grant.clone()],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let active = sessions
            .sessions
            .lock()
            .get(&endpoint)
            .expect("original active session retained")
            .clone();
        assert!(Arc::ptr_eq(&original.state, &active.state));
        assert!(active.matches_kind(GatewayChannelKind::GATEWAY_CHANNEL_QUIC));

        sessions.clear_gateway_grant();
        sessions.set_gateway_grants(
            &[https_grant],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        assert!(sessions.sessions.lock().is_empty());
        let dormant = sessions
            .dormant_stream_sessions
            .lock()
            .get(&endpoint)
            .expect("original dormant session retained")
            .clone();
        assert!(Arc::ptr_eq(&original.state, &dormant.state));
        assert!(dormant.matches_kind(GatewayChannelKind::GATEWAY_CHANNEL_QUIC));
        assert!(!dormant.active.load());
    }

    #[test]
    fn removed_gateway_can_be_recreated_with_the_same_endpoint() {
        fn udp_grant(gateway_id: &str, endpoint: &str, session_id: u64) -> GatewayAccessGrant {
            let now_ms = now_time() as i64;
            GatewayAccessGrant {
                gateway_id: gateway_id.into(),
                ticket: vec![1, 2, 3],
                session_id,
                policy_rev: session_id,
                soft_refresh_after_unix_ms: now_ms + 30_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                lease_secs: 30,
                grace_secs: 60,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: format!("udp://{endpoint}"),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: format!("key-{session_id}"),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }

        let sessions = GatewaySessions::default();
        let stop_manager = StopManager::new(|| {});
        let endpoint_1 = "127.0.0.1:29931".parse().unwrap();
        let endpoint_2 = "127.0.0.1:29932".parse().unwrap();
        let grant_1 = udp_grant("gw-1", "127.0.0.1:29931", 1);
        let grant_2 = udp_grant("gw-2", "127.0.0.1:29932", 2);

        sessions
            .start(stop_manager.clone(), |_, _| {})
            .expect("start gateway sessions");
        sessions.set_gateway_grants(
            &[grant_1.clone()],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let original = sessions
            .sessions
            .lock()
            .get(&endpoint_1)
            .expect("original gateway session")
            .clone();
        assert!(original.udp_stop_handle.lock().is_some());
        assert!(original
            .udp_stop_handle
            .lock()
            .as_ref()
            .expect("original UDP runtime")
            .runtime_active
            .load());

        sessions.set_gateway_grants(&[grant_2], Ipv4Addr::new(10, 26, 0, 3), "device-1".into());
        assert!(original.udp_stop_handle.lock().is_none());
        assert!(sessions.sessions.lock().contains_key(&endpoint_2));

        sessions.set_gateway_grants(&[grant_1], Ipv4Addr::new(10, 26, 0, 3), "device-1".into());
        let recreated = sessions
            .sessions
            .lock()
            .get(&endpoint_1)
            .expect("recreated gateway session")
            .clone();
        assert!(!Arc::ptr_eq(
            &original.udp_stop_handle,
            &recreated.udp_stop_handle
        ));
        assert!(recreated.udp_stop_handle.lock().is_some());
        assert!(recreated
            .udp_stop_handle
            .lock()
            .as_ref()
            .expect("recreated UDP runtime")
            .runtime_active
            .load());

        stop_manager.stop();
        assert!(stop_manager.wait_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn peer_ingress_gateway_expiry_is_reclaimed() {
        let sessions = GatewaySessions::default();
        let peer = PeerIdentity::from_device_public_key(b"peer-one");
        let endpoint = "127.0.0.1:29931".parse().unwrap();
        sessions.peer_ingress_gateways.lock().insert(
            peer.clone(),
            super::PeerIngressGateway {
                endpoint,
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        assert_eq!(sessions.peer_ingress_gateway(&peer), None);
        assert!(sessions.peer_ingress_gateways.lock().is_empty());
    }

    #[test]
    fn peer_ingress_gateways_are_pruned_with_peer_list() {
        let sessions = GatewaySessions::default();
        let retained = PeerIdentity::from_device_public_key(b"peer-retained");
        let removed = PeerIdentity::from_device_public_key(b"peer-removed");
        let endpoint = "127.0.0.1:29931".parse().unwrap();
        let expires_at = Instant::now() + Duration::from_secs(60);
        let mut ingress = sessions.peer_ingress_gateways.lock();
        ingress.insert(
            retained.clone(),
            super::PeerIngressGateway {
                endpoint,
                expires_at,
            },
        );
        ingress.insert(
            removed.clone(),
            super::PeerIngressGateway {
                endpoint,
                expires_at,
            },
        );
        drop(ingress);

        sessions.retain_peer_ingress_gateways(&std::collections::HashSet::from([retained]));

        assert!(sessions
            .peer_ingress_gateways
            .lock()
            .contains_key(&PeerIdentity::from_device_public_key(b"peer-retained")));
        assert!(!sessions.peer_ingress_gateways.lock().contains_key(&removed));
    }

    #[test]
    fn clearing_gateway_grants_clears_peer_ingress_gateways() {
        let sessions = GatewaySessions::default();
        sessions.peer_ingress_gateways.lock().insert(
            PeerIdentity::from_device_public_key(b"peer-one"),
            super::PeerIngressGateway {
                endpoint: "127.0.0.1:29931".parse().unwrap(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        sessions.clear_gateway_grant();

        assert!(sessions.peer_ingress_gateways.lock().is_empty());
    }

    #[test]
    fn peer_ingress_session_prefers_the_learned_gateway() {
        let sessions = GatewaySessions::default();
        let peer = PeerIdentity::from_device_public_key(b"peer-one");
        let ingress_endpoint = "127.0.0.1:29931".parse().unwrap();
        let active_endpoint = "127.0.0.1:29932".parse().unwrap();
        let grant = GatewayAccessGrant {
            session_id: 7,
            ..Default::default()
        };
        let channel_meta = GatewayChannel {
            kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
            addr: "udp://127.0.0.1:29931".into(),
            udp_public_key: [7; 32].to_vec(),
            udp_key_id: "key-1".into(),
            ..Default::default()
        };
        let ingress = GatewaySession::new_udp(
            ingress_endpoint,
            &grant,
            &channel_meta,
            super::DebugWatch::default(),
            DataPlaneStats::new(true),
        )
        .expect("create ingress UDP session");
        let active = GatewaySession::new_udp(
            active_endpoint,
            &grant,
            &channel_meta,
            super::DebugWatch::default(),
            DataPlaneStats::new(true),
        )
        .expect("create active UDP session");
        for session in [&ingress, &active] {
            session.active.store(true);
            let mut state = session.state.lock();
            state.authenticated = true;
            state.hard_expire_unix_ms = now_time() as i64 + 60_000;
        }
        let mut configured = sessions.sessions.lock();
        configured.insert(ingress_endpoint, ingress);
        configured.insert(active_endpoint, active);
        drop(configured);
        sessions.peer_ingress_gateways.lock().insert(
            peer.clone(),
            super::PeerIngressGateway {
                endpoint: ingress_endpoint,
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        assert_eq!(
            sessions
                .peer_ingress_session(&peer)
                .map(|session| session.endpoint),
            Some(ingress_endpoint)
        );
    }
}
