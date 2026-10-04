//! Gateway session state and coordination across relay transports.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::core::PeerIdentity;
use crate::data_plane::stats::DataPlaneStats;
use crate::handle::CurrentDeviceInfo;
use crate::transport::gateway_udp_channel::GatewayUdpChannel;
use crate::transport::http2_channel::Http2Channel;
use crate::transport::quic_channel::{PacketCallback, QuicChannel};
use crate::util::{DebugWatch, StopManager};

mod auth;
mod endpoint;
mod grants;
mod health;
mod maintenance;
mod relay;
mod selection;
mod session;

const GATEWAY_SWITCH_BETTER_RT_MS: i64 = 15;
const GATEWAY_SWITCH_COOLDOWN_MS: i64 = 10_000;
const GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS: u64 = 10;
const GATEWAY_GRANT_SOFT_REFRESH_LEAD_MS: i64 = 120_000;
const GATEWAY_UDP_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const GATEWAY_HELLOS_BEFORE_TIMEOUT: u32 = 3;
const UDP_GATEWAY_REBUILD_BASE_DELAY_MS: i64 = 5_000;
const UDP_GATEWAY_REBUILD_MAX_DELAY_MS: i64 = 60_000;
const PEER_INGRESS_GATEWAY_TTL: Duration = Duration::from_secs(60);
const GATEWAY_PROBE_INTERVAL_MS: i64 = 10_000;
// Standby sessions still send GatewayConnectHello at the gateway-provided
// keepalive interval, so their lease and authentication recovery remain fast.
// Only their independent health probe is less frequent.
const STANDBY_GATEWAY_PROBE_INTERVAL_MS: i64 = 60_000;
const GATEWAY_PROBE_UNREACHABLE_AFTER: u32 = 3;
const PEER_RELAY_PROBE_INTERVAL_MS: i64 = 30_000;
const NO_GATEWAY_MAINTENANCE_DELAY: Duration = Duration::from_secs(60);
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
    ConnectTimeout,
    SendFailed,
    ProbeUnreachable,
}

impl GatewayErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthRejected => "auth-rejected",
            Self::ConnectTimeout => "connect-timeout",
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

#[derive(Clone, Copy, Debug)]
enum GatewayWorkerSignal {
    Stop,
    Wake,
}

#[derive(Clone, Copy, Debug, Default)]
struct UdpGatewayRebuildBackoff {
    attempts: u32,
    retry_after_unix_ms: i64,
}

#[derive(Clone)]
struct GatewaySession {
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

#[derive(Clone)]
enum GatewayTransport {
    Quic(QuicChannel),
    Https(Http2Channel),
    Udp(GatewayUdpChannel),
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
    worker_waker: Arc<Mutex<Option<mpsc::Sender<GatewayWorkerSignal>>>>,
    maintenance_lock: Arc<Mutex<()>>,
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
            worker_waker: Arc::new(Mutex::new(None)),
            maintenance_lock: Arc::new(Mutex::new(())),
            debug_watch,
            stats,
        }
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
