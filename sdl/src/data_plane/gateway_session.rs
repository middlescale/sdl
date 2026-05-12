use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use http::Uri;
use parking_lot::Mutex;
use protobuf::Message;
use rand::RngCore;

use crate::data_plane::route::RouteKey;
use crate::data_plane::stats::DataPlaneStats;
use crate::handle::{now_time, CurrentDeviceInfo};
use crate::proto::message::{
    GatewayAccessGrant, GatewayChannelKind, GatewayConnectAck, GatewayConnectHello,
};
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};
use crate::transport::gateway_udp_channel::GatewayUdpChannel;
use crate::transport::http2_channel::Http2Channel;
use crate::transport::quic_channel::{PacketCallback, QuicChannel};
use crate::util::{DebugWatch, StopManager};

const GATEWAY_SWITCH_BETTER_RT_MS: i64 = 15;
const GATEWAY_SWITCH_COOLDOWN_MS: i64 = 10_000;
const GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS: u64 = 10;
const GATEWAY_CONNECT_RETRY_BASE_MS: u64 = 1_000;
const GATEWAY_CONNECT_RETRY_MAX_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GatewaySessionPhase {
    #[default]
    Disconnected,
    Connected,
    Stale,
    Grace,
    Expired,
}

impl GatewaySessionPhase {
    pub fn is_live(self) -> bool {
        matches!(self, Self::Connected | Self::Grace)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Connected => "connected",
            Self::Stale => "stale",
            Self::Grace => "grace",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Default)]
struct GatewaySessionState {
    gateway_id: String,
    ticket: Vec<u8>,
    session_id: u64,
    policy_rev: u64,
    ticket_expire_unix_ms: i64,
    device_id: String,
    channel_name: String,
    phase: GatewaySessionPhase,
    last_hello_unix_ms: i64,
    keepalive_secs: u32,
    lease_expire_unix_ms: i64,
    grace_expire_unix_ms: i64,
    lease_secs_hint: u32,
    grace_secs_hint: u32,
    reauth_required: bool,
    last_rtt_ms: Option<i64>,
    connect_retry_count: u32,
    last_retry_nudge_unix_ms: i64,
}

#[derive(Clone)]
pub struct GatewaySession {
    endpoint: SocketAddr,
    state: Arc<Mutex<GatewaySessionState>>,
    channel: GatewayTransport,
    started: Arc<AtomicCell<bool>>,
    debug_watch: DebugWatch,
    stats: DataPlaneStats,
}

#[derive(Clone)]
enum GatewayTransport {
    Quic(QuicChannel),
    Https(Http2Channel),
    Udp(GatewayUdpChannel),
}

impl GatewaySession {
    fn live_expire_unix_ms(guard: &GatewaySessionState) -> i64 {
        guard.grace_expire_unix_ms.max(guard.lease_expire_unix_ms)
    }

    fn current_phase(guard: &GatewaySessionState, now_ms: i64) -> GatewaySessionPhase {
        match guard.phase {
            GatewaySessionPhase::Disconnected => GatewaySessionPhase::Disconnected,
            GatewaySessionPhase::Stale => {
                if now_ms > Self::live_expire_unix_ms(guard) {
                    GatewaySessionPhase::Expired
                } else {
                    GatewaySessionPhase::Stale
                }
            }
            GatewaySessionPhase::Connected
            | GatewaySessionPhase::Grace
            | GatewaySessionPhase::Expired => {
                if now_ms <= guard.lease_expire_unix_ms {
                    GatewaySessionPhase::Connected
                } else if now_ms <= guard.grace_expire_unix_ms {
                    GatewaySessionPhase::Grace
                } else if guard.lease_expire_unix_ms > 0 || guard.grace_expire_unix_ms > 0 {
                    GatewaySessionPhase::Expired
                } else {
                    guard.phase
                }
            }
        }
    }

    fn refresh_phase(guard: &mut GatewaySessionState, now_ms: i64) -> GatewaySessionPhase {
        let phase = Self::current_phase(guard, now_ms);
        if guard.phase != phase {
            guard.phase = phase;
        }
        phase
    }

    fn mark_transport_stale(guard: &mut GatewaySessionState, now_ms: i64) {
        match Self::refresh_phase(guard, now_ms) {
            GatewaySessionPhase::Connected
            | GatewaySessionPhase::Grace
            | GatewaySessionPhase::Stale => {
                guard.phase = GatewaySessionPhase::Stale;
            }
            GatewaySessionPhase::Disconnected | GatewaySessionPhase::Expired => {}
        }
    }

    fn new_quic(endpoint: SocketAddr, debug_watch: DebugWatch, stats: DataPlaneStats) -> Self {
        Self {
            endpoint,
            state: Arc::new(Mutex::new(GatewaySessionState::default())),
            channel: GatewayTransport::Quic(QuicChannel::new(endpoint, endpoint.ip().to_string())),
            started: Arc::new(AtomicCell::new(false)),
            debug_watch,
            stats,
        }
    }

    fn new_udp(
        endpoint: SocketAddr,
        grant: &GatewayAccessGrant,
        debug_watch: DebugWatch,
        stats: DataPlaneStats,
    ) -> anyhow::Result<Self> {
        let gateway_udp_public_key: [u8; 32] =
            grant
                .gateway_udp_public_key
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("gateway udp public key must be 32 bytes"))?;
        Ok(Self {
            endpoint,
            state: Arc::new(Mutex::new(GatewaySessionState::default())),
            channel: GatewayTransport::Udp(GatewayUdpChannel::new(
                endpoint,
                gateway_udp_public_key,
                grant.gateway_udp_key_id.clone(),
                grant.session_id,
            )?),
            started: Arc::new(AtomicCell::new(false)),
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
            debug_watch,
            stats,
        }
    }

    fn start(&self, stop_manager: &StopManager, on_packet: &PacketCallback) -> anyhow::Result<()> {
        if self.started.swap(true) {
            return Ok(());
        }
        let worker_name = format!("gateway-{}", sanitize_worker_name(self.endpoint));
        let endpoint = self.endpoint;
        let stats = self.stats.clone();
        let on_packet = on_packet.clone();
        match &self.channel {
            GatewayTransport::Quic(channel) => {
                let on_packet = on_packet.clone();
                let stats = stats.clone();
                channel.start_named(
                    stop_manager.clone(),
                    &worker_name,
                    move |packet: Vec<u8>, route_key| {
                        stats.record_transport_down(endpoint.ip(), packet.len());
                        on_packet(packet, route_key);
                    },
                )?
            }
            GatewayTransport::Https(channel) => {
                let on_packet = on_packet.clone();
                let stats = stats.clone();
                channel.start_named(
                    stop_manager.clone(),
                    &worker_name,
                    move |packet: Vec<u8>, route_key| {
                        stats.record_transport_down(endpoint.ip(), packet.len());
                        on_packet(packet, route_key);
                    },
                )?
            }
            GatewayTransport::Udp(channel) => {
                let callback: PacketCallback = Arc::new(move |packet: Vec<u8>, route_key| {
                    stats.record_transport_down(endpoint.ip(), packet.len());
                    on_packet(packet, route_key);
                });
                channel.start_named(stop_manager.clone(), &worker_name, callback)?
            }
        }
        Ok(())
    }

    fn update_grant(&self, grant: &GatewayAccessGrant, device_id: String) -> anyhow::Result<()> {
        let mut guard = self.state.lock();
        guard.gateway_id = grant.gateway_id.clone();
        guard.ticket = grant.ticket.clone();
        guard.session_id = grant.session_id;
        guard.policy_rev = grant.policy_rev;
        guard.ticket_expire_unix_ms = grant.ticket_expire_unix_ms;
        guard.device_id = device_id;
        guard.channel_name = match &self.channel {
            GatewayTransport::Quic(_) => "quic".to_string(),
            GatewayTransport::Https(_) => "https".to_string(),
            GatewayTransport::Udp(_) => "udp".to_string(),
        };
        guard.phase = GatewaySessionPhase::Disconnected;
        guard.last_hello_unix_ms = 0;
        guard.keepalive_secs = 0;
        guard.lease_expire_unix_ms = 0;
        guard.grace_expire_unix_ms = 0;
        guard.lease_secs_hint = grant.lease_secs;
        guard.grace_secs_hint = grant.grace_secs;
        guard.reauth_required = false;
        guard.last_rtt_ms = None;
        guard.connect_retry_count = 0;
        guard.last_retry_nudge_unix_ms = 0;
        let http2_idle_timeout = gateway_http2_idle_timeout(guard.keepalive_secs);
        drop(guard);
        match &self.channel {
            GatewayTransport::Quic(channel) => {
                let selected_channel = grant.gateway_channels.iter().find(|channel_meta| {
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
                channel.update_server_name(server_name);
                channel.update_server_addr(self.endpoint);
            }
            GatewayTransport::Https(channel) => {
                let selected_channel = grant.gateway_channels.iter().find(|channel_meta| {
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
                channel.update_server_addr(self.endpoint);
                channel.update_server_name(server_name);
                channel.update_request_uri(request_uri);
                channel.update_idle_timeout(http2_idle_timeout);
            }
            GatewayTransport::Udp(channel) => {
                let gateway_udp_public_key: [u8; 32] = grant
                    .gateway_udp_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("gateway udp public key must be 32 bytes"))?;
                channel.update_server_addr(self.endpoint);
                channel.update_gateway_udp_auth(
                    gateway_udp_public_key,
                    grant.gateway_udp_key_id.clone(),
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
            ticket_expire_unix_ms: guard.ticket_expire_unix_ms,
        }
    }

    fn summary(&self) -> GatewaySessionSummary {
        let mut guard = self.state.lock();
        let now_ms = now_time() as i64;
        let phase = Self::refresh_phase(&mut guard, now_ms);
        GatewaySessionSummary {
            configured: true,
            available: phase.is_live(),
            phase,
            endpoint: Some(self.endpoint),
            gateway_id: guard.gateway_id.clone(),
            channel_name: guard.channel_name.clone(),
            reauth_required: guard.reauth_required,
            rt_ms: guard.last_rtt_ms,
            active: false,
        }
    }

    fn matches_addr(&self, addr: SocketAddr) -> bool {
        self.endpoint == addr
    }

    fn request_immediate_retry(&self) {
        let mut guard = self.state.lock();
        let now_ms = now_time() as i64;
        if !Self::refresh_phase(&mut guard, now_ms).is_live() {
            let retry_interval_ms =
                gateway_connect_retry_interval_ms(guard.connect_retry_count) as i64;
            if now_ms - guard.last_retry_nudge_unix_ms >= retry_interval_ms {
                guard.last_hello_unix_ms = guard.last_hello_unix_ms.min(now_ms - retry_interval_ms);
                guard.last_retry_nudge_unix_ms = now_ms;
            }
        }
    }

    fn tick(&self, current_device: &CurrentDeviceInfo) -> anyhow::Result<()> {
        if current_device.virtual_ip == Ipv4Addr::UNSPECIFIED {
            return Ok(());
        }
        let Some(packet) = self.maybe_build_connect_hello(current_device)? else {
            return Ok(());
        };
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
            let mut guard = self.state.lock();
            Self::mark_transport_stale(&mut guard, now_time() as i64);
            guard.connect_retry_count = guard.connect_retry_count.saturating_add(1);
            return Err(e.into());
        }
        Ok(())
    }

    fn send_relay<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        {
            let mut guard = self.state.lock();
            let now_ms = now_time() as i64;
            let phase = Self::refresh_phase(&mut guard, now_ms);
            let expire_unix_ms = Self::live_expire_unix_ms(&guard);
            if !phase.is_live() {
                log::debug!(
                    "gateway relay unavailable endpoint={}, phase={}, now_ms={}, expire_unix_ms={}, session_id={}",
                    self.endpoint,
                    phase.as_str(),
                    now_ms,
                    expire_unix_ms,
                    guard.session_id
                );
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "gateway relay is not available",
                ));
            }
        }
        if let Err(e) = self.send_packet(packet) {
            let mut guard = self.state.lock();
            Self::mark_transport_stale(&mut guard, now_time() as i64);
            guard.connect_retry_count = guard.connect_retry_count.saturating_add(1);
            return Err(e);
        }
        self.stats
            .record_transport_up(self.endpoint.ip(), packet.buffer().as_ref().len());
        Ok(())
    }

    fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        match &self.channel {
            GatewayTransport::Quic(channel) => channel.send_packet(packet),
            GatewayTransport::Https(channel) => channel.send_packet(packet),
            GatewayTransport::Udp(channel) => channel.send_packet(packet),
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
        if ack.ok {
            guard.phase = GatewaySessionPhase::Connected;
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
            guard.connect_retry_count = 0;
            guard.last_retry_nudge_unix_ms = 0;
            if let GatewayTransport::Https(channel) = &self.channel {
                channel.update_idle_timeout(gateway_http2_idle_timeout(ack.keepalive_secs));
            }
            log::info!(
                "gateway relay connected, session={}, endpoint={}, keepalive_secs={}, lease_expire={}, grace_expire={}, reauth_required={}",
                ack.session_id,
                self.endpoint,
                ack.keepalive_secs,
                ack.lease_expire_unix_ms,
                ack.grace_expire_unix_ms,
                ack.reauth_required
            );
            self.debug_watch.emit(
                "gateway",
                "connected",
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
            guard.phase = GatewaySessionPhase::Disconnected;
            guard.keepalive_secs = 0;
            guard.lease_expire_unix_ms = 0;
            guard.grace_expire_unix_ms = 0;
            guard.reauth_required = ack.reauth_required;
            guard.last_rtt_ms = None;
            guard.connect_retry_count = guard.connect_retry_count.saturating_add(1);
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

    fn maybe_build_connect_hello(
        &self,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<Option<NetPacket<Vec<u8>>>> {
        let mut guard = self.state.lock();
        let now_ms = now_time() as i64;
        let phase = Self::refresh_phase(&mut guard, now_ms);
        let ticket_available = now_ms <= guard.ticket_expire_unix_ms && !guard.ticket.is_empty();
        if !ticket_available && now_ms > guard.grace_expire_unix_ms {
            return Ok(None);
        }
        let interval_ms = if phase.is_live() {
            u64::from(guard.keepalive_secs.max(3)) * 1_000
        } else {
            gateway_connect_retry_interval_ms(guard.connect_retry_count)
        } as i64;
        if now_ms - guard.last_hello_unix_ms < interval_ms {
            return Ok(None);
        }
        guard.last_hello_unix_ms = now_ms;
        if !phase.is_live() {
            guard.connect_retry_count = guard.connect_retry_count.saturating_add(1);
        }
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
    pub ticket_expire_unix_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct GatewaySessionSummary {
    pub configured: bool,
    pub available: bool,
    pub phase: GatewaySessionPhase,
    pub endpoint: Option<SocketAddr>,
    pub gateway_id: String,
    pub channel_name: String,
    pub reauth_required: bool,
    pub rt_ms: Option<i64>,
    pub active: bool,
}

#[derive(Default)]
struct GatewaySelectionState {
    manual_endpoint: Option<SocketAddr>,
    selected_endpoint: Option<SocketAddr>,
    last_switch_unix_ms: i64,
}

#[derive(Clone)]
pub struct GatewaySessions {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    runtime: Arc<OnceLock<(StopManager, PacketCallback)>>,
    sessions: Arc<Mutex<HashMap<SocketAddr, GatewaySession>>>,
    selection: Arc<Mutex<GatewaySelectionState>>,
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
            selection: Arc::new(Mutex::new(GatewaySelectionState::default())),
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
            if let Err(e) = session.tick(&current_device) {
                log::debug!(
                    "gateway session tick failed endpoint={}: {:?}",
                    session.endpoint,
                    e
                );
            }
        }
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
            let preferred_kind = grant.default_gateway_channel.enum_value_or_default();
            let mut selected_channels: Vec<ResolvedGatewayChannel> = grant
                .gateway_channels
                .iter()
                .filter_map(|channel| {
                    let kind = channel.kind.enum_value_or_default();
                    let supported = match kind {
                        GatewayChannelKind::GATEWAY_CHANNEL_UDP => {
                            grant.gateway_udp_public_key.len() == 32
                                && !grant.gateway_udp_key_id.is_empty()
                        }
                        GatewayChannelKind::GATEWAY_CHANNEL_QUIC => true,
                        GatewayChannelKind::GATEWAY_CHANNEL_HTTPS => true,
                        _ => false,
                    };
                    if !supported || kind != preferred_kind {
                        return None;
                    }
                    resolve_gateway_channel(channel).ok()
                })
                .collect();
            if selected_channels.is_empty() {
                selected_channels = grant
                    .gateway_channels
                    .iter()
                    .filter_map(|channel| {
                        let kind = channel.kind.enum_value_or_default();
                        let supported = match kind {
                            GatewayChannelKind::GATEWAY_CHANNEL_UDP => {
                                grant.gateway_udp_public_key.len() == 32
                                    && !grant.gateway_udp_key_id.is_empty()
                            }
                            GatewayChannelKind::GATEWAY_CHANNEL_QUIC => true,
                            GatewayChannelKind::GATEWAY_CHANNEL_HTTPS => true,
                            _ => false,
                        };
                        if !supported {
                            return None;
                        }
                        resolve_gateway_channel(channel).ok()
                    })
                    .collect();
            }
            for channel in selected_channels {
                if desired.insert(channel.endpoint) {
                    parsed.push((grant.clone(), channel));
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
        guard.retain(|addr, _| desired.contains(addr));
        for (grant, resolved_channel) in parsed {
            let endpoint = resolved_channel.endpoint;
            let session = if let Some(existing) = guard.get(&endpoint).cloned() {
                existing
            } else {
                let created = match resolved_channel.kind {
                    GatewayChannelKind::GATEWAY_CHANNEL_UDP => {
                        match GatewaySession::new_udp(
                            endpoint,
                            &grant,
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
                continue;
            }
            if let Some((stop_manager, on_packet)) = self.runtime.get() {
                if let Err(e) = session.start(stop_manager, on_packet) {
                    log::warn!("start gateway session failed {}: {:?}", endpoint, e);
                }
            }
        }
        self.reset_selection_if_missing(&guard);
        drop(guard);
        self.trigger_connect_now();
    }

    pub fn clear_gateway_grant(&self) {
        self.sessions.lock().clear();
        *self.selection.lock() = GatewaySelectionState::default();
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
            .max_by_key(|snapshot| snapshot.ticket_expire_unix_ms)
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
                !summary.phase.is_live(),
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
        let had_sessions = !sessions.is_empty();
        for session in &sessions {
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
        if had_sessions {
            for session in &sessions {
                session.request_immediate_retry();
            }
        }
        self.trigger_connect_now();
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no available gateway session")
        }))
    }

    pub fn handle_connect_ack(&self, from: SocketAddr, ack: &GatewayConnectAck) {
        if let Some(session) = self.sessions.lock().get(&from).cloned() {
            session.handle_connect_ack(ack);
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
                } else if !current_summary.phase.is_live() {
                    best_endpoint
                } else if best_summary.phase.is_live()
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
    let kind = channel.kind.enum_value_or_default();
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
    std::cmp::Reverse<i64>,
    bool,
    std::cmp::Reverse<String>,
) {
    (
        summary.phase.is_live(),
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
) -> (bool, bool, i64, String) {
    let summary = session.summary();
    (
        Some(session.endpoint) != active,
        !summary.phase.is_live(),
        summary.rt_ms.unwrap_or(i64::MAX),
        summary.gateway_id,
    )
}

fn gateway_http2_idle_timeout(keepalive_secs: u32) -> Duration {
    let keepalive_secs = u64::from(keepalive_secs.max(3));
    Duration::from_secs((keepalive_secs * 2).max(GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS))
}

fn gateway_connect_retry_interval_ms(retry_count: u32) -> u64 {
    let factor = 2u64.saturating_pow(retry_count.saturating_sub(1).min(3));
    GATEWAY_CONNECT_RETRY_BASE_MS
        .saturating_mul(factor)
        .min(GATEWAY_CONNECT_RETRY_MAX_MS)
}

#[cfg(test)]
mod tests {
    use super::{
        gateway_connect_retry_interval_ms, gateway_http2_idle_timeout,
        parse_https_transport_target, parse_transport_endpoint, GatewaySession,
        GatewaySessionPhase, GatewaySessionState, GatewaySessions,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use protobuf::EnumOrUnknown;

    use crate::proto::message::{GatewayAccessGrant, GatewayChannel, GatewayChannelKind};

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
    fn gateway_connect_retry_interval_backs_off_and_caps() {
        assert_eq!(gateway_connect_retry_interval_ms(0), 1_000);
        assert_eq!(gateway_connect_retry_interval_ms(1), 1_000);
        assert_eq!(gateway_connect_retry_interval_ms(2), 2_000);
        assert_eq!(gateway_connect_retry_interval_ms(3), 4_000);
        assert_eq!(gateway_connect_retry_interval_ms(4), 5_000);
        assert_eq!(gateway_connect_retry_interval_ms(8), 5_000);
    }

    #[test]
    fn gateway_live_availability_ignores_ticket_expiry() {
        let state = GatewaySessionState {
            phase: GatewaySessionPhase::Connected,
            lease_expire_unix_ms: 1_000,
            grace_expire_unix_ms: 2_000,
            ticket_expire_unix_ms: 60_000,
            ..Default::default()
        };
        assert_eq!(
            GatewaySession::current_phase(&state, 2_001),
            GatewaySessionPhase::Expired
        );
        assert!(!GatewaySession::current_phase(&state, 2_001).is_live());
    }

    #[test]
    fn gateway_may_retry_existing_session_without_ticket_inside_grace() {
        let session = GatewaySession::new_quic(
            "127.0.0.1:29900".parse().unwrap(),
            crate::util::DebugWatch::default(),
            crate::data_plane::stats::DataPlaneStats::new(true),
        );
        {
            let mut guard = session.state.lock();
            guard.device_id = "device-1".into();
            guard.session_id = 7;
            guard.ticket.clear();
            guard.ticket_expire_unix_ms = 0;
            guard.phase = GatewaySessionPhase::Stale;
            guard.grace_expire_unix_ms = crate::handle::now_time() as i64 + 30_000;
        }

        let current_device = crate::handle::CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 2),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        assert!(session
            .maybe_build_connect_hello(&current_device)
            .unwrap()
            .is_some());
    }

    #[test]
    fn immediate_retry_nudge_respects_existing_backoff_window() {
        let session = GatewaySession::new_quic(
            "127.0.0.1:29900".parse().unwrap(),
            crate::util::DebugWatch::default(),
            crate::data_plane::stats::DataPlaneStats::new(true),
        );
        let now_ms = crate::handle::now_time() as i64;
        {
            let mut guard = session.state.lock();
            guard.phase = GatewaySessionPhase::Disconnected;
            guard.connect_retry_count = 3;
            guard.last_hello_unix_ms = now_ms - 500;
            guard.last_retry_nudge_unix_ms = now_ms;
        }
        session.request_immediate_retry();
        let guard = session.state.lock();
        assert_eq!(guard.connect_retry_count, 3);
        assert_eq!(guard.last_hello_unix_ms, now_ms - 500);
    }

    #[test]
    fn transport_failure_marks_live_session_stale() {
        let mut state = GatewaySessionState {
            phase: GatewaySessionPhase::Connected,
            lease_expire_unix_ms: 10_000,
            grace_expire_unix_ms: 20_000,
            ..Default::default()
        };
        GatewaySession::mark_transport_stale(&mut state, 5_000);
        assert_eq!(state.phase, GatewaySessionPhase::Stale);
        assert_eq!(
            GatewaySession::current_phase(&state, 5_000),
            GatewaySessionPhase::Stale
        );
    }

    #[test]
    fn mark_refresh_requested_keeps_existing_ticket_expiry() {
        let sessions = GatewaySessions::default();
        let ticket_expire_unix_ms = 12_345;
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-1".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                ticket_expire_unix_ms,
                gateway_channels: vec![GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_QUIC),
                    addr: "quic://127.0.0.1:29900".into(),
                    ..Default::default()
                }],
                default_gateway_channel: EnumOrUnknown::new(
                    GatewayChannelKind::GATEWAY_CHANNEL_QUIC,
                ),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        sessions.mark_refresh_requested();

        let snapshot = sessions.current_grant_snapshot().expect("grant snapshot");
        assert_eq!(snapshot.ticket_expire_unix_ms, ticket_expire_unix_ms);
        assert!(sessions.last_refresh_requested_at_ms() > 0);
    }
}
