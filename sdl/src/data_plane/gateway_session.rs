use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use rand::RngCore;

use crate::data_plane::route::RoutePath;
use crate::handle::{now_time, CurrentDeviceInfo};
use crate::proto::message::{
    GatewayAccessGrant, GatewayChannelKind, GatewayConnectAck, GatewayConnectHello,
};
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};
use crate::transport::gateway_udp_channel::GatewayUdpChannel;
use crate::transport::quic_channel::{PacketCallback, QuicChannel};
use crate::util::{DebugWatch, StopManager};

#[derive(Clone, Default)]
struct GatewaySessionState {
    ticket: Vec<u8>,
    session_id: u64,
    policy_rev: u64,
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
}

#[derive(Clone)]
pub struct GatewaySession {
    endpoint: SocketAddr,
    state: Arc<Mutex<GatewaySessionState>>,
    channel: GatewayTransport,
    started: Arc<AtomicCell<bool>>,
    debug_watch: DebugWatch,
}

#[derive(Clone)]
enum GatewayTransport {
    Quic(QuicChannel),
    Udp(GatewayUdpChannel),
}

impl GatewaySession {
    fn new_quic(endpoint: SocketAddr, debug_watch: DebugWatch) -> Self {
        Self {
            endpoint,
            state: Arc::new(Mutex::new(GatewaySessionState::default())),
            channel: GatewayTransport::Quic(QuicChannel::new(endpoint, endpoint.ip().to_string())),
            started: Arc::new(AtomicCell::new(false)),
            debug_watch,
        }
    }

    fn new_udp(
        endpoint: SocketAddr,
        grant: &GatewayAccessGrant,
        debug_watch: DebugWatch,
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
        })
    }

    fn start(&self, stop_manager: &StopManager, on_packet: &PacketCallback) -> anyhow::Result<()> {
        if self.started.swap(true) {
            return Ok(());
        }
        let worker_name = format!("gateway-{}", sanitize_worker_name(self.endpoint));
        let on_packet = on_packet.clone();
        match &self.channel {
            GatewayTransport::Quic(channel) => {
                let on_packet = on_packet.clone();
                channel.start_named(
                    stop_manager.clone(),
                    &worker_name,
                    move |packet, route_key| {
                        on_packet(packet, route_key);
                    },
                )?
            }
            GatewayTransport::Udp(channel) => {
                channel.start_named(stop_manager.clone(), &worker_name, on_packet)?
            }
        }
        Ok(())
    }

    fn update_grant(&self, grant: &GatewayAccessGrant, device_id: String) -> anyhow::Result<()> {
        let mut guard = self.state.lock();
        guard.ticket = grant.ticket.clone();
        guard.session_id = grant.session_id;
        guard.policy_rev = grant.policy_rev;
        guard.ticket_expire_unix_ms = grant.ticket_expire_unix_ms;
        guard.device_id = device_id;
        guard.channel_name = match &self.channel {
            GatewayTransport::Quic(_) => "quic".to_string(),
            GatewayTransport::Udp(_) => "udp".to_string(),
        };
        guard.authenticated = false;
        guard.last_hello_unix_ms = 0;
        guard.keepalive_secs = 0;
        guard.lease_expire_unix_ms = 0;
        guard.grace_expire_unix_ms = 0;
        guard.lease_secs_hint = grant.lease_secs;
        guard.grace_secs_hint = grant.grace_secs;
        guard.reauth_required = false;
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

    fn ticket_expire_unix_ms(&self) -> i64 {
        self.state.lock().ticket_expire_unix_ms
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
        let guard = self.state.lock();
        GatewaySessionSummary {
            configured: true,
            authenticated: guard.authenticated,
            endpoint: Some(self.endpoint),
            channel_name: guard.channel_name.clone(),
            reauth_required: guard.reauth_required,
        }
    }

    fn mark_refresh_requested(&self) {
        self.state.lock().ticket_expire_unix_ms = 0;
    }

    fn matches_addr(&self, addr: SocketAddr) -> bool {
        self.endpoint == addr
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
            self.state.lock().authenticated = false;
            return Err(e.into());
        }
        Ok(())
    }

    fn send_relay<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        {
            let guard = self.state.lock();
            let now_ms = now_time() as i64;
            let expire_unix_ms = guard
                .grace_expire_unix_ms
                .max(guard.lease_expire_unix_ms)
                .max(guard.ticket_expire_unix_ms);
            if !guard.authenticated || now_ms > expire_unix_ms {
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
        log::debug!(
            "sending relay packet endpoint={} src={} dst={} protocol={:?} transport_protocol={} len={}",
            self.endpoint,
            packet.source(),
            packet.destination(),
            packet.protocol(),
            packet.transport_protocol(),
            packet.data_len()
        );
        if let Err(e) = self.send_packet(packet) {
            self.state.lock().authenticated = false;
            return Err(e);
        }
        Ok(())
    }

    fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        match &self.channel {
            GatewayTransport::Quic(channel) => channel.send_packet(packet),
            GatewayTransport::Udp(channel) => channel.send_packet(packet),
        }
    }

    fn handle_connect_ack(&self, ack: &GatewayConnectAck) -> bool {
        let mut guard = self.state.lock();
        if guard.session_id != ack.session_id {
            log::debug!(
                "ignoring gateway connect ack for endpoint={} due to session mismatch local={} remote={}",
                self.endpoint,
                guard.session_id,
                ack.session_id
            );
            return false;
        }
        guard.authenticated = ack.ok;
        if ack.ok {
            let now_ms = now_time() as i64;
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
            guard.keepalive_secs = 0;
            guard.lease_expire_unix_ms = 0;
            guard.grace_expire_unix_ms = 0;
            guard.reauth_required = ack.reauth_required;
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
        ack.ok
    }

    fn maybe_build_connect_hello(
        &self,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<Option<NetPacket<Vec<u8>>>> {
        let mut guard = self.state.lock();
        let now_ms = now_time() as i64;
        let ticket_available = now_ms <= guard.ticket_expire_unix_ms && !guard.ticket.is_empty();
        if !ticket_available && (!guard.authenticated || now_ms > guard.grace_expire_unix_ms) {
            return Ok(None);
        }
        let interval_ms = if guard.authenticated {
            u64::from(guard.keepalive_secs.max(3)) * 1_000
        } else {
            3_000
        } as i64;
        if now_ms - guard.last_hello_unix_ms < interval_ms {
            return Ok(None);
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
    pub ticket_expire_unix_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct GatewaySessionSummary {
    pub configured: bool,
    pub authenticated: bool,
    pub endpoint: Option<SocketAddr>,
    pub channel_name: String,
    pub reauth_required: bool,
}

#[derive(Clone)]
pub struct GatewaySessions {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    runtime: Arc<OnceLock<(StopManager, PacketCallback)>>,
    sessions: Arc<Mutex<HashMap<SocketAddr, GatewaySession>>>,
    worker_started: Arc<AtomicCell<bool>>,
    debug_watch: DebugWatch,
}

impl GatewaySessions {
    pub fn new(
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        debug_watch: DebugWatch,
    ) -> Self {
        Self {
            current_device,
            runtime: Arc::new(OnceLock::new()),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            worker_started: Arc::new(AtomicCell::new(false)),
            debug_watch,
        }
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RoutePath) + Send + Sync + 'static,
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
    }

    pub fn set_gateway_grant(
        &self,
        grant: &GatewayAccessGrant,
        virtual_ip: Ipv4Addr,
        device_id: String,
    ) {
        let preferred_kind = grant.default_gateway_channel.enum_value_or_default();
        let mut parsed = Vec::new();
        let mut desired = HashSet::new();
        let mut selected_channels: Vec<(SocketAddr, GatewayChannelKind)> = grant
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
                    _ => false,
                };
                if !supported || kind != preferred_kind {
                    return None;
                }
                parse_transport_endpoint(&channel.addr)
                    .ok()
                    .map(|endpoint| (endpoint, kind))
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
                        _ => false,
                    };
                    if !supported {
                        return None;
                    }
                    parse_transport_endpoint(&channel.addr)
                        .ok()
                        .map(|endpoint| (endpoint, kind))
                })
                .collect();
        }
        for (endpoint, kind) in selected_channels {
            if desired.insert(endpoint) {
                parsed.push((endpoint, kind));
            }
        }
        if parsed.is_empty() {
            self.clear_gateway_grant();
            log::info!(
                "gateway relay disabled for virtual ip {virtual_ip}: no supported gateway channel"
            );
            return;
        }
        log::info!(
            "gateway grant applied for virtual ip {} with endpoints {:?}, session_id={}, default_channel={:?}",
            virtual_ip,
            parsed.iter().map(|(endpoint, _)| *endpoint).collect::<Vec<_>>(),
            grant.session_id,
            grant.default_gateway_channel.enum_value_or_default()
        );
        let mut guard = self.sessions.lock();
        guard.retain(|addr, _| desired.contains(addr));
        for (endpoint, kind) in parsed {
            let session = if let Some(existing) = guard.get(&endpoint).cloned() {
                existing
            } else {
                let created = match kind {
                    GatewayChannelKind::GATEWAY_CHANNEL_UDP => {
                        match GatewaySession::new_udp(endpoint, grant, self.debug_watch.clone()) {
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
                    _ => GatewaySession::new_quic(endpoint, self.debug_watch.clone()),
                };
                guard.insert(endpoint, created.clone());
                created
            };
            if let Err(e) = session.update_grant(grant, device_id.clone()) {
                log::warn!("update gateway session failed {}: {:?}", endpoint, e);
                continue;
            }
            if let Some((stop_manager, on_packet)) = self.runtime.get() {
                if let Err(e) = session.start(stop_manager, on_packet) {
                    log::warn!("start gateway session failed {}: {:?}", endpoint, e);
                }
            }
        }
    }

    pub fn clear_gateway_grant(&self) {
        self.sessions.lock().clear();
    }

    pub fn ticket_expire_unix_ms(&self) -> i64 {
        self.sessions
            .lock()
            .values()
            .map(GatewaySession::ticket_expire_unix_ms)
            .max()
            .unwrap_or(0)
    }

    pub fn current_grant_snapshot(&self) -> Option<GatewayGrantSnapshot> {
        self.sessions
            .lock()
            .values()
            .map(GatewaySession::grant_snapshot)
            .max_by_key(|snapshot| snapshot.ticket_expire_unix_ms)
    }

    pub fn session_summary(&self) -> GatewaySessionSummary {
        self.sessions
            .lock()
            .values()
            .map(GatewaySession::summary)
            .max_by_key(|summary| (summary.authenticated, summary.reauth_required))
            .unwrap_or_default()
    }

    pub fn mark_refresh_requested(&self) {
        for session in self.sessions.lock().values() {
            session.mark_refresh_requested();
        }
    }

    pub fn is_gateway_addr(&self, addr: SocketAddr) -> bool {
        self.sessions
            .lock()
            .values()
            .any(|session| session.matches_addr(addr))
    }

    pub fn send_relay<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        let sessions: Vec<GatewaySession> = self.sessions.lock().values().cloned().collect();
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

    pub fn handle_connect_ack(&self, from: SocketAddr, ack: &GatewayConnectAck) -> bool {
        if let Some(session) = self.sessions.lock().get(&from).cloned() {
            session.handle_connect_ack(ack)
        } else {
            log::debug!(
                "received gateway connect ack from unknown endpoint={} session_id={} ok={} reason={}",
                from,
                ack.session_id,
                ack.ok,
                ack.reason
            );
            false
        }
    }
}

impl Default for GatewaySessions {
    fn default() -> Self {
        Self::new(
            Arc::new(AtomicCell::new(CurrentDeviceInfo::new0())),
            DebugWatch::default(),
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

fn sanitize_worker_name(addr: SocketAddr) -> String {
    addr.to_string()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_transport_endpoint, GatewaySession};
    use crate::proto::message::GatewayConnectAck;
    use crate::util::DebugWatch;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn handle_connect_ack_reports_successful_acks() {
        let session =
            GatewaySession::new_quic("127.0.0.1:29900".parse().unwrap(), DebugWatch::default());
        session.state.lock().session_id = 7;
        let ack = GatewayConnectAck {
            ok: true,
            session_id: 7,
            keepalive_secs: 5,
            ..Default::default()
        };

        assert!(session.handle_connect_ack(&ack));
        assert!(session.handle_connect_ack(&ack));
    }

    #[test]
    fn handle_connect_ack_ignores_session_mismatch() {
        let session =
            GatewaySession::new_quic("127.0.0.1:29900".parse().unwrap(), DebugWatch::default());
        session.state.lock().session_id = 7;
        let ack = GatewayConnectAck {
            ok: true,
            session_id: 8,
            keepalive_secs: 5,
            ..Default::default()
        };

        assert!(!session.handle_connect_ack(&ack));
        assert!(!session.state.lock().authenticated);
    }
}
