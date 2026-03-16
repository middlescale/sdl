use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use rand::RngCore;

use crate::channel::RouteKey;
use crate::handle::{now_time, CurrentDeviceInfo};
use crate::proto::message::{GatewayAccessGrant, GatewayConnectAck, GatewayConnectHello};
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};
use crate::transport::quic_channel::{PacketCallback, QuicChannel};
use crate::util::StopManager;

#[derive(Clone)]
struct GatewayRuntime {
    stop_manager: StopManager,
    on_packet: PacketCallback,
}

#[derive(Clone, Default)]
struct GatewaySessionState {
    ticket: Vec<u8>,
    session_id: u64,
    policy_rev: u64,
    ticket_expire_unix_ms: i64,
    device_id: String,
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
    channel: QuicChannel,
    started: Arc<AtomicCell<bool>>,
}

impl GatewaySession {
    fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            state: Arc::new(Mutex::new(GatewaySessionState::default())),
            channel: QuicChannel::new(endpoint),
            started: Arc::new(AtomicCell::new(false)),
        }
    }

    fn start(&self, runtime: &GatewayRuntime) -> anyhow::Result<()> {
        if self.started.swap(true) {
            return Ok(());
        }
        let worker_name = format!("gatewayQuic-{}", sanitize_worker_name(self.endpoint));
        let on_packet = runtime.on_packet.clone();
        self.channel.start_named(
            runtime.stop_manager.clone(),
            &worker_name,
            move |packet, route_key| {
                on_packet(packet, route_key);
            },
        )?;
        Ok(())
    }

    fn update_grant(&self, grant: &GatewayAccessGrant, device_id: String) {
        let mut guard = self.state.lock();
        guard.ticket = grant.ticket.clone();
        guard.session_id = grant.session_id;
        guard.policy_rev = grant.policy_rev;
        guard.ticket_expire_unix_ms = grant.ticket_expire_unix_ms;
        guard.device_id = device_id;
        guard.authenticated = false;
        guard.last_hello_unix_ms = 0;
        guard.keepalive_secs = 0;
        guard.lease_expire_unix_ms = 0;
        guard.grace_expire_unix_ms = 0;
        guard.lease_secs_hint = grant.lease_secs;
        guard.grace_secs_hint = grant.grace_secs;
        guard.reauth_required = false;
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

    fn mark_refresh_requested(&self) {
        self.state.lock().ticket_expire_unix_ms = 0;
    }

    fn matches_addr(&self, addr: SocketAddr) -> bool {
        self.endpoint == addr
    }

    fn tick(&self, current_device: &CurrentDeviceInfo) -> anyhow::Result<()> {
        if current_device.status.offline() || current_device.virtual_ip == Ipv4Addr::UNSPECIFIED {
            return Ok(());
        }
        let Some(packet) = self.maybe_build_connect_hello(current_device)? else {
            return Ok(());
        };
        if let Err(e) = self.channel.send_packet(&packet) {
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
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "gateway relay is not authenticated",
                ));
            }
        }
        if let Err(e) = self.channel.send_packet(packet) {
            self.state.lock().authenticated = false;
            return Err(e);
        }
        Ok(())
    }

    fn handle_connect_ack(&self, ack: &GatewayConnectAck) {
        let mut guard = self.state.lock();
        if guard.session_id != ack.session_id {
            return;
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
        }
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
            device_pub_key: vec![],
            device_pub_key_alg: String::new(),
            device_signature: vec![],
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
        Ok(Some(packet))
    }
}

#[derive(Clone)]
pub struct GatewayGrantSnapshot {
    pub session_id: u64,
    pub policy_rev: u64,
    pub ticket_expire_unix_ms: i64,
}

#[derive(Clone)]
pub struct GatewaySessions {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    runtime: Arc<Mutex<Option<GatewayRuntime>>>,
    sessions: Arc<Mutex<HashMap<SocketAddr, GatewaySession>>>,
    worker_started: Arc<AtomicCell<bool>>,
}

impl GatewaySessions {
    pub fn new(current_device: Arc<AtomicCell<CurrentDeviceInfo>>) -> Self {
        Self {
            current_device,
            runtime: Arc::new(Mutex::new(None)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            worker_started: Arc::new(AtomicCell::new(false)),
        }
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        let runtime = GatewayRuntime {
            stop_manager: stop_manager.clone(),
            on_packet: Arc::new(on_packet),
        };
        {
            let mut guard = self.runtime.lock();
            *guard = Some(runtime.clone());
        }
        for session in self.sessions.lock().values() {
            session.start(&runtime)?;
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
        let mut parsed = Vec::new();
        let mut desired = HashSet::new();
        for addr in grant.gateway_addrs.iter() {
            match parse_transport_endpoint(addr) {
                Ok(endpoint) => {
                    if desired.insert(endpoint) {
                        parsed.push(endpoint);
                    }
                }
                Err(e) => {
                    log::warn!("skip invalid gateway endpoint {}: {:?}", addr, e);
                }
            }
        }
        if parsed.is_empty() {
            self.clear_gateway_grant();
            log::info!("gateway relay disabled for virtual ip {virtual_ip}: no quic gateway addr");
            return;
        }
        let runtime = self.runtime.lock().clone();
        let mut guard = self.sessions.lock();
        guard.retain(|addr, _| desired.contains(addr));
        for endpoint in parsed {
            let session = guard
                .entry(endpoint)
                .or_insert_with(|| GatewaySession::new(endpoint))
                .clone();
            session.update_grant(grant, device_id.clone());
            if let Some(runtime) = runtime.as_ref() {
                if let Err(e) = session.start(runtime) {
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
                    last_err = Some(e);
                }
                Err(e) => {
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
        }
    }
}

impl Default for GatewaySessions {
    fn default() -> Self {
        Self::new(Arc::new(AtomicCell::new(CurrentDeviceInfo::new0(
            "0.0.0.0:0".parse().unwrap(),
        ))))
    }
}

fn parse_transport_endpoint(addr: &str) -> anyhow::Result<SocketAddr> {
    let normalized = addr
        .strip_prefix("quic://")
        .unwrap_or(addr)
        .trim()
        .to_string();
    Ok(SocketAddr::from_str(&normalized)?)
}

fn sanitize_worker_name(addr: SocketAddr) -> String {
    addr.to_string()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}
