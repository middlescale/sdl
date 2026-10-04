//! Single gateway transport lifecycle and packet transmission.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::data_plane::stats::DataPlaneStats;
use crate::handle::now_time;
use crate::proto::message::{GatewayAccessGrant, GatewayChannelKind};
use crate::protocol::NetPacket;
use crate::transport::gateway_udp_channel::GatewayUdpChannel;
use crate::transport::http2_channel::Http2Channel;
use crate::transport::quic_channel::{PacketCallback, QuicChannel};
use crate::util::{DebugWatch, StopManager};

use super::{
    GatewaySession, GatewaySessionState, GatewayTransport, UdpStopHandle, GATEWAY_RUNTIME_ID,
    GATEWAY_UDP_STOP_TIMEOUT,
};

impl UdpStopHandle {
    fn stop(&mut self, timeout: Duration) -> bool {
        if let Some(stop_sender) = self.stop_sender.take() {
            let _ = stop_sender.send(());
        }
        self.stopped_receiver.recv_timeout(timeout).is_ok()
    }
}

impl GatewaySession {
    pub(super) fn new_quic(
        endpoint: SocketAddr,
        debug_watch: DebugWatch,
        stats: DataPlaneStats,
    ) -> Self {
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

    pub(super) fn new_udp(
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

    pub(super) fn new_https(
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

    pub(super) fn start(
        &self,
        stop_manager: &StopManager,
        on_packet: &PacketCallback,
    ) -> anyhow::Result<()> {
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

    pub(super) fn start_udp(
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

    pub(super) fn is_udp(&self) -> bool {
        matches!(&self.channel, GatewayTransport::Udp(_))
    }

    pub(super) fn matches_kind(&self, kind: GatewayChannelKind) -> bool {
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

    pub(super) fn reactivate(&self) {
        self.active.store(true);
    }

    pub(super) fn retire(&self) {
        self.active.store(false);
        let mut state = self.state.lock();
        state.authenticated = false;
        state.ticket.clear();
        state.hard_expire_unix_ms = 0;
        state.ticket_expire_unix_ms = 0;
        state.lease_expire_unix_ms = 0;
        state.grace_expire_unix_ms = 0;
    }

    pub(super) fn stop_udp_runtime(&self) -> bool {
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

    pub(super) fn recreate_udp(&self) -> anyhow::Result<Self> {
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

    pub(super) fn matches_addr(&self, addr: SocketAddr) -> bool {
        self.endpoint == addr
    }

    pub(super) fn send_relay<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
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

    pub(super) fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
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
}

pub(super) fn sanitize_worker_name(addr: SocketAddr) -> String {
    addr.to_string()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use crossbeam_utils::atomic::AtomicCell;
    use protobuf::EnumOrUnknown;

    use crate::handle::{now_time, CurrentDeviceInfo};
    use crate::proto::message::{GatewayAccessGrant, GatewayChannel, GatewayChannelKind};
    use crate::protocol::NetPacket;
    use crate::util::StopManager;

    use super::super::{GatewaySession, GatewaySessions, UdpStopHandle};

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
}
