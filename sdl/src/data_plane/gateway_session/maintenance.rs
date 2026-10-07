//! Deadline-driven maintenance and UDP transport recovery.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use crate::data_plane::route::RouteKey;
use crate::handle::{now_time, CurrentDeviceInfo};
use crate::util::StopManager;

use super::{
    GatewaySession, GatewaySessions, GatewayTickOutcome, GatewayWorkerSignal,
    GATEWAY_PROBE_INTERVAL_MS, NO_GATEWAY_MAINTENANCE_DELAY, STANDBY_GATEWAY_PROBE_INTERVAL_MS,
    UDP_GATEWAY_REBUILD_BASE_DELAY_MS, UDP_GATEWAY_REBUILD_MAX_DELAY_MS,
};

impl GatewaySession {
    pub(super) fn tick(
        &self,
        current_device: &CurrentDeviceInfo,
        probe_interval_ms: i64,
    ) -> anyhow::Result<GatewayTickOutcome> {
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
        if let Some(packet) = self.maybe_build_gateway_probe(current_device, probe_interval_ms)? {
            if let Err(err) = self.send_packet(&packet) {
                self.record_send_failure(err.kind());
                return Err(err.into());
            }
            self.record_send_success();
        }
        Ok(GatewayTickOutcome::Idle)
    }

    /// Returns when this session next needs maintenance. Authentication and
    /// lease recovery use the Hello deadline; only the separate health probe
    /// may use the longer standby interval.
    pub(super) fn next_maintenance_delay(
        &self,
        current_device: &CurrentDeviceInfo,
        probe_interval_ms: i64,
    ) -> Duration {
        if current_device.virtual_ip == Ipv4Addr::UNSPECIFIED {
            return NO_GATEWAY_MAINTENANCE_DELAY;
        }
        let state = self.state.lock();
        if state.udp_rebuild_requested {
            return Duration::ZERO;
        }
        let now_ms = now_time() as i64;
        let ticket_available = now_ms <= state.ticket_expire_unix_ms && !state.ticket.is_empty();
        if !ticket_available && now_ms > state.grace_expire_unix_ms {
            return NO_GATEWAY_MAINTENANCE_DELAY;
        }
        if state.authenticated
            && state.lease_expire_unix_ms > 0
            && now_ms > state.lease_expire_unix_ms
        {
            return Duration::ZERO;
        }
        let hello_interval_ms = if state.authenticated {
            i64::from(state.keepalive_secs.max(3)) * 1_000
        } else {
            3_000
        };
        let hello_delay_ms = (state.last_hello_unix_ms + hello_interval_ms - now_ms).max(0);
        let probe_delay_ms = if state.is_available(now_ms) {
            (state.last_probe_sent_unix_ms + probe_interval_ms - now_ms).max(0)
        } else {
            i64::MAX
        };
        Duration::from_millis(hello_delay_ms.min(probe_delay_ms) as u64)
    }

    pub(super) fn take_udp_rebuild_request(&self) -> bool {
        if !self.is_udp() {
            return false;
        }
        let mut state = self.state.lock();
        let requested = state.udp_rebuild_requested;
        state.udp_rebuild_requested = false;
        requested
    }
}

impl GatewaySessions {
    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        let _ = self
            .runtime
            .set((stop_manager.clone(), Arc::new(on_packet)));
        let (stop_manager, on_packet) = self.runtime.get().unwrap();
        self.start_registered_sessions(stop_manager, on_packet)?;
        if self.worker_started.swap(true) {
            return Ok(());
        }
        let (stop_sender, stop_receiver) = mpsc::channel::<GatewayWorkerSignal>();
        *self.worker_waker.lock() = Some(stop_sender.clone());
        let worker = stop_manager.add_listener("gatewaySessions".into(), move || {
            let _ = stop_sender.send(GatewayWorkerSignal::Stop);
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

    pub(super) fn run(&self, stop_receiver: mpsc::Receiver<GatewayWorkerSignal>) {
        loop {
            self.trigger_connect_now();
            match stop_receiver.recv_timeout(self.next_maintenance_delay()) {
                Ok(GatewayWorkerSignal::Stop) => break,
                Ok(GatewayWorkerSignal::Wake) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        *self.worker_waker.lock() = None;
    }

    pub(super) fn wake_maintenance(&self) {
        if let Some(sender) = self.worker_waker.lock().as_ref() {
            let _ = sender.send(GatewayWorkerSignal::Wake);
        }
    }

    pub fn trigger_connect_now(&self) {
        // Serialize periodic and immediate maintenance passes, including UDP
        // rebuilds. The registry lock only protects membership and selection.
        let _maintenance = self.maintenance_lock.lock();
        let current_device = self.current_device.load();
        let snapshot = self.refresh_selection_and_snapshot();
        let active_endpoint = snapshot.active_endpoint;
        for session in snapshot.sessions {
            let endpoint = session.endpoint;
            let probe_interval_ms = if Some(endpoint) == active_endpoint {
                GATEWAY_PROBE_INTERVAL_MS
            } else {
                STANDBY_GATEWAY_PROBE_INTERVAL_MS
            };
            match session.tick(&current_device, probe_interval_ms) {
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

    pub(super) fn next_maintenance_delay(&self) -> Duration {
        let current_device = self.current_device.load();
        let snapshot = self.session_snapshot();
        let active_endpoint = snapshot.active_endpoint;
        snapshot
            .sessions
            .iter()
            .map(|session| {
                let probe_interval_ms = if Some(session.endpoint) == active_endpoint {
                    GATEWAY_PROBE_INTERVAL_MS
                } else {
                    STANDBY_GATEWAY_PROBE_INTERVAL_MS
                };
                session.next_maintenance_delay(&current_device, probe_interval_ms)
            })
            .min()
            .unwrap_or(NO_GATEWAY_MAINTENANCE_DELAY)
    }

    /// Recreates UDP gateway sockets after the local underlay changed. Stream
    /// transports keep their self-healing connections and are not rebuilt.
    pub fn rebuild_udp_sessions_after_underlay_change(&self) {
        self.udp_rebuild_backoff.lock().clear();
        let endpoints = self.udp_endpoints();
        for endpoint in endpoints {
            self.rebuild_udp_session(endpoint);
        }
        self.trigger_connect_now();
        self.wake_maintenance();
    }

    pub(super) fn rebuild_udp_session(&self, endpoint: SocketAddr) {
        let old = {
            let mut registry = self.registry.lock();
            let Some(session) = registry.session_at(endpoint) else {
                return;
            };
            if !session.is_udp() {
                return;
            }
            if !self.try_begin_udp_rebuild(endpoint) {
                return;
            }
            log::warn!("rebuilding UDP gateway session endpoint={}", endpoint);
            registry
                .remove_session(endpoint)
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
        let mut registry = self.registry.lock();
        if registry.contains_endpoint(endpoint) {
            log::debug!(
                "skip stale UDP gateway replacement because a newer session exists endpoint={}",
                endpoint
            );
            replacement.retire();
            let _ = replacement.stop_udp_runtime();
            return;
        }
        registry.install_session(replacement);
    }

    pub(super) fn try_begin_udp_rebuild(&self, endpoint: SocketAddr) -> bool {
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
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use protobuf::EnumOrUnknown;

    use crate::data_plane::stats::DataPlaneStats;
    use crate::handle::{now_time, CurrentDeviceInfo};
    use crate::proto::message::{
        GatewayAccessGrant, GatewayChannel, GatewayChannelKind, GatewayConnectAck,
    };
    use crate::util::{DebugWatch, StopManager};

    use super::super::{
        GatewayErrorKind, GatewaySession, GatewaySessions, GATEWAY_HELLOS_BEFORE_TIMEOUT,
        GATEWAY_PROBE_INTERVAL_MS,
    };

    #[test]
    fn connected_gateway_maintenance_waits_for_the_next_probe_not_one_second() {
        let endpoint = "127.0.0.1:29900".parse().unwrap();
        let session =
            GatewaySession::new_quic(endpoint, DebugWatch::default(), DataPlaneStats::new(true));
        let now_ms = now_time() as i64;
        {
            let mut state = session.state.lock();
            state.authenticated = true;
            state.ticket = vec![1];
            state.ticket_expire_unix_ms = i64::MAX;
            state.lease_expire_unix_ms = i64::MAX;
            state.grace_expire_unix_ms = i64::MAX;
            state.keepalive_secs = 30;
            state.last_hello_unix_ms = now_ms;
            state.last_probe_sent_unix_ms = now_ms;
        }
        let delay = session.next_maintenance_delay(
            &CurrentDeviceInfo {
                virtual_ip: Ipv4Addr::new(10, 26, 0, 3),
                ..CurrentDeviceInfo::new0()
            },
            GATEWAY_PROBE_INTERVAL_MS,
        );

        assert!((Duration::from_secs(9)..=Duration::from_secs(10)).contains(&delay));
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
        let session = sessions.session_at(endpoint).unwrap().clone();

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
        let old = sessions.session_at(endpoint).unwrap().clone();
        assert!(old.record_send_failure(io::ErrorKind::AddrNotAvailable));

        sessions.trigger_connect_now();

        let replacement = sessions.session_at(endpoint).unwrap().clone();
        assert!(!Arc::ptr_eq(&old.state, &replacement.state));
        assert!(old.udp_stop_handle.lock().is_none());
        assert!(replacement.started.load());
        stop_manager.stop();
        assert!(stop_manager.wait_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn unanswered_gateway_hellos_record_timeout_and_rebuild_udp() {
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

        for _ in 0..GATEWAY_HELLOS_BEFORE_TIMEOUT - 1 {
            assert!(!session.record_unanswered_hello());
        }
        assert!(session.record_unanswered_hello());
        assert!(session.take_udp_rebuild_request());
        let state = session.state.lock();
        assert_eq!(state.last_gateway_error.as_deref(), Some("connect_timeout"));
        assert_eq!(
            state.last_gateway_error_kind,
            Some(GatewayErrorKind::ConnectTimeout)
        );
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
}
