//! Gateway health probes, error accounting, and status snapshots.

use std::io;
use std::net::Ipv4Addr;

use crate::data_plane::route::RouteKey;
use crate::handle::{now_time, CurrentDeviceInfo};
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{NetPacket, Protocol, MAX_TTL};

use super::{
    GatewayErrorKind, GatewayRelayHealth, GatewaySession, GatewaySessionState,
    GatewaySessionSummary, GATEWAY_HELLOS_BEFORE_TIMEOUT, GATEWAY_PROBE_UNREACHABLE_AFTER,
};

impl GatewaySessionState {
    pub(super) fn relay_health(&self, now_ms: i64) -> GatewayRelayHealth {
        if !self.is_available(now_ms) {
            return GatewayRelayHealth::Unknown;
        }
        if self.consecutive_probe_failures >= GATEWAY_PROBE_UNREACHABLE_AFTER {
            return GatewayRelayHealth::Unreachable;
        }
        if self.last_probe_reply_unix_ms <= 0 {
            return GatewayRelayHealth::Degraded;
        }
        GatewayRelayHealth::Healthy
    }

    pub(super) fn record_gateway_error(
        &mut self,
        kind: GatewayErrorKind,
        error: String,
        now_ms: i64,
    ) {
        if self.last_gateway_error_kind == Some(kind)
            && self.last_gateway_error.as_deref() == Some(error.as_str())
        {
            self.consecutive_gateway_errors = self.consecutive_gateway_errors.saturating_add(1);
        } else {
            self.consecutive_gateway_errors = 1;
        }
        self.last_gateway_error = Some(error);
        self.last_gateway_error_kind = Some(kind);
        self.last_gateway_error_unix_ms = now_ms;
    }

    pub(super) fn clear_gateway_error(&mut self) {
        self.last_gateway_error = None;
        self.last_gateway_error_kind = None;
        self.last_gateway_error_unix_ms = 0;
        self.consecutive_gateway_errors = 0;
    }
}

impl GatewaySession {
    pub(super) fn summary(&self) -> GatewaySessionSummary {
        self.reconcile_stream_authentication();
        let state = self.state.lock();
        let now_ms = now_time() as i64;
        let grant_phase = state.grant_phase(now_ms);
        GatewaySessionSummary {
            configured: true,
            authenticated: state.is_available(now_ms),
            endpoint: Some(self.endpoint),
            gateway_id: state.gateway_id.clone(),
            channel_name: state.channel_name.clone(),
            grant_state: grant_phase.grant_state(),
            soft_refresh_after_unix_ms: state.soft_refresh_after_unix_ms(),
            hard_expire_unix_ms: state.hard_expire_unix_ms(),
            lease_expire_unix_ms: state.lease_expire_unix_ms,
            grace_expire_unix_ms: state.grace_expire_unix_ms,
            reauth_required: state.reauth_required,
            last_gateway_error: state.last_gateway_error.clone(),
            last_gateway_error_kind: state.last_gateway_error_kind,
            last_gateway_error_unix_ms: state.last_gateway_error_unix_ms,
            consecutive_gateway_errors: state.consecutive_gateway_errors,
            rt_ms: state.last_rtt_ms,
            active: false,
            grant_phase,
            consecutive_send_failures: state.consecutive_send_failures,
            relay_health: state.relay_health(now_ms),
            last_probe_unix_ms: state.last_probe_reply_unix_ms,
            last_probe_rtt_ms: state.last_probe_rtt_ms,
            consecutive_probe_failures: state.consecutive_probe_failures,
            relay_send_failures_total: self.stats.gateway_send_failures_total(),
        }
    }

    pub(super) fn is_relay_available(&self) -> bool {
        if !self.active.load() {
            return false;
        }
        self.reconcile_stream_authentication();
        let state = self.state.lock();
        state.is_available(now_time() as i64)
    }

    pub(super) fn record_send_failure(&self, kind: io::ErrorKind) -> bool {
        let mut state = self.state.lock();
        state.record_gateway_error(
            GatewayErrorKind::SendFailed,
            format!("send_failed:{}", gateway_send_error_code(kind)),
            now_time() as i64,
        );
        state.consecutive_send_failures += 1;
        let udp_transport_error = self.is_udp()
            && matches!(
                kind,
                io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::NotConnected
            );
        if udp_transport_error {
            state.udp_rebuild_requested = true;
        }
        if state.consecutive_send_failures >= 3 {
            state.authenticated = false;
        }
        state.udp_rebuild_requested
    }

    pub(super) fn record_send_success(&self) {
        let mut state = self.state.lock();
        state.consecutive_send_failures = 0;
        if state.last_gateway_error_kind == Some(GatewayErrorKind::SendFailed) {
            state.clear_gateway_error();
        }
    }

    pub(super) fn record_unanswered_hello(&self) -> bool {
        let mut state = self.state.lock();
        if state.authenticated {
            state.unanswered_hello_count = 0;
            return false;
        }
        state.unanswered_hello_count += 1;
        if state.unanswered_hello_count >= GATEWAY_HELLOS_BEFORE_TIMEOUT {
            state.record_gateway_error(
                GatewayErrorKind::ConnectTimeout,
                "connect_timeout".to_string(),
                now_time() as i64,
            );
            if self.is_udp() {
                state.udp_rebuild_requested = true;
            }
        }
        state.udp_rebuild_requested
    }

    pub(super) fn maybe_build_gateway_probe(
        &self,
        current_device: &CurrentDeviceInfo,
        probe_interval_ms: i64,
    ) -> anyhow::Result<Option<NetPacket<Vec<u8>>>> {
        let mut state = self.state.lock();
        let now_ms = now_time() as i64;
        if !state.is_available(now_ms) || now_ms - state.last_probe_sent_unix_ms < probe_interval_ms
        {
            return Ok(None);
        }
        if state.last_probe_sent_unix_ms > state.last_probe_reply_unix_ms {
            state.consecutive_probe_failures = state.consecutive_probe_failures.saturating_add(1);
            if state.consecutive_probe_failures >= GATEWAY_PROBE_UNREACHABLE_AFTER {
                state.record_gateway_error(
                    GatewayErrorKind::ProbeUnreachable,
                    "probe_unreachable".to_string(),
                    now_ms,
                );
            }
        }
        state.last_probe_sent_unix_ms = now_ms;
        state.gateway_virtual_ip = Some(current_device.virtual_gateway);
        state.probe_epoch = state.probe_epoch.wrapping_add(1).max(1);
        let mut packet = NetPacket::new(vec![0u8; 12 + 4])?;
        packet.set_default_version();
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
        packet.set_initial_ttl(MAX_TTL);
        packet.set_source(current_device.virtual_ip);
        packet.set_destination(current_device.virtual_gateway);
        let mut ping = PingPacket::new(packet.payload_mut())?;
        ping.set_time(now_time() as u16);
        ping.set_epoch(state.probe_epoch);
        Ok(Some(packet))
    }

    pub(super) fn handle_gateway_probe_pong(
        &self,
        source: Ipv4Addr,
        route_key: RouteKey,
        epoch: u16,
    ) -> bool {
        if !self.matches_addr(route_key.addr) {
            return false;
        }
        let mut state = self.state.lock();
        if Some(source) != state.gateway_virtual_ip || epoch != state.probe_epoch {
            return false;
        }
        let now_ms = now_time() as i64;
        state.last_probe_reply_unix_ms = now_ms;
        state.last_probe_rtt_ms = Some((now_ms - state.last_probe_sent_unix_ms).max(1));
        state.consecutive_probe_failures = 0;
        if state.last_gateway_error_kind == Some(GatewayErrorKind::ProbeUnreachable) {
            state.clear_gateway_error();
        }
        true
    }
}

pub(super) fn gateway_send_error_code(kind: io::ErrorKind) -> &'static str {
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::Ipv4Addr;

    use crate::data_plane::route::RouteKey;
    use crate::data_plane::stats::DataPlaneStats;
    use crate::handle::{now_time, CurrentDeviceInfo};
    use crate::transport::connect_protocol::ConnectProtocol;
    use crate::util::DebugWatch;

    use super::super::{
        GatewayErrorKind, GatewayRelayHealth, GatewaySession, GatewaySessionState,
        GATEWAY_PROBE_INTERVAL_MS, GATEWAY_PROBE_UNREACHABLE_AFTER,
        STANDBY_GATEWAY_PROBE_INTERVAL_MS,
    };

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
        assert_eq!(state.relay_health(1), GatewayRelayHealth::Degraded);
        state.consecutive_probe_failures = GATEWAY_PROBE_UNREACHABLE_AFTER;
        assert_eq!(state.relay_health(1), GatewayRelayHealth::Unreachable);
        state.last_probe_reply_unix_ms = 1;
        state.consecutive_probe_failures = 0;
        assert_eq!(state.relay_health(1), GatewayRelayHealth::Healthy);
    }

    #[test]
    fn standby_gateway_probe_interval_is_longer_without_affecting_authentication() {
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
            state.last_probe_sent_unix_ms = now_ms - 15_000;
        }
        let device = CurrentDeviceInfo::new0();

        assert!(session
            .maybe_build_gateway_probe(&device, STANDBY_GATEWAY_PROBE_INTERVAL_MS)
            .unwrap()
            .is_none());
        assert!(session
            .maybe_build_gateway_probe(&device, GATEWAY_PROBE_INTERVAL_MS)
            .unwrap()
            .is_some());
    }

    #[test]
    fn matching_gateway_probe_pong_marks_the_session_healthy() {
        let endpoint = "127.0.0.1:29900".parse().unwrap();
        let session =
            GatewaySession::new_quic(endpoint, DebugWatch::default(), DataPlaneStats::new(true));
        {
            let mut state = session.state.lock();
            state.gateway_virtual_ip = Some(Ipv4Addr::new(10, 26, 0, 1));
            state.probe_epoch = 42;
            state.last_probe_sent_unix_ms = now_time() as i64;
            state.consecutive_probe_failures = GATEWAY_PROBE_UNREACHABLE_AFTER;
        }

        assert!(session.handle_gateway_probe_pong(
            Ipv4Addr::new(10, 26, 0, 1),
            RouteKey::new(ConnectProtocol::QUIC, endpoint),
            42,
        ));
        let state = session.state.lock();
        assert!(state.last_probe_reply_unix_ms > 0);
        assert!(state.last_probe_rtt_ms.is_some());
        assert_eq!(state.consecutive_probe_failures, 0);
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
                Some(GatewayErrorKind::SendFailed)
            );
        }

        session.record_send_success();
        assert!(session.state.lock().last_gateway_error.is_none());
    }
}
