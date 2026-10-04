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

impl GatewaySession {
    pub(super) fn summary(&self) -> GatewaySessionSummary {
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

    pub(super) fn relay_health(guard: &GatewaySessionState, now_ms: i64) -> GatewayRelayHealth {
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

    pub(super) fn is_relay_available(&self) -> bool {
        if !self.active.load() {
            return false;
        }
        self.reconcile_stream_authentication();
        let guard = self.state.lock();
        Self::is_available(&guard, now_time() as i64)
    }

    pub(super) fn record_send_failure(&self, kind: io::ErrorKind) -> bool {
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

    pub(super) fn record_send_success(&self) {
        let mut guard = self.state.lock();
        guard.consecutive_send_failures = 0;
        if guard.last_gateway_error_kind == Some(GatewayErrorKind::SendFailed) {
            Self::clear_gateway_error(&mut guard);
        }
    }

    pub(super) fn record_gateway_error(
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

    pub(super) fn clear_gateway_error(guard: &mut GatewaySessionState) {
        guard.last_gateway_error = None;
        guard.last_gateway_error_kind = None;
        guard.last_gateway_error_unix_ms = 0;
        guard.consecutive_gateway_errors = 0;
    }

    pub(super) fn record_unanswered_hello(&self) -> bool {
        let mut guard = self.state.lock();
        if guard.authenticated {
            guard.unanswered_hello_count = 0;
            return false;
        }
        guard.unanswered_hello_count += 1;
        if guard.unanswered_hello_count >= GATEWAY_HELLOS_BEFORE_TIMEOUT {
            Self::record_gateway_error(
                &mut guard,
                GatewayErrorKind::ConnectTimeout,
                "connect_timeout".to_string(),
                now_time() as i64,
            );
            if self.is_udp() {
                guard.udp_rebuild_requested = true;
            }
        }
        guard.udp_rebuild_requested
    }

    pub(super) fn maybe_build_gateway_probe(
        &self,
        current_device: &CurrentDeviceInfo,
        probe_interval_ms: i64,
    ) -> anyhow::Result<Option<NetPacket<Vec<u8>>>> {
        let mut guard = self.state.lock();
        let now_ms = now_time() as i64;
        if !Self::is_available(&guard, now_ms)
            || now_ms - guard.last_probe_sent_unix_ms < probe_interval_ms
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

    pub(super) fn handle_gateway_probe_pong(
        &self,
        source: Ipv4Addr,
        route_key: RouteKey,
        epoch: u16,
    ) -> bool {
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
        assert_eq!(
            GatewaySession::relay_health(&state, 1),
            GatewayRelayHealth::Degraded
        );
        state.consecutive_probe_failures = GATEWAY_PROBE_UNREACHABLE_AFTER;
        assert_eq!(
            GatewaySession::relay_health(&state, 1),
            GatewayRelayHealth::Unreachable
        );
        state.last_probe_reply_unix_ms = 1;
        state.consecutive_probe_failures = 0;
        assert_eq!(
            GatewaySession::relay_health(&state, 1),
            GatewayRelayHealth::Healthy
        );
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
