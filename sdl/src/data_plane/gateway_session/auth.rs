//! Gateway grants, lease decisions, and transport-bound authentication.

use std::time::Duration;

use protobuf::Message;
use rand::RngCore;

use crate::handle::{now_time, CurrentDeviceInfo};
use crate::proto::message::{
    GatewayAccessGrant, GatewayChannelKind, GatewayConnectAck, GatewayConnectHello,
};
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};

use super::endpoint::{parse_https_transport_target, parse_transport_endpoint};
use super::{
    GatewayErrorKind, GatewayGrantPhase, GatewayGrantSnapshot, GatewayGrantState, GatewaySession,
    GatewaySessionState, GatewayTransport, GATEWAY_GRANT_SOFT_REFRESH_LEAD_MS,
    GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS,
};

pub(super) fn default_soft_refresh_after_unix_ms(hard_expire_unix_ms: i64) -> i64 {
    if hard_expire_unix_ms <= 0 {
        return 0;
    }
    if hard_expire_unix_ms <= GATEWAY_GRANT_SOFT_REFRESH_LEAD_MS {
        return hard_expire_unix_ms;
    }
    hard_expire_unix_ms - GATEWAY_GRANT_SOFT_REFRESH_LEAD_MS
}

impl GatewaySessionState {
    pub(super) fn hard_expire_unix_ms(&self) -> i64 {
        self.hard_expire_unix_ms.max(self.ticket_expire_unix_ms)
    }

    pub(super) fn soft_refresh_after_unix_ms(&self) -> i64 {
        if self.soft_refresh_after_unix_ms > 0 {
            self.soft_refresh_after_unix_ms
        } else {
            default_soft_refresh_after_unix_ms(self.hard_expire_unix_ms())
        }
    }

    pub(super) fn grant_phase(&self, now_ms: i64) -> GatewayGrantPhase {
        let hard_expire_unix_ms = self.hard_expire_unix_ms();
        if self.ticket.is_empty() || hard_expire_unix_ms <= 0 {
            return GatewayGrantPhase::Missing;
        }
        if now_ms > hard_expire_unix_ms {
            return GatewayGrantPhase::Expired;
        }
        if self.authenticated
            && self.lease_expire_unix_ms > 0
            && now_ms > self.lease_expire_unix_ms
            && now_ms <= self.grace_expire_unix_ms
        {
            return GatewayGrantPhase::Grace;
        }
        if now_ms >= self.soft_refresh_after_unix_ms() {
            return GatewayGrantPhase::RefreshDue;
        }
        GatewayGrantPhase::Active
    }

    pub(super) fn is_available(&self, now_ms: i64) -> bool {
        let expire_unix_ms = self
            .grace_expire_unix_ms
            .max(self.lease_expire_unix_ms)
            .max(self.hard_expire_unix_ms());
        self.authenticated && now_ms <= expire_unix_ms
    }
}

impl GatewayGrantPhase {
    pub(super) fn grant_state(self) -> GatewayGrantState {
        match self {
            GatewayGrantPhase::Active => GatewayGrantState::Active,
            GatewayGrantPhase::RefreshDue
            | GatewayGrantPhase::Grace
            | GatewayGrantPhase::Missing
            | GatewayGrantPhase::Expired => GatewayGrantState::NeedsRefresh,
        }
    }
}

impl GatewaySession {
    pub(super) fn update_grant(
        &self,
        grant: &GatewayAccessGrant,
        device_id: String,
    ) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        let auth_changed = state.session_id != grant.session_id || state.ticket != grant.ticket;
        state.gateway_id = grant.gateway_id.clone();
        state.ticket = grant.ticket.clone();
        state.session_id = grant.session_id;
        state.policy_rev = grant.policy_rev;
        state.hard_expire_unix_ms = grant.hard_expire_unix_ms.max(grant.ticket_expire_unix_ms);
        state.soft_refresh_after_unix_ms = if grant.soft_refresh_after_unix_ms > 0 {
            grant.soft_refresh_after_unix_ms
        } else {
            default_soft_refresh_after_unix_ms(state.hard_expire_unix_ms)
        };
        state.ticket_expire_unix_ms = state.hard_expire_unix_ms;
        state.device_id = device_id;
        state.channel_name = match &self.channel {
            GatewayTransport::Quic(_) => "quic".to_string(),
            GatewayTransport::Https(_) => "https".to_string(),
            GatewayTransport::Udp(_) => "udp".to_string(),
        };
        if auth_changed {
            state.authenticated = false;
            state.last_hello_unix_ms = 0;
            state.keepalive_secs = 0;
            state.lease_expire_unix_ms = 0;
            state.grace_expire_unix_ms = 0;
            state.reauth_required = false;
            state.clear_gateway_error();
            state.last_rtt_ms = None;
            state.consecutive_send_failures = 0;
            state.unanswered_hello_count = 0;
            state.udp_rebuild_requested = false;
        }
        state.lease_secs_hint = grant.lease_secs;
        state.grace_secs_hint = grant.grace_secs;
        let http2_idle_timeout = gateway_http2_idle_timeout(state.keepalive_secs);
        drop(state);
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

    pub(super) fn grant_snapshot(&self) -> GatewayGrantSnapshot {
        let state = self.state.lock();
        GatewayGrantSnapshot {
            session_id: state.session_id,
            policy_rev: state.policy_rev,
            soft_refresh_after_unix_ms: state.soft_refresh_after_unix_ms(),
            hard_expire_unix_ms: state.hard_expire_unix_ms(),
            ticket_expire_unix_ms: state.hard_expire_unix_ms(),
        }
    }

    pub(super) fn handle_connect_ack(&self, ack: &GatewayConnectAck) {
        let mut state = self.state.lock();
        if state.session_id != ack.session_id {
            log::debug!(
                "ignoring gateway connect ack for endpoint={} due to session mismatch local={} remote={}",
                self.endpoint,
                state.session_id,
                ack.session_id
            );
            return;
        }
        state.authenticated = ack.ok;
        state.authenticated_transport_generation = match &self.channel {
            GatewayTransport::Https(channel) if ack.ok => channel.connection_generation(),
            GatewayTransport::Quic(channel) if ack.ok => channel.connection_generation(),
            _ => 0,
        };
        state.consecutive_send_failures = 0;
        state.unanswered_hello_count = 0;
        state.udp_rebuild_requested = false;
        if ack.ok {
            state.clear_gateway_error();
            let now_ms = now_time() as i64;
            if state.last_hello_unix_ms > 0 && now_ms >= state.last_hello_unix_ms {
                state.last_rtt_ms = Some((now_ms - state.last_hello_unix_ms).max(1));
            }
            state.keepalive_secs = ack.keepalive_secs;
            state.lease_expire_unix_ms = if ack.lease_expire_unix_ms > 0 {
                ack.lease_expire_unix_ms
            } else {
                now_ms + i64::from(state.lease_secs_hint.max(ack.keepalive_secs.max(3))) * 1_000
            };
            state.grace_expire_unix_ms = if ack.grace_expire_unix_ms > 0 {
                ack.grace_expire_unix_ms
            } else {
                state.lease_expire_unix_ms + i64::from(state.grace_secs_hint) * 1_000
            };
            state.reauth_required = ack.reauth_required;
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
            state.keepalive_secs = 0;
            state.lease_expire_unix_ms = 0;
            state.grace_expire_unix_ms = 0;
            state.reauth_required = ack.reauth_required;
            let error = if ack.reason.is_empty() {
                "gateway_rejected".to_string()
            } else {
                ack.reason.clone()
            };
            state.record_gateway_error(GatewayErrorKind::AuthRejected, error, now_ms);
            state.last_rtt_ms = None;
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

    pub(super) fn invalidate_stream_authentication(&self) {
        let mut state = self.state.lock();
        state.authenticated = false;
        state.authenticated_transport_generation = 0;
        state.last_hello_unix_ms = 0;
        state.last_rtt_ms = None;
        state.consecutive_send_failures = 0;
        state.unanswered_hello_count = 0;
    }

    pub(super) fn reconcile_stream_authentication(&self) {
        let generation = match &self.channel {
            GatewayTransport::Https(channel) => channel.connection_generation(),
            GatewayTransport::Quic(channel) => channel.connection_generation(),
            GatewayTransport::Udp(_) => return,
        };
        let mut state = self.state.lock();
        if state.authenticated
            && (generation == 0 || generation != state.authenticated_transport_generation)
        {
            state.authenticated = false;
            state.authenticated_transport_generation = 0;
            state.last_hello_unix_ms = 0;
            state.last_rtt_ms = None;
            state.consecutive_send_failures = 0;
            state.unanswered_hello_count = 0;
        }
    }

    pub(super) fn maybe_build_connect_hello(
        &self,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<Option<NetPacket<Vec<u8>>>> {
        let mut state = self.state.lock();
        let now_ms = now_time() as i64;
        let ticket_available = now_ms <= state.ticket_expire_unix_ms && !state.ticket.is_empty();
        if !ticket_available && now_ms > state.grace_expire_unix_ms {
            return Ok(None);
        }
        if state.authenticated
            && state.lease_expire_unix_ms > 0
            && now_ms > state.lease_expire_unix_ms
        {
            state.authenticated = false;
        }
        let interval_ms = if state.authenticated {
            u64::from(state.keepalive_secs.max(3)) * 1_000
        } else {
            3_000
        } as i64;
        if now_ms - state.last_hello_unix_ms < interval_ms {
            return Ok(None);
        }
        if !state.authenticated {
            if let GatewayTransport::Udp(channel) = &self.channel {
                channel.mark_bootstrap_pending();
            }
        }
        state.last_hello_unix_ms = now_ms;
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let hello = GatewayConnectHello {
            device_id: state.device_id.clone(),
            virtual_ip: u32::from(current_device.virtual_ip),
            session_id: state.session_id,
            ticket: state.ticket.clone(),
            nonce,
            client_time_unix_ms: now_ms,
            reauth: state.reauth_required || !ticket_available,
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
            state.device_id,
            state.session_id,
            state.reauth_required || !ticket_available,
            ticket_available
        );
        Ok(Some(packet))
    }
}

pub(super) fn gateway_http2_idle_timeout(keepalive_secs: u32) -> Duration {
    let keepalive_secs = u64::from(keepalive_secs.max(3));
    Duration::from_secs((keepalive_secs * 2).max(GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS))
}

#[cfg(test)]
mod tests {
    use super::default_soft_refresh_after_unix_ms;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use protobuf::EnumOrUnknown;

    use crate::data_plane::stats::DataPlaneStats;
    use crate::handle::{now_time, CurrentDeviceInfo};
    use crate::proto::message::{
        GatewayAccessGrant, GatewayChannel, GatewayChannelKind, GatewayConnectAck,
    };
    use crate::util::DebugWatch;

    use super::super::{
        GatewayErrorKind, GatewayGrantPhase, GatewayGrantState, GatewaySession,
        GatewaySessionState, GatewaySessions, GatewayTransport,
        GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS,
    };
    use super::gateway_http2_idle_timeout;

    #[test]
    fn gateway_http2_idle_timeout_uses_minimum_before_ack() {
        assert_eq!(
            gateway_http2_idle_timeout(0),
            Duration::from_secs(GATEWAY_HTTP2_IDLE_TIMEOUT_MIN_SECS)
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
        assert_eq!(state.grant_phase(99), GatewayGrantPhase::Active);
        assert_eq!(state.grant_phase(100), GatewayGrantPhase::RefreshDue);

        state.authenticated = true;
        state.lease_expire_unix_ms = 120;
        state.grace_expire_unix_ms = 150;
        assert_eq!(state.grant_phase(130), GatewayGrantPhase::Grace);
        assert_eq!(state.grant_phase(201), GatewayGrantPhase::Expired);
    }

    #[test]
    fn grant_state_collapse_keeps_only_active_and_needs_refresh() {
        assert_eq!(
            GatewayGrantPhase::Active.grant_state(),
            GatewayGrantState::Active
        );
        assert_eq!(
            GatewayGrantPhase::RefreshDue.grant_state(),
            GatewayGrantState::NeedsRefresh
        );
        assert_eq!(
            GatewayGrantPhase::Grace.grant_state(),
            GatewayGrantState::NeedsRefresh
        );
        assert_eq!(
            GatewayGrantPhase::Missing.grant_state(),
            GatewayGrantState::NeedsRefresh
        );
        assert_eq!(
            GatewayGrantPhase::Expired.grant_state(),
            GatewayGrantState::NeedsRefresh
        );
    }

    #[test]
    fn fallback_soft_refresh_after_clamps_invalid_early_expiry() {
        assert_eq!(default_soft_refresh_after_unix_ms(0), 0);
        assert_eq!(default_soft_refresh_after_unix_ms(1_000), 1_000);
        assert_eq!(default_soft_refresh_after_unix_ms(500_000), 380_000);
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
            DebugWatch::default(),
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
                Some(GatewayErrorKind::AuthRejected)
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
}
