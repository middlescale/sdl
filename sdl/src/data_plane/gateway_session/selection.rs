//! Session query boundaries, manual pinning, and active-gateway selection.

use std::net::{Ipv4Addr, SocketAddr};

use crate::data_plane::route::RouteKey;
use crate::transport::quic_channel::PacketCallback;
use crate::util::StopManager;

use super::registry::{GatewayRelaySnapshot, GatewaySessionSnapshot};

use super::{
    GatewayGrantPhase, GatewayGrantSnapshot, GatewaySession, GatewaySessionSummary,
    GatewaySessions, GATEWAY_SWITCH_BETTER_RT_MS,
};

impl GatewaySessions {
    // Registry query/operation lock boundaries are centralized here. Business
    // modules use these methods; grant batches and UDP rebuilds retain explicit
    // registry guards because their multi-step updates must stay atomic.
    pub fn is_gateway_addr(&self, addr: SocketAddr) -> bool {
        self.registry.lock().matches_addr(addr)
    }

    pub fn current_grant_snapshot(&self) -> Option<GatewayGrantSnapshot> {
        self.registry.lock().current_grant_snapshot()
    }

    pub(super) fn udp_endpoints(&self) -> Vec<SocketAddr> {
        self.registry.lock().udp_endpoints()
    }

    pub(super) fn start_registered_sessions(
        &self,
        stop: &StopManager,
        on_packet: &PacketCallback,
    ) -> anyhow::Result<()> {
        self.registry.lock().start_sessions(stop, on_packet)
    }

    pub fn handle_gateway_probe_pong(
        &self,
        source: Ipv4Addr,
        route_key: RouteKey,
        epoch: u16,
    ) -> bool {
        self.registry
            .lock()
            .handle_gateway_probe_pong(source, route_key, epoch)
    }

    fn summary_snapshot(&self) -> Vec<GatewaySessionSummary> {
        self.registry.lock().summary_snapshot()
    }

    pub(super) fn session_at(&self, endpoint: SocketAddr) -> Option<GatewaySession> {
        self.registry.lock().session_at(endpoint)
    }

    pub(super) fn contains_endpoint(&self, endpoint: SocketAddr) -> bool {
        self.registry.lock().contains_endpoint(endpoint)
    }

    /// Runtime events explicitly refresh selection; read-only queries never do.
    pub(super) fn refresh_selection(&self) {
        self.registry.lock().refresh_selection();
    }

    /// A maintenance pass needs the refreshed choice and handles from the
    /// same membership view. Hold one guard across refresh and snapshot creation.
    pub(super) fn refresh_selection_and_snapshot(&self) -> GatewaySessionSnapshot {
        let mut registry = self.registry.lock();
        registry.refresh_selection();
        registry.snapshot()
    }

    /// Clone the already-selected session without refreshing selection. No table
    /// lock escapes this method; the handle shares the session's state.
    pub(super) fn active_session(&self) -> Option<GatewaySession> {
        self.registry.lock().active_session()
    }

    /// Read selection and handles from one membership view without changing
    /// selection or the switch cooldown.
    pub(super) fn session_snapshot(&self) -> GatewaySessionSnapshot {
        self.registry.lock().snapshot()
    }

    /// Manual pinning has exactly one candidate; automatic selection retains
    /// the existing ordered retry list instead of becoming a single-shot send.
    pub(super) fn relay_candidates(&self) -> Vec<GatewaySession> {
        let snapshot = self.registry.lock().refresh_relay_snapshot();
        // The registry guard is gone before sorting. Both selection and retry
        // ordering use the sampled summaries, not additional session.summary().
        match snapshot {
            GatewayRelaySnapshot::Pinned(session) => vec![session],
            GatewayRelaySnapshot::Automatic {
                active_endpoint,
                mut sessions,
            } => {
                sessions.sort_by_cached_key(|candidate| {
                    gateway_summary_order_key(&candidate.summary, active_endpoint)
                });
                sessions
                    .into_iter()
                    .map(|candidate| candidate.session)
                    .collect()
            }
        }
    }

    pub fn set_manual_endpoint(&self, endpoint: Option<SocketAddr>) -> anyhow::Result<()> {
        self.registry.lock().set_manual_endpoint(endpoint)?;
        self.trigger_connect_now();
        self.wake_maintenance();
        Ok(())
    }

    pub fn session_summary(&self) -> GatewaySessionSummary {
        // Sample only the selected handle and release the registry before
        // taking its session-state lock. This handle is active by construction.
        self.active_session()
            .map(|session| {
                let mut summary = session.summary();
                summary.active = true;
                summary
            })
            .unwrap_or_default()
    }

    pub fn session_summaries(&self) -> Vec<GatewaySessionSummary> {
        let mut summaries = self.summary_snapshot();
        summaries.sort_by_key(|summary| {
            (
                !summary.active,
                !summary.authenticated,
                summary.rt_ms.unwrap_or(i64::MAX),
                summary.gateway_id.clone(),
                summary.channel_name.clone(),
            )
        });
        summaries
    }
}

pub(super) fn gateway_summary_sort_key(
    summary: &GatewaySessionSummary,
) -> (
    std::cmp::Reverse<GatewayHealthOrderKey>,
    bool,
    std::cmp::Reverse<String>,
) {
    // Selection maximizes health, then prefers no reauth and a stable ID.
    (
        std::cmp::Reverse(gateway_health_order_key(summary)),
        !summary.reauth_required,
        std::cmp::Reverse(summary.gateway_id.clone()),
    )
}

pub(super) fn gateway_summary_is_clearly_better(
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

pub(super) fn gateway_summary_order_key(
    summary: &GatewaySessionSummary,
    active: Option<SocketAddr>,
) -> (bool, GatewayHealthOrderKey, String) {
    // Retry order keeps the established winner first, then shares the same
    // health ranking as selection. Unlike selection it has no reauth tie-break.
    (
        summary.endpoint != active,
        gateway_health_order_key(summary),
        summary.gateway_id.clone(),
    )
}

type GatewayHealthOrderKey = (bool, std::cmp::Reverse<u8>, i64);

/// Lower is healthier; shared by winner selection and relay retry ordering.
fn gateway_health_order_key(summary: &GatewaySessionSummary) -> GatewayHealthOrderKey {
    (
        !summary.authenticated,
        std::cmp::Reverse(gateway_grant_phase_rank(summary.grant_phase)),
        summary.rt_ms.unwrap_or(i64::MAX),
    )
}

pub(super) fn gateway_grant_phase_rank(phase: GatewayGrantPhase) -> u8 {
    match phase {
        GatewayGrantPhase::Active => 4,
        GatewayGrantPhase::RefreshDue => 3,
        GatewayGrantPhase::Grace => 2,
        GatewayGrantPhase::Missing => 1,
        GatewayGrantPhase::Expired => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use protobuf::EnumOrUnknown;

    use crate::handle::now_time;
    use crate::proto::message::{GatewayAccessGrant, GatewayChannel, GatewayChannelKind};

    use super::super::{GatewayGrantPhase, GatewaySession, GatewaySessionSummary, GatewaySessions};
    use super::{gateway_summary_order_key, gateway_summary_sort_key};

    #[test]
    fn selection_and_retry_share_health_ranking_but_keep_distinct_priorities() {
        let healthy = GatewaySessionSummary {
            endpoint: Some("127.0.0.1:29950".parse().unwrap()),
            authenticated: true,
            grant_phase: GatewayGrantPhase::Active,
            rt_ms: Some(10),
            gateway_id: "gateway".into(),
            ..Default::default()
        };
        let mut weaker_auth = healthy.clone();
        weaker_auth.authenticated = false;
        let mut weaker_grant = healthy.clone();
        weaker_grant.grant_phase = GatewayGrantPhase::Grace;
        let mut slower = healthy.clone();
        slower.rt_ms = Some(40);
        let mut unmeasured = healthy.clone();
        unmeasured.rt_ms = None;
        for weaker in [weaker_auth, weaker_grant, slower, unmeasured] {
            assert!(gateway_summary_sort_key(&healthy) > gateway_summary_sort_key(&weaker));
            assert!(
                gateway_summary_order_key(&healthy, None)
                    < gateway_summary_order_key(&weaker, None)
            );
        }

        let mut reauth = healthy.clone();
        reauth.reauth_required = true;
        assert!(gateway_summary_sort_key(&healthy) > gateway_summary_sort_key(&reauth));
        assert_eq!(
            gateway_summary_order_key(&healthy, None),
            gateway_summary_order_key(&reauth, None)
        );

        let mut active = healthy.clone();
        active.endpoint = Some("127.0.0.1:29951".parse().unwrap());
        active.rt_ms = Some(100);
        assert!(gateway_summary_sort_key(&healthy) > gateway_summary_sort_key(&active));
        assert!(
            gateway_summary_order_key(&active, active.endpoint)
                < gateway_summary_order_key(&healthy, active.endpoint)
        );
    }

    #[test]
    fn single_and_full_summary_queries_agree_without_initializing_selection() {
        let gateways = GatewaySessions::default();
        let first = test_session(29952, 10);
        let second = test_session(29953, 40);
        let first_endpoint = first.endpoint;
        {
            let mut registry = gateways.registry.lock();
            registry.install_session(first);
            registry.install_session(second.clone());
        }
        assert!(gateways.session_summary().endpoint.is_none());
        assert!(gateways
            .session_summaries()
            .iter()
            .all(|summary| !summary.active));

        gateways.set_manual_endpoint(Some(second.endpoint)).unwrap();
        let single = gateways.session_summary();
        let full = gateways.session_summaries();
        let selected = full.iter().find(|summary| summary.active).unwrap();
        assert_eq!(full.iter().filter(|summary| summary.active).count(), 1);
        assert_eq!(single.endpoint, Some(second.endpoint));
        assert_eq!(single.endpoint, selected.endpoint);
        assert_eq!(single.rt_ms, selected.rt_ms);
        assert_eq!(single.authenticated, selected.authenticated);
        assert_eq!(single.grant_phase, selected.grant_phase);
        assert_eq!(single.active, selected.active);
        assert_eq!(full[0].endpoint, single.endpoint);

        gateways.set_manual_endpoint(None).unwrap();
        // Clearing a pin is a runtime event: trigger_connect_now explicitly
        // refreshes automatic selection, unlike the read-only queries above.
        assert_eq!(gateways.session_summary().endpoint, Some(first_endpoint));
        assert_eq!(
            gateways
                .session_summaries()
                .iter()
                .find(|summary| summary.active)
                .unwrap()
                .endpoint,
            Some(first_endpoint)
        );
    }

    fn test_session(port: u16, rtt_ms: i64) -> GatewaySession {
        let session = GatewaySession::new_quic(
            format!("127.0.0.1:{port}").parse().unwrap(),
            Default::default(),
            crate::data_plane::stats::DataPlaneStats::new(false),
        );
        {
            let mut state = session.state.lock();
            state.ticket = vec![1];
            state.hard_expire_unix_ms = now_time() as i64 + 60_000;
            state.last_rtt_ms = Some(rtt_ms);
        }
        session
    }

    #[test]
    fn active_session_returns_a_shared_handle_without_holding_table_locks() {
        let gateways = GatewaySessions::default();
        assert!(gateways.active_session().is_none());
        let slow = test_session(29920, 100);
        let fast = test_session(29921, 10);
        {
            let mut registry = gateways.registry.lock();
            registry.install_session(slow);
            registry.install_session(fast.clone());
        }
        gateways.refresh_selection();
        let selected = gateways.active_session().unwrap();
        assert_eq!(selected.endpoint, fast.endpoint);
        assert!(Arc::ptr_eq(&selected.state, &fast.state));
        assert!(gateways.registry.try_lock().is_some());
        let looked_up = gateways.session_at(fast.endpoint).unwrap();
        assert!(Arc::ptr_eq(&looked_up.state, &fast.state));
        assert!(gateways.registry.try_lock().is_some());
        assert!(gateways.session_summary().active);

        fast.reactivate();
        assert!(selected.active.load());
        fast.retire();
        assert!(!selected.active.load());
    }

    #[test]
    fn relay_candidates_preserve_auto_fallback_and_manual_pin() {
        let gateways = GatewaySessions::default();
        let slow = test_session(29922, 100);
        let fast = test_session(29923, 10);
        {
            let mut registry = gateways.registry.lock();
            registry.install_session(slow.clone());
            registry.install_session(fast.clone());
        }
        let candidates = gateways.relay_candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].endpoint, fast.endpoint);
        assert_eq!(candidates[1].endpoint, slow.endpoint);

        gateways
            .registry
            .lock()
            .set_manual_endpoint(Some(slow.endpoint))
            .unwrap();
        assert_eq!(gateways.active_session().unwrap().endpoint, slow.endpoint);
        let candidates = gateways.relay_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].endpoint, slow.endpoint);
    }

    #[test]
    fn removing_the_pinned_session_restores_automatic_selection() {
        let gateways = GatewaySessions::default();
        let pinned = test_session(29924, 100);
        let remaining = test_session(29925, 10);
        {
            let mut registry = gateways.registry.lock();
            registry.install_session(pinned.clone());
            registry.install_session(remaining.clone());
        }
        gateways
            .registry
            .lock()
            .set_manual_endpoint(Some(pinned.endpoint))
            .unwrap();
        let snapshot = gateways.session_snapshot();
        assert_eq!(snapshot.active_endpoint, Some(pinned.endpoint));
        assert_eq!(snapshot.sessions.len(), 2);
        gateways.registry.lock().remove_session(pinned.endpoint);
        gateways.refresh_selection();

        assert_eq!(
            gateways.active_session().unwrap().endpoint,
            remaining.endpoint
        );
        let candidates = gateways.relay_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].endpoint, remaining.endpoint);
        assert_eq!(snapshot.sessions.len(), 2);
    }

    #[test]
    fn clearing_grants_resets_membership_and_selection_together() {
        let gateways = GatewaySessions::default();
        let pinned = test_session(29926, 10);
        {
            let mut registry = gateways.registry.lock();
            registry.install_session(pinned.clone());
            registry.set_manual_endpoint(Some(pinned.endpoint)).unwrap();
        }

        gateways.clear_gateway_grant();

        let snapshot = gateways.session_snapshot();
        assert!(snapshot.sessions.is_empty());
        assert!(snapshot.active_endpoint.is_none());
    }

    #[test]
    fn concurrent_membership_changes_keep_selection_snapshots_consistent() {
        let gateways = GatewaySessions::default();
        let first = test_session(29927, 10);
        let second = test_session(29928, 20);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let writer = {
            let gateways = gateways.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for index in 0..1_000 {
                    let session = if index % 2 == 0 { &first } else { &second };
                    let mut registry = gateways.registry.lock();
                    registry.take_all_sessions();
                    registry.install_session(session.clone());
                    registry
                        .set_manual_endpoint(Some(session.endpoint))
                        .unwrap();
                }
            })
        };
        barrier.wait();
        for _ in 0..1_000 {
            let snapshot = gateways.session_snapshot();
            if let Some(endpoint) = snapshot.active_endpoint {
                assert_eq!(snapshot.sessions.len(), 1);
                assert_eq!(snapshot.sessions[0].endpoint, endpoint);
            } else {
                assert!(snapshot.sessions.is_empty());
            }
        }
        writer.join().unwrap();
    }

    #[test]
    fn gateway_summary_order_key_prefers_active_grants() {
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

        let registry = sessions.registry.lock();
        let active = registry
            .session_at("127.0.0.1:29910".parse().unwrap())
            .expect("active session")
            .clone();
        let expired = registry
            .session_at("127.0.0.1:29911".parse().unwrap())
            .expect("expired session")
            .clone();
        drop(registry);

        assert!(
            gateway_summary_order_key(&active.summary(), None)
                < gateway_summary_order_key(&expired.summary(), None)
        );
    }
}
