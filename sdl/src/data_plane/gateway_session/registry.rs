//! Session membership and selection, protected by the manager's registry lock.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};

use crate::data_plane::route::RouteKey;
use crate::handle::now_time;
use crate::transport::quic_channel::PacketCallback;
use crate::util::StopManager;

use super::selection::{gateway_summary_is_clearly_better, gateway_summary_sort_key};
use super::{
    GatewayGrantSnapshot, GatewaySession, GatewaySessionSummary, GATEWAY_SWITCH_COOLDOWN_MS,
};

/// Membership and selection share a single consistency boundary. No method
/// exposes the map, iterators, or mutable references to its stored sessions.
#[derive(Default)]
pub(super) struct GatewaySessionRegistry {
    entries: HashMap<SocketAddr, GatewaySession>,
    /// User-requested pin; when present, explicit refresh bypasses auto ranking.
    manual_endpoint: Option<SocketAddr>,
    /// Current choice maintained by runtime refreshes or explicit pin changes.
    /// This is selection state, not proof that the transport is healthy.
    selected_endpoint: Option<SocketAddr>,
    last_switch_unix_ms: i64,
}

/// A selected endpoint and cloned handles from one locked session-table view.
/// Handles can be retired afterward; sending still checks their runtime gates.
pub(super) struct GatewaySessionSnapshot {
    /// Valid copy of selected_endpoint in this membership view, not a new winner.
    pub(super) active_endpoint: Option<SocketAddr>,
    pub(super) sessions: Vec<GatewaySession>,
}

/// One operation-local health sample paired with its shared session handle.
pub(super) struct RelayCandidate {
    pub(super) session: GatewaySession,
    pub(super) summary: GatewaySessionSummary,
}

/// Sending reuses the health sampled by the explicit selection refresh. A pin
/// needs only one handle, so it avoids sampling unrelated sessions entirely.
pub(super) enum GatewayRelaySnapshot {
    Pinned(GatewaySession),
    Automatic {
        /// Choice established by this explicit refresh, using the samples below.
        active_endpoint: Option<SocketAddr>,
        sessions: Vec<RelayCandidate>,
    },
}

impl GatewaySessionRegistry {
    /// Selection needs sampled health only, not cloned transport handles.
    fn sample_summaries(&self) -> Vec<GatewaySessionSummary> {
        self.entries.values().map(GatewaySession::summary).collect()
    }

    fn sample_candidates(&self) -> Vec<RelayCandidate> {
        self.entries
            .values()
            .map(|session| RelayCandidate {
                session: session.clone(),
                summary: session.summary(),
            })
            .collect()
    }

    pub(super) fn refresh_selection(&mut self) -> Option<SocketAddr> {
        self.reset_selection_if_missing();
        // Preserve the manual-pin fast path: no unrelated summaries are needed.
        if let Some(endpoint) = self.manual_endpoint {
            // Membership was reconciled above under the same registry guard.
            self.selected_endpoint = Some(endpoint);
            return Some(endpoint);
        }
        let now_ms = now_time() as i64;
        let summaries = self.sample_summaries();
        self.refresh_automatic_selection(summaries.iter(), now_ms)
    }

    pub(super) fn refresh_relay_snapshot(&mut self) -> GatewayRelaySnapshot {
        self.reset_selection_if_missing();
        if let Some(session) = self
            .manual_endpoint
            .and_then(|endpoint| self.session_at(endpoint))
        {
            self.selected_endpoint = Some(session.endpoint);
            return GatewayRelaySnapshot::Pinned(session);
        }
        let now_ms = now_time() as i64;
        let candidates = self.sample_candidates();
        let active_endpoint = self.refresh_automatic_selection(
            candidates.iter().map(|candidate| &candidate.summary),
            now_ms,
        );
        GatewayRelaySnapshot::Automatic {
            active_endpoint,
            sessions: candidates,
        }
    }

    /// Rank sampled health only, whether obtained alone or with relay handles.
    /// Cloning the iterator below does not clone summaries or session handles.
    /// Callers first reconcile membership and
    /// handle any remaining pin; invalid-pin cleanup belongs to one method.
    fn refresh_automatic_selection<'a>(
        &mut self,
        summaries: impl Iterator<Item = &'a GatewaySessionSummary> + Clone,
        now_ms: i64,
    ) -> Option<SocketAddr> {
        debug_assert!(self.manual_endpoint.is_none());
        let mut summaries = summaries.filter(|summary| summary.endpoint.is_some());
        let best_summary = summaries
            .clone()
            .max_by_key(|summary| gateway_summary_sort_key(summary))?;
        let best_endpoint = best_summary.endpoint?;
        let current = summaries.find_map(|summary| {
            summary
                .endpoint
                .filter(|endpoint| Some(*endpoint) == self.selected_endpoint)
                .map(|endpoint| (endpoint, summary))
        });
        let chosen = match current {
            Some((current_endpoint, current_summary)) => {
                if current_endpoint == best_endpoint {
                    current_endpoint
                } else if !current_summary.authenticated
                    || (best_summary.authenticated
                        && gateway_summary_is_clearly_better(best_summary, current_summary)
                        && now_ms - self.last_switch_unix_ms >= GATEWAY_SWITCH_COOLDOWN_MS)
                {
                    best_endpoint
                } else {
                    current_endpoint
                }
            }
            None => best_endpoint,
        };
        if self.selected_endpoint != Some(chosen) {
            self.selected_endpoint = Some(chosen);
            self.last_switch_unix_ms = now_ms;
        }
        Some(chosen)
    }

    /// Single membership-removal cleanup for both the pin and current choice.
    pub(super) fn reset_selection_if_missing(&mut self) {
        if self
            .manual_endpoint
            .is_some_and(|endpoint| !self.entries.contains_key(&endpoint))
        {
            self.manual_endpoint = None;
        }
        if self
            .selected_endpoint
            .is_some_and(|endpoint| !self.entries.contains_key(&endpoint))
        {
            self.selected_endpoint = None;
            self.last_switch_unix_ms = 0;
        }
    }
}

impl GatewaySessionRegistry {
    pub(super) fn session_at(&self, endpoint: SocketAddr) -> Option<GatewaySession> {
        self.entries.get(&endpoint).cloned()
    }

    pub(super) fn contains_endpoint(&self, endpoint: SocketAddr) -> bool {
        self.entries.contains_key(&endpoint)
    }

    pub(super) fn matches_addr(&self, addr: SocketAddr) -> bool {
        self.entries
            .values()
            .any(|session| session.matches_addr(addr))
    }

    pub(super) fn udp_endpoints(&self) -> Vec<SocketAddr> {
        self.entries
            .values()
            .filter(|session| session.is_udp())
            .map(|session| session.endpoint)
            .collect()
    }

    pub(super) fn current_grant_snapshot(&self) -> Option<GatewayGrantSnapshot> {
        self.entries
            .values()
            .map(GatewaySession::grant_snapshot)
            .max_by_key(|snapshot| {
                snapshot
                    .hard_expire_unix_ms
                    .max(snapshot.ticket_expire_unix_ms)
            })
    }

    fn active_endpoint(&self) -> Option<SocketAddr> {
        self.selected_endpoint
            .filter(|endpoint| self.contains_endpoint(*endpoint))
    }

    pub(super) fn active_session(&self) -> Option<GatewaySession> {
        self.session_at(self.active_endpoint()?)
    }

    pub(super) fn snapshot(&self) -> GatewaySessionSnapshot {
        let active_endpoint = self.active_endpoint();
        GatewaySessionSnapshot {
            active_endpoint,
            sessions: self.entries.values().cloned().collect(),
        }
    }

    /// Read the established selection and sample each session once for display.
    /// This does not advance selection or its cooldown. Session summaries retain
    /// their existing stream-auth reconciliation; this is not a persistent cache.
    pub(super) fn summary_snapshot(&self) -> Vec<GatewaySessionSummary> {
        let active_endpoint = self.active_endpoint();
        self.entries
            .values()
            .map(|session| Self::sample_summary(session, active_endpoint))
            .collect()
    }

    fn sample_summary(
        session: &GatewaySession,
        active_endpoint: Option<SocketAddr>,
    ) -> GatewaySessionSummary {
        let mut summary = session.summary();
        summary.active = Some(session.endpoint) == active_endpoint;
        summary
    }

    pub(super) fn set_manual_endpoint(
        &mut self,
        endpoint: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        if let Some(endpoint) = endpoint {
            if !self.contains_endpoint(endpoint) {
                anyhow::bail!("gateway endpoint {endpoint} not found");
            }
        }
        self.manual_endpoint = endpoint;
        self.selected_endpoint = endpoint;
        self.last_switch_unix_ms = now_time() as i64;
        Ok(())
    }

    pub(super) fn endpoints_outside(&self, desired: &HashSet<SocketAddr>) -> Vec<SocketAddr> {
        self.entries
            .keys()
            .filter(|endpoint| !desired.contains(endpoint))
            .copied()
            .collect()
    }

    /// Lifecycle orchestration holds the registry lock across each grant batch.
    pub(super) fn install_session(&mut self, session: GatewaySession) {
        self.entries.insert(session.endpoint, session);
    }

    /// Selection is reconciled at the end of a grant batch, not during a
    /// temporary UDP rebuild removal; that preserves a pin across replacement.
    pub(super) fn remove_session(&mut self, endpoint: SocketAddr) -> Option<GatewaySession> {
        self.entries.remove(&endpoint)
    }

    /// Return owned handles for retirement; never expose the map's Drain.
    pub(super) fn take_all_sessions(&mut self) -> Vec<GatewaySession> {
        self.entries.drain().map(|(_, session)| session).collect()
    }

    pub(super) fn clear_selection(&mut self) {
        self.manual_endpoint = None;
        self.selected_endpoint = None;
        self.last_switch_unix_ms = 0;
    }

    /// Startup and probe handling deliberately remain under the registry lock,
    /// matching their existing synchronization.
    pub(super) fn start_sessions(
        &self,
        stop: &StopManager,
        on_packet: &PacketCallback,
    ) -> anyhow::Result<()> {
        for session in self.entries.values() {
            session.start(stop, on_packet)?;
        }
        Ok(())
    }

    pub(super) fn handle_gateway_probe_pong(
        &self,
        source: Ipv4Addr,
        route_key: RouteKey,
        epoch: u16,
    ) -> bool {
        self.entries
            .get(&route_key.addr)
            .is_some_and(|session| session.handle_gateway_probe_pong(source, route_key, epoch))
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayRelaySnapshot, GatewaySessionRegistry};
    use crate::data_plane::gateway_session::{GatewaySession, GatewaySessions};
    use crate::data_plane::stats::DataPlaneStats;

    fn test_session(port: u16) -> GatewaySession {
        GatewaySession::new_quic(
            format!("127.0.0.1:{port}").parse().unwrap(),
            Default::default(),
            DataPlaneStats::new(false),
        )
    }

    #[test]
    fn selection_samples_do_not_retain_handles_but_transport_snapshots_do() {
        let mut registry = GatewaySessionRegistry::default();
        let session = test_session(29954);
        registry.install_session(session.clone());
        let baseline = std::sync::Arc::strong_count(&session.state);

        let summaries = registry.sample_summaries();
        assert_eq!(std::sync::Arc::strong_count(&session.state), baseline);
        assert_eq!(summaries[0].endpoint, Some(session.endpoint));
        assert_eq!(registry.refresh_selection(), Some(session.endpoint));
        assert_eq!(std::sync::Arc::strong_count(&session.state), baseline);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.active_endpoint, Some(session.endpoint));
        assert_eq!(std::sync::Arc::strong_count(&session.state), baseline + 1);
        drop(snapshot);
        assert_eq!(std::sync::Arc::strong_count(&session.state), baseline);

        let GatewayRelaySnapshot::Automatic {
            sessions,
            active_endpoint,
        } = registry.refresh_relay_snapshot()
        else {
            panic!("automatic mode must return sampled candidates");
        };
        assert_eq!(active_endpoint, Some(session.endpoint));
        assert_eq!(sessions[0].summary.endpoint, Some(session.endpoint));
        assert_eq!(std::sync::Arc::strong_count(&session.state), baseline + 1);
    }

    #[test]
    fn rejecting_an_unknown_pin_preserves_the_existing_selection() {
        let mut registry = GatewaySessionRegistry::default();
        let session = test_session(29929);
        let endpoint = session.endpoint;
        registry.install_session(session);
        registry.set_manual_endpoint(Some(endpoint)).unwrap();

        assert!(registry
            .set_manual_endpoint(Some("127.0.0.1:29930".parse().unwrap()))
            .is_err());
        let snapshot = registry.snapshot();
        assert_eq!(registry.manual_endpoint, Some(endpoint));
        assert_eq!(snapshot.active_endpoint, Some(endpoint));
    }

    #[test]
    fn batch_removal_reconciles_selection_and_clears_the_switch_deadline() {
        let mut registry = GatewaySessionRegistry::default();
        let session = test_session(29931);
        let endpoint = session.endpoint;
        registry.install_session(session);
        registry.set_manual_endpoint(Some(endpoint)).unwrap();
        assert!(registry.last_switch_unix_ms > 0);

        registry.remove_session(endpoint).unwrap();
        registry.reset_selection_if_missing();

        assert!(!registry.contains_endpoint(endpoint));
        assert!(registry.session_at(endpoint).is_none());
        assert!(registry.manual_endpoint.is_none());
        assert!(registry.selected_endpoint.is_none());
        assert_eq!(registry.last_switch_unix_ms, 0);
    }

    #[test]
    fn selection_reuses_sampled_health_and_preserves_the_switch_cooldown() {
        let mut registry = GatewaySessionRegistry::default();
        let current = test_session(29932);
        let challenger = test_session(29933);
        let mut current_summary = current.summary();
        let mut challenger_summary = challenger.summary();
        // Live sessions are not authenticated. A re-read would incorrectly
        // bypass the cooldown instead of using this sampled healthy state.
        current_summary.authenticated = true;
        current_summary.rt_ms = Some(40);
        challenger_summary.authenticated = true;
        challenger_summary.rt_ms = Some(10);
        registry.install_session(current.clone());
        registry.install_session(challenger.clone());
        // Deterministic synthetic time is needed to exercise both sides of
        // the cooldown boundary without sleeping or changing production APIs.
        let samples = [current_summary, challenger_summary];

        assert_eq!(
            registry.refresh_automatic_selection(samples[..1].iter(), 1_000),
            Some(current.endpoint)
        );
        assert_eq!(
            registry.refresh_automatic_selection(samples.iter(), 1_050),
            Some(current.endpoint)
        );
        assert_eq!(
            registry.refresh_automatic_selection(samples.iter(), 11_000),
            Some(challenger.endpoint)
        );
    }

    #[test]
    fn summary_snapshots_share_selection_samples_without_caching_future_reads() {
        let mut registry = GatewaySessionRegistry::default();
        let first = test_session(29934);
        let second = test_session(29935);
        first.state.lock().last_rtt_ms = Some(10);
        second.state.lock().last_rtt_ms = Some(40);
        registry.install_session(first.clone());
        registry.install_session(second.clone());

        registry.refresh_selection();
        let before = registry.summary_snapshot();
        let selected = before.iter().find(|summary| summary.active).unwrap();
        assert_eq!(selected.endpoint, Some(first.endpoint));
        assert_eq!(selected.rt_ms, Some(10));

        first.state.lock().last_rtt_ms = Some(50);
        second.state.lock().last_rtt_ms = Some(5);
        // Health changes are visible to queries without changing selection.
        assert_eq!(
            registry
                .summary_snapshot()
                .iter()
                .find(|summary| summary.active)
                .unwrap()
                .endpoint,
            Some(first.endpoint)
        );
        registry.refresh_selection();
        let after = registry.summary_snapshot();
        let selected = after.iter().find(|summary| summary.active).unwrap();
        assert_eq!(selected.rt_ms, Some(5));
        assert_eq!(selected.endpoint, Some(second.endpoint));
        // The old operation-local sample stays unchanged; the next query
        // reflects new health rather than reusing a persistent summary cache.
        assert_eq!(
            before.iter().find(|summary| summary.active).unwrap().rt_ms,
            Some(10)
        );
    }

    #[test]
    fn status_queries_and_deadline_reads_do_not_refresh_selection() {
        let gateways = GatewaySessions::default();
        let first = test_session(29936);
        let second = test_session(29937);
        first.state.lock().last_rtt_ms = Some(10);
        second.state.lock().last_rtt_ms = Some(40);
        {
            let mut registry = gateways.registry.lock();
            registry.install_session(first.clone());
            registry.install_session(second.clone());
        }
        // Even the first read must not implicitly initialize selection.
        assert!(gateways.active_session().is_none());
        assert!(gateways.session_summary().endpoint.is_none());
        assert!(gateways
            .session_summaries()
            .iter()
            .all(|summary| !summary.active));
        {
            let registry = gateways.registry.lock();
            assert!(registry.selected_endpoint.is_none());
            assert_eq!(registry.last_switch_unix_ms, 0);
        }

        gateways.refresh_selection();
        let switched_at = gateways.registry.lock().last_switch_unix_ms;
        first.state.lock().last_rtt_ms = Some(50);
        second.state.lock().last_rtt_ms = Some(5);
        for _ in 0..10 {
            assert_eq!(gateways.active_session().unwrap().endpoint, first.endpoint);
            assert_eq!(
                gateways.session_snapshot().active_endpoint,
                Some(first.endpoint)
            );
            assert_eq!(gateways.session_summary().endpoint, Some(first.endpoint));
            let summaries = gateways.session_summaries();
            assert_eq!(
                summaries
                    .iter()
                    .find(|summary| summary.active)
                    .unwrap()
                    .endpoint,
                Some(first.endpoint)
            );
            gateways.next_maintenance_delay();
        }
        {
            let registry = gateways.registry.lock();
            assert_eq!(registry.selected_endpoint, Some(first.endpoint));
            assert_eq!(registry.last_switch_unix_ms, switched_at);
        }
        // The next runtime refresh, not a query, responds to changed health.
        gateways.refresh_selection();
        assert_eq!(gateways.active_session().unwrap().endpoint, second.endpoint);
    }

    #[test]
    fn relay_snapshot_keeps_the_health_used_for_selection() {
        let mut registry = GatewaySessionRegistry::default();
        let first = test_session(29938);
        let second = test_session(29939);
        first.state.lock().last_rtt_ms = Some(10);
        second.state.lock().last_rtt_ms = Some(40);
        registry.install_session(first.clone());
        registry.install_session(second.clone());

        let GatewayRelaySnapshot::Automatic {
            active_endpoint,
            mut sessions,
        } = registry.refresh_relay_snapshot()
        else {
            panic!("automatic mode must return sampled candidates");
        };
        assert_eq!(active_endpoint, Some(first.endpoint));
        // Changing live health after sampling must not make retry ordering use
        // a different health view from the selection that produced this list.
        first.state.lock().last_rtt_ms = Some(50);
        second.state.lock().last_rtt_ms = Some(5);
        sessions.sort_by_cached_key(|candidate| {
            super::super::selection::gateway_summary_order_key(&candidate.summary, None)
        });
        assert_eq!(sessions[0].session.endpoint, first.endpoint);
        assert!(std::sync::Arc::ptr_eq(
            &sessions[0].session.state,
            &first.state
        ));
        assert_eq!(sessions[0].summary.rt_ms, Some(10));
        assert_eq!(sessions[1].session.endpoint, second.endpoint);
        assert!(std::sync::Arc::ptr_eq(
            &sessions[1].session.state,
            &second.state
        ));
        assert_eq!(sessions[1].summary.rt_ms, Some(40));
    }

    #[test]
    fn refresh_entry_points_reconcile_missing_pins_before_auto_selection() {
        for relay_refresh in [false, true] {
            let mut registry = GatewaySessionRegistry::default();
            let pinned = test_session(29940);
            let fallback = test_session(29941);
            registry.install_session(pinned.clone());
            registry.install_session(fallback.clone());
            registry.set_manual_endpoint(Some(pinned.endpoint)).unwrap();
            registry.remove_session(pinned.endpoint).unwrap();

            if relay_refresh {
                let GatewayRelaySnapshot::Automatic {
                    active_endpoint,
                    sessions,
                } = registry.refresh_relay_snapshot()
                else {
                    panic!("removed pin must resume automatic candidates");
                };
                assert_eq!(active_endpoint, Some(fallback.endpoint));
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0].session.endpoint, fallback.endpoint);
            } else {
                assert_eq!(registry.refresh_selection(), Some(fallback.endpoint));
            }
            assert!(registry.manual_endpoint.is_none());
            assert_eq!(registry.selected_endpoint, Some(fallback.endpoint));
        }
    }
}
