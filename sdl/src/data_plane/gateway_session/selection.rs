//! Manual pinning and automatic active-gateway selection.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::handle::now_time;

use super::{
    GatewayGrantPhase, GatewaySession, GatewaySessionSummary, GatewaySessions,
    GATEWAY_SWITCH_BETTER_RT_MS, GATEWAY_SWITCH_COOLDOWN_MS,
};

impl GatewaySessions {
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
        drop(selection);
        drop(sessions);
        self.trigger_connect_now();
        self.wake_maintenance();
        Ok(())
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
                !summary.authenticated,
                summary.rt_ms.unwrap_or(i64::MAX),
                summary.gateway_id.clone(),
                summary.channel_name.clone(),
            )
        });
        summaries
    }

    pub(super) fn reset_selection_if_missing(
        &self,
        sessions: &HashMap<SocketAddr, GatewaySession>,
    ) {
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

    pub(super) fn choose_active_endpoint_locked(
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
                } else if !current_summary.authenticated
                    || (best_summary.authenticated
                        && gateway_summary_is_clearly_better(&best_summary, &current_summary)
                        && now_ms - selection.last_switch_unix_ms >= GATEWAY_SWITCH_COOLDOWN_MS)
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

pub(super) fn gateway_summary_sort_key(
    summary: &GatewaySessionSummary,
) -> (
    bool,
    u8,
    std::cmp::Reverse<i64>,
    bool,
    std::cmp::Reverse<String>,
) {
    (
        summary.authenticated,
        gateway_grant_phase_rank(summary.grant_phase),
        std::cmp::Reverse(summary.rt_ms.unwrap_or(i64::MAX)),
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

pub(super) fn gateway_session_order_key(
    session: &GatewaySession,
    active: Option<SocketAddr>,
) -> (bool, bool, std::cmp::Reverse<u8>, i64, String) {
    let summary = session.summary();
    (
        Some(session.endpoint) != active,
        !summary.authenticated,
        std::cmp::Reverse(gateway_grant_phase_rank(summary.grant_phase)),
        summary.rt_ms.unwrap_or(i64::MAX),
        summary.gateway_id,
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

    use protobuf::EnumOrUnknown;

    use crate::handle::now_time;
    use crate::proto::message::{GatewayAccessGrant, GatewayChannel, GatewayChannelKind};

    use super::super::GatewaySessions;
    use super::gateway_session_order_key;

    #[test]
    fn gateway_session_order_key_prefers_active_grants() {
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

        let guard = sessions.sessions.lock();
        let active = guard
            .get(&"127.0.0.1:29910".parse().unwrap())
            .expect("active session")
            .clone();
        let expired = guard
            .get(&"127.0.0.1:29911".parse().unwrap())
            .expect("expired session")
            .clone();
        drop(guard);

        assert!(
            gateway_session_order_key(&active, None) < gateway_session_order_key(&expired, None)
        );
    }
}
