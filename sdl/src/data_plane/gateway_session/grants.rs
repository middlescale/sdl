//! Apply and retire the control-plane gateway grant set.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::handle::now_time;
use crate::proto::message::{GatewayAccessGrant, GatewayChannelKind};

use super::endpoint::{resolve_gateway_channel, ResolvedGatewayChannel};
use super::{GatewaySession, GatewaySessions};

impl GatewaySessions {
    pub fn set_gateway_grant(
        &self,
        grant: &GatewayAccessGrant,
        virtual_ip: Ipv4Addr,
        device_id: String,
    ) {
        self.set_gateway_grants(std::slice::from_ref(grant), virtual_ip, device_id);
    }

    pub fn set_gateway_grants(
        &self,
        grants: &[GatewayAccessGrant],
        virtual_ip: Ipv4Addr,
        device_id: String,
    ) {
        let mut parsed: Vec<(GatewayAccessGrant, ResolvedGatewayChannel)> = Vec::new();
        let mut desired = HashSet::new();
        for grant in grants {
            if let Some(channel) = grant.gateway_channel.as_ref() {
                let kind = match channel.kind.enum_value() {
                    Ok(
                        kind @ (GatewayChannelKind::GATEWAY_CHANNEL_UDP
                        | GatewayChannelKind::GATEWAY_CHANNEL_QUIC
                        | GatewayChannelKind::GATEWAY_CHANNEL_HTTPS),
                    ) => kind,
                    Ok(GatewayChannelKind::GATEWAY_CHANNEL_UNKNOWN) => {
                        log::warn!(
                            "ignore gateway channel with unspecified kind gateway_id={} addr={}",
                            grant.gateway_id,
                            channel.addr
                        );
                        continue;
                    }
                    Err(value) => {
                        log::warn!(
                            "ignore gateway channel with unknown kind gateway_id={} kind={} addr={}",
                            grant.gateway_id,
                            value,
                            channel.addr
                        );
                        continue;
                    }
                };
                if kind == GatewayChannelKind::GATEWAY_CHANNEL_UDP
                    && (channel.udp_public_key.len() != 32 || channel.udp_key_id.is_empty())
                {
                    log::warn!(
                        "ignore UDP gateway channel with invalid key metadata gateway_id={} addr={}",
                        grant.gateway_id,
                        channel.addr
                    );
                    continue;
                }
                match resolve_gateway_channel(channel) {
                    Ok(channel) if desired.insert(channel.endpoint) => {
                        parsed.push((grant.clone(), channel));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!(
                            "ignore invalid gateway channel gateway_id={} kind={:?} addr={}: {:?}",
                            grant.gateway_id,
                            kind,
                            channel.addr,
                            e
                        );
                    }
                }
            }
        }
        if parsed.is_empty() {
            self.clear_gateway_grant();
            log::info!(
                "gateway relay disabled for virtual ip {virtual_ip}: no supported gateway channel"
            );
            return;
        }
        self.refresh_requested_at_ms.store(0);
        log::info!(
            "gateway grants applied for virtual ip {} with endpoints {:?}, gateways={:?}",
            virtual_ip,
            parsed
                .iter()
                .map(|(_, channel)| channel.endpoint)
                .collect::<Vec<_>>(),
            parsed
                .iter()
                .map(|(grant, _)| grant.gateway_id.clone())
                .collect::<Vec<_>>()
        );
        let mut registry = self.registry.lock();
        let removed_endpoints = registry.endpoints_outside(&desired);
        let mut dormant = self.dormant_stream_sessions.lock();
        for endpoint in removed_endpoints {
            self.udp_rebuild_backoff.lock().remove(&endpoint);
            let Some(session) = registry.remove_session(endpoint) else {
                continue;
            };
            session.retire();
            if session.is_udp() {
                if !session.stop_udp_runtime() {
                    log::warn!(
                        "udp gateway session stop timed out; detaching endpoint={}",
                        endpoint
                    );
                }
            } else {
                dormant.insert(endpoint, session);
            }
        }
        for (grant, resolved_channel) in parsed {
            let endpoint = resolved_channel.endpoint;
            let session = if let Some(existing) = registry.session_at(endpoint) {
                if !existing.matches_kind(resolved_channel.kind) {
                    log::warn!(
                        "ignore gateway channel kind change for active endpoint={} requested_kind={:?}",
                        endpoint,
                        resolved_channel.kind
                    );
                    continue;
                }
                existing
            } else if let Some(existing) = dormant.remove(&endpoint) {
                if existing.matches_kind(resolved_channel.kind) {
                    registry.install_session(existing.clone());
                    existing
                } else {
                    log::warn!(
                        "ignore gateway channel kind change for dormant endpoint={} requested_kind={:?}",
                        endpoint,
                        resolved_channel.kind
                    );
                    dormant.insert(endpoint, existing);
                    continue;
                }
            } else {
                let created = match resolved_channel.kind {
                    GatewayChannelKind::GATEWAY_CHANNEL_UDP => {
                        match GatewaySession::new_udp(
                            endpoint,
                            &grant,
                            grant
                                .gateway_channel
                                .as_ref()
                                .expect("parsed gateway channel"),
                            self.debug_watch.clone(),
                            self.stats.clone(),
                        ) {
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
                    GatewayChannelKind::GATEWAY_CHANNEL_HTTPS => GatewaySession::new_https(
                        endpoint,
                        resolved_channel
                            .request_uri
                            .clone()
                            .unwrap_or_else(|| format!("https://{}/gateway", endpoint)),
                        resolved_channel.server_name.clone(),
                        self.debug_watch.clone(),
                        self.stats.clone(),
                    ),
                    _ => GatewaySession::new_quic(
                        endpoint,
                        self.debug_watch.clone(),
                        self.stats.clone(),
                    ),
                };
                registry.install_session(created.clone());
                created
            };
            if let Err(e) = session.update_grant(&grant, device_id.clone()) {
                log::warn!("update gateway session failed {}: {:?}", endpoint, e);
                session.retire();
                if session.is_udp() && !session.stop_udp_runtime() {
                    log::warn!(
                        "udp gateway session stop timed out after grant update failure; detaching endpoint={}",
                        endpoint
                    );
                }
                registry.remove_session(endpoint);
                continue;
            }
            if let Some((stop_manager, on_packet)) = self.runtime.get() {
                if let Err(e) = session.start(stop_manager, on_packet) {
                    log::warn!("start gateway session failed {}: {:?}", endpoint, e);
                    session.retire();
                    if session.is_udp() && !session.stop_udp_runtime() {
                        log::warn!(
                            "udp gateway session stop timed out after start failure; detaching endpoint={}",
                            endpoint
                        );
                    }
                    registry.remove_session(endpoint);
                    continue;
                }
            }
            session.reactivate();
        }
        registry.reset_selection_if_missing();
        drop(registry);
        self.peer_ingress_gateways
            .lock()
            .retain(|_, ingress| desired.contains(&ingress.endpoint));
        self.trigger_connect_now();
        self.wake_maintenance();
    }

    pub fn clear_gateway_grant(&self) {
        let mut registry = self.registry.lock();
        let mut dormant = self.dormant_stream_sessions.lock();
        self.udp_rebuild_backoff.lock().clear();
        for session in registry.take_all_sessions() {
            let endpoint = session.endpoint;
            session.retire();
            if session.is_udp() {
                if !session.stop_udp_runtime() {
                    log::warn!(
                        "udp gateway session stop timed out while clearing grants; detaching endpoint={}",
                        endpoint
                    );
                }
            } else {
                dormant.insert(endpoint, session);
            }
        }
        drop(dormant);
        registry.clear_selection();
        drop(registry);
        self.peer_ingress_gateways.lock().clear();
        self.refresh_requested_at_ms.store(0);
        self.wake_maintenance();
    }

    pub fn mark_refresh_requested(&self) {
        self.refresh_requested_at_ms.store(now_time() as i64);
    }

    pub fn last_refresh_requested_at_ms(&self) -> i64 {
        self.refresh_requested_at_ms.load()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use protobuf::EnumOrUnknown;

    use crate::core::PeerIdentity;
    use crate::handle::now_time;
    use crate::proto::message::{GatewayAccessGrant, GatewayChannel, GatewayChannelKind};
    use crate::util::StopManager;

    use super::super::{GatewaySessions, PeerIngressGateway};

    #[test]
    fn mark_refresh_requested_keeps_existing_ticket_expiry() {
        let sessions = GatewaySessions::default();
        let soft_refresh_after_unix_ms = 9_000;
        let hard_expire_unix_ms = 12_345;
        let ticket_expire_unix_ms = 12_345;
        sessions.set_gateway_grants(
            &[GatewayAccessGrant {
                gateway_id: "gw-1".into(),
                ticket: vec![1, 2, 3],
                session_id: 7,
                policy_rev: 8,
                soft_refresh_after_unix_ms,
                hard_expire_unix_ms,
                ticket_expire_unix_ms,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_QUIC),
                    addr: "quic://127.0.0.1:29900".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        sessions.mark_refresh_requested();

        let snapshot = sessions.current_grant_snapshot().expect("grant snapshot");
        assert_eq!(
            snapshot.soft_refresh_after_unix_ms,
            soft_refresh_after_unix_ms
        );
        assert_eq!(snapshot.hard_expire_unix_ms, hard_expire_unix_ms);
        assert_eq!(snapshot.ticket_expire_unix_ms, ticket_expire_unix_ms);
        assert!(sessions.last_refresh_requested_at_ms() > 0);
    }

    #[test]
    fn stream_gateway_session_is_reused_after_clear_and_readd() {
        let cases = [
            (
                GatewayChannelKind::GATEWAY_CHANNEL_QUIC,
                "quic://127.0.0.1:29941",
                "127.0.0.1:29941",
            ),
            (
                GatewayChannelKind::GATEWAY_CHANNEL_HTTPS,
                "https://127.0.0.1:444/gateway",
                "127.0.0.1:444",
            ),
        ];

        for (kind, addr, endpoint) in cases {
            let sessions = GatewaySessions::default();
            let now_ms = now_time() as i64;
            let grant = GatewayAccessGrant {
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
            };
            let endpoint = endpoint.parse().unwrap();

            sessions.set_gateway_grants(
                &[grant.clone()],
                Ipv4Addr::new(10, 26, 0, 3),
                "device-1".into(),
            );
            let original = sessions
                .session_at(endpoint)
                .expect("original stream session")
                .clone();

            sessions.clear_gateway_grant();
            assert!(!original.active.load());
            assert!(sessions.session_snapshot().sessions.is_empty());
            assert!(sessions
                .dormant_stream_sessions
                .lock()
                .contains_key(&endpoint));

            sessions.set_gateway_grants(&[grant], Ipv4Addr::new(10, 26, 0, 3), "device-1".into());
            let reused = sessions
                .session_at(endpoint)
                .expect("reused stream session")
                .clone();

            assert!(Arc::ptr_eq(&original.active, &reused.active));
            assert!(Arc::ptr_eq(&original.state, &reused.state));
            assert!(reused.active.load());
            assert!(!sessions
                .dormant_stream_sessions
                .lock()
                .contains_key(&endpoint));
        }
    }

    #[test]
    fn gateway_kind_change_for_same_endpoint_is_rejected() {
        fn stream_grant(
            gateway_id: &str,
            kind: GatewayChannelKind,
            addr: &str,
        ) -> GatewayAccessGrant {
            let now_ms = now_time() as i64;
            GatewayAccessGrant {
                gateway_id: gateway_id.into(),
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
            }
        }

        let sessions = GatewaySessions::default();
        let endpoint = "127.0.0.1:29961".parse().unwrap();
        let quic_grant = stream_grant(
            "gw-quic",
            GatewayChannelKind::GATEWAY_CHANNEL_QUIC,
            "quic://127.0.0.1:29961",
        );
        let https_grant = stream_grant(
            "gw-https",
            GatewayChannelKind::GATEWAY_CHANNEL_HTTPS,
            "https://127.0.0.1:29961/gateway",
        );

        sessions.set_gateway_grants(
            &[quic_grant],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let original = sessions
            .session_at(endpoint)
            .expect("original QUIC session")
            .clone();

        sessions.set_gateway_grants(
            &[https_grant.clone()],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let active = sessions
            .session_at(endpoint)
            .expect("original active session retained")
            .clone();
        assert!(Arc::ptr_eq(&original.state, &active.state));
        assert!(active.matches_kind(GatewayChannelKind::GATEWAY_CHANNEL_QUIC));

        sessions.clear_gateway_grant();
        sessions.set_gateway_grants(
            &[https_grant],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );

        assert!(sessions.session_snapshot().sessions.is_empty());
        let dormant = sessions
            .dormant_stream_sessions
            .lock()
            .get(&endpoint)
            .expect("original dormant session retained")
            .clone();
        assert!(Arc::ptr_eq(&original.state, &dormant.state));
        assert!(dormant.matches_kind(GatewayChannelKind::GATEWAY_CHANNEL_QUIC));
        assert!(!dormant.active.load());
    }

    #[test]
    fn removed_gateway_can_be_recreated_with_the_same_endpoint() {
        fn udp_grant(gateway_id: &str, endpoint: &str, session_id: u64) -> GatewayAccessGrant {
            let now_ms = now_time() as i64;
            GatewayAccessGrant {
                gateway_id: gateway_id.into(),
                ticket: vec![1, 2, 3],
                session_id,
                policy_rev: session_id,
                soft_refresh_after_unix_ms: now_ms + 30_000,
                hard_expire_unix_ms: now_ms + 60_000,
                ticket_expire_unix_ms: now_ms + 60_000,
                lease_secs: 30,
                grace_secs: 60,
                gateway_channel: Some(GatewayChannel {
                    kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
                    addr: format!("udp://{endpoint}"),
                    udp_public_key: [7; 32].to_vec(),
                    udp_key_id: format!("key-{session_id}"),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }

        let sessions = GatewaySessions::default();
        let stop_manager = StopManager::new(|| {});
        let endpoint_1 = "127.0.0.1:29931".parse().unwrap();
        let endpoint_2 = "127.0.0.1:29932".parse().unwrap();
        let grant_1 = udp_grant("gw-1", "127.0.0.1:29931", 1);
        let grant_2 = udp_grant("gw-2", "127.0.0.1:29932", 2);

        sessions
            .start(stop_manager.clone(), |_, _| {})
            .expect("start gateway sessions");
        sessions.set_gateway_grants(
            &[grant_1.clone()],
            Ipv4Addr::new(10, 26, 0, 3),
            "device-1".into(),
        );
        let original = sessions
            .session_at(endpoint_1)
            .expect("original gateway session")
            .clone();
        assert!(original.udp_stop_handle.lock().is_some());
        assert!(original
            .udp_stop_handle
            .lock()
            .as_ref()
            .expect("original UDP runtime")
            .runtime_active
            .load());

        sessions.set_gateway_grants(&[grant_2], Ipv4Addr::new(10, 26, 0, 3), "device-1".into());
        assert!(original.udp_stop_handle.lock().is_none());
        assert!(sessions.contains_endpoint(endpoint_2));

        sessions.set_gateway_grants(&[grant_1], Ipv4Addr::new(10, 26, 0, 3), "device-1".into());
        let recreated = sessions
            .session_at(endpoint_1)
            .expect("recreated gateway session")
            .clone();
        assert!(!Arc::ptr_eq(
            &original.udp_stop_handle,
            &recreated.udp_stop_handle
        ));
        assert!(recreated.udp_stop_handle.lock().is_some());
        assert!(recreated
            .udp_stop_handle
            .lock()
            .as_ref()
            .expect("recreated UDP runtime")
            .runtime_active
            .load());

        stop_manager.stop();
        assert!(stop_manager.wait_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn clearing_gateway_grants_clears_peer_ingress_gateways() {
        let sessions = GatewaySessions::default();
        sessions.peer_ingress_gateways.lock().insert(
            PeerIdentity::from_device_public_key(b"peer-one"),
            PeerIngressGateway {
                endpoint: "127.0.0.1:29931".parse().unwrap(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        sessions.clear_gateway_grant();

        assert!(sessions.peer_ingress_gateways.lock().is_empty());
    }
}
