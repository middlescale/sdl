use super::*;
impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    pub(super) fn handle_refresh_gateway_grant_response(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let response = RefreshGatewayGrantResponse::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("RefreshGatewayGrantResponse {:?}", e)))?;
        if should_clear_gateway_grants_from_refresh_response(&response) {
            self.context.state.gateway.sessions.clear_gateway_grant();
            self.context
                .state
                .gateway
                .grant_policy_rev
                .store(response.gateway_policy_rev, Ordering::Relaxed);
            log::warn!(
                "gateway grant revoked by refresh response: {}",
                response.reason
            );
            return Ok(());
        }
        if !response.has_update {
            if response.result.enum_value_or_default()
                == RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_NO_CHANGE
            {
                let current_policy_rev = self
                    .context
                    .state
                    .gateway
                    .grant_policy_rev
                    .load(Ordering::Relaxed);
                if should_apply_gateway_policy_rev(current_policy_rev, response.gateway_policy_rev)
                {
                    self.context
                        .state
                        .gateway
                        .grant_policy_rev
                        .store(response.gateway_policy_rev, Ordering::Relaxed);
                }
            }
            log::info!(
                "gateway grant refresh skipped: {} (result={:?})",
                response.reason,
                response.result.enum_value_or_default()
            );
            return Ok(());
        }
        self.apply_gateway_grants(
            &response.gateway_access_grants,
            response.gateway_access_grant.as_ref(),
            response.gateway_policy_rev,
            current_device.virtual_ip,
        );
        log::info!("gateway grant refreshed for {}", current_device.virtual_ip);
        Ok(())
    }

    pub(super) fn handle_gateway_connect_ack(
        &self,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        let ack = GatewayConnectAck::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("GatewayConnectAck {:?}", e)))?;
        self.context
            .state
            .gateway
            .sessions
            .handle_connect_ack(route_key.addr, &ack);
        Ok(())
    }

    pub(super) fn apply_gateway_grants(
        &self,
        grants: &[proto::message::GatewayAccessGrant],
        legacy_grant: Option<&proto::message::GatewayAccessGrant>,
        gateway_policy_rev: u64,
        virtual_ip: Ipv4Addr,
    ) {
        let effective_grants = collect_gateway_grants(grants, legacy_grant);
        let incoming_policy_rev =
            effective_gateway_policy_rev(gateway_policy_rev, &effective_grants, legacy_grant);
        let current_policy_rev = self
            .context
            .state
            .gateway
            .grant_policy_rev
            .load(Ordering::Relaxed);
        if !should_apply_gateway_policy_rev(current_policy_rev, incoming_policy_rev) {
            log::info!(
                "ignore stale gateway grants: current_policy_rev={}, incoming_policy_rev={}",
                current_policy_rev,
                incoming_policy_rev
            );
            return;
        }
        if effective_grants.is_empty() {
            if self
                .context
                .state
                .gateway
                .sessions
                .current_grant_snapshot()
                .is_some()
            {
                self.context
                    .state
                    .gateway
                    .grant_policy_rev
                    .store(incoming_policy_rev, Ordering::Relaxed);
                log::warn!(
                    "gateway grant update omitted grants; retaining cached gateway grant policy_rev={}",
                    incoming_policy_rev
                );
                return;
            }
            self.context.state.gateway.sessions.clear_gateway_grant();
            self.context
                .state
                .gateway
                .grant_policy_rev
                .store(incoming_policy_rev, Ordering::Relaxed);
            log::info!("gateway grant cleared");
            return;
        }
        self.context.state.gateway.sessions.set_gateway_grants(
            &effective_grants,
            virtual_ip,
            self.context.config.device_id.clone(),
        );
        self.context
            .state
            .gateway
            .grant_policy_rev
            .store(incoming_policy_rev, Ordering::Relaxed);
        log::info!(
            "gateway grants applied policy_rev={} count={} gateways={:?}",
            incoming_policy_rev,
            effective_grants.len(),
            effective_grants
                .iter()
                .map(|grant| grant.gateway_id.clone())
                .collect::<Vec<_>>()
        );
    }
}

pub(super) fn observed_udp_port_from_registration(
    protocol: crate::transport::connect_protocol::ConnectProtocol,
    public_port: u16,
) -> u16 {
    if protocol.is_udp() {
        public_port
    } else {
        0
    }
}

pub(super) fn collect_gateway_grants(
    grants: &[proto::message::GatewayAccessGrant],
    legacy_grant: Option<&proto::message::GatewayAccessGrant>,
) -> Vec<proto::message::GatewayAccessGrant> {
    if !grants.is_empty() {
        return grants.to_vec();
    }
    legacy_grant.cloned().into_iter().collect()
}

pub(super) fn effective_gateway_policy_rev(
    gateway_policy_rev: u64,
    grants: &[proto::message::GatewayAccessGrant],
    legacy_grant: Option<&proto::message::GatewayAccessGrant>,
) -> u64 {
    if gateway_policy_rev != 0 {
        return gateway_policy_rev;
    }
    collect_gateway_grants(grants, legacy_grant)
        .into_iter()
        .map(|grant| grant.policy_rev)
        .max()
        .unwrap_or(0)
}

pub(super) fn is_gateway_peer_ipturn_source(
    source: Ipv4Addr,
    current_device: &CurrentDeviceInfo,
    from_gateway: bool,
) -> bool {
    from_gateway && source != current_device.virtual_gateway
}

pub(super) fn should_apply_gateway_policy_rev(
    current_policy_rev: u64,
    incoming_policy_rev: u64,
) -> bool {
    incoming_policy_rev == 0 || incoming_policy_rev >= current_policy_rev
}

pub(super) fn has_gateway_grants(
    grants: &[proto::message::GatewayAccessGrant],
    legacy_grant: Option<&proto::message::GatewayAccessGrant>,
) -> bool {
    !grants.is_empty() || legacy_grant.is_some()
}

pub(super) fn should_clear_gateway_grants_from_refresh_response(
    response: &RefreshGatewayGrantResponse,
) -> bool {
    let result = response.result.enum_value_or_default();
    if result == RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_REVOKED {
        return true;
    }
    response.has_update
        && !has_gateway_grants(
            &response.gateway_access_grants,
            response.gateway_access_grant.as_ref(),
        )
        && response
            .reason
            .trim()
            .eq_ignore_ascii_case("gateway policy cleared")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::CurrentDeviceInfo;
    use crate::proto::message::GatewayAccessGrant;
    use crate::transport::connect_protocol::ConnectProtocol;

    #[test]
    fn gateway_peer_ipturn_source_only_matches_non_gateway_peer_packets() {
        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        assert!(is_gateway_peer_ipturn_source(
            Ipv4Addr::new(10, 26, 0, 5),
            &current_device,
            true,
        ));
        assert!(!is_gateway_peer_ipturn_source(
            Ipv4Addr::new(10, 26, 0, 1),
            &current_device,
            true,
        ));
        assert!(!is_gateway_peer_ipturn_source(
            Ipv4Addr::new(10, 26, 0, 5),
            &current_device,
            false,
        ));
    }

    #[test]
    fn effective_gateway_policy_rev_prefers_message_level_value() {
        let mut grant = GatewayAccessGrant::new();
        grant.policy_rev = 7;
        assert_eq!(effective_gateway_policy_rev(11, &[grant], None), 11);
    }

    #[test]
    fn effective_gateway_policy_rev_falls_back_to_grant_policy_rev() {
        let mut grant1 = GatewayAccessGrant::new();
        grant1.policy_rev = 3;
        let mut grant2 = GatewayAccessGrant::new();
        grant2.policy_rev = 5;
        assert_eq!(effective_gateway_policy_rev(0, &[grant1, grant2], None), 5);
    }

    #[test]
    fn should_apply_gateway_policy_rev_rejects_older_policy() {
        assert!(!should_apply_gateway_policy_rev(9, 8));
        assert!(should_apply_gateway_policy_rev(9, 9));
        assert!(should_apply_gateway_policy_rev(9, 10));
    }

    #[test]
    fn observed_udp_port_from_registration_only_trusts_udp_control() {
        assert_eq!(
            observed_udp_port_from_registration(ConnectProtocol::UDP, 29901),
            29901
        );
        assert_eq!(
            observed_udp_port_from_registration(ConnectProtocol::QUIC, 443),
            0
        );
        assert_eq!(
            observed_udp_port_from_registration(ConnectProtocol::TCP, 443),
            0
        );
    }

    #[test]
    fn refresh_response_only_clears_gateway_on_revoke() {
        let mut temporary = RefreshGatewayGrantResponse::new();
        temporary.has_update = false;
        temporary.reason = "no gateway available".into();
        temporary.result =
            RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_TEMPORARILY_UNAVAILABLE.into();
        assert!(!should_clear_gateway_grants_from_refresh_response(
            &temporary
        ));

        let mut no_change = RefreshGatewayGrantResponse::new();
        no_change.has_update = false;
        no_change.reason = "gateway grant unchanged".into();
        no_change.result = RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_NO_CHANGE.into();
        assert!(!should_clear_gateway_grants_from_refresh_response(
            &no_change
        ));

        let mut revoked = RefreshGatewayGrantResponse::new();
        revoked.has_update = true;
        revoked.reason = "gateway policy cleared".into();
        revoked.result = RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_REVOKED.into();
        assert!(should_clear_gateway_grants_from_refresh_response(&revoked));
    }
}
