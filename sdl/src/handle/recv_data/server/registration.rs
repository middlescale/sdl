use super::gateway::{has_gateway_grants, observed_udp_port_from_registration};
use super::*;
impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    pub(super) fn handle_registration_response(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        let response = RegistrationResponse::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("RegistrationResponse {:?}", e)))?;
        if response.error_code != 0 {
            let reason = if response.error_message.is_empty() {
                "registration rejected by control".to_string()
            } else {
                response.error_message.clone()
            };
            let error_reason = response.error_reason.enum_value_or_default();
            let error_type = if registration_error_is_auth_pending(error_reason, &reason) {
                ErrorType::AuthPending
            } else {
                ErrorType::Unknown
            };
            self.callback.error(ErrorInfo::new_msg(
                error_type,
                format!(
                    "registration rejected: code={}, reason={}",
                    response.error_code, reason
                ),
            ));
            if should_retry_registration_with_fresh_handshake(
                response.error_code,
                error_reason,
                &reason,
            ) {
                match self
                    .context
                    .services
                    .control_session
                    .try_send_registration_reject_recovery_handshake()
                {
                    Ok(true) => {
                        log::warn!(
                                    "registration rejected due to stale/missing handshake state, requesting fresh handshake before retry: code={}, route={:?}, reason={}",
                                    response.error_code,
                                    route_key,
                                    reason
                                );
                    }
                    Ok(false) => {
                        log::debug!(
                                    "registration reject recovery handshake suppressed by cooldown: code={}, route={:?}, reason={}",
                                    response.error_code,
                                    route_key,
                                    reason
                                );
                    }
                    Err(err) => {
                        log::warn!(
                            "fresh handshake request after registration reject failed: {:?}",
                            err
                        );
                    }
                }
            }
            return Ok(());
        }
        let virtual_ip = Ipv4Addr::from(response.virtual_ip);
        let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);
        let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
        #[cfg_attr(feature = "integrated_tun", allow(unused_variables))]
        let virtual_network = Ipv4Addr::from(response.virtual_ip & response.virtual_netmask);
        let register_info = RegisterInfo::new(virtual_ip, virtual_netmask, virtual_gateway);
        log::info!("注册成功：{:?}", register_info);
        let _device_list_update_guard = self.device_list_update_lock.lock();
        let recovering_from_auth_pending =
            self.context.reset_peer_epoch_for_auth_pending_recovery();
        let Some(device_list_update) =
            self.prepare_device_list_update(response.device_info_list.clone(), response.epoch as _)
        else {
            log::info!(
                "ignore stale registration response: virtual_ip={}, epoch={}",
                virtual_ip,
                response.epoch
            );
            return Ok(());
        };
        self.apply_gateway_grants(
            &response.gateway_access_grants,
            response.gateway_access_grant.as_ref(),
            response.gateway_policy_rev,
            virtual_ip,
        );
        let dns_profile = response.dns_profile.as_ref().map(|profile| DnsProfile {
            servers: profile.servers.clone(),
            match_domains: profile.match_domains.clone(),
            peer_name_domain: profile.peer_name_domain.clone(),
        });
        if self.callback.register(register_info) {
            let route = Route::from_default_rt(route_key, 1);
            self.context
                .services
                .route_manager
                .add_path_if_absent(virtual_gateway, route);
            let public_ip = response.public_ip.into();
            let public_port = response.public_port as u16;
            let observed_udp_port =
                observed_udp_port_from_registration(route_key.protocol(), public_port);
            // For QUIC/TCP control, the observed remote port belongs to the control-plane
            // connection, not the data-plane UDP socket used for punching.
            self.context
                .services
                .nat_test
                .update_addr(public_ip, observed_udp_port);
            let old = current_device;
            let dns_changed = self.context.state.dns.replace_profile(dns_profile);
            let vip_changed = old.virtual_ip != virtual_ip
                || old.virtual_gateway != virtual_gateway
                || old.virtual_netmask != virtual_netmask;
            let mut cur = *current_device;
            loop {
                let mut new_current_device = cur;
                new_current_device.update(virtual_ip, virtual_netmask, virtual_gateway);
                new_current_device.virtual_ip = virtual_ip;
                new_current_device.virtual_netmask = virtual_netmask;
                new_current_device.virtual_gateway = virtual_gateway;
                new_current_device.status = ConnectStatus::Connected;
                if let Err(c) = self
                    .context
                    .state
                    .current_device
                    .compare_exchange(cur, new_current_device)
                {
                    cur = c;
                } else {
                    break;
                }
            }
            self.context.state.gateway.sessions.trigger_connect_now();

            if vip_changed || dns_changed {
                if old.virtual_ip != Ipv4Addr::UNSPECIFIED {
                    log::info!("ip发生变化,old:{:?},response={:?}", old, response);
                }
                #[cfg(not(feature = "integrated_tun"))]
                {
                    let device_config = crate::handle::callback::DeviceConfig::new(
                        #[cfg(any(
                            target_os = "windows",
                            target_os = "linux",
                            target_os = "macos"
                        ))]
                        self.context.config.device_name.clone(),
                        self.context.config.mtu,
                        virtual_ip,
                        virtual_netmask,
                        virtual_gateway,
                        virtual_network,
                    );
                    self.callback.create_device(device_config);
                }
                #[cfg(feature = "integrated_tun")]
                {
                    if let Err(e) = self.context.sync_tun_with_current_device(&self.callback) {
                        log::error!("{:?}", e);
                        self.callback.error(ErrorInfo::new_msg(
                            ErrorType::FailedToCreateDevice,
                            format!("{:?}", e),
                        ));
                    }
                }
            } else if old.status.offline() {
                #[cfg(feature = "integrated_tun")]
                self.context.force_apply_dns_profile(&self.callback);
            }
            self.set_device_info_list(device_list_update);
            if recovering_from_auth_pending {
                self.context.finish_auth_pending_recovery();
            }
            if vip_changed {
                // apply_gateway_grants() may have kicked the gateway session while
                // current_device still held the old/unspecified VIP; trigger again
                // only when the virtual addressing actually changed so wake/reconnect
                // paths use the committed VIP without adding an extra round for
                // unchanged registrations.
                self.context.state.gateway.sessions.trigger_connect_now();
            }
            self.context
                .services
                .control_session
                .request_punch_status_report_with_nat_ready(if old.status.offline() {
                    crate::proto::message::PunchTriggerReason::PunchTriggerReconnectRecovery
                } else {
                    crate::proto::message::PunchTriggerReason::PunchTriggerStatusUpdate
                });
            if should_refresh_gateway_grant_after_registration(
                old.status.offline(),
                has_gateway_grants(
                    &response.gateway_access_grants,
                    response.gateway_access_grant.as_ref(),
                ),
            ) {
                match self
                    .context
                    .services
                    .control_session
                    .send_refresh_gateway_grant_request(&self.context.state.gateway.sessions, false)
                {
                    Ok(_) => {
                        log::info!(
                                    "registration recovered from offline without gateway grant, requested dedicated gateway grant refresh"
                                );
                    }
                    Err(e) => {
                        log::warn!(
                                    "registration recovered from offline but gateway grant refresh failed: {:?}",
                                    e
                                );
                    }
                }
            }
            if old.status.offline() {
                self.callback.success();
            }
        }
        Ok(())
    }
}

pub(super) fn should_refresh_gateway_grant_after_registration(
    was_offline: bool,
    registration_has_gateway_grant: bool,
) -> bool {
    was_offline && !registration_has_gateway_grant
}

pub(super) fn should_retry_registration_with_fresh_handshake(
    error_code: u32,
    error_reason: RegistrationErrorReason,
    reason: &str,
) -> bool {
    if error_reason
        == RegistrationErrorReason::REGISTRATION_ERROR_REASON_MISSING_HANDSHAKE_CAPABILITY
    {
        return true;
    }
    if error_code == 0 {
        return false;
    }
    reason
        .trim()
        .to_ascii_lowercase()
        .contains("missing required handshake capability")
}

pub(super) fn registration_error_is_auth_pending(
    error_reason: RegistrationErrorReason,
    reason: &str,
) -> bool {
    if error_reason == RegistrationErrorReason::REGISTRATION_ERROR_REASON_NOT_AUTHED {
        return true;
    }
    let reason = reason.trim().to_ascii_lowercase();
    reason.contains("auth check failed")
        || reason.contains("not_auth")
        || reason.contains("auth_expired")
        || reason.contains("reauth_required")
        || reason.contains("device_key_mismatch")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_gateway_grant_after_registration_only_for_offline_recovery_without_grant() {
        assert!(should_refresh_gateway_grant_after_registration(true, false));
        assert!(!should_refresh_gateway_grant_after_registration(true, true));
        assert!(!should_refresh_gateway_grant_after_registration(
            false, false
        ));
    }

    #[test]
    fn registration_reject_retries_only_for_stale_handshake_state() {
        assert!(should_retry_registration_with_fresh_handshake(
            1999,
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_MISSING_HANDSHAKE_CAPABILITY,
            "client 203.0.113.10:443 missing required handshake capability \"udp_endpoint_report_v1\""
        ));
        assert!(!should_retry_registration_with_fresh_handshake(
            1002,
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_NOT_AUTHED,
            "device auth check failed"
        ));
        assert!(!should_retry_registration_with_fresh_handshake(
            1999,
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_INTERNAL,
            "address exhausted"
        ));
    }

    #[test]
    fn registration_auth_errors_are_auth_pending() {
        assert!(registration_error_is_auth_pending(
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_NOT_AUTHED,
            "device auth check failed"
        ));
        assert!(registration_error_is_auth_pending(
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_UNSPECIFIED,
            "auth_expired"
        ));
        assert!(!registration_error_is_auth_pending(
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_INTERNAL,
            "address exhausted"
        ));
    }
}
