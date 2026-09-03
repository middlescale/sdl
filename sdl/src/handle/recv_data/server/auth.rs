use super::*;
impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    pub(super) fn handle_device_auth_ack(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        let ack = DeviceAuthAck::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("DeviceAuthAck {:?}", e)))?;
        if !ack.ok {
            let error_reason = ack.error_reason.enum_value_or_default();
            let error_type = if device_auth_error_is_auth_pending(error_reason, &ack.reason) {
                ErrorType::AuthPending
            } else {
                ErrorType::Unknown
            };
            println!("auth device failed: {}", ack.reason);
            self.callback.error(ErrorInfo::new_msg(
                error_type,
                format!("auth device failed: {}", ack.reason),
            ));
            if should_retry_device_auth_after_challenge_expired(error_reason, &ack.reason) {
                match self
                    .context
                    .services
                    .control_session
                    .try_retry_device_auth_after_challenge_expired()
                {
                    Ok(true) => {
                        log::warn!(
                                    "device auth challenge expired, retrying auth request with cooldown: route={:?}, reason={}",
                                    route_key,
                                    ack.reason
                                );
                    }
                    Ok(false) => {
                        log::debug!(
                            "device auth retry suppressed by cooldown: route={:?}, reason={}",
                            route_key,
                            ack.reason
                        );
                    }
                    Err(err) => {
                        log::warn!(
                            "device auth retry after challenge_expired failed: {:?}",
                            err
                        );
                    }
                }
            }
            return Ok(());
        }
        self.device_auth_ok.store(true);
        println!(
            "auth device success: user={} group={} device={}",
            ack.user_id, ack.group, ack.device_id
        );
        self.callback.success();
        self.register(current_device, route_key, true)?;
        Ok(())
    }

    pub(super) fn handle_device_auth_challenge(
        &self,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let challenge = DeviceAuthChallenge::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("DeviceAuthChallenge {:?}", e)))?;
        self.context
            .services
            .control_session
            .send_device_auth_proof(&challenge)?;
        Ok(())
    }

    pub(super) fn handle_device_rename_response(
        &self,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let response = DeviceRenameResponse::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("DeviceRenameResponse {:?}", e)))?;
        let result = if response.ok {
            if response.pending_approval {
                Ok(crate::core::RenameRequestOutcome::RestartRequired(
                    response.applied_name.clone(),
                ))
            } else {
                Ok(crate::core::RenameRequestOutcome::Applied(
                    response.applied_name.clone(),
                ))
            }
        } else {
            Err(response.reason.clone())
        };
        let rename_completed = self
            .context
            .state
            .pending_rename_requests
            .take(response.request_id)
            .map(|request| {
                let _ = request.responder.send(result);
            })
            .is_some();
        if !rename_completed {
            if response.ok && !response.pending_approval && !response.applied_name.is_empty() {
                log::info!(
                    "apply async device rename request_id={} applied_name={}",
                    response.request_id,
                    response.applied_name
                );
                self.callback.device_renamed(response.applied_name.clone());
            } else {
                log::debug!(
                    "drop rename response for unknown request_id={}",
                    response.request_id
                );
            }
        }
        Ok(())
    }
}

pub(super) fn should_retry_device_auth_after_challenge_expired(
    error_reason: DeviceAuthErrorReason,
    reason: &str,
) -> bool {
    if error_reason == DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED {
        return true;
    }
    reason.trim().eq_ignore_ascii_case("challenge_expired")
}

pub(super) fn device_auth_error_is_auth_pending(
    error_reason: DeviceAuthErrorReason,
    reason: &str,
) -> bool {
    match error_reason {
        DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_AUTH_CHECK_FAILED
        | DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_DEVICE_KEY_MISMATCH => true,
        DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_UNSPECIFIED => {
            let reason = reason.trim().to_ascii_lowercase();
            reason.contains("auth check failed")
                || reason.contains("not_auth")
                || reason.contains("auth_expired")
                || reason.contains("reauth_required")
                || reason.contains("device_key_mismatch")
        }
        DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED
        | DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_INVALID_SIGNATURE => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_auth_retries_only_for_challenge_expired() {
        assert!(should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED,
            "challenge_expired"
        ));
        assert!(should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_UNSPECIFIED,
            " CHALLENGE_EXPIRED "
        ));
        assert!(!should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_DEVICE_KEY_MISMATCH,
            "device_key_mismatch"
        ));
        assert!(!should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_INVALID_SIGNATURE,
            "invalid_signature"
        ));
    }

    #[test]
    fn device_auth_pending_errors_are_auth_pending() {
        assert!(device_auth_error_is_auth_pending(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_AUTH_CHECK_FAILED,
            "not_auth"
        ));
        assert!(device_auth_error_is_auth_pending(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_DEVICE_KEY_MISMATCH,
            "device_key_mismatch"
        ));
        assert!(device_auth_error_is_auth_pending(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_UNSPECIFIED,
            "reauth_required"
        ));
        assert!(!device_auth_error_is_auth_pending(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED,
            "challenge_expired"
        ));
        assert!(!device_auth_error_is_auth_pending(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_INVALID_SIGNATURE,
            "invalid_signature"
        ));
    }
}
