use super::*;
impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    pub(super) fn handle_push_device_list(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let response = DeviceList::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("PushDeviceList {:?}", e)))?;
        let _device_list_update_guard = self.device_list_update_lock.lock();
        // Keep a recovered push from being rejected by the epoch
        // accumulated while authorization was pending.  Do not clear
        // the flag here: only RegistrationResponse clears CLI/runtime
        // auth-pending state after its authoritative snapshot commits.
        self.context.reset_peer_epoch_for_auth_pending_recovery();
        let device_list_update =
            self.prepare_device_list_update(response.device_info_list, response.epoch as _);
        self.apply_gateway_grants(
            &response.gateway_access_grants,
            None,
            response.gateway_policy_rev,
            current_device.virtual_ip,
        );
        if device_list_update.is_none() {
            log::info!(
                "skip stale push device list peer update: epoch={}",
                response.epoch
            );
        }
        let Some(device_list_update) = device_list_update else {
            return Ok(());
        };
        self.set_device_info_list(device_list_update);
        self.context.services.control_session.report_client_status();
        Ok(())
    }

    pub(super) fn prepare_device_list_update(
        &self,
        device_info_list: Vec<proto::message::DeviceInfo>,
        epoch: u16,
    ) -> Option<DeviceListUpdate> {
        let ip_list: Vec<PeerInfo> = device_info_list
            .into_iter()
            .map(PeerInfo::from_control_device)
            .collect();
        let next_devices: HashMap<Ipv4Addr, PeerInfo> = ip_list
            .iter()
            .cloned()
            .map(|peer| (peer.virtual_ip, peer))
            .collect();
        let previous_peers = {
            let previous_peers = match self
                .context
                .state
                .peers
                .replace_devices_if_fresh(epoch, next_devices)
            {
                Ok(previous_peers) => previous_peers,
                Err(current_epoch) => {
                    log::info!(
                        "ignore stale device list: current_epoch={}, incoming_epoch={}",
                        current_epoch,
                        epoch
                    );
                    return None;
                }
            };
            previous_peers
        };
        Some(DeviceListUpdate {
            previous_peers,
            ip_list,
        })
    }

    pub(super) fn set_device_info_list(&self, device_list_update: DeviceListUpdate) {
        let DeviceListUpdate {
            previous_peers,
            ip_list,
        } = device_list_update;
        let active_vips: HashSet<Ipv4Addr> = ip_list.iter().map(|peer| peer.virtual_ip).collect();
        let identity_plan = plan_peer_identity_update(&previous_peers, &ip_list);
        let previous_by_identity: HashMap<_, Ipv4Addr> = previous_peers
            .values()
            .map(|peer| (peer.identity(), peer.virtual_ip))
            .collect();
        let current_by_vip: HashMap<Ipv4Addr, _> = ip_list
            .iter()
            .map(|peer| (peer.virtual_ip, peer.identity()))
            .collect();
        let mut reset_vips: HashSet<Ipv4Addr> = previous_peers
            .keys()
            .filter(|vip| !active_vips.contains(vip))
            .copied()
            .collect();
        for (vip, previous_peer) in &previous_peers {
            if let Some(next_identity) = current_by_vip.get(vip) {
                let previous_identity = previous_peer.identity();
                if &previous_identity != next_identity {
                    reset_vips.insert(*vip);
                }
            }
        }
        for peer in &ip_list {
            let identity = peer.identity();
            if let Some(previous_vip) = previous_by_identity.get(&identity) {
                if *previous_vip != peer.virtual_ip {
                    log::info!(
                        "peer {} moved vip {} -> {}",
                        peer.device_id,
                        previous_vip,
                        peer.virtual_ip
                    );
                    reset_vips.insert(*previous_vip);
                }
            }
            if peer.preferred_channel_mode == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY
            {
                reset_vips.insert(peer.virtual_ip);
            }
        }
        for vip in &reset_vips {
            self.context.services.route_manager.clear_peer(vip);
        }
        self.context
            .services
            .route_manager
            .retain_peers(&active_vips);
        self.context
            .state
            .peers
            .nat_info_map
            .write()
            .retain(|vip, _| active_vips.contains(vip) && !reset_vips.contains(vip));
        let mut peer_session_ciphers = std::collections::HashMap::with_capacity(ip_list.len());
        let local_online_session_key = self.context.state.peers.crypto.online_session_key();
        for peer_info in &ip_list {
            let Some(local_online_session_key) = local_online_session_key.as_ref() else {
                log::warn!("missing local online session key, skip deriving peer session ciphers");
                break;
            };
            match crate::util::derive_peer_session_key(
                local_online_session_key,
                &peer_info.online_kx_pub,
                &self.context.config.token,
            )
            .and_then(crate::cipher::Cipher::new_key)
            {
                Ok(cipher) => {
                    peer_session_ciphers.insert(peer_info.identity(), cipher);
                }
                Err(err) => {
                    log::warn!(
                        "derive peer session cipher failed peer={} device_id={} err={:?}",
                        peer_info.virtual_ip,
                        peer_info.device_id,
                        err
                    );
                }
            }
        }
        self.context
            .state
            .peers
            .crypto
            .rotate_peer_session_ciphers(peer_session_ciphers);
        self.context
            .state
            .peers
            .crypto
            .retain_peers(&identity_plan.active_identities);
        self.context
            .state
            .gateway
            .sessions
            .retain_peer_ingress_gateways(&identity_plan.active_identities);
        self.context
            .state
            .peers
            .crypto
            .clear_previous_ciphers_for(&identity_plan.reset_identities);
        self.context.apply_selected_exit_node_route();
        self.callback.peer_client_list(
            ip_list
                .into_iter()
                .map(|peer_info| {
                    PeerClientInfo::new(peer_info.virtual_ip, peer_info.name, peer_info.status)
                })
                .collect(),
        );
    }
}

#[cfg(test)]
pub(super) fn is_stale_epoch(current_epoch: u16, incoming_epoch: u16) -> bool {
    if current_epoch == 0 || current_epoch == incoming_epoch {
        return false;
    }
    current_epoch.wrapping_sub(incoming_epoch) < (u16::MAX / 2)
}

#[cfg(test)]
pub(super) fn try_commit_device_list_state(
    peer_table: &mut crate::core::PeerTable,
    epoch: u16,
    next_devices: HashMap<Ipv4Addr, PeerInfo>,
) -> Option<HashMap<Ipv4Addr, PeerInfo>> {
    if is_stale_epoch(peer_table.epoch(), epoch) {
        return None;
    }
    Some(peer_table.replace_devices(epoch, next_devices))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::recv_data::server::test_util::test_peer;
    use crate::proto::message::ChannelMode;

    #[test]
    fn peer_identity_plan_tracks_same_vip_public_key_change() {
        let vip = Ipv4Addr::new(10, 26, 0, 4);
        let old_peer = test_peer(vip, 1, ChannelMode::CHANNEL_MODE_AUTO);
        let new_peer = test_peer(vip, 2, ChannelMode::CHANNEL_MODE_AUTO);
        let previous = HashMap::from([(vip, old_peer.clone())]);

        let plan = plan_peer_identity_update(&previous, &[new_peer.clone()]);

        assert!(plan.active_identities.contains(&new_peer.identity()));
        assert!(!plan.active_identities.contains(&old_peer.identity()));
        assert!(plan.reset_identities.contains(&old_peer.identity()));
    }

    #[test]
    fn peer_identity_plan_clears_grace_cipher_for_relay_only_peer() {
        let vip = Ipv4Addr::new(10, 26, 0, 5);
        let peer = test_peer(vip, 3, ChannelMode::CHANNEL_MODE_RELAY);
        let previous = HashMap::from([(vip, peer.clone())]);

        let plan = plan_peer_identity_update(&previous, &[peer.clone()]);

        assert!(plan.active_identities.contains(&peer.identity()));
        assert!(plan.reset_identities.contains(&peer.identity()));
    }

    #[test]
    fn is_stale_epoch_accepts_zero_and_same_epoch() {
        assert!(!is_stale_epoch(0, 10));
        assert!(!is_stale_epoch(10, 10));
    }

    #[test]
    fn is_stale_epoch_rejects_older_epoch_without_wrap() {
        assert!(is_stale_epoch(83, 63));
        assert!(!is_stale_epoch(63, 83));
    }

    fn peer(vip: Ipv4Addr, seed: u8) -> PeerInfo {
        PeerInfo::new(
            vip,
            format!("peer-{seed}"),
            0,
            format!("peer-{seed}"),
            vec![seed],
            vec![seed + 1],
            ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        )
    }

    #[test]
    fn try_commit_device_list_state_rejects_stale_without_overwriting_state() {
        let existing_peer = peer(Ipv4Addr::new(10, 26, 0, 3), 1);
        let mut peer_table = crate::core::PeerTable::new(
            83,
            HashMap::from([(existing_peer.virtual_ip, existing_peer.clone())]),
        );
        let next_peer = peer(Ipv4Addr::new(10, 26, 0, 4), 3);

        let previous = try_commit_device_list_state(
            &mut peer_table,
            63,
            HashMap::from([(next_peer.virtual_ip, next_peer)]),
        );

        assert!(previous.is_none());
        assert_eq!(peer_table.epoch(), 83);
        assert_eq!(peer_table.len(), 1);
        assert_eq!(
            peer_table.get(&existing_peer.virtual_ip),
            Some(&existing_peer)
        );
    }

    #[test]
    fn try_commit_device_list_state_updates_epoch_and_returns_previous_peers() {
        let existing_peer = peer(Ipv4Addr::new(10, 26, 0, 3), 1);
        let next_peer = peer(Ipv4Addr::new(10, 26, 0, 4), 3);
        let mut peer_table = crate::core::PeerTable::new(
            63,
            HashMap::from([(existing_peer.virtual_ip, existing_peer.clone())]),
        );

        let previous = try_commit_device_list_state(
            &mut peer_table,
            83,
            HashMap::from([(next_peer.virtual_ip, next_peer.clone())]),
        )
        .expect("fresh epoch should commit");

        assert_eq!(previous.len(), 1);
        assert_eq!(
            previous.get(&existing_peer.virtual_ip),
            Some(&existing_peer)
        );
        assert_eq!(peer_table.epoch(), 83);
        assert_eq!(peer_table.len(), 1);
        assert_eq!(peer_table.get(&next_peer.virtual_ip), Some(&next_peer));
        assert_eq!(
            peer_table.vip_for_identity(&next_peer.identity()),
            Some(next_peer.virtual_ip)
        );
        assert_eq!(peer_table.vip_for_identity(&existing_peer.identity()), None);
    }
}

pub(super) fn plan_peer_identity_update(
    previous_peers: &HashMap<Ipv4Addr, PeerInfo>,
    ip_list: &[PeerInfo],
) -> PeerIdentityPlan {
    let active_identities: HashSet<_> = ip_list.iter().map(PeerInfo::identity).collect();
    let current_by_vip: HashMap<Ipv4Addr, _> = ip_list
        .iter()
        .map(|peer| (peer.virtual_ip, peer.identity()))
        .collect();
    let mut reset_identities = HashSet::new();
    for (vip, previous_peer) in previous_peers {
        if let Some(next_identity) = current_by_vip.get(vip) {
            let previous_identity = previous_peer.identity();
            if &previous_identity != next_identity {
                reset_identities.insert(previous_identity);
            }
        }
    }
    for peer in ip_list {
        if peer.preferred_channel_mode == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY {
            reset_identities.insert(peer.identity());
        }
    }
    PeerIdentityPlan {
        active_identities,
        reset_identities,
    }
}
