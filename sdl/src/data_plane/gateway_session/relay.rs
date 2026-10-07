//! Relay delivery, learned ingress gateways, and peer health probes.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use crate::core::PeerIdentity;
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route::RouteKey;
use crate::handle::now_time;
use crate::proto::message::GatewayConnectAck;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{NetPacket, Protocol, MAX_TTL};

use super::{
    GatewaySession, GatewaySessions, PeerIngressGateway, PeerRelayHealthSummary,
    PEER_INGRESS_GATEWAY_TTL, PEER_RELAY_PROBE_INTERVAL_MS,
};

impl GatewaySessions {
    /// Records the gateway that most recently delivered relay traffic for a peer.
    ///
    /// This is only a relay fallback hint. Measured P2P routes remain preferred by
    /// `SdlRuntime`, and the hint expires so a peer can move to another gateway.
    pub fn remember_peer_ingress_gateway(&self, peer: PeerIdentity, endpoint: SocketAddr) {
        if !self.contains_endpoint(endpoint) {
            return;
        }
        self.peer_ingress_gateways.lock().insert(
            peer,
            PeerIngressGateway {
                endpoint,
                expires_at: Instant::now() + PEER_INGRESS_GATEWAY_TTL,
            },
        );
    }

    pub fn retain_peer_ingress_gateways(&self, active_peers: &HashSet<PeerIdentity>) {
        self.peer_ingress_gateways.lock().retain(|peer, ingress| {
            active_peers.contains(peer) && ingress.expires_at > Instant::now()
        });
    }

    pub(super) fn peer_ingress_gateway(&self, peer: &PeerIdentity) -> Option<SocketAddr> {
        let mut ingress_gateways = self.peer_ingress_gateways.lock();
        let ingress = ingress_gateways.get(peer).copied()?;
        if ingress.expires_at <= Instant::now() {
            ingress_gateways.remove(peer);
            return None;
        }
        Some(ingress.endpoint)
    }

    pub(super) fn relay_session_at(&self, endpoint: SocketAddr) -> Option<GatewaySession> {
        let session = self.session_at(endpoint)?;
        session.is_relay_available().then_some(session)
    }

    pub(super) fn peer_ingress_session(&self, peer: &PeerIdentity) -> Option<GatewaySession> {
        self.peer_ingress_gateway(peer)
            .and_then(|endpoint| self.relay_session_at(endpoint))
    }

    pub fn send_relay_to<B: AsRef<[u8]>>(
        &self,
        endpoint: SocketAddr,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        let session = self.session_at(endpoint).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "requested gateway session is unavailable",
            )
        })?;
        session.send_relay(packet)
    }

    /// Sends a reply through the gateway that delivered the request when it is
    /// still usable; otherwise falls back to normal active-gateway selection.
    ///
    /// A send failure from a usable preferred session is returned directly. Retrying
    /// through another gateway at that point could duplicate a packet already handed
    /// to the transport.
    pub fn send_relay_to_or_active<B: AsRef<[u8]>>(
        &self,
        endpoint: SocketAddr,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(session) = self.relay_session_at(endpoint) {
            return session.send_relay(packet);
        }
        self.send_relay(packet)
    }

    pub fn send_relay_for_peer<B: AsRef<[u8]>>(
        &self,
        peer: Option<&PeerIdentity>,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(session) = peer.and_then(|peer| self.peer_ingress_session(peer)) {
            return session.send_relay(packet);
        }
        self.send_relay(packet)
    }

    pub fn send_relay<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        let sessions = self.relay_candidates();
        let mut last_err = None;
        for session in sessions {
            match session.send_relay(packet) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                    log::debug!(
                        "gateway relay send skipped endpoint={}: {}",
                        session.endpoint,
                        e
                    );
                    last_err = Some(e);
                }
                Err(e) => {
                    log::warn!(
                        "gateway relay send failed endpoint={}: {:?}",
                        session.endpoint,
                        e
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no available gateway session")
        }))
    }

    pub fn handle_connect_ack(&self, from: SocketAddr, ack: &GatewayConnectAck) {
        // session_at returns an owned handle and releases the registry lock;
        // authentication/channel updates and backoff locking happen outside it.
        if let Some(session) = self.session_at(from) {
            session.handle_connect_ack(ack);
            if ack.ok {
                self.udp_rebuild_backoff.lock().remove(&from);
            }
            // Authentication changes are runtime events, not status reads.
            self.refresh_selection();
            self.wake_maintenance();
        } else {
            log::debug!(
                "received gateway connect ack from unknown endpoint={} session_id={} ok={} reason={}",
                from,
                ack.session_id,
                ack.ok,
                ack.reason
            );
        }
    }

    /// Best-effort, rate-limited end-to-end health probe for a peer relay path.
    ///
    /// This is called immediately before normal payload is relayed to `peer_ip`.
    /// When a current peer cipher is available, it emits an encrypted control
    /// Ping through that peer's ingress gateway (or the active gateway fallback)
    /// at most once per [`PEER_RELAY_PROBE_INTERVAL_MS`]. The matching Pong is
    /// consumed by [`Self::handle_peer_relay_probe_pong`] and updates the peer's
    /// relay-health summary.
    ///
    /// Probe construction, encryption, or sending failures are intentionally
    /// non-fatal: they are diagnostic signals and must not prevent the payload
    /// relay attempt that follows this call.
    pub fn maybe_send_peer_relay_probe(
        &self,
        peer_ip: Ipv4Addr,
        peer_identity: Option<&PeerIdentity>,
        peer_crypto: &PeerCryptoManager,
    ) {
        let Some(peer_identity) = peer_identity else {
            return;
        };
        let now_ms = now_time() as i64;
        let epoch = {
            let mut probes = self.peer_relay_probes.lock();
            let probe = probes.entry(peer_ip).or_default();
            if now_ms - probe.last_sent_unix_ms < PEER_RELAY_PROBE_INTERVAL_MS {
                return;
            }
            if probe.last_sent_unix_ms > probe.last_reply_unix_ms {
                probe.consecutive_failures = probe.consecutive_failures.saturating_add(1);
            }
            probe.last_sent_unix_ms = now_ms;
            probe.epoch = probe.epoch.wrapping_add(1).max(1);
            probe.epoch
        };
        let Some(cipher) = peer_crypto.current_cipher(peer_identity).ok() else {
            return;
        };
        let current = self.current_device.load();
        let mut packet = match NetPacket::new_encrypt(vec![0u8; 12 + 4 + ENCRYPTION_RESERVED]) {
            Ok(packet) => packet,
            Err(err) => {
                log::debug!(
                    "failed to create relay peer probe for {}: {:?}",
                    peer_ip,
                    err
                );
                return;
            }
        };
        packet.set_default_version();
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
        packet.set_initial_ttl(MAX_TTL);
        packet.set_source(current.virtual_ip);
        packet.set_destination(peer_ip);
        if let Ok(mut ping) = PingPacket::new(packet.payload_mut()) {
            ping.set_time(now_time() as u16);
            ping.set_epoch(epoch);
        } else {
            return;
        }
        if let Err(err) = cipher.encrypt_ipv4(&mut packet) {
            log::debug!(
                "failed to encrypt relay peer probe for {}: {:?}",
                peer_ip,
                err
            );
            return;
        }
        if let Err(err) = self.send_relay_for_peer(Some(peer_identity), &packet) {
            log::debug!("failed to send relay peer probe for {}: {:?}", peer_ip, err);
        }
    }

    pub fn handle_peer_relay_probe_pong(
        &self,
        peer_ip: Ipv4Addr,
        route_key: RouteKey,
        epoch: u16,
    ) -> bool {
        if !self.is_gateway_addr(route_key.addr) {
            return false;
        }
        let mut probes = self.peer_relay_probes.lock();
        let Some(probe) = probes.get_mut(&peer_ip) else {
            return false;
        };
        if probe.epoch != epoch {
            return false;
        }
        probe.last_reply_unix_ms = now_time() as i64;
        probe.consecutive_failures = 0;
        true
    }

    pub fn observe_peer_relay_receive(&self, peer_ip: Ipv4Addr, route_key: RouteKey) {
        if self.is_gateway_addr(route_key.addr) {
            self.peer_relay_receives
                .lock()
                .insert(peer_ip, now_time() as i64);
        }
    }

    pub fn peer_relay_health_summary(&self, peer_ip: Ipv4Addr) -> PeerRelayHealthSummary {
        let probe = self
            .peer_relay_probes
            .lock()
            .get(&peer_ip)
            .copied()
            .unwrap_or_default();
        PeerRelayHealthSummary {
            last_relay_receive_unix_ms: self
                .peer_relay_receives
                .lock()
                .get(&peer_ip)
                .copied()
                .unwrap_or_default(),
            last_probe_unix_ms: probe.last_reply_unix_ms,
            consecutive_probe_failures: probe.consecutive_failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use protobuf::EnumOrUnknown;

    use crate::core::PeerIdentity;
    use crate::data_plane::stats::DataPlaneStats;
    use crate::handle::now_time;
    use crate::proto::message::{GatewayAccessGrant, GatewayChannel, GatewayChannelKind};
    use crate::util::DebugWatch;

    use super::super::{GatewaySession, GatewaySessions, PeerIngressGateway};

    #[test]
    fn peer_ingress_gateway_expiry_is_reclaimed() {
        let sessions = GatewaySessions::default();
        let peer = PeerIdentity::from_device_public_key(b"peer-one");
        let endpoint = "127.0.0.1:29931".parse().unwrap();
        sessions.peer_ingress_gateways.lock().insert(
            peer.clone(),
            PeerIngressGateway {
                endpoint,
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        assert_eq!(sessions.peer_ingress_gateway(&peer), None);
        assert!(sessions.peer_ingress_gateways.lock().is_empty());
    }

    #[test]
    fn peer_ingress_gateways_are_pruned_with_peer_list() {
        let sessions = GatewaySessions::default();
        let retained = PeerIdentity::from_device_public_key(b"peer-retained");
        let removed = PeerIdentity::from_device_public_key(b"peer-removed");
        let endpoint = "127.0.0.1:29931".parse().unwrap();
        let expires_at = Instant::now() + Duration::from_secs(60);
        let mut ingress = sessions.peer_ingress_gateways.lock();
        ingress.insert(
            retained.clone(),
            PeerIngressGateway {
                endpoint,
                expires_at,
            },
        );
        ingress.insert(
            removed.clone(),
            PeerIngressGateway {
                endpoint,
                expires_at,
            },
        );
        drop(ingress);

        sessions.retain_peer_ingress_gateways(&std::collections::HashSet::from([retained]));

        assert!(sessions
            .peer_ingress_gateways
            .lock()
            .contains_key(&PeerIdentity::from_device_public_key(b"peer-retained")));
        assert!(!sessions.peer_ingress_gateways.lock().contains_key(&removed));
    }

    #[test]
    fn peer_ingress_session_prefers_the_learned_gateway() {
        let sessions = GatewaySessions::default();
        let peer = PeerIdentity::from_device_public_key(b"peer-one");
        let ingress_endpoint = "127.0.0.1:29931".parse().unwrap();
        let active_endpoint = "127.0.0.1:29932".parse().unwrap();
        let grant = GatewayAccessGrant {
            session_id: 7,
            ..Default::default()
        };
        let channel_meta = GatewayChannel {
            kind: EnumOrUnknown::new(GatewayChannelKind::GATEWAY_CHANNEL_UDP),
            addr: "udp://127.0.0.1:29931".into(),
            udp_public_key: [7; 32].to_vec(),
            udp_key_id: "key-1".into(),
            ..Default::default()
        };
        let ingress = GatewaySession::new_udp(
            ingress_endpoint,
            &grant,
            &channel_meta,
            DebugWatch::default(),
            DataPlaneStats::new(true),
        )
        .expect("create ingress UDP session");
        let active = GatewaySession::new_udp(
            active_endpoint,
            &grant,
            &channel_meta,
            DebugWatch::default(),
            DataPlaneStats::new(true),
        )
        .expect("create active UDP session");
        for session in [&ingress, &active] {
            session.active.store(true);
            let mut state = session.state.lock();
            state.authenticated = true;
            state.hard_expire_unix_ms = now_time() as i64 + 60_000;
        }
        let mut registry = sessions.registry.lock();
        registry.install_session(ingress);
        registry.install_session(active);
        drop(registry);
        sessions.peer_ingress_gateways.lock().insert(
            peer.clone(),
            PeerIngressGateway {
                endpoint: ingress_endpoint,
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );

        assert_eq!(
            sessions
                .peer_ingress_session(&peer)
                .map(|session| session.endpoint),
            Some(ingress_endpoint)
        );
    }
}
