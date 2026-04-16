use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use parking_lot::RwLock;

use crate::data_plane::route::Route;
use crate::data_plane::use_channel_type::UseChannelType;
use crate::protocol::peer_discovery_packet::DiscoverySessionId;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeerSessionTransport {
    Direct,
    Relay,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeerSessionPhase {
    Recovering,
    DiscoveryReady,
    CipherReady,
    ProbeSent,
    Ready,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeerSessionState {
    pub discovery_session: DiscoverySessionId,
    pub negotiated_generation: Option<u8>,
    pub phase: PeerSessionPhase,
    pub cipher_ready: bool,
    pub direct_path_ready: bool,
    pub relay_path_ready: bool,
    pub probe_sent: bool,
    pub probe_succeeded: bool,
    pub preferred_transport: PeerSessionTransport,
}

impl PeerSessionState {
    fn new(discovery_session: DiscoverySessionId) -> Self {
        Self {
            discovery_session,
            negotiated_generation: None,
            phase: PeerSessionPhase::Recovering,
            cipher_ready: false,
            direct_path_ready: false,
            relay_path_ready: false,
            probe_sent: false,
            probe_succeeded: false,
            preferred_transport: PeerSessionTransport::Relay,
        }
    }

    fn set_discovery_ready(&mut self) {
        if self.phase == PeerSessionPhase::Recovering {
            self.phase = PeerSessionPhase::DiscoveryReady;
        }
    }

    fn set_cipher_ready(&mut self) {
        self.cipher_ready = true;
        if self.phase != PeerSessionPhase::Ready {
            self.phase = PeerSessionPhase::CipherReady;
        }
    }

    fn set_probe_sent(&mut self) {
        self.probe_sent = true;
        if self.phase != PeerSessionPhase::Ready {
            self.phase = PeerSessionPhase::ProbeSent;
        }
    }

    fn set_probe_succeeded(&mut self) {
        self.probe_succeeded = true;
        if !self.direct_path_ready {
            self.preferred_transport = PeerSessionTransport::Relay;
        }
        self.phase = PeerSessionPhase::Ready;
    }

    fn set_relay_path_ready(&mut self) {
        if !self.cipher_ready {
            return;
        }
        self.relay_path_ready = true;
        if !self.direct_path_ready {
            self.preferred_transport = PeerSessionTransport::Relay;
        }
        self.phase = PeerSessionPhase::Ready;
    }

    fn set_direct_path_ready(&mut self) {
        self.direct_path_ready = true;
        self.preferred_transport = PeerSessionTransport::Direct;
        self.phase = PeerSessionPhase::Ready;
    }

    pub fn is_ready(&self) -> bool {
        self.direct_path_ready || self.relay_path_ready || self.probe_succeeded
    }
}

pub struct PeerSessionManager {
    inner: RwLock<HashMap<Ipv4Addr, PeerSessionState>>,
}

impl PeerSessionManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(capacity)),
        }
    }

    pub fn begin_recovery(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.inner
            .write()
            .insert(peer_ip, PeerSessionState::new(discovery_session));
    }

    pub fn mark_discovery_ready(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.set_discovery_ready();
        });
    }

    pub fn mark_cipher_ready(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.set_cipher_ready();
        });
    }

    pub fn set_negotiated_generation(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
        generation: u8,
    ) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.negotiated_generation = Some(generation & 0x03);
        });
    }

    pub fn mark_direct_path_ready(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.set_direct_path_ready();
        });
    }

    pub fn mark_probe_sent(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.set_probe_sent();
        });
    }

    pub fn mark_probe_succeeded(&self, peer_ip: Ipv4Addr) {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return;
        };
        state.set_probe_succeeded();
    }

    pub fn mark_relay_path_ready(&self, peer_ip: Ipv4Addr) {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return;
        };
        state.set_relay_path_ready();
    }

    pub fn state(&self, peer_ip: &Ipv4Addr) -> Option<PeerSessionState> {
        self.inner.read().get(peer_ip).copied()
    }

    pub fn negotiated_generation(&self, peer_ip: &Ipv4Addr) -> Option<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.negotiated_generation)
    }

    pub fn probe_candidates(&self) -> Vec<(Ipv4Addr, DiscoverySessionId)> {
        self.inner
            .read()
            .iter()
            .filter_map(|(peer_ip, state)| {
                if state.cipher_ready && !state.is_ready() {
                    Some((*peer_ip, state.discovery_session))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn observe_transport(&self, peer_ip: Ipv4Addr, transport: PeerSessionTransport) {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return;
        };
        if state.is_ready() || transport == PeerSessionTransport::Relay {
            state.preferred_transport = transport;
        }
    }

    pub fn preferred_transport(
        &self,
        peer_ip: &Ipv4Addr,
        use_channel_type: UseChannelType,
        direct_route: Option<Route>,
        allow_recovering: bool,
    ) -> Option<PeerSessionTransport> {
        let state = self.state(peer_ip);
        select_transport(use_channel_type, direct_route, state, allow_recovering)
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        self.inner
            .write()
            .retain(|peer_ip, _| valid_peers.contains(peer_ip));
    }

    pub fn clear_peers_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        self.inner
            .write()
            .retain(|peer_ip, _| !peers.contains(peer_ip));
    }

    fn with_matching_session(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
        f: impl FnOnce(&mut PeerSessionState),
    ) {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return;
        };
        if !state.discovery_session.same_transaction(&discovery_session) {
            return;
        }
        f(state);
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerSessionManager, PeerSessionPhase, PeerSessionTransport};
    use crate::data_plane::route::{Route, RouteOrigin};
    use crate::data_plane::use_channel_type::UseChannelType;
    use crate::protocol::peer_discovery_packet::DiscoverySessionId;
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::net::{SocketAddr, SocketAddrV4};

    fn session(id: u64, attempt: u32, txid: u64) -> DiscoverySessionId {
        DiscoverySessionId::new(id, attempt, txid)
    }

    fn direct_route() -> Route {
        Route::new_with_origin(
            ConnectProtocol::UDP,
            RouteOrigin::PeerUdp,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3000)),
            1,
            10,
        )
    }

    #[test]
    fn matching_session_advances_phase() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.mark_discovery_ready(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);
        manager.mark_direct_path_ready(peer, discovery);

        let state = manager.state(&peer).unwrap();
        assert_eq!(state.phase, PeerSessionPhase::Ready);
        assert!(state.cipher_ready);
        assert!(state.direct_path_ready);
        assert!(state.is_ready());
    }

    #[test]
    fn stale_session_does_not_override_new_recovery() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let old_discovery = session(7, 1, 9);
        let new_discovery = session(8, 1, 10);

        manager.begin_recovery(peer, old_discovery);
        manager.begin_recovery(peer, new_discovery);
        manager.mark_cipher_ready(peer, old_discovery);

        let state = manager.state(&peer).unwrap();
        assert_eq!(state.phase, PeerSessionPhase::Recovering);
        assert_eq!(state.discovery_session, new_discovery);
        assert!(!state.cipher_ready);
    }

    #[test]
    fn probe_success_marks_session_ready() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);
        manager.mark_probe_sent(peer, discovery);
        manager.mark_probe_succeeded(peer);

        let state = manager.state(&peer).unwrap();
        assert_eq!(state.phase, PeerSessionPhase::Ready);
        assert!(state.probe_sent);
        assert!(state.probe_succeeded);
        assert!(state.is_ready());
        assert_eq!(state.preferred_transport, PeerSessionTransport::Relay);
    }

    #[test]
    fn relay_path_ready_marks_session_ready_after_cipher_ready() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);
        manager.mark_relay_path_ready(peer);

        let state = manager.state(&peer).unwrap();
        assert_eq!(state.phase, PeerSessionPhase::Ready);
        assert!(state.relay_path_ready);
        assert!(state.is_ready());
        assert_eq!(state.preferred_transport, PeerSessionTransport::Relay);
    }

    #[test]
    fn retain_and_clear_drop_selected_peers() {
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let manager = PeerSessionManager::new(2);

        manager.begin_recovery(peer1, session(7, 1, 9));
        manager.begin_recovery(peer2, session(8, 1, 10));
        manager.clear_peers_for(&HashSet::from([peer1]));
        manager.retain_peers(&HashSet::from([peer2]));

        assert!(manager.state(&peer1).is_none());
        assert!(manager.state(&peer2).is_some());
    }

    #[test]
    fn select_transport_uses_session_preference_when_ready() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);
        manager.mark_probe_sent(peer, discovery);
        manager.mark_probe_succeeded(peer);

        let transport =
            manager.preferred_transport(&peer, UseChannelType::All, Some(direct_route()), false);
        assert_eq!(transport, Some(PeerSessionTransport::Relay));
    }

    #[test]
    fn select_transport_allows_recovery_probe_over_relay() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);

        let transport = manager.preferred_transport(&peer, UseChannelType::All, None, true);
        assert_eq!(transport, Some(PeerSessionTransport::Relay));
    }

    #[test]
    fn select_transport_blocks_unready_session_for_normal_data() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);

        let transport = manager.preferred_transport(&peer, UseChannelType::All, None, false);
        assert_eq!(transport, None);
    }

    #[test]
    fn observed_transport_updates_ready_session_preference() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);
        manager.mark_probe_sent(peer, discovery);
        manager.mark_probe_succeeded(peer);

        manager.observe_transport(peer, PeerSessionTransport::Direct);

        let state = manager.state(&peer).unwrap();
        assert_eq!(state.preferred_transport, PeerSessionTransport::Direct);
    }
}

fn select_transport(
    use_channel_type: UseChannelType,
    direct_route: Option<Route>,
    state: Option<PeerSessionState>,
    allow_recovering: bool,
) -> Option<PeerSessionTransport> {
    let direct_available = direct_route.is_some();
    match state {
        Some(state) if state.is_ready() => match use_channel_type {
            UseChannelType::Relay => Some(PeerSessionTransport::Relay),
            UseChannelType::P2p => direct_available.then_some(PeerSessionTransport::Direct),
            UseChannelType::All => {
                if state.preferred_transport == PeerSessionTransport::Direct && direct_available {
                    Some(PeerSessionTransport::Direct)
                } else if !direct_available {
                    Some(PeerSessionTransport::Relay)
                } else {
                    Some(state.preferred_transport)
                }
            }
        },
        Some(state) if allow_recovering && state.cipher_ready => match use_channel_type {
            UseChannelType::Relay => Some(PeerSessionTransport::Relay),
            UseChannelType::P2p => direct_available.then_some(PeerSessionTransport::Direct),
            UseChannelType::All => {
                if direct_available {
                    Some(PeerSessionTransport::Direct)
                } else {
                    Some(PeerSessionTransport::Relay)
                }
            }
        },
        None => match use_channel_type {
            UseChannelType::Relay => Some(PeerSessionTransport::Relay),
            UseChannelType::P2p => direct_available.then_some(PeerSessionTransport::Direct),
            UseChannelType::All => direct_available
                .then_some(PeerSessionTransport::Direct)
                .or(Some(PeerSessionTransport::Relay)),
        },
        _ => None,
    }
}
