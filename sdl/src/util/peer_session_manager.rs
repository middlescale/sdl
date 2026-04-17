use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use parking_lot::RwLock;

/// Typed error returned when an incoming packet's generation does not match any
/// installed cipher slot.  This is expected and transient during peer recovery
/// (e.g. after a restart or key rotation) and should be handled as a silent
/// packet drop rather than a hard error.
#[derive(Debug)]
pub struct GenerationMismatchError {
    detail: String,
}

impl GenerationMismatchError {
    fn new(detail: String) -> Self {
        Self { detail }
    }
}

impl fmt::Display for GenerationMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for GenerationMismatchError {}

use crate::cipher::Cipher;
use crate::cipher::CipherModel;
use crate::data_plane::route::Route;
use crate::data_plane::use_channel_type::UseChannelType;
use crate::protocol::NetPacket;
use crate::protocol::peer_discovery_packet::DiscoverySessionId;

const PEER_SESSION_CIPHER_GRACE_WINDOW: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct PeerCipherSlot {
    cipher: Cipher,
    generation: u8,
}

#[derive(Clone, Default)]
struct PeerCryptoState {
    current: Option<PeerCipherSlot>,
    previous: Option<PeerCipherSlot>,
    next: Option<PeerCipherSlot>,
    grace_until: Option<Instant>,
}

impl PeerCryptoState {
    fn grace_active(&self) -> bool {
        self.grace_until
            .map(|deadline| Instant::now() <= deadline)
            .unwrap_or(false)
    }
}

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

#[derive(Clone)]
pub struct PeerSessionState {
    pub discovery_session: DiscoverySessionId,
    pub negotiated_generation: Option<u8>,
    pub cipher_model: Option<CipherModel>,
    pub phase: PeerSessionPhase,
    pub cipher_ready: bool,
    pub direct_path_ready: bool,
    pub relay_path_ready: bool,
    pub probe_sent: bool,
    pub probe_succeeded: bool,
    pub preferred_transport: PeerSessionTransport,
    crypto: PeerCryptoState,
}

impl PeerSessionState {
    fn new(discovery_session: DiscoverySessionId) -> Self {
        Self {
            discovery_session,
            negotiated_generation: None,
            cipher_model: None,
            phase: PeerSessionPhase::Recovering,
            cipher_ready: false,
            direct_path_ready: false,
            relay_path_ready: false,
            probe_sent: false,
            probe_succeeded: false,
            preferred_transport: PeerSessionTransport::Relay,
            crypto: PeerCryptoState::default(),
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
    }

    fn set_direct_data_confirmed(&mut self) {
        self.direct_path_ready = true;
        self.probe_succeeded = true;
        self.preferred_transport = PeerSessionTransport::Direct;
        self.phase = PeerSessionPhase::Ready;
    }

    pub fn is_ready(&self) -> bool {
        self.relay_path_ready || self.probe_succeeded
    }

    fn reset_runtime_state_preserving_crypto(&mut self) {
        self.discovery_session = DiscoverySessionId::new(0, 0, 0);
        self.negotiated_generation = None;
        self.phase = PeerSessionPhase::Recovering;
        self.cipher_ready = false;
        self.direct_path_ready = false;
        self.relay_path_ready = false;
        self.probe_sent = false;
        self.probe_succeeded = false;
        self.preferred_transport = PeerSessionTransport::Relay;
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
        let mut guard = self.inner.write();
        let mut state = PeerSessionState::new(discovery_session);
        if let Some(existing) = guard.get(&peer_ip) {
            state.crypto = existing.crypto.clone();
        }
        guard.insert(peer_ip, state);
    }

    pub fn allows_attempt(&self, peer_ip: &Ipv4Addr, discovery_session: DiscoverySessionId) -> bool {
        let guard = self.inner.read();
        let Some(state) = guard.get(peer_ip) else {
            return true;
        };
        if state.discovery_session.session_id() == 0 && state.discovery_session.attempt() == 0 {
            return true;
        }
        state.discovery_session.same_attempt(&discovery_session)
    }

    pub fn matches_current_session(
        &self,
        peer_ip: &Ipv4Addr,
        discovery_session: DiscoverySessionId,
        require_txid: bool,
    ) -> bool {
        let guard = self.inner.read();
        let Some(state) = guard.get(peer_ip) else {
            return false;
        };
        if require_txid {
            state.discovery_session.same_transaction(&discovery_session)
        } else {
            state.discovery_session.same_attempt(&discovery_session)
        }
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

    pub fn install_cipher(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
        cipher_model: CipherModel,
        generation: u8,
    ) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.negotiated_generation = Some(generation & 0x03);
            state.cipher_model = Some(cipher_model);
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

    pub fn mark_direct_path_ready(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
    ) -> bool {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.set_direct_path_ready();
            state.is_ready()
        })
        .unwrap_or(false)
    }

    pub fn mark_probe_sent(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            state.set_probe_sent();
        });
    }

    pub fn mark_probe_succeeded(&self, peer_ip: Ipv4Addr) -> bool {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return false;
        };
        if !state.cipher_ready || !state.probe_sent {
            return false;
        }
        state.set_probe_succeeded();
        state.is_ready()
    }

    pub fn mark_relay_path_ready(&self, peer_ip: Ipv4Addr, generation: u8) -> bool {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return false;
        };
        if !state.cipher_ready || state.negotiated_generation != Some(generation & 0x03) {
            return false;
        }
        state.set_relay_path_ready();
        state.is_ready()
    }

    pub fn mark_direct_data_confirmed(&self, peer_ip: Ipv4Addr, generation: u8) -> bool {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return false;
        };
        if !state.cipher_ready || state.negotiated_generation != Some(generation & 0x03) {
            return false;
        }
        state.set_direct_data_confirmed();
        state.is_ready()
    }

    pub fn state(&self, peer_ip: &Ipv4Addr) -> Option<PeerSessionState> {
        self.inner.read().get(peer_ip).cloned()
    }

    pub fn negotiated_generation(&self, peer_ip: &Ipv4Addr) -> Option<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.negotiated_generation)
    }

    pub fn cipher_model(&self, peer_ip: &Ipv4Addr) -> Option<CipherModel> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.cipher_model)
    }

    pub fn current_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.crypto.current.as_ref())
            .map(|slot| slot.cipher.clone())
            .ok_or_else(|| anyhow!("missing peer session cipher for {}", peer_ip))
    }

    pub fn previous_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.crypto.previous.as_ref())
            .map(|slot| slot.cipher.clone())
            .ok_or_else(|| anyhow!("missing previous peer session cipher for {}", peer_ip))
    }

    pub fn next_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.crypto.next.as_ref())
            .map(|slot| slot.cipher.clone())
            .ok_or_else(|| anyhow!("missing next peer session cipher for {}", peer_ip))
    }

    pub fn current_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.crypto.current.as_ref())
            .map(|slot| slot.generation)
            .ok_or_else(|| anyhow!("missing peer session generation for {}", peer_ip))
    }

    pub fn previous_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.crypto.previous.as_ref())
            .map(|slot| slot.generation)
            .ok_or_else(|| anyhow!("missing previous peer session generation for {}", peer_ip))
    }

    pub fn next_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.crypto.next.as_ref())
            .map(|slot| slot.generation)
            .ok_or_else(|| anyhow!("missing next peer session generation for {}", peer_ip))
    }

    pub fn next_available_generation(&self, peer_ip: &Ipv4Addr) -> u8 {
        let guard = self.inner.read();
        let Some(state) = guard.get(peer_ip) else {
            return 0;
        };
        let current = state.crypto.current.as_ref().map(|slot| slot.generation);
        let previous = state.crypto.previous.as_ref().map(|slot| slot.generation);
        let next = state.crypto.next.as_ref().map(|slot| slot.generation);
        for candidate in 0..=3 {
            let candidate = candidate as u8;
            if Some(candidate) != current && Some(candidate) != previous && Some(candidate) != next {
                return candidate;
            }
        }
        current.map(next_generation).unwrap_or(0)
    }

    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let generation = self.current_generation(peer_ip)?;
        net_packet.set_peer_generation(generation);
        self.current_cipher(peer_ip)?.encrypt_ipv4(net_packet)?;
        Ok(())
    }

    pub fn encrypt_ipv4_with_previous<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let generation = self.previous_generation(peer_ip)?;
        net_packet.set_peer_generation(generation);
        self.previous_cipher(peer_ip)?.encrypt_ipv4(net_packet)?;
        Ok(())
    }

    pub fn encrypt_ipv4_with_next<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let generation = self.next_generation(peer_ip)?;
        net_packet.set_peer_generation(generation);
        self.next_cipher(peer_ip)?.encrypt_ipv4(net_packet)?;
        Ok(())
    }

    pub fn encrypt_recovery_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if self.has_pending_next(peer_ip) {
            self.encrypt_ipv4_with_next(peer_ip, net_packet)
        } else {
            self.encrypt_ipv4(peer_ip, net_packet)
        }
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let packet_generation = net_packet.peer_generation();
        let (current, previous, next, grace_active) = {
            let guard = self.inner.read();
            let Some(state) = guard.get(peer_ip) else {
                return Err(GenerationMismatchError::new(format!(
                    "peer session generation mismatch for {}: packet={}, current=None, previous=None, next=None, grace_active=false",
                    peer_ip,
                    packet_generation
                ))
                .into());
            };
            (
                state.crypto.current.clone(),
                state.crypto.previous.clone(),
                state.crypto.next.clone(),
                state.crypto.grace_active(),
            )
        };
        if current.as_ref().map(|slot| slot.generation) == Some(packet_generation) {
            return current
                .expect("checked current presence")
                .cipher
                .decrypt_ipv4(net_packet)
                .map_err(Into::into);
        }
        if grace_active && previous.as_ref().map(|slot| slot.generation) == Some(packet_generation)
        {
            return previous
                .expect("checked previous presence")
                .cipher
                .decrypt_ipv4(net_packet)
                .map_err(Into::into);
        }
        if next.as_ref().map(|slot| slot.generation) == Some(packet_generation) {
            next.clone()
                .expect("checked next presence")
                .cipher
                .decrypt_ipv4(net_packet)
                .map_err(anyhow::Error::from)?;
            self.promote_next(peer_ip);
            return Ok(());
        }
        Err(GenerationMismatchError::new(format!(
            "peer session generation mismatch for {}: packet={}, current={:?}, previous={:?}, next={:?}, grace_active={}",
            peer_ip,
            packet_generation,
            current.as_ref().map(|slot| slot.generation),
            previous.as_ref().map(|slot| slot.generation),
            next.as_ref().map(|slot| slot.generation),
            grace_active
        ))
        .into())
    }

    pub fn install_pending_cipher_with_generation(
        &self,
        peer_ip: Ipv4Addr,
        cipher: Cipher,
        generation: u8,
    ) {
        let mut guard = self.inner.write();
        let state = guard
            .entry(peer_ip)
            .or_insert_with(|| PeerSessionState::new(DiscoverySessionId::new(0, 0, 0)));
        let next_slot = PeerCipherSlot {
            cipher,
            generation: generation & 0x03,
        };
        if state.crypto.current.is_none() {
            state.crypto.current = Some(next_slot);
            state.crypto.next = None;
            state.crypto.previous = None;
            state.crypto.grace_until = None;
        } else {
            state.crypto.next = Some(next_slot);
        }
    }

    pub fn replace_current_cipher_with_generation(
        &self,
        peer_ip: Ipv4Addr,
        cipher: Cipher,
        generation: u8,
    ) {
        self.install_pending_cipher_with_generation(peer_ip, cipher, generation);
        self.promote_next(&peer_ip);
    }

    pub fn clear_previous_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        let mut guard = self.inner.write();
        for peer_ip in peers {
            let Some(state) = guard.get_mut(peer_ip) else {
                continue;
            };
            state.crypto.previous = None;
            state.crypto.grace_until = None;
        }
    }

    pub fn clear_pending_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        let mut guard = self.inner.write();
        for peer_ip in peers {
            let Some(state) = guard.get_mut(peer_ip) else {
                continue;
            };
            state.crypto.next = None;
        }
    }

    pub fn clear_crypto_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        let mut guard = self.inner.write();
        for peer_ip in peers {
            let Some(state) = guard.get_mut(peer_ip) else {
                continue;
            };
            state.crypto = PeerCryptoState::default();
        }
    }

    pub fn has_pending_next(&self, peer_ip: &Ipv4Addr) -> bool {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(|state| state.crypto.next.as_ref())
            .is_some()
    }

    pub fn is_grace_active_for(&self, peer_ip: &Ipv4Addr) -> bool {
        self.inner
            .read()
            .get(peer_ip)
            .map(|state| state.crypto.grace_active())
            .unwrap_or(false)
    }

    pub fn is_grace_active(&self) -> bool {
        self.inner
            .read()
            .values()
            .any(|state| state.crypto.grace_active())
    }

    pub fn debug_counts(&self) -> (usize, usize, bool) {
        let guard = self.inner.read();
        let current = guard
            .values()
            .filter(|state| state.crypto.current.is_some())
            .count();
        let previous = guard
            .values()
            .filter(|state| state.crypto.previous.is_some())
            .count();
        let grace_active = guard.values().any(|state| state.crypto.grace_active());
        (current, previous, grace_active)
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

    pub fn clear_all_crypto(&self) {
        for state in self.inner.write().values_mut() {
            state.crypto = PeerCryptoState::default();
        }
    }

    pub fn clear_runtime_state_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        let mut inner = self.inner.write();
        for peer in peers {
            if let Some(state) = inner.get_mut(peer) {
                state.reset_runtime_state_preserving_crypto();
            }
        }
    }

    pub fn clear_peers_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        self.inner
            .write()
            .retain(|peer_ip, _| !peers.contains(peer_ip));
    }

    fn with_matching_session<R>(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
        f: impl FnOnce(&mut PeerSessionState) -> R,
    ) -> Option<R> {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return None;
        };
        if !state.discovery_session.same_transaction(&discovery_session) {
            return None;
        }
        Some(f(state))
    }

    fn promote_next(&self, peer_ip: &Ipv4Addr) {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(peer_ip) else {
            return;
        };
        let Some(next) = state.crypto.next.take() else {
            return;
        };
        state.crypto.previous = state.crypto.current.replace(next);
        if state.crypto.previous.is_some() {
            state.crypto.grace_until = Some(Instant::now() + PEER_SESSION_CIPHER_GRACE_WINDOW);
        } else {
            state.crypto.grace_until = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerSessionManager, PeerSessionPhase, PeerSessionTransport};
    use crate::cipher::CipherModel;
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
        assert_eq!(state.phase, PeerSessionPhase::CipherReady);
        assert!(state.cipher_ready);
        assert!(state.direct_path_ready);
        assert!(!state.is_ready());
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
    fn allows_only_current_attempt_to_take_over() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let current = session(7, 2, 9);

        manager.begin_recovery(peer, current);

        assert!(manager.allows_attempt(&peer, session(7, 2, 10)));
        assert!(!manager.allows_attempt(&peer, session(7, 3, 10)));
        assert!(!manager.allows_attempt(&peer, session(8, 2, 10)));
    }

    #[test]
    fn current_session_match_can_require_transaction() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let current = session(7, 2, 9);

        manager.begin_recovery(peer, current);

        assert!(manager.matches_current_session(&peer, session(7, 2, 10), false));
        assert!(manager.matches_current_session(&peer, current, true));
        assert!(!manager.matches_current_session(&peer, session(7, 2, 10), true));
        assert!(!manager.matches_current_session(&peer, session(7, 3, 9), false));
    }

    #[test]
    fn probe_success_marks_session_ready() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);
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
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);
        manager.mark_relay_path_ready(peer, 2);

        let state = manager.state(&peer).unwrap();
        assert_eq!(state.phase, PeerSessionPhase::Ready);
        assert!(state.relay_path_ready);
        assert!(state.is_ready());
        assert_eq!(state.preferred_transport, PeerSessionTransport::Relay);
    }

    #[test]
    fn install_cipher_records_generation_and_model() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);

        let state = manager.state(&peer).unwrap();
        assert_eq!(state.negotiated_generation, Some(2));
        assert_eq!(state.cipher_model, Some(CipherModel::AesGcm));
        assert!(state.cipher_ready);
        assert_eq!(state.phase, PeerSessionPhase::CipherReady);
        assert_eq!(manager.cipher_model(&peer), Some(CipherModel::AesGcm));
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

    #[test]
    fn direct_data_confirmed_marks_session_ready() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);
        manager.mark_direct_path_ready(peer, discovery);

        assert!(manager.mark_direct_data_confirmed(peer, 2));
        let state = manager.state(&peer).unwrap();
        assert!(state.is_ready());
        assert_eq!(state.phase, PeerSessionPhase::Ready);
        assert_eq!(state.preferred_transport, PeerSessionTransport::Direct);
    }

    #[test]
    fn relay_path_ready_ignores_stale_generation() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);

        assert!(!manager.mark_relay_path_ready(peer, 1));
        let state = manager.state(&peer).unwrap();
        assert!(!state.relay_path_ready);
        assert_eq!(state.phase, PeerSessionPhase::CipherReady);
    }

    #[test]
    fn probe_success_requires_probe_sent() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);

        assert!(!manager.mark_probe_succeeded(peer));
        let state = manager.state(&peer).unwrap();
        assert!(!state.probe_succeeded);
        assert_eq!(state.phase, PeerSessionPhase::CipherReady);
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

fn next_generation(current: u8) -> u8 {
    (current + 1) & 0x03
}
