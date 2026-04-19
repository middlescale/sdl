use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use parking_lot::RwLock;

/// Typed error returned when an incoming packet's generation does not match any
/// installed cipher slot. This is expected and transient during peer recovery
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
use crate::protocol::peer_discovery_packet::DiscoverySessionId;
use crate::protocol::NetPacket;

const PEER_SESSION_CIPHER_GRACE_WINDOW: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct ActiveCipher {
    cipher: Cipher,
    generation: u8,
    model: CipherModel,
}

#[derive(Clone)]
struct RetiringCipher {
    cipher: Cipher,
    generation: u8,
    grace_until: Instant,
}

impl RetiringCipher {
    fn grace_active(&self) -> bool {
        Instant::now() <= self.grace_until
    }
}

#[derive(Clone)]
struct PreservedCipher {
    cipher: Cipher,
    generation: u8,
    model: CipherModel,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeerSessionTransport {
    Direct,
    Relay,
}

#[derive(Clone)]
enum PeerSessionEntry {
    Discovering {
        session: DiscoverySessionId,
        negotiated_generation: Option<u8>,
        pending_relay_ready: Option<u8>,
        preserved: Option<PreservedCipher>,
    },
    Active {
        session: DiscoverySessionId,
        cipher: ActiveCipher,
        retiring: Option<RetiringCipher>,
        relay_ready: bool,
        direct_confirmed: bool,
        probe_sent: bool,
        preferred_transport: PeerSessionTransport,
    },
}

impl PeerSessionEntry {
    fn discovering(
        session: DiscoverySessionId,
        negotiated_generation: Option<u8>,
        pending_relay_ready: Option<u8>,
        preserved: Option<PreservedCipher>,
    ) -> Self {
        Self::Discovering {
            session,
            negotiated_generation,
            pending_relay_ready,
            preserved,
        }
    }

    fn active(
        session: DiscoverySessionId,
        cipher: ActiveCipher,
        retiring: Option<RetiringCipher>,
        relay_ready: bool,
        direct_confirmed: bool,
        probe_sent: bool,
        preferred_transport: PeerSessionTransport,
    ) -> Self {
        Self::Active {
            session,
            cipher,
            retiring,
            relay_ready,
            direct_confirmed,
            probe_sent,
            preferred_transport,
        }
    }

    fn session(&self) -> DiscoverySessionId {
        match self {
            PeerSessionEntry::Discovering { session, .. }
            | PeerSessionEntry::Active { session, .. } => *session,
        }
    }

    fn cipher_ready(&self) -> bool {
        matches!(self, PeerSessionEntry::Active { .. })
    }

    fn is_ready(&self) -> bool {
        match self {
            PeerSessionEntry::Discovering { .. } => false,
            PeerSessionEntry::Active {
                relay_ready,
                direct_confirmed,
                ..
            } => *relay_ready || *direct_confirmed,
        }
    }

    fn has_recovery_cipher(&self) -> bool {
        self.recovery_generation().is_some()
    }

    fn has_preserved_cipher(&self) -> bool {
        matches!(
            self,
            PeerSessionEntry::Discovering {
                preserved: Some(_),
                ..
            }
        )
    }

    fn negotiated_generation(&self) -> Option<u8> {
        match self {
            PeerSessionEntry::Discovering {
                negotiated_generation,
                ..
            } => *negotiated_generation,
            PeerSessionEntry::Active { cipher, .. } => Some(cipher.generation),
        }
    }

    fn cipher_model(&self) -> Option<CipherModel> {
        match self {
            PeerSessionEntry::Discovering { preserved, .. } => preserved.as_ref().map(|p| p.model),
            PeerSessionEntry::Active { cipher, .. } => Some(cipher.model),
        }
    }

    fn active_cipher(&self) -> Option<&Cipher> {
        match self {
            PeerSessionEntry::Discovering { .. } => None,
            PeerSessionEntry::Active { cipher, .. } => Some(&cipher.cipher),
        }
    }

    fn active_generation(&self) -> Option<u8> {
        match self {
            PeerSessionEntry::Discovering { .. } => None,
            PeerSessionEntry::Active { cipher, .. } => Some(cipher.generation),
        }
    }

    fn recovery_cipher(&self) -> Option<&Cipher> {
        match self {
            PeerSessionEntry::Discovering { preserved, .. } => {
                preserved.as_ref().map(|p| &p.cipher)
            }
            PeerSessionEntry::Active { cipher, .. } => Some(&cipher.cipher),
        }
    }

    fn recovery_generation(&self) -> Option<u8> {
        match self {
            PeerSessionEntry::Discovering { preserved, .. } => {
                preserved.as_ref().map(|p| p.generation)
            }
            PeerSessionEntry::Active { cipher, .. } => Some(cipher.generation),
        }
    }

    fn retiring_cipher(&self) -> Option<&Cipher> {
        match self {
            PeerSessionEntry::Active {
                retiring: Some(retiring),
                ..
            } => Some(&retiring.cipher),
            _ => None,
        }
    }

    fn retiring_generation(&self) -> Option<u8> {
        match self {
            PeerSessionEntry::Active {
                retiring: Some(retiring),
                ..
            } => Some(retiring.generation),
            _ => None,
        }
    }

    fn grace_active(&self) -> bool {
        match self {
            PeerSessionEntry::Active {
                retiring: Some(retiring),
                ..
            } => retiring.grace_active(),
            _ => false,
        }
    }

    fn as_preserved(&self) -> Option<PreservedCipher> {
        match self {
            PeerSessionEntry::Discovering { preserved, .. } => preserved.clone(),
            PeerSessionEntry::Active { cipher, .. } => Some(PreservedCipher {
                cipher: cipher.cipher.clone(),
                generation: cipher.generation,
                model: cipher.model,
            }),
        }
    }

    fn clear_crypto(&mut self) {
        let session = self.session();
        *self = PeerSessionEntry::discovering(session, None, None, None);
    }

    fn reset_runtime_state(&mut self) {
        let preserved = self.as_preserved();
        *self =
            PeerSessionEntry::discovering(DiscoverySessionId::new(0, 0, 0), None, None, preserved);
    }

    fn to_state(&self) -> PeerSessionState {
        match self {
            PeerSessionEntry::Discovering {
                session,
                negotiated_generation,
                ..
            } => PeerSessionState {
                discovery_session: *session,
                negotiated_generation: *negotiated_generation,
                cipher_model: self.cipher_model(),
                cipher_ready: false,
                direct_path_ready: false,
                relay_path_ready: false,
                probe_sent: false,
                preferred_transport: PeerSessionTransport::Relay,
            },
            PeerSessionEntry::Active {
                session,
                cipher,
                relay_ready,
                direct_confirmed,
                probe_sent,
                preferred_transport,
                ..
            } => PeerSessionState {
                discovery_session: *session,
                negotiated_generation: Some(cipher.generation),
                cipher_model: Some(cipher.model),
                cipher_ready: true,
                direct_path_ready: *direct_confirmed,
                relay_path_ready: *relay_ready,
                probe_sent: *probe_sent,
                preferred_transport: *preferred_transport,
            },
        }
    }
}

#[derive(Clone)]
pub struct PeerSessionState {
    pub discovery_session: DiscoverySessionId,
    pub negotiated_generation: Option<u8>,
    pub cipher_model: Option<CipherModel>,
    pub cipher_ready: bool,
    pub direct_path_ready: bool,
    pub relay_path_ready: bool,
    pub probe_sent: bool,
    pub preferred_transport: PeerSessionTransport,
}

impl PeerSessionState {
    pub fn is_ready(&self) -> bool {
        self.cipher_ready && (self.relay_path_ready || self.direct_path_ready)
    }
}

pub struct PeerSessionManager {
    inner: RwLock<HashMap<Ipv4Addr, PeerSessionEntry>>,
}

impl PeerSessionManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(capacity)),
        }
    }

    pub fn begin_recovery(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        let mut guard = self.inner.write();
        let preserved = guard.get(&peer_ip).and_then(PeerSessionEntry::as_preserved);
        guard.insert(
            peer_ip,
            PeerSessionEntry::discovering(discovery_session, None, None, preserved),
        );
    }

    pub fn allows_attempt(
        &self,
        peer_ip: &Ipv4Addr,
        discovery_session: DiscoverySessionId,
    ) -> bool {
        let guard = self.inner.read();
        let Some(state) = guard.get(peer_ip) else {
            return true;
        };
        let current = state.session();
        if current.session_id() == 0 && current.attempt() == 0 {
            return true;
        }
        current.same_attempt(&discovery_session)
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
            state.session().same_transaction(&discovery_session)
        } else {
            state.session().same_attempt(&discovery_session)
        }
    }

    pub fn mark_discovery_ready(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        let _ = (peer_ip, discovery_session);
    }

    pub fn mark_cipher_ready(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.install_cipher(peer_ip, discovery_session, CipherModel::AesGcm, 0);
    }

    pub fn install_cipher(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
        cipher_model: CipherModel,
        generation: u8,
    ) {
        let cipher =
            Cipher::new_session_key(cipher_model, [0u8; 32]).expect("dummy peer session cipher");
        self.install_session_cipher_complete(
            peer_ip,
            discovery_session,
            cipher,
            cipher_model,
            generation,
        );
    }

    pub fn install_session_cipher_complete(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
        cipher: Cipher,
        cipher_model: CipherModel,
        generation: u8,
    ) {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return;
        };
        if !state.session().same_attempt(&discovery_session) {
            return;
        }
        let generation = generation & 0x03;
        let new_cipher = ActiveCipher {
            cipher,
            generation,
            model: cipher_model,
        };
        let session = state.session();
        let (retiring, relay_ready, direct_confirmed, probe_sent, preferred_transport) = match state
        {
            PeerSessionEntry::Discovering {
                pending_relay_ready,
                ..
            } => (
                None,
                pending_relay_ready.map(|candidate| candidate & 0x03) == Some(generation),
                false,
                false,
                PeerSessionTransport::Relay,
            ),
            PeerSessionEntry::Active {
                cipher,
                relay_ready,
                direct_confirmed,
                probe_sent,
                preferred_transport,
                ..
            } => (
                Some(RetiringCipher {
                    cipher: cipher.cipher.clone(),
                    generation: cipher.generation,
                    grace_until: Instant::now() + PEER_SESSION_CIPHER_GRACE_WINDOW,
                }),
                *relay_ready,
                *direct_confirmed,
                *probe_sent,
                *preferred_transport,
            ),
        };
        *state = PeerSessionEntry::active(
            session,
            new_cipher,
            retiring,
            relay_ready,
            direct_confirmed,
            probe_sent,
            preferred_transport,
        );
    }

    pub fn set_negotiated_generation(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
        generation: u8,
    ) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            if let PeerSessionEntry::Discovering {
                negotiated_generation,
                ..
            } = state
            {
                *negotiated_generation = Some(generation & 0x03);
            }
        });
    }

    pub fn mark_direct_path_ready(
        &self,
        peer_ip: Ipv4Addr,
        discovery_session: DiscoverySessionId,
    ) -> bool {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            if let PeerSessionEntry::Active {
                preferred_transport,
                ..
            } = state
            {
                *preferred_transport = PeerSessionTransport::Direct;
            }
            state.is_ready()
        })
        .unwrap_or(false)
    }

    pub fn mark_probe_sent(&self, peer_ip: Ipv4Addr, discovery_session: DiscoverySessionId) {
        self.with_matching_session(peer_ip, discovery_session, |state| {
            if let PeerSessionEntry::Active { probe_sent, .. } = state {
                *probe_sent = true;
            }
        });
    }

    pub fn mark_probe_succeeded(&self, peer_ip: Ipv4Addr) -> bool {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return false;
        };
        let PeerSessionEntry::Active {
            relay_ready,
            direct_confirmed,
            probe_sent,
            preferred_transport,
            ..
        } = state
        else {
            return false;
        };
        if !*probe_sent {
            return false;
        }
        *relay_ready = true;
        if !*direct_confirmed {
            *preferred_transport = PeerSessionTransport::Relay;
        }
        true
    }

    pub fn mark_relay_path_ready(&self, peer_ip: Ipv4Addr, generation: u8) -> bool {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return false;
        };
        let generation = generation & 0x03;
        match state {
            PeerSessionEntry::Discovering {
                pending_relay_ready,
                ..
            } => {
                *pending_relay_ready = Some(generation);
                false
            }
            PeerSessionEntry::Active {
                cipher,
                relay_ready,
                direct_confirmed,
                preferred_transport,
                ..
            } => {
                if cipher.generation != generation {
                    return false;
                }
                *relay_ready = true;
                if !*direct_confirmed {
                    *preferred_transport = PeerSessionTransport::Relay;
                }
                true
            }
        }
    }

    pub fn mark_direct_data_confirmed(&self, peer_ip: Ipv4Addr, generation: u8) -> bool {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return false;
        };
        let PeerSessionEntry::Active {
            cipher,
            direct_confirmed,
            preferred_transport,
            ..
        } = state
        else {
            return false;
        };
        if cipher.generation != (generation & 0x03) {
            return false;
        }
        *direct_confirmed = true;
        *preferred_transport = PeerSessionTransport::Direct;
        true
    }

    pub fn state(&self, peer_ip: &Ipv4Addr) -> Option<PeerSessionState> {
        self.inner
            .read()
            .get(peer_ip)
            .map(PeerSessionEntry::to_state)
    }

    pub fn negotiated_generation(&self, peer_ip: &Ipv4Addr) -> Option<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(PeerSessionEntry::negotiated_generation)
    }

    pub fn cipher_model(&self, peer_ip: &Ipv4Addr) -> Option<CipherModel> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(PeerSessionEntry::cipher_model)
    }

    pub fn current_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(PeerSessionEntry::active_cipher)
            .cloned()
            .ok_or_else(|| anyhow!("missing peer session cipher for {}", peer_ip))
    }

    pub fn previous_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(PeerSessionEntry::retiring_cipher)
            .cloned()
            .ok_or_else(|| anyhow!("missing previous peer session cipher for {}", peer_ip))
    }

    pub fn current_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(PeerSessionEntry::active_generation)
            .ok_or_else(|| anyhow!("missing peer session generation for {}", peer_ip))
    }

    pub fn previous_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.inner
            .read()
            .get(peer_ip)
            .and_then(PeerSessionEntry::retiring_generation)
            .ok_or_else(|| anyhow!("missing previous peer session generation for {}", peer_ip))
    }

    pub fn next_available_generation(&self, peer_ip: &Ipv4Addr) -> u8 {
        let guard = self.inner.read();
        let Some(state) = guard.get(peer_ip) else {
            return 0;
        };
        let current = state.recovery_generation();
        let previous = state.retiring_generation();
        for candidate in 0..=3u8 {
            if Some(candidate) != current && Some(candidate) != previous {
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

    pub fn encrypt_recovery_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let (cipher, generation) = self
            .inner
            .read()
            .get(peer_ip)
            .and_then(|state| {
                state
                    .recovery_cipher()
                    .cloned()
                    .zip(state.recovery_generation())
            })
            .ok_or_else(|| anyhow!("missing recovery peer session cipher for {}", peer_ip))?;
        net_packet.set_peer_generation(generation);
        cipher.encrypt_ipv4(net_packet)?;
        Ok(())
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let packet_generation = net_packet.peer_generation();
        let (current, previous, grace_active) = {
            let guard = self.inner.read();
            let Some(state) = guard.get(peer_ip) else {
                return Err(GenerationMismatchError::new(format!(
                    "peer session generation mismatch for {}: packet={}, current=None, previous=None, grace_active=false",
                    peer_ip, packet_generation
                ))
                .into());
            };
            (
                state
                    .active_cipher()
                    .cloned()
                    .zip(state.active_generation()),
                state
                    .retiring_cipher()
                    .cloned()
                    .zip(state.retiring_generation()),
                state.grace_active(),
            )
        };
        if current.as_ref().map(|(_, generation)| *generation) == Some(packet_generation) {
            return current
                .expect("checked current presence")
                .0
                .decrypt_ipv4(net_packet)
                .map_err(Into::into);
        }
        if grace_active
            && previous.as_ref().map(|(_, generation)| *generation) == Some(packet_generation)
        {
            return previous
                .expect("checked previous presence")
                .0
                .decrypt_ipv4(net_packet)
                .map_err(Into::into);
        }
        Err(GenerationMismatchError::new(format!(
            "peer session generation mismatch for {}: packet={}, current={:?}, previous={:?}, grace_active={}",
            peer_ip,
            packet_generation,
            current.as_ref().map(|(_, generation)| *generation),
            previous.as_ref().map(|(_, generation)| *generation),
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
        let state = guard.entry(peer_ip).or_insert_with(|| {
            PeerSessionEntry::discovering(DiscoverySessionId::new(0, 0, 0), None, None, None)
        });
        let session = state.session();
        let retiring = state
            .active_cipher()
            .cloned()
            .zip(state.active_generation())
            .map(|(cipher, generation)| RetiringCipher {
                cipher,
                generation,
                grace_until: Instant::now() + PEER_SESSION_CIPHER_GRACE_WINDOW,
            });
        let cipher = ActiveCipher {
            cipher,
            generation: generation & 0x03,
            model: CipherModel::AesGcm,
        };
        *state = PeerSessionEntry::active(
            session,
            cipher,
            retiring,
            true,
            false,
            false,
            PeerSessionTransport::Relay,
        );
    }

    pub fn replace_current_cipher_with_generation(
        &self,
        peer_ip: Ipv4Addr,
        cipher: Cipher,
        generation: u8,
    ) {
        self.install_pending_cipher_with_generation(peer_ip, cipher, generation);
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
            if let PeerSessionEntry::Active { retiring, .. } = state {
                *retiring = None;
            }
        }
    }

    pub fn clear_pending_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        let _ = peers;
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
            state.clear_crypto();
        }
    }

    pub fn has_pending_next(&self, peer_ip: &Ipv4Addr) -> bool {
        let _ = peer_ip;
        false
    }

    pub fn is_grace_active_for(&self, peer_ip: &Ipv4Addr) -> bool {
        self.inner
            .read()
            .get(peer_ip)
            .map(PeerSessionEntry::grace_active)
            .unwrap_or(false)
    }

    pub fn is_grace_active(&self) -> bool {
        self.inner
            .read()
            .values()
            .any(PeerSessionEntry::grace_active)
    }

    pub fn debug_counts(&self) -> (usize, usize, bool) {
        let guard = self.inner.read();
        let current = guard
            .values()
            .filter(|state| state.has_recovery_cipher())
            .count();
        let previous = guard
            .values()
            .filter(|state| state.retiring_generation().is_some())
            .count();
        let grace_active = guard.values().any(PeerSessionEntry::grace_active);
        (current, previous, grace_active)
    }

    pub fn probe_candidates(&self) -> Vec<(Ipv4Addr, DiscoverySessionId)> {
        self.inner
            .read()
            .iter()
            .filter_map(|(peer_ip, state)| {
                if state.cipher_ready() && !state.is_ready() {
                    Some((*peer_ip, state.session()))
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
        if let PeerSessionEntry::Active {
            relay_ready,
            direct_confirmed,
            preferred_transport,
            ..
        } = state
        {
            if *relay_ready || *direct_confirmed || transport == PeerSessionTransport::Relay {
                *preferred_transport = transport;
            }
        }
    }

    pub fn preferred_transport(
        &self,
        peer_ip: &Ipv4Addr,
        use_channel_type: UseChannelType,
        direct_route: Option<Route>,
        allow_recovering: bool,
    ) -> Option<PeerSessionTransport> {
        let guard = self.inner.read();
        select_transport(
            use_channel_type,
            direct_route,
            guard.get(peer_ip),
            allow_recovering,
        )
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        self.inner
            .write()
            .retain(|peer_ip, _| valid_peers.contains(peer_ip));
    }

    pub fn clear_all_crypto(&self) {
        for state in self.inner.write().values_mut() {
            state.clear_crypto();
        }
    }

    pub fn clear_runtime_state_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        let mut inner = self.inner.write();
        for peer in peers {
            if let Some(state) = inner.get_mut(peer) {
                state.reset_runtime_state();
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
        f: impl FnOnce(&mut PeerSessionEntry) -> R,
    ) -> Option<R> {
        let mut guard = self.inner.write();
        let Some(state) = guard.get_mut(&peer_ip) else {
            return None;
        };
        if !state.session().same_transaction(&discovery_session) {
            return None;
        }
        Some(f(state))
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerSessionManager, PeerSessionTransport};
    use crate::cipher::{Cipher, CipherModel};
    use crate::data_plane::route::{Route, RouteOrigin};
    use crate::data_plane::use_channel_type::UseChannelType;
    use crate::protocol::body::ENCRYPTION_RESERVED;
    use crate::protocol::peer_discovery_packet::DiscoverySessionId;
    use crate::protocol::NetPacket;
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
    fn matching_session_prefers_direct_without_marking_ready() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        manager.mark_discovery_ready(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);
        manager.mark_direct_path_ready(peer, discovery);

        let state = manager.state(&peer).unwrap();
        assert!(state.cipher_ready);
        assert!(!state.direct_path_ready);
        assert!(!state.is_ready());
        assert_eq!(state.preferred_transport, PeerSessionTransport::Direct);
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
        assert!(state.probe_sent);
        assert!(state.relay_path_ready);
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
        assert!(state.relay_path_ready);
        assert!(state.is_ready());
        assert_eq!(state.preferred_transport, PeerSessionTransport::Relay);
    }

    #[test]
    fn relay_path_ready_buffers_until_cipher_install() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);

        manager.begin_recovery(peer, discovery);
        assert!(!manager.mark_relay_path_ready(peer, 2));
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);

        let state = manager.state(&peer).unwrap();
        assert!(state.relay_path_ready);
        assert!(state.is_ready());
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
    fn select_transport_allows_relay_fallback_when_cipher_ready_all_mode() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);

        let transport = manager.preferred_transport(&peer, UseChannelType::All, None, false);
        assert_eq!(transport, Some(PeerSessionTransport::Relay));
    }

    #[test]
    fn select_transport_blocks_p2p_only_when_unready() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        manager.begin_recovery(peer, discovery);
        manager.mark_cipher_ready(peer, discovery);

        let transport =
            manager.preferred_transport(&peer, UseChannelType::P2p, Some(direct_route()), false);
        assert_eq!(transport, None);
    }

    #[test]
    fn select_transport_blocks_normal_data_after_soft_reset() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        manager.begin_recovery(peer, discovery);
        let cipher = Cipher::new_session_key(CipherModel::AesGcm, [0u8; 32]).unwrap();
        manager.install_session_cipher_complete(peer, discovery, cipher, CipherModel::AesGcm, 2);
        manager.mark_probe_sent(peer, discovery);
        manager.mark_probe_succeeded(peer);

        let state = manager.state(&peer).unwrap();
        assert!(state.is_ready());

        let peers: HashSet<Ipv4Addr> = std::iter::once(peer).collect();
        manager.clear_runtime_state_for(&peers);

        let state = manager.state(&peer).unwrap();
        assert!(!state.cipher_ready);
        assert!(!state.is_ready());

        let relay = manager.preferred_transport(&peer, UseChannelType::Relay, None, false);
        assert_eq!(relay, None);

        let all = manager.preferred_transport(&peer, UseChannelType::All, None, false);
        assert_eq!(all, None);

        let p2p =
            manager.preferred_transport(&peer, UseChannelType::P2p, Some(direct_route()), false);
        assert_eq!(p2p, None);

        let recovery_relay = manager.preferred_transport(&peer, UseChannelType::Relay, None, true);
        assert_eq!(recovery_relay, Some(PeerSessionTransport::Relay));

        let recovery_all = manager.preferred_transport(&peer, UseChannelType::All, None, true);
        assert_eq!(recovery_all, Some(PeerSessionTransport::Relay));
    }

    #[test]
    fn soft_reset_preserves_cipher_only_for_recovery_probe() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerSessionManager::new(1);
        let discovery = session(7, 1, 9);
        let mut normal_packet =
            NetPacket::new_encrypt(vec![0u8; 13 + ENCRYPTION_RESERVED]).unwrap();
        let mut recovery_packet =
            NetPacket::new_encrypt(vec![0u8; 13 + ENCRYPTION_RESERVED]).unwrap();

        manager.begin_recovery(peer, discovery);
        manager.install_cipher(peer, discovery, CipherModel::AesGcm, 2);
        manager.clear_runtime_state_for(&HashSet::from([peer]));

        assert!(manager.encrypt_ipv4(&peer, &mut normal_packet).is_err());
        assert!(manager
            .encrypt_recovery_ipv4(&peer, &mut recovery_packet)
            .is_ok());
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
        assert!(state.direct_path_ready);
        assert!(state.is_ready());
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
        assert!(!state.is_ready());
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
        assert!(!state.relay_path_ready);
        assert!(!state.is_ready());
    }
}

fn select_transport(
    use_channel_type: UseChannelType,
    direct_route: Option<Route>,
    state: Option<&PeerSessionEntry>,
    allow_recovering: bool,
) -> Option<PeerSessionTransport> {
    let direct_available = direct_route.is_some();
    match state {
        Some(state) if state.is_ready() => {
            let preferred_transport = match state {
                PeerSessionEntry::Active {
                    preferred_transport,
                    ..
                } => *preferred_transport,
                PeerSessionEntry::Discovering { .. } => PeerSessionTransport::Relay,
            };
            match use_channel_type {
                UseChannelType::Relay => Some(PeerSessionTransport::Relay),
                UseChannelType::P2p => direct_available.then_some(PeerSessionTransport::Direct),
                UseChannelType::All => {
                    if preferred_transport == PeerSessionTransport::Direct && direct_available {
                        Some(PeerSessionTransport::Direct)
                    } else if !direct_available {
                        Some(PeerSessionTransport::Relay)
                    } else {
                        Some(preferred_transport)
                    }
                }
            }
        }
        Some(state) if allow_recovering && state.cipher_ready() => match use_channel_type {
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
        Some(state) if state.cipher_ready() => match use_channel_type {
            UseChannelType::Relay | UseChannelType::All => Some(PeerSessionTransport::Relay),
            UseChannelType::P2p => None,
        },
        Some(state) if allow_recovering && state.has_preserved_cipher() => match use_channel_type {
            UseChannelType::Relay | UseChannelType::All => Some(PeerSessionTransport::Relay),
            UseChannelType::P2p => None,
        },
        Some(_) => None,
        None => match use_channel_type {
            UseChannelType::Relay => Some(PeerSessionTransport::Relay),
            UseChannelType::P2p => direct_available.then_some(PeerSessionTransport::Direct),
            UseChannelType::All => direct_available
                .then_some(PeerSessionTransport::Direct)
                .or(Some(PeerSessionTransport::Relay)),
        },
    }
}

fn next_generation(current: u8) -> u8 {
    (current + 1) & 0x03
}
