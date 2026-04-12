use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::protocol::body::{AesGcmSecretBody, AES_GCM_NONCE_RESERVED, TAG_RESERVED};
use crate::protocol::NetPacket;

const REPLAY_WINDOW: Duration = Duration::from_secs(30);
const MAX_RECENT_PACKETS_PER_PEER: usize = 256;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct PeerReplayId {
    protocol: u8,
    transport_protocol: u8,
    nonce: [u8; AES_GCM_NONCE_RESERVED],
    tag: [u8; TAG_RESERVED],
}

#[derive(Clone)]
pub struct PeerReplayGuard {
    inner: std::sync::Arc<Mutex<HashMap<Ipv4Addr, PeerReplayState>>>,
}

#[derive(Default)]
struct PeerReplayState {
    order: VecDeque<(PeerReplayId, Instant)>,
    recent: HashMap<PeerReplayId, Instant>,
}

impl PeerReplayId {
    pub fn from_aes_gcm_packet<B: AsRef<[u8]>>(net_packet: &NetPacket<B>) -> anyhow::Result<Self> {
        let secret_body = AesGcmSecretBody::new(net_packet.payload())?;
        let nonce: [u8; AES_GCM_NONCE_RESERVED] = secret_body
            .nonce()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid aes-gcm nonce for replay guard"))?;
        let tag: [u8; TAG_RESERVED] = secret_body
            .tag()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid aes-gcm tag for replay guard"))?;
        Ok(Self {
            protocol: net_packet.protocol().into(),
            transport_protocol: net_packet.transport_protocol(),
            nonce,
            tag,
        })
    }
}

impl PeerReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(HashMap::with_capacity(capacity))),
        }
    }

    pub fn check_and_remember(&self, peer_ip: Ipv4Addr, replay_id: PeerReplayId) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.lock();
        let state = guard.entry(peer_ip).or_default();
        state.evict_expired(now);
        if state.recent.contains_key(&replay_id) {
            return false;
        }
        state.order.push_back((replay_id, now));
        state.recent.insert(replay_id, now);
        state.evict_expired(now);
        true
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        self.inner
            .lock()
            .retain(|peer_ip, _| valid_peers.contains(peer_ip));
    }
}

impl PeerReplayState {
    fn evict_expired(&mut self, now: Instant) {
        while let Some((replay_id, seen_at)) = self.order.front().copied() {
            if self.order.len() > MAX_RECENT_PACKETS_PER_PEER
                || now.duration_since(seen_at) > REPLAY_WINDOW
            {
                self.order.pop_front();
                self.recent.remove(&replay_id);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerReplayGuard, PeerReplayId};
    use crate::protocol::body::{AES_GCM_NONCE_RESERVED, ENCRYPTION_RESERVED, TAG_RESERVED};
    use crate::protocol::{NetPacket, Protocol, HEAD_LEN};
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    fn replay_id(seed: u8) -> PeerReplayId {
        let mut packet = NetPacket::new_encrypt(vec![
            0u8;
            HEAD_LEN
                + TAG_RESERVED
                + AES_GCM_NONCE_RESERVED
                + ENCRYPTION_RESERVED
        ])
        .unwrap();
        packet.set_default_version();
        packet.set_protocol(Protocol::IpTurn);
        packet.set_transport_protocol(seed);
        packet.set_initial_ttl(1);
        packet.set_source(Ipv4Addr::new(10, 0, 0, 1));
        packet.set_destination(Ipv4Addr::new(10, 0, 0, 2));
        packet.payload_mut().fill(seed);
        PeerReplayId::from_aes_gcm_packet(&packet).unwrap()
    }

    #[test]
    fn duplicate_packet_for_same_peer_is_rejected() {
        let guard = PeerReplayGuard::new(1);
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let replay_id = replay_id(1);

        assert!(guard.check_and_remember(peer, replay_id));
        assert!(!guard.check_and_remember(peer, replay_id));
    }

    #[test]
    fn same_packet_bytes_for_different_peers_do_not_conflict() {
        let guard = PeerReplayGuard::new(2);
        let replay_id = replay_id(7);

        assert!(guard.check_and_remember(Ipv4Addr::new(10, 0, 0, 9), replay_id));
        assert!(guard.check_and_remember(Ipv4Addr::new(10, 0, 0, 10), replay_id));
    }

    #[test]
    fn retain_peers_drops_stale_replay_state() {
        let guard = PeerReplayGuard::new(2);
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let replay_id = replay_id(5);

        assert!(guard.check_and_remember(peer1, replay_id));
        assert!(guard.check_and_remember(peer2, replay_id));

        guard.retain_peers(&HashSet::from([peer2]));

        assert!(guard.check_and_remember(peer1, replay_id));
        assert!(!guard.check_and_remember(peer2, replay_id));
    }
}
