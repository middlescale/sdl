use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use parking_lot::RwLock;

use crate::cipher::Cipher;
use crate::core::PeerIdentity;
use crate::protocol::NetPacket;
use crate::util::OnlineSessionKeyMaterial;

const PEER_SESSION_CIPHER_GRACE_WINDOW: Duration = Duration::from_secs(30);

pub struct PeerCryptoManager {
    online_session_key: RwLock<Option<OnlineSessionKeyMaterial>>,
    current_ciphers: RwLock<HashMap<PeerIdentity, Cipher>>,
    previous_ciphers: RwLock<HashMap<PeerIdentity, Cipher>>,
    grace_until: RwLock<Option<Instant>>,
}

impl PeerCryptoManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            online_session_key: RwLock::new(None),
            current_ciphers: RwLock::new(HashMap::with_capacity(capacity)),
            previous_ciphers: RwLock::new(HashMap::with_capacity(capacity)),
            grace_until: RwLock::new(None),
        }
    }

    pub fn online_session_key(&self) -> Option<OnlineSessionKeyMaterial> {
        self.online_session_key.read().clone()
    }

    pub fn ensure_online_session_key(&self) -> OnlineSessionKeyMaterial {
        let mut guard = self.online_session_key.write();
        guard
            .get_or_insert_with(OnlineSessionKeyMaterial::generate)
            .clone()
    }

    pub fn clear_online_session_key(&self) {
        *self.online_session_key.write() = None;
    }

    pub fn clear_peer_session_ciphers(&self) {
        self.current_ciphers.write().clear();
        self.previous_ciphers.write().clear();
        *self.grace_until.write() = None;
    }

    pub fn clear_all(&self) {
        self.clear_online_session_key();
        self.clear_peer_session_ciphers();
    }

    pub fn current_cipher(&self, peer_identity: &PeerIdentity) -> anyhow::Result<Cipher> {
        self.current_ciphers
            .read()
            .get(peer_identity)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "missing peer session cipher for {}",
                    peer_identity.fingerprint_hex()
                )
            })
    }

    pub fn previous_cipher(&self, peer_identity: &PeerIdentity) -> anyhow::Result<Cipher> {
        self.previous_ciphers
            .read()
            .get(peer_identity)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "missing previous peer session cipher for {}",
                    peer_identity.fingerprint_hex()
                )
            })
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_identity: &PeerIdentity,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let current_cipher = self.current_cipher(peer_identity)?;
        let original = net_packet.buffer().to_vec();
        if current_cipher.decrypt_ipv4(net_packet).is_ok() {
            return Ok(());
        }
        if self.is_grace_active() {
            if let Ok(previous_cipher) = self.previous_cipher(peer_identity) {
                net_packet.buffer_mut().copy_from_slice(&original);
                previous_cipher.decrypt_ipv4(net_packet)?;
                return Ok(());
            }
        }
        net_packet.buffer_mut().copy_from_slice(&original);
        current_cipher.decrypt_ipv4(net_packet)?;
        Ok(())
    }

    pub fn rotate_peer_session_ciphers(&self, next: HashMap<PeerIdentity, Cipher>) {
        let mut current = self.current_ciphers.write();
        let mut previous = self.previous_ciphers.write();
        *previous = std::mem::take(&mut *current);
        *current = next;
        *self.grace_until.write() = Some(Instant::now() + PEER_SESSION_CIPHER_GRACE_WINDOW);
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<PeerIdentity>) {
        self.current_ciphers
            .write()
            .retain(|peer_identity, _| valid_peers.contains(peer_identity));
        self.previous_ciphers
            .write()
            .retain(|peer_identity, _| valid_peers.contains(peer_identity));
    }

    pub fn clear_previous_ciphers_for(&self, peers: &HashSet<PeerIdentity>) {
        if peers.is_empty() {
            return;
        }
        self.previous_ciphers
            .write()
            .retain(|peer_identity, _| !peers.contains(peer_identity));
    }

    pub fn is_grace_active(&self) -> bool {
        self.grace_until
            .read()
            .as_ref()
            .map(|deadline| Instant::now() <= *deadline)
            .unwrap_or(false)
    }

    pub fn debug_counts(&self) -> (usize, usize, bool) {
        (
            self.current_ciphers.read().len(),
            self.previous_ciphers.read().len(),
            self.is_grace_active(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use crate::core::PeerIdentity;
    use crate::protocol::body::ENCRYPTION_RESERVED;
    use crate::protocol::{NetPacket, Protocol, HEAD_LEN};

    use super::*;

    fn test_cipher(seed: u8) -> Cipher {
        Cipher::new_key([seed; 32]).expect("create test cipher")
    }

    fn peer_identity(seed: u8) -> PeerIdentity {
        PeerIdentity::from_device_public_key(&[seed; 32])
    }

    fn encrypted_packet(cipher: &Cipher, payload: &[u8]) -> NetPacket<Vec<u8>> {
        let mut packet =
            NetPacket::new_encrypt(vec![0u8; HEAD_LEN + payload.len() + ENCRYPTION_RESERVED])
                .expect("create test packet");
        packet.set_default_version();
        packet.set_protocol(Protocol::IpTurn);
        packet.set_transport_protocol(1);
        packet.set_initial_ttl(5);
        packet.set_source(Ipv4Addr::new(10, 0, 0, 1));
        packet.set_destination(Ipv4Addr::new(10, 0, 0, 2));
        packet.set_payload(payload).expect("set payload");
        cipher.encrypt_ipv4(&mut packet).expect("encrypt packet");
        packet
    }

    #[test]
    fn online_session_key_is_reused_until_cleared() {
        let manager = PeerCryptoManager::new(4);

        let first = manager.ensure_online_session_key();
        let second = manager.ensure_online_session_key();
        assert_eq!(first, second);

        manager.clear_online_session_key();
        let third = manager.ensure_online_session_key();
        assert_ne!(first.public_key(), third.public_key());
    }

    #[test]
    fn rotate_keeps_sending_with_current_cipher() {
        let peer = peer_identity(9);
        let manager = PeerCryptoManager::new(1);

        manager.rotate_peer_session_ciphers(HashMap::from([(peer.clone(), test_cipher(1))]));
        manager.rotate_peer_session_ciphers(HashMap::from([(peer.clone(), test_cipher(2))]));

        assert_eq!(
            manager.current_cipher(&peer).unwrap().key().unwrap(),
            manager.current_cipher(&peer).unwrap().key().unwrap()
        );
    }

    #[test]
    fn decrypt_uses_previous_cipher_within_grace_window() {
        let peer = peer_identity(9);
        let manager = PeerCryptoManager::new(1);
        let payload = b"hello-peer";

        manager.rotate_peer_session_ciphers(HashMap::from([(peer.clone(), test_cipher(1))]));
        let old_cipher = manager.current_cipher(&peer).unwrap();
        let mut packet = encrypted_packet(&old_cipher, payload);

        manager.rotate_peer_session_ciphers(HashMap::from([(peer.clone(), test_cipher(2))]));

        manager.decrypt_ipv4(&peer, &mut packet).unwrap();
        assert_eq!(packet.payload(), payload);
        assert!(!packet.is_encrypt());
    }

    #[test]
    fn clear_all_resets_peer_crypto_state() {
        let peer = peer_identity(9);
        let manager = PeerCryptoManager::new(1);

        manager.ensure_online_session_key();
        manager.rotate_peer_session_ciphers(HashMap::from([(peer.clone(), test_cipher(1))]));
        manager.clear_all();

        assert!(manager.online_session_key().is_none());
        assert!(manager.current_cipher(&peer).is_err());
        assert!(manager.previous_cipher(&peer).is_err());
        assert!(!manager.is_grace_active());
    }

    #[test]
    fn retain_peers_drops_stale_ciphers() {
        let peer1 = peer_identity(9);
        let peer2 = peer_identity(10);
        let manager = PeerCryptoManager::new(2);

        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1.clone(), test_cipher(1)),
            (peer2.clone(), test_cipher(2)),
        ]));
        manager.retain_peers(&HashSet::from([peer2.clone()]));

        assert!(manager.current_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer2).is_ok());
    }

    #[test]
    fn clear_previous_ciphers_for_drops_grace_cipher_only() {
        let peer1 = peer_identity(9);
        let peer2 = peer_identity(10);
        let manager = PeerCryptoManager::new(2);

        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1.clone(), test_cipher(1)),
            (peer2.clone(), test_cipher(2)),
        ]));
        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1.clone(), test_cipher(3)),
            (peer2.clone(), test_cipher(4)),
        ]));
        manager.clear_previous_ciphers_for(&HashSet::from([peer1.clone()]));

        assert!(manager.previous_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer1).is_ok());
        assert!(manager.previous_cipher(&peer2).is_ok());
    }

    #[test]
    fn same_vip_with_different_identity_does_not_reuse_cipher() {
        let old_identity = peer_identity(9);
        let new_identity = peer_identity(10);
        let manager = PeerCryptoManager::new(2);

        manager
            .rotate_peer_session_ciphers(HashMap::from([(old_identity.clone(), test_cipher(1))]));

        assert!(manager.current_cipher(&old_identity).is_ok());
        assert!(manager.current_cipher(&new_identity).is_err());
    }
}
