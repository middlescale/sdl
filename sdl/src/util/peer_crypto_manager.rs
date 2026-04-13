use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use parking_lot::RwLock;

use crate::cipher::Cipher;
use crate::protocol::NetPacket;

const PEER_SESSION_CIPHER_GRACE_WINDOW: Duration = Duration::from_secs(10);

pub struct PeerCryptoManager {
    current_ciphers: RwLock<HashMap<Ipv4Addr, Cipher>>,
    previous_ciphers: RwLock<HashMap<Ipv4Addr, Cipher>>,
    grace_until: RwLock<Option<Instant>>,
}

impl PeerCryptoManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            current_ciphers: RwLock::new(HashMap::with_capacity(capacity)),
            previous_ciphers: RwLock::new(HashMap::with_capacity(capacity)),
            grace_until: RwLock::new(None),
        }
    }

    pub fn clear_peer_session_ciphers(&self) {
        self.current_ciphers.write().clear();
        self.previous_ciphers.write().clear();
        *self.grace_until.write() = None;
    }

    pub fn clear_all(&self) {
        self.clear_peer_session_ciphers();
    }

    pub fn current_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.current_ciphers
            .read()
            .get(peer_ip)
            .cloned()
            .ok_or_else(|| anyhow!("missing peer session cipher for {}", peer_ip))
    }

    pub fn previous_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.previous_ciphers
            .read()
            .get(peer_ip)
            .cloned()
            .ok_or_else(|| anyhow!("missing previous peer session cipher for {}", peer_ip))
    }

    pub fn send_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.current_cipher(peer_ip)
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let current_cipher = self.current_cipher(peer_ip)?;
        let original = net_packet.buffer().to_vec();
        if current_cipher.decrypt_ipv4(net_packet).is_ok() {
            return Ok(());
        }
        if self.is_grace_active() {
            if let Ok(previous_cipher) = self.previous_cipher(peer_ip) {
                net_packet.buffer_mut().copy_from_slice(&original);
                previous_cipher.decrypt_ipv4(net_packet)?;
                return Ok(());
            }
        }
        net_packet.buffer_mut().copy_from_slice(&original);
        current_cipher.decrypt_ipv4(net_packet)?;
        Ok(())
    }

    pub fn rotate_peer_session_ciphers(&self, next: HashMap<Ipv4Addr, Cipher>) {
        let mut current = self.current_ciphers.write();
        let mut previous = self.previous_ciphers.write();
        *previous = std::mem::take(&mut *current);
        *current = next;
        *self.grace_until.write() = Some(Instant::now() + PEER_SESSION_CIPHER_GRACE_WINDOW);
    }

    pub fn replace_current_cipher(&self, peer_ip: Ipv4Addr, cipher: Cipher) {
        let mut current = self.current_ciphers.write();
        let mut previous = self.previous_ciphers.write();
        if let Some(prior) = current.insert(peer_ip, cipher) {
            previous.insert(peer_ip, prior);
        }
        *self.grace_until.write() = Some(Instant::now() + PEER_SESSION_CIPHER_GRACE_WINDOW);
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        self.current_ciphers
            .write()
            .retain(|peer_ip, _| valid_peers.contains(peer_ip));
        self.previous_ciphers
            .write()
            .retain(|peer_ip, _| valid_peers.contains(peer_ip));
    }

    pub fn clear_previous_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        self.previous_ciphers
            .write()
            .retain(|peer_ip, _| !peers.contains(peer_ip));
    }

    pub fn clear_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        if peers.is_empty() {
            return;
        }
        self.current_ciphers
            .write()
            .retain(|peer_ip, _| !peers.contains(peer_ip));
        self.previous_ciphers
            .write()
            .retain(|peer_ip, _| !peers.contains(peer_ip));
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

    use crate::protocol::body::ENCRYPTION_RESERVED;
    use crate::protocol::{NetPacket, Protocol, HEAD_LEN};

    use super::*;

    fn test_cipher(seed: u8) -> Cipher {
        Cipher::new_key([seed; 32]).expect("create test cipher")
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
    fn rotate_keeps_sending_with_current_cipher() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerCryptoManager::new(1);

        manager.rotate_peer_session_ciphers(HashMap::from([(peer, test_cipher(1))]));
        manager.rotate_peer_session_ciphers(HashMap::from([(peer, test_cipher(2))]));

        assert_eq!(
            manager.send_cipher(&peer).unwrap().key().unwrap(),
            manager.current_cipher(&peer).unwrap().key().unwrap()
        );
    }

    #[test]
    fn decrypt_uses_previous_cipher_within_grace_window() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerCryptoManager::new(1);
        let payload = b"hello-peer";

        manager.rotate_peer_session_ciphers(HashMap::from([(peer, test_cipher(1))]));
        let old_cipher = manager.current_cipher(&peer).unwrap();
        let mut packet = encrypted_packet(&old_cipher, payload);

        manager.rotate_peer_session_ciphers(HashMap::from([(peer, test_cipher(2))]));

        manager.decrypt_ipv4(&peer, &mut packet).unwrap();
        assert_eq!(packet.payload(), payload);
        assert!(!packet.is_encrypt());
    }

    #[test]
    fn clear_all_resets_peer_crypto_state() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerCryptoManager::new(1);

        manager.rotate_peer_session_ciphers(HashMap::from([(peer, test_cipher(1))]));
        manager.clear_all();

        assert!(manager.current_cipher(&peer).is_err());
        assert!(manager.previous_cipher(&peer).is_err());
        assert!(!manager.is_grace_active());
    }

    #[test]
    fn retain_peers_drops_stale_ciphers() {
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let manager = PeerCryptoManager::new(2);

        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1, test_cipher(1)),
            (peer2, test_cipher(2)),
        ]));
        manager.retain_peers(&HashSet::from([peer2]));

        assert!(manager.current_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer2).is_ok());
    }

    #[test]
    fn clear_previous_ciphers_for_drops_grace_cipher_only() {
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let manager = PeerCryptoManager::new(2);

        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1, test_cipher(1)),
            (peer2, test_cipher(2)),
        ]));
        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1, test_cipher(3)),
            (peer2, test_cipher(4)),
        ]));
        manager.clear_previous_ciphers_for(&HashSet::from([peer1]));

        assert!(manager.previous_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer1).is_ok());
        assert!(manager.previous_cipher(&peer2).is_ok());
    }

    #[test]
    fn replace_current_cipher_keeps_previous_for_grace() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerCryptoManager::new(1);
        let payload = b"hello-peer";

        manager.rotate_peer_session_ciphers(HashMap::from([(peer, test_cipher(1))]));
        let old_cipher = manager.current_cipher(&peer).unwrap();
        let mut packet = encrypted_packet(&old_cipher, payload);

        manager.replace_current_cipher(peer, test_cipher(2));
        manager.decrypt_ipv4(&peer, &mut packet).unwrap();

        assert_eq!(packet.payload(), payload);
        assert_eq!(
            manager.current_cipher(&peer).unwrap().key().unwrap(),
            &[2; 32]
        );
        assert_eq!(
            manager.previous_cipher(&peer).unwrap().key().unwrap(),
            &[1; 32]
        );
    }

    #[test]
    fn clear_ciphers_for_drops_current_and_previous() {
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let manager = PeerCryptoManager::new(2);

        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1, test_cipher(1)),
            (peer2, test_cipher(2)),
        ]));
        manager.rotate_peer_session_ciphers(HashMap::from([
            (peer1, test_cipher(3)),
            (peer2, test_cipher(4)),
        ]));
        manager.clear_ciphers_for(&HashSet::from([peer1]));

        assert!(manager.current_cipher(&peer1).is_err());
        assert!(manager.previous_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer2).is_ok());
        assert!(manager.previous_cipher(&peer2).is_ok());
    }
}
