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
    current_generations: RwLock<HashMap<Ipv4Addr, u8>>,
    previous_generations: RwLock<HashMap<Ipv4Addr, u8>>,
    grace_until: RwLock<Option<Instant>>,
}

impl PeerCryptoManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            current_ciphers: RwLock::new(HashMap::with_capacity(capacity)),
            previous_ciphers: RwLock::new(HashMap::with_capacity(capacity)),
            current_generations: RwLock::new(HashMap::with_capacity(capacity)),
            previous_generations: RwLock::new(HashMap::with_capacity(capacity)),
            grace_until: RwLock::new(None),
        }
    }

    pub fn clear_peer_session_ciphers(&self) {
        self.current_ciphers.write().clear();
        self.previous_ciphers.write().clear();
        self.current_generations.write().clear();
        self.previous_generations.write().clear();
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

    pub fn current_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.current_generations
            .read()
            .get(peer_ip)
            .copied()
            .ok_or_else(|| anyhow!("missing peer session generation for {}", peer_ip))
    }

    pub fn previous_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.previous_generations
            .read()
            .get(peer_ip)
            .copied()
            .ok_or_else(|| anyhow!("missing previous peer session generation for {}", peer_ip))
    }

    pub fn next_available_generation(&self, peer_ip: &Ipv4Addr) -> u8 {
        let current = self.current_generations.read().get(peer_ip).copied();
        let previous = self.previous_generations.read().get(peer_ip).copied();
        for candidate in 0..=3 {
            let candidate = candidate as u8;
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

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let packet_generation = net_packet.peer_generation();
        let current_generation = self.current_generation(peer_ip).ok();
        if current_generation == Some(packet_generation) {
            return self.current_cipher(peer_ip)?.decrypt_ipv4(net_packet).map_err(Into::into);
        }
        let previous_generation = self.previous_generation(peer_ip).ok();
        if self.is_grace_active() && previous_generation == Some(packet_generation) {
            return self.previous_cipher(peer_ip)?.decrypt_ipv4(net_packet).map_err(Into::into);
        }
        Err(anyhow!(
            "peer session generation mismatch for {}: packet={}, current={:?}, previous={:?}, grace_active={}",
            peer_ip,
            packet_generation,
            current_generation,
            previous_generation,
            self.is_grace_active()
        ))
    }

    pub fn replace_current_cipher_with_generation(
        &self,
        peer_ip: Ipv4Addr,
        cipher: Cipher,
        generation: u8,
    ) {
        let mut current = self.current_ciphers.write();
        let mut previous = self.previous_ciphers.write();
        let mut current_generations = self.current_generations.write();
        let mut previous_generations = self.previous_generations.write();
        if let Some(prior) = current.insert(peer_ip, cipher) {
            previous.insert(peer_ip, prior);
            let prior_generation = current_generations.get(&peer_ip).copied().unwrap_or(0);
            previous_generations.insert(peer_ip, prior_generation);
            current_generations.insert(peer_ip, generation & 0x03);
        } else {
            previous.remove(&peer_ip);
            previous_generations.remove(&peer_ip);
            current_generations.insert(peer_ip, generation & 0x03);
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
        self.current_generations
            .write()
            .retain(|peer_ip, _| valid_peers.contains(peer_ip));
        self.previous_generations
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
        self.previous_generations
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
        self.current_generations
            .write()
            .retain(|peer_ip, _| !peers.contains(peer_ip));
        self.previous_generations
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

fn next_generation(current: u8) -> u8 {
    (current + 1) & 0x03
}

#[cfg(test)]
mod tests {
    use crate::protocol::body::ENCRYPTION_RESERVED;
    use crate::protocol::{NetPacket, Protocol, HEAD_LEN};

    use super::*;

    fn test_cipher(seed: u8) -> Cipher {
        Cipher::new_key([seed; 32]).expect("create test cipher")
    }

    fn encrypted_packet(cipher: &Cipher, generation: u8, payload: &[u8]) -> NetPacket<Vec<u8>> {
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
        packet.set_peer_generation(generation);
        packet
    }

    #[test]
    fn decrypt_uses_previous_cipher_within_grace_window() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerCryptoManager::new(1);
        let payload = b"hello-peer";

        manager.replace_current_cipher_with_generation(peer, test_cipher(1), 0);
        let old_cipher = manager.current_cipher(&peer).unwrap();
        let mut packet =
            encrypted_packet(&old_cipher, manager.current_generation(&peer).unwrap(), payload);

        manager.replace_current_cipher_with_generation(peer, test_cipher(2), 1);

        manager.decrypt_ipv4(&peer, &mut packet).unwrap();
        assert_eq!(packet.payload(), payload);
        assert!(!packet.is_encrypt());
    }

    #[test]
    fn encrypt_sets_generation_before_aead_authentication() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerCryptoManager::new(1);
        let payload = b"hello-peer";

        manager.replace_current_cipher_with_generation(peer, test_cipher(1), 0);
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

        manager.encrypt_ipv4(&peer, &mut packet).unwrap();
        manager.decrypt_ipv4(&peer, &mut packet).unwrap();

        assert_eq!(packet.payload(), payload);
        assert!(!packet.is_encrypt());
    }

    #[test]
    fn clear_all_resets_peer_crypto_state() {
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        let manager = PeerCryptoManager::new(1);

        manager.replace_current_cipher_with_generation(peer, test_cipher(1), 0);
        manager.clear_all();

        assert!(manager.current_cipher(&peer).is_err());
        assert!(manager.previous_cipher(&peer).is_err());
        assert!(manager.current_generation(&peer).is_err());
        assert!(manager.previous_generation(&peer).is_err());
        assert!(!manager.is_grace_active());
    }

    #[test]
    fn retain_peers_drops_stale_ciphers() {
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let manager = PeerCryptoManager::new(2);

        manager.replace_current_cipher_with_generation(peer1, test_cipher(1), 0);
        manager.replace_current_cipher_with_generation(peer2, test_cipher(2), 0);
        manager.retain_peers(&HashSet::from([peer2]));

        assert!(manager.current_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer2).is_ok());
    }

    #[test]
    fn clear_previous_ciphers_for_drops_grace_cipher_only() {
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let manager = PeerCryptoManager::new(2);

        manager.replace_current_cipher_with_generation(peer1, test_cipher(1), 0);
        manager.replace_current_cipher_with_generation(peer2, test_cipher(2), 0);
        manager.replace_current_cipher_with_generation(peer1, test_cipher(3), 1);
        manager.replace_current_cipher_with_generation(peer2, test_cipher(4), 1);
        manager.clear_previous_ciphers_for(&HashSet::from([peer1]));

        assert!(manager.previous_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer1).is_ok());
        assert!(manager.previous_cipher(&peer2).is_ok());
        assert!(manager.previous_generation(&peer1).is_err());
        assert!(manager.previous_generation(&peer2).is_ok());
    }

    #[test]
    fn clear_ciphers_for_drops_current_and_previous() {
        let peer1 = Ipv4Addr::new(10, 0, 0, 9);
        let peer2 = Ipv4Addr::new(10, 0, 0, 10);
        let manager = PeerCryptoManager::new(2);

        manager.replace_current_cipher_with_generation(peer1, test_cipher(1), 0);
        manager.replace_current_cipher_with_generation(peer2, test_cipher(2), 0);
        manager.replace_current_cipher_with_generation(peer1, test_cipher(3), 1);
        manager.replace_current_cipher_with_generation(peer2, test_cipher(4), 1);
        manager.clear_ciphers_for(&HashSet::from([peer1]));

        assert!(manager.current_cipher(&peer1).is_err());
        assert!(manager.previous_cipher(&peer1).is_err());
        assert!(manager.current_cipher(&peer2).is_ok());
        assert!(manager.previous_cipher(&peer2).is_ok());
        assert!(manager.current_generation(&peer1).is_err());
        assert!(manager.previous_generation(&peer1).is_err());
        assert!(manager.current_generation(&peer2).is_ok());
        assert!(manager.previous_generation(&peer2).is_ok());
    }
}
