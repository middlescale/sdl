use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use parking_lot::RwLock;

use crate::cipher::Cipher;
use crate::protocol::NetPacket;

use super::OnlineSessionKeyMaterial;

const PEER_SESSION_CIPHER_GRACE_WINDOW: Duration = Duration::from_secs(10);

pub struct PeerCryptoManager {
    online_session_key: RwLock<Option<OnlineSessionKeyMaterial>>,
    current_ciphers: RwLock<HashMap<Ipv4Addr, Cipher>>,
    previous_ciphers: RwLock<HashMap<Ipv4Addr, Cipher>>,
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

    pub fn is_grace_active(&self) -> bool {
        self.grace_until
            .read()
            .as_ref()
            .map(|deadline| Instant::now() <= *deadline)
            .unwrap_or(false)
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

        manager.ensure_online_session_key();
        manager.rotate_peer_session_ciphers(HashMap::from([(peer, test_cipher(1))]));
        manager.clear_all();

        assert!(manager.online_session_key().is_none());
        assert!(manager.current_cipher(&peer).is_err());
        assert!(manager.previous_cipher(&peer).is_err());
        assert!(!manager.is_grace_active());
    }
}
