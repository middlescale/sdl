use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::cipher::Cipher;
use crate::protocol::NetPacket;

use super::PeerSessionManager;

pub struct PeerCryptoManager {
    sessions: Arc<PeerSessionManager>,
}

impl PeerCryptoManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            sessions: Arc::new(PeerSessionManager::new(capacity)),
        }
    }

    pub fn from_sessions(sessions: Arc<PeerSessionManager>) -> Self {
        Self { sessions }
    }

    pub fn clear_peer_session_ciphers(&self) {
        self.sessions.clear_all_crypto();
    }

    pub fn clear_all(&self) {
        self.clear_peer_session_ciphers();
    }

    pub fn current_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.sessions.current_cipher(peer_ip)
    }

    pub fn previous_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.sessions.previous_cipher(peer_ip)
    }

    pub fn next_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.sessions.next_cipher(peer_ip)
    }

    pub fn send_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<Cipher> {
        self.sessions.current_cipher(peer_ip)
    }

    pub fn current_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.sessions.current_generation(peer_ip)
    }

    pub fn previous_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.sessions.previous_generation(peer_ip)
    }

    pub fn next_generation(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<u8> {
        self.sessions.next_generation(peer_ip)
    }

    pub fn next_available_generation(&self, peer_ip: &Ipv4Addr) -> u8 {
        self.sessions.next_available_generation(peer_ip)
    }

    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        self.sessions.encrypt_ipv4(peer_ip, net_packet)
    }

    pub fn encrypt_ipv4_with_previous<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        self.sessions.encrypt_ipv4_with_previous(peer_ip, net_packet)
    }

    pub fn encrypt_ipv4_with_next<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        self.sessions.encrypt_ipv4_with_next(peer_ip, net_packet)
    }

    pub fn encrypt_recovery_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        self.sessions.encrypt_recovery_ipv4(peer_ip, net_packet)
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        self.sessions.decrypt_ipv4(peer_ip, net_packet)
    }

    pub fn install_pending_cipher_with_generation(
        &self,
        peer_ip: Ipv4Addr,
        cipher: Cipher,
        generation: u8,
    ) {
        self.sessions
            .install_pending_cipher_with_generation(peer_ip, cipher, generation);
    }

    pub fn replace_current_cipher_with_generation(
        &self,
        peer_ip: Ipv4Addr,
        cipher: Cipher,
        generation: u8,
    ) {
        self.sessions
            .replace_current_cipher_with_generation(peer_ip, cipher, generation);
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        self.sessions.retain_peers(valid_peers);
    }

    pub fn clear_previous_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        self.sessions.clear_previous_ciphers_for(peers);
    }

    pub fn clear_pending_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        self.sessions.clear_pending_ciphers_for(peers);
    }

    pub fn clear_ciphers_for(&self, peers: &HashSet<Ipv4Addr>) {
        self.sessions.clear_crypto_for(peers);
    }

    pub fn clear_runtime_state_for(&self, peers: &HashSet<Ipv4Addr>) {
        self.sessions.clear_runtime_state_for(peers);
    }

    pub fn has_pending_next(&self, peer_ip: &Ipv4Addr) -> bool {
        self.sessions.has_pending_next(peer_ip)
    }

    pub fn is_grace_active_for(&self, peer_ip: &Ipv4Addr) -> bool {
        self.sessions.is_grace_active_for(peer_ip)
    }

    pub fn is_grace_active(&self) -> bool {
        self.sessions.is_grace_active()
    }

    pub fn debug_counts(&self) -> (usize, usize, bool) {
        self.sessions.debug_counts()
    }
}
