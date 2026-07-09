use sha2::{Digest, Sha256};

/// Stable peer identity derived from the peer device public key.
///
/// This is deliberately based on the device public key rather than VIP, device_id, or
/// online session key. VIPs can be reused, device_id is metadata, and online session
/// keys rotate. PeerIdentity is the stable key for security-sensitive peer state such
/// as data-plane session ciphers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerIdentity([u8; 32]);

impl PeerIdentity {
    pub fn from_device_public_key(device_pub_key: &[u8]) -> Self {
        Self(Sha256::digest(device_pub_key).into())
    }

    pub fn fingerprint_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
