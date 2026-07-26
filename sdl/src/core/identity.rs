use sha2::{Digest, Sha256};

/// Stable peer identity derived from the peer device public key.
///
/// This is deliberately based on the device public key rather than VIP, device_id, or
/// online session key. VIPs can be reused, device_id is metadata, and online session
/// keys rotate. PeerIdentity is the stable key for security-sensitive peer state such
/// as data-plane session ciphers.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
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

    pub fn from_fingerprint_hex(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char).to_digit(16)? as u8;
            let low = (chunk[1] as char).to_digit(16)? as u8;
            bytes[index] = (high << 4) | low;
        }
        Some(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::PeerIdentity;

    #[test]
    fn fingerprint_round_trip() {
        let identity = PeerIdentity::from_device_public_key(b"test device key");
        assert_eq!(
            PeerIdentity::from_fingerprint_hex(&identity.fingerprint_hex()),
            Some(identity)
        );
        assert_eq!(
            PeerIdentity::from_fingerprint_hex("not-a-fingerprint"),
            None
        );
    }
}
