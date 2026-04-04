use anyhow::anyhow;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::{Digest, Sha256};

const GATEWAY_UDP_MAGIC: [u8; 4] = *b"MGW0";
const GATEWAY_UDP_VERSION: u8 = 1;
const PAYLOAD_HASH_LEN: usize = 32;
const HEADER_LEN: usize = 1 + 1 + 8 + 8 + 2 + PAYLOAD_HASH_LEN;
const NONCE_LEN: usize = 12;
pub const GATEWAY_UDP_PACKET_BOOTSTRAP: u8 = 1;
pub const GATEWAY_UDP_PACKET_DATA: u8 = 2;
const GATEWAY_UDP_CLIENT_PUBKEY_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayUdpEnvelopeHeader {
    pub flags: u8,
    pub session_id: u64,
    pub sequence: u64,
    pub payload_len: u16,
    pub payload_hash: [u8; PAYLOAD_HASH_LEN],
}

impl GatewayUdpEnvelopeHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = GATEWAY_UDP_VERSION;
        out[1] = self.flags;
        out[2..10].copy_from_slice(&self.session_id.to_be_bytes());
        out[10..18].copy_from_slice(&self.sequence.to_be_bytes());
        out[18..20].copy_from_slice(&self.payload_len.to_be_bytes());
        out[20..20 + PAYLOAD_HASH_LEN].copy_from_slice(&self.payload_hash);
        out
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        if buf.len() != HEADER_LEN {
            return Err(anyhow!("invalid gateway udp header length {}", buf.len()));
        }
        if buf[0] != GATEWAY_UDP_VERSION {
            return Err(anyhow!("unsupported gateway udp header version {}", buf[0]));
        }
        Ok(Self {
            flags: buf[1],
            session_id: u64::from_be_bytes(buf[2..10].try_into().unwrap()),
            sequence: u64::from_be_bytes(buf[10..18].try_into().unwrap()),
            payload_len: u16::from_be_bytes(buf[18..20].try_into().unwrap()),
            payload_hash: buf[20..20 + PAYLOAD_HASH_LEN].try_into().unwrap(),
        })
    }

    pub fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.session_id.to_be_bytes());
        nonce[8..].copy_from_slice(&(self.sequence as u32).to_be_bytes());
        nonce
    }
}

pub fn gateway_udp_payload_hash(payload: &[u8]) -> [u8; PAYLOAD_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayUdpPacket {
    pub packet_type: u8,
    pub session_id: u64,
    pub sequence: u64,
    pub client_public_key: Option<[u8; GATEWAY_UDP_CLIENT_PUBKEY_LEN]>,
    pub sealed_header: Vec<u8>,
    pub payload: Vec<u8>,
}

impl GatewayUdpPacket {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let header_len: u16 = self
            .sealed_header
            .len()
            .try_into()
            .map_err(|_| anyhow!("sealed header too large"))?;
        let mut out = Vec::with_capacity(
            4 + 1 + 8 + 8 + 2 + self.sealed_header.len() + self.payload.len() + 32,
        );
        out.extend_from_slice(&GATEWAY_UDP_MAGIC);
        out.push(self.packet_type);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        if let Some(client_public_key) = self.client_public_key {
            out.extend_from_slice(&client_public_key);
        }
        out.extend_from_slice(&header_len.to_be_bytes());
        out.extend_from_slice(&self.sealed_header);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        if buf.len() < 4 + 1 + 8 + 8 + 2 {
            return Err(anyhow!("gateway udp packet too short"));
        }
        if buf[..4] != GATEWAY_UDP_MAGIC {
            return Err(anyhow!("invalid gateway udp magic"));
        }
        let packet_type = buf[4];
        let session_id = u64::from_be_bytes(buf[5..13].try_into().unwrap());
        let sequence = u64::from_be_bytes(buf[13..21].try_into().unwrap());
        let mut cursor = 21;
        let client_public_key = if packet_type == GATEWAY_UDP_PACKET_BOOTSTRAP {
            if buf.len() < cursor + GATEWAY_UDP_CLIENT_PUBKEY_LEN + 2 {
                return Err(anyhow!("bootstrap gateway udp packet too short"));
            }
            let value: [u8; GATEWAY_UDP_CLIENT_PUBKEY_LEN] = buf
                [cursor..cursor + GATEWAY_UDP_CLIENT_PUBKEY_LEN]
                .try_into()
                .unwrap();
            cursor += GATEWAY_UDP_CLIENT_PUBKEY_LEN;
            Some(value)
        } else {
            None
        };
        let header_len = u16::from_be_bytes(buf[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        if buf.len() < cursor + header_len {
            return Err(anyhow!("gateway udp sealed header truncated"));
        }
        let sealed_header = buf[cursor..cursor + header_len].to_vec();
        cursor += header_len;
        Ok(Self {
            packet_type,
            session_id,
            sequence,
            client_public_key,
            sealed_header,
            payload: buf[cursor..].to_vec(),
        })
    }
}

pub fn generate_gateway_udp_keypair(private_key: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let public_key = MontgomeryPoint::mul_base_clamped(private_key).to_bytes();
    (private_key, public_key)
}

pub fn derive_gateway_udp_shared_secret(
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
) -> anyhow::Result<[u8; 32]> {
    let shared = MontgomeryPoint(peer_public_key)
        .mul_clamped(private_key)
        .to_bytes();
    if shared.iter().all(|byte| *byte == 0) {
        return Err(anyhow!("invalid gateway udp shared secret"));
    }
    Ok(shared)
}

pub fn derive_gateway_udp_header_key(
    shared_secret: [u8; 32],
    session_id: u64,
    gateway_udp_key_id: &str,
    client_public_key: [u8; 32],
    gateway_public_key: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sdl-gateway-udp-v1");
    hasher.update(session_id.to_be_bytes());
    hasher.update((gateway_udp_key_id.len() as u32).to_be_bytes());
    hasher.update(gateway_udp_key_id.as_bytes());
    hasher.update(shared_secret);
    hasher.update(client_public_key);
    hasher.update(gateway_public_key);
    hasher.finalize().into()
}

pub fn seal_gateway_udp_header(
    key_bytes: &[u8; 32],
    header: &GatewayUdpEnvelopeHeader,
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = header.nonce();
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &header.encode(),
                aad: &GATEWAY_UDP_MAGIC,
            },
        )
        .map_err(|_| anyhow!("seal gateway udp header failed"))
}

pub fn open_gateway_udp_header(
    key_bytes: &[u8; 32],
    session_id: u64,
    sequence: u64,
    ciphertext: &[u8],
) -> anyhow::Result<GatewayUdpEnvelopeHeader> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&session_id.to_be_bytes());
    nonce[8..].copy_from_slice(&(sequence as u32).to_be_bytes());
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: &GATEWAY_UDP_MAGIC,
            },
        )
        .map_err(|_| anyhow!("open gateway udp header failed"))?;
    let header = GatewayUdpEnvelopeHeader::decode(&plain)?;
    if header.session_id != session_id || header.sequence != sequence {
        return Err(anyhow!("gateway udp header identity mismatch"));
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_gateway_udp_header_key, derive_gateway_udp_shared_secret,
        generate_gateway_udp_keypair, GatewayUdpPacket, GATEWAY_UDP_PACKET_BOOTSTRAP,
    };
    use super::{
        gateway_udp_payload_hash, open_gateway_udp_header, seal_gateway_udp_header,
        GatewayUdpEnvelopeHeader,
    };

    #[test]
    fn gateway_udp_header_round_trip() {
        let key = [7u8; 32];
        let header = GatewayUdpEnvelopeHeader {
            flags: 3,
            session_id: 42,
            sequence: 9,
            payload_len: 1200,
            payload_hash: gateway_udp_payload_hash(b"payload"),
        };
        let sealed = seal_gateway_udp_header(&key, &header).unwrap();
        let opened = open_gateway_udp_header(&key, 42, 9, &sealed).unwrap();
        assert_eq!(opened, header);
    }

    #[test]
    fn gateway_udp_header_rejects_wrong_sequence() {
        let key = [9u8; 32];
        let header = GatewayUdpEnvelopeHeader {
            flags: 1,
            session_id: 7,
            sequence: 11,
            payload_len: 512,
            payload_hash: gateway_udp_payload_hash(b"payload"),
        };
        let sealed = seal_gateway_udp_header(&key, &header).unwrap();
        assert!(open_gateway_udp_header(&key, 7, 12, &sealed).is_err());
    }

    #[test]
    fn gateway_udp_packet_round_trip() {
        let packet = GatewayUdpPacket {
            packet_type: GATEWAY_UDP_PACKET_BOOTSTRAP,
            session_id: 9,
            sequence: 1,
            client_public_key: Some([3u8; 32]),
            sealed_header: vec![1, 2, 3],
            payload: vec![4, 5, 6],
        };
        let decoded = GatewayUdpPacket::decode(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn gateway_udp_key_derivation_is_symmetric() {
        let (_, client_pub) = generate_gateway_udp_keypair([11u8; 32]);
        let (_, gateway_pub) = generate_gateway_udp_keypair([22u8; 32]);
        let client_shared = derive_gateway_udp_shared_secret([11u8; 32], gateway_pub).unwrap();
        let gateway_shared = derive_gateway_udp_shared_secret([22u8; 32], client_pub).unwrap();
        assert_eq!(client_shared, gateway_shared);
        let client_key =
            derive_gateway_udp_header_key(client_shared, 7, "gw-key", client_pub, gateway_pub);
        let gateway_key =
            derive_gateway_udp_header_key(gateway_shared, 7, "gw-key", client_pub, gateway_pub);
        assert_eq!(client_key, gateway_key);
    }

    #[test]
    fn gateway_udp_payload_hash_changes_with_payload() {
        assert_ne!(
            gateway_udp_payload_hash(b"payload-a"),
            gateway_udp_payload_hash(b"payload-b")
        );
    }
}
