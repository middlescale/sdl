use anyhow::anyhow;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256, Sha512};
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use std::net::Ipv4Addr;

use crate::protocol::peer_discovery_packet::DiscoverySessionId;

const PEER_DISCOVERY_NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MESSAGE_LEN: usize = 1024;

fn build_noise_params() -> anyhow::Result<NoiseParams> {
    PEER_DISCOVERY_NOISE_PATTERN
        .parse()
        .map_err(|e| anyhow!("parse peer discovery noise params failed: {:?}", e))
}

pub struct PeerDiscoveryNoiseInitiator {
    state: HandshakeState,
}

impl PeerDiscoveryNoiseInitiator {
    pub fn new(
        local_static_private: &[u8],
        remote_static_public: &[u8],
        prologue: &[u8],
    ) -> anyhow::Result<Self> {
        let params = build_noise_params()?;
        let state = Builder::new(params)
            .local_private_key(local_static_private)
            .remote_public_key(remote_static_public)
            .prologue(prologue)
            .build_initiator()
            .map_err(|e| anyhow!("build initiator noise state failed: {:?}", e))?;
        Ok(Self { state })
    }

    pub fn write_hello(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        write_noise_message(&mut self.state, payload)
    }

    pub fn read_hello_ack(&mut self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        read_noise_message(&mut self.state, message)
    }

    pub fn into_transport(self) -> anyhow::Result<TransportState> {
        self.state
            .into_transport_mode()
            .map_err(|e| anyhow!("initiator into transport failed: {:?}", e))
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn derived_session_key(&self) -> anyhow::Result<[u8; 32]> {
        derive_noise_session_key(&self.state)
    }
}

pub fn derive_peer_discovery_static_private(signing_key: &SigningKey) -> [u8; 32] {
    let digest = Sha512::digest(signing_key.to_bytes());
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&digest[..32]);
    clamp_x25519_private(&mut private_key);
    private_key
}

pub fn derive_peer_discovery_static_public(signing_key: &SigningKey) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(derive_peer_discovery_static_private(signing_key)).to_bytes()
}

pub fn derive_peer_discovery_static_public_from_device_pub(
    device_pub_key: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let device_pub_key: [u8; 32] = device_pub_key
        .try_into()
        .map_err(|_| anyhow!("invalid peer device public key length"))?;
    let point = CompressedEdwardsY(device_pub_key)
        .decompress()
        .ok_or_else(|| anyhow!("invalid peer device public key"))?;
    Ok(point.to_montgomery().to_bytes())
}

pub fn derive_peer_discovery_bootstrap_key(
    local_signing_key: &SigningKey,
    remote_device_pub_key: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let local_static_private = derive_peer_discovery_static_private(local_signing_key);
    let local_static_public = derive_peer_discovery_static_public(local_signing_key);
    let remote_static_public =
        derive_peer_discovery_static_public_from_device_pub(remote_device_pub_key)?;
    let shared = MontgomeryPoint(remote_static_public)
        .mul_clamped(local_static_private)
        .to_bytes();
    if shared.iter().all(|byte| *byte == 0) {
        return Err(anyhow!("invalid peer discovery bootstrap shared secret"));
    }
    let (first_pub, second_pub) = if local_static_public <= remote_static_public {
        (local_static_public, remote_static_public)
    } else {
        (remote_static_public, local_static_public)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"sdl-peer-discovery-bootstrap-v1");
    hasher.update(shared);
    hasher.update(first_pub);
    hasher.update(second_pub);
    Ok(hasher.finalize().into())
}

pub fn build_peer_discovery_noise_prologue(
    session: DiscoverySessionId,
    initiator_vip: Ipv4Addr,
    responder_vip: Ipv4Addr,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sdl-peer-discovery-noise-prologue-v1");
    hasher.update(session.session_id().to_be_bytes());
    hasher.update(session.attempt().to_be_bytes());
    hasher.update(session.txid().to_be_bytes());
    hasher.update(u32::from(initiator_vip).to_be_bytes());
    hasher.update(u32::from(responder_vip).to_be_bytes());
    hasher.finalize().into()
}

pub fn build_peer_discovery_noise_initiator(
    local_signing_key: &SigningKey,
    remote_device_pub_key: &[u8],
    session: DiscoverySessionId,
    initiator_vip: Ipv4Addr,
    responder_vip: Ipv4Addr,
) -> anyhow::Result<PeerDiscoveryNoiseInitiator> {
    let local_static_private = derive_peer_discovery_static_private(local_signing_key);
    let remote_static_public =
        derive_peer_discovery_static_public_from_device_pub(remote_device_pub_key)?;
    let prologue = build_peer_discovery_noise_prologue(session, initiator_vip, responder_vip);
    PeerDiscoveryNoiseInitiator::new(&local_static_private, &remote_static_public, &prologue)
}

pub struct PeerDiscoveryNoiseResponder {
    state: HandshakeState,
}

impl PeerDiscoveryNoiseResponder {
    pub fn new(
        local_static_private: &[u8],
        remote_static_public: &[u8],
        prologue: &[u8],
    ) -> anyhow::Result<Self> {
        let params = build_noise_params()?;
        let state = Builder::new(params)
            .local_private_key(local_static_private)
            .remote_public_key(remote_static_public)
            .prologue(prologue)
            .build_responder()
            .map_err(|e| anyhow!("build responder noise state failed: {:?}", e))?;
        Ok(Self { state })
    }

    pub fn read_hello(&mut self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        read_noise_message(&mut self.state, message)
    }

    pub fn write_hello_ack(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        write_noise_message(&mut self.state, payload)
    }

    pub fn into_transport(self) -> anyhow::Result<TransportState> {
        self.state
            .into_transport_mode()
            .map_err(|e| anyhow!("responder into transport failed: {:?}", e))
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn derived_session_key(&self) -> anyhow::Result<[u8; 32]> {
        derive_noise_session_key(&self.state)
    }
}

pub fn build_peer_discovery_noise_responder(
    local_signing_key: &SigningKey,
    remote_device_pub_key: &[u8],
    session: DiscoverySessionId,
    initiator_vip: Ipv4Addr,
    responder_vip: Ipv4Addr,
) -> anyhow::Result<PeerDiscoveryNoiseResponder> {
    let local_static_private = derive_peer_discovery_static_private(local_signing_key);
    let remote_static_public =
        derive_peer_discovery_static_public_from_device_pub(remote_device_pub_key)?;
    let prologue = build_peer_discovery_noise_prologue(session, initiator_vip, responder_vip);
    PeerDiscoveryNoiseResponder::new(&local_static_private, &remote_static_public, &prologue)
}

fn clamp_x25519_private(private_key: &mut [u8; 32]) {
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
}

fn derive_noise_session_key(state: &HandshakeState) -> anyhow::Result<[u8; 32]> {
    if !state.is_handshake_finished() {
        return Err(anyhow!("peer discovery noise handshake not finished"));
    }
    let handshake_hash = state.get_handshake_hash();
    let mut hasher = Sha256::new();
    hasher.update(b"sdl-peer-session-noise-v1");
    hasher.update((handshake_hash.len() as u32).to_be_bytes());
    hasher.update(handshake_hash);
    Ok(hasher.finalize().into())
}

fn write_noise_message(state: &mut HandshakeState, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0u8; MAX_NOISE_MESSAGE_LEN];
    let len = state
        .write_message(payload, &mut out)
        .map_err(|e| anyhow!("write peer discovery noise message failed: {:?}", e))?;
    out.truncate(len);
    Ok(out)
}

fn read_noise_message(state: &mut HandshakeState, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0u8; MAX_NOISE_MESSAGE_LEN];
    let len = state
        .read_message(message, &mut out)
        .map_err(|e| anyhow!("read peer discovery noise message failed: {:?}", e))?;
    out.truncate(len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        build_noise_params, build_peer_discovery_noise_initiator,
        build_peer_discovery_noise_prologue, build_peer_discovery_noise_responder,
        derive_peer_discovery_bootstrap_key, derive_peer_discovery_static_public,
        derive_peer_discovery_static_public_from_device_pub, PeerDiscoveryNoiseInitiator,
        PeerDiscoveryNoiseResponder,
    };
    use crate::protocol::peer_discovery_packet::DiscoverySessionId;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use snow::Builder;
    use std::net::Ipv4Addr;

    #[test]
    fn peer_discovery_noise_round_trips_and_enters_transport() {
        let params = build_noise_params().unwrap();
        let initiator_keys = Builder::new(params.clone()).generate_keypair().unwrap();
        let responder_keys = Builder::new(params).generate_keypair().unwrap();

        let mut initiator = PeerDiscoveryNoiseInitiator::new(
            &initiator_keys.private,
            &responder_keys.public,
            b"sdl-peer-discovery",
        )
        .unwrap();
        let mut responder = PeerDiscoveryNoiseResponder::new(
            &responder_keys.private,
            &initiator_keys.public,
            b"sdl-peer-discovery",
        )
        .unwrap();

        let hello = initiator.write_hello(b"hello").unwrap();
        let hello_payload = responder.read_hello(&hello).unwrap();
        assert_eq!(hello_payload, b"hello");

        let hello_ack = responder.write_hello_ack(b"ack").unwrap();
        let ack_payload = initiator.read_hello_ack(&hello_ack).unwrap();
        assert_eq!(ack_payload, b"ack");
        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());

        let mut initiator_transport = initiator.into_transport().unwrap();
        let mut responder_transport = responder.into_transport().unwrap();
        let mut encrypted = vec![0u8; 128];
        let encrypted_len = initiator_transport
            .write_message(b"payload", &mut encrypted)
            .unwrap();
        let mut decrypted = vec![0u8; 128];
        let decrypted_len = responder_transport
            .read_message(&encrypted[..encrypted_len], &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..decrypted_len], b"payload");
    }

    #[test]
    fn converted_device_identity_round_trips_through_noise() {
        let initiator_key = SigningKey::generate(&mut OsRng);
        let responder_key = SigningKey::generate(&mut OsRng);
        let session = DiscoverySessionId::new(9, 4, 13);
        let initiator_vip = Ipv4Addr::new(10, 0, 0, 1);
        let responder_vip = Ipv4Addr::new(10, 0, 0, 2);

        let mut initiator = build_peer_discovery_noise_initiator(
            &initiator_key,
            &responder_key.verifying_key().to_bytes(),
            session,
            initiator_vip,
            responder_vip,
        )
        .unwrap();
        let mut responder = build_peer_discovery_noise_responder(
            &responder_key,
            &initiator_key.verifying_key().to_bytes(),
            session,
            initiator_vip,
            responder_vip,
        )
        .unwrap();

        let hello = initiator.write_hello(b"").unwrap();
        responder.read_hello(&hello).unwrap();
        let hello_ack = responder.write_hello_ack(b"").unwrap();
        initiator.read_hello_ack(&hello_ack).unwrap();
        assert!(initiator.is_handshake_finished());
        assert!(responder.is_handshake_finished());
        assert_eq!(
            initiator.derived_session_key().unwrap(),
            responder.derived_session_key().unwrap()
        );
    }

    #[test]
    fn discovery_noise_prologue_depends_on_roles() {
        let session = DiscoverySessionId::new(9, 4, 13);
        let first = build_peer_discovery_noise_prologue(
            session,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let second = build_peer_discovery_noise_prologue(
            session,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        assert_ne!(first, second);
    }

    #[test]
    fn peer_device_pub_converts_to_same_x25519_public() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let derived = derive_peer_discovery_static_public(&signing_key);
        let converted = derive_peer_discovery_static_public_from_device_pub(
            &signing_key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(derived, converted);
    }

    #[test]
    fn bootstrap_key_is_symmetric_between_peers() {
        let initiator_key = SigningKey::generate(&mut OsRng);
        let responder_key = SigningKey::generate(&mut OsRng);
        let initiator = derive_peer_discovery_bootstrap_key(
            &initiator_key,
            &responder_key.verifying_key().to_bytes(),
        )
        .unwrap();
        let responder = derive_peer_discovery_bootstrap_key(
            &responder_key,
            &initiator_key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(initiator, responder);
    }
}
