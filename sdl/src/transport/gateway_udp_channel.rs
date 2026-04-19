use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use curve25519_dalek::montgomery::MontgomeryPoint;
use parking_lot::Mutex;
use rand::RngCore;

use crate::data_plane::route::RouteKey;
use crate::protocol::NetPacket;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::transport::gateway_udp_envelope::{
    derive_gateway_udp_header_key, derive_gateway_udp_shared_secret, gateway_udp_payload_hash,
    open_gateway_udp_header, seal_gateway_udp_header, GatewayUdpEnvelopeHeader, GatewayUdpPacket,
    GATEWAY_UDP_PACKET_BOOTSTRAP, GATEWAY_UDP_PACKET_DATA,
};
use crate::transport::quic_channel::PacketCallback;
use crate::transport::udp_channel::UdpSocketDriver;
use crate::util::StopManager;

#[derive(Clone)]
pub struct GatewayUdpChannel {
    server_addr: Arc<Mutex<SocketAddr>>,
    gateway_udp_public_key: Arc<Mutex<[u8; 32]>>,
    gateway_udp_key_id: Arc<Mutex<String>>,
    driver: UdpSocketDriver,
    crypto: Arc<Mutex<GatewayUdpCrypto>>,
    started: Arc<AtomicBool>,
}

#[derive(Clone)]
struct GatewayUdpCrypto {
    session_id: u64,
    client_public_key: [u8; 32],
    header_key: [u8; 32],
    send_sequence: u64,
    last_recv_sequence: u64,
    bootstrap_pending: bool,
}

impl GatewayUdpChannel {
    pub fn new(
        server_addr: SocketAddr,
        gateway_udp_public_key: [u8; 32],
        gateway_udp_key_id: String,
        session_id: u64,
    ) -> anyhow::Result<Self> {
        let driver = UdpSocketDriver::bind_unspecified_for_remote(server_addr)?;
        let crypto =
            GatewayUdpCrypto::new(gateway_udp_public_key, &gateway_udp_key_id, session_id)?;
        Ok(Self {
            server_addr: Arc::new(Mutex::new(server_addr)),
            gateway_udp_public_key: Arc::new(Mutex::new(gateway_udp_public_key)),
            gateway_udp_key_id: Arc::new(Mutex::new(gateway_udp_key_id)),
            driver,
            crypto: Arc::new(Mutex::new(crypto)),
            started: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn start_named(
        &self,
        stop_manager: StopManager,
        worker_name: &str,
        on_packet: PacketCallback,
    ) -> anyhow::Result<()> {
        if self.started.swap(true, Ordering::Relaxed) {
            return Ok(());
        }
        let server_addr = self.server_addr.clone();
        let crypto = self.crypto.clone();
        self.driver.start_named(
            stop_manager,
            worker_name,
            move |buf, _extend, route_key| {
                let from = route_key.addr;
                if from != *server_addr.lock() {
                    return;
                }
                let packet = match GatewayUdpPacket::decode(buf) {
                    Ok(packet) => packet,
                    Err(err) => {
                        log::debug!("drop invalid gateway udp packet {}: {:?}", from, err);
                        return;
                    }
                };
                let mut crypto_guard = crypto.lock();
                if packet.session_id == 0 || packet.sequence <= crypto_guard.last_recv_sequence {
                    return;
                }
                let header = match open_gateway_udp_header(
                    &crypto_guard.header_key,
                    crypto_guard.session_id,
                    packet.sequence,
                    &packet.sealed_header,
                ) {
                    Ok(header) => header,
                    Err(err) => {
                        log::debug!(
                            "drop gateway udp packet due to header open failure {}: {:?}",
                            from,
                            err
                        );
                        return;
                    }
                };
                if usize::from(header.payload_len) != packet.payload.len() {
                    return;
                }
                if header.payload_hash != gateway_udp_payload_hash(&packet.payload) {
                    return;
                }
                crypto_guard.last_recv_sequence = packet.sequence;
                drop(crypto_guard);
                on_packet(packet.payload, RouteKey::new(ConnectProtocol::UDP, from));
            },
            |_| true,
            |_| true,
            |_| {},
        )
    }

    pub fn update_server_addr(&self, server_addr: SocketAddr) {
        *self.server_addr.lock() = server_addr;
    }

    pub fn update_gateway_udp_auth(
        &self,
        gateway_udp_public_key: [u8; 32],
        gateway_udp_key_id: String,
        session_id: u64,
    ) -> anyhow::Result<()> {
        *self.gateway_udp_public_key.lock() = gateway_udp_public_key;
        *self.gateway_udp_key_id.lock() = gateway_udp_key_id.clone();
        *self.crypto.lock() =
            GatewayUdpCrypto::new(gateway_udp_public_key, &gateway_udp_key_id, session_id)?;
        Ok(())
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        let server_addr = *self.server_addr.lock();
        let mut crypto = self.crypto.lock();
        let packet_type = if crypto.bootstrap_pending {
            GATEWAY_UDP_PACKET_BOOTSTRAP
        } else {
            GATEWAY_UDP_PACKET_DATA
        };
        crypto.send_sequence = crypto.send_sequence.saturating_add(1);
        let sequence = crypto.send_sequence;
        let payload = packet.buffer().as_ref().to_vec();
        let header = GatewayUdpEnvelopeHeader {
            flags: 0,
            session_id: crypto.session_id,
            sequence,
            payload_len: payload.len().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "gateway udp payload too large")
            })?,
            payload_hash: gateway_udp_payload_hash(&payload),
        };
        let sealed_header = seal_gateway_udp_header(&crypto.header_key, &header)
            .map_err(|e| io::Error::other(format!("seal gateway udp header failed: {e:#}")))?;
        let packet = GatewayUdpPacket {
            packet_type,
            session_id: crypto.session_id,
            sequence,
            client_public_key: if packet_type == GATEWAY_UDP_PACKET_BOOTSTRAP {
                Some(crypto.client_public_key)
            } else {
                None
            },
            sealed_header,
            payload,
        };
        let encoded = packet
            .encode()
            .map_err(|e| io::Error::other(format!("encode gateway udp packet failed: {e:#}")))?;
        self.driver.send_to(&encoded, server_addr)?;
        crypto.bootstrap_pending = false;
        Ok(())
    }
}

impl GatewayUdpCrypto {
    fn new(
        gateway_udp_public_key: [u8; 32],
        gateway_udp_key_id: &str,
        session_id: u64,
    ) -> anyhow::Result<Self> {
        let mut client_private_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_private_key);
        let client_public_key = MontgomeryPoint::mul_base_clamped(client_private_key).to_bytes();
        let shared_secret =
            derive_gateway_udp_shared_secret(client_private_key, gateway_udp_public_key)?;
        let header_key = derive_gateway_udp_header_key(
            shared_secret,
            session_id,
            gateway_udp_key_id,
            client_public_key,
            gateway_udp_public_key,
        );
        Ok(Self {
            session_id,
            client_public_key,
            header_key,
            send_sequence: 0,
            last_recv_sequence: 0,
            bootstrap_pending: true,
        })
    }
}
