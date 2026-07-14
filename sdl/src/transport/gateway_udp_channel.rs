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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvSequenceDropKind {
    Duplicate,
    Reordered,
}

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
    duplicate_drop_count: u64,
    reordered_drop_count: u64,
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
        let server_addr = self.server_addr.clone();
        let crypto = self.crypto.clone();
        self.driver.start_named(
            stop_manager,
            worker_name,
            move |buf, _extend, route_key| {
                let from = route_key.addr;
                let expected = *server_addr.lock();
                if from != expected {
                    log::debug!(
                        "drop gateway udp packet from unexpected source {} (expected {})",
                        from,
                        expected
                    );
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
                if packet.session_id == 0 {
                    return;
                }
                if let Some(drop_kind) =
                    classify_recv_sequence_drop(crypto_guard.last_recv_sequence, packet.sequence)
                {
                    let drop_count = crypto_guard.record_recv_sequence_drop(drop_kind);
                    if should_log_recv_sequence_drop(drop_count) {
                        log::debug!(
                            "drop {} gateway udp packet {} sequence={} last_recv_sequence={} duplicate_drops={} reordered_drops={}",
                            match drop_kind {
                                RecvSequenceDropKind::Duplicate => "duplicate",
                                RecvSequenceDropKind::Reordered => "reordered",
                            },
                            from,
                            packet.sequence,
                            crypto_guard.last_recv_sequence,
                            crypto_guard.duplicate_drop_count,
                            crypto_guard.reordered_drop_count
                        );
                    }
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
            |_, _| {},
        )?;
        self.started.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn update_server_addr(&self, server_addr: SocketAddr) {
        *self.server_addr.lock() = server_addr;
    }

    pub fn recreate(&self) -> anyhow::Result<Self> {
        let server_addr = *self.server_addr.lock();
        let gateway_udp_public_key = *self.gateway_udp_public_key.lock();
        let gateway_udp_key_id = self.gateway_udp_key_id.lock().clone();
        let session_id = self.crypto.lock().session_id;
        Self::new(
            server_addr,
            gateway_udp_public_key,
            gateway_udp_key_id,
            session_id,
        )
    }

    pub fn mark_bootstrap_pending(&self) {
        let mut crypto = self.crypto.lock();
        crypto.bootstrap_pending = true;
        // A fresh bootstrap makes the gateway create a new per-peer UDP state whose
        // outbound sequence restarts from 1. Reset our receive-side sequence gate so
        // the next connect ack is not dropped as a stale/reordered packet.
        crypto.last_recv_sequence = 0;
        crypto.duplicate_drop_count = 0;
        crypto.reordered_drop_count = 0;
    }

    #[cfg(test)]
    pub(crate) fn set_bootstrap_pending_for_test(&self, pending: bool) {
        self.crypto.lock().bootstrap_pending = pending;
    }

    #[cfg(test)]
    pub(crate) fn bootstrap_pending_for_test(&self) -> bool {
        self.crypto.lock().bootstrap_pending
    }

    pub fn update_gateway_udp_auth(
        &self,
        gateway_udp_public_key: [u8; 32],
        gateway_udp_key_id: String,
        session_id: u64,
    ) -> anyhow::Result<()> {
        let mut current_public_key = self.gateway_udp_public_key.lock();
        let mut current_key_id = self.gateway_udp_key_id.lock();
        let mut crypto = self.crypto.lock();
        if *current_public_key == gateway_udp_public_key
            && *current_key_id == gateway_udp_key_id
            && crypto.session_id == session_id
        {
            return Ok(());
        }
        *current_public_key = gateway_udp_public_key;
        *current_key_id = gateway_udp_key_id.clone();
        *crypto = GatewayUdpCrypto::new(gateway_udp_public_key, &gateway_udp_key_id, session_id)?;
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
    fn record_recv_sequence_drop(&mut self, drop_kind: RecvSequenceDropKind) -> u64 {
        let counter = match drop_kind {
            RecvSequenceDropKind::Duplicate => &mut self.duplicate_drop_count,
            RecvSequenceDropKind::Reordered => &mut self.reordered_drop_count,
        };
        *counter = counter.saturating_add(1);
        *counter
    }

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
            duplicate_drop_count: 0,
            reordered_drop_count: 0,
            bootstrap_pending: true,
        })
    }
}

fn classify_recv_sequence_drop(
    last_recv_sequence: u64,
    sequence: u64,
) -> Option<RecvSequenceDropKind> {
    if sequence > last_recv_sequence {
        None
    } else if sequence == last_recv_sequence {
        Some(RecvSequenceDropKind::Duplicate)
    } else {
        Some(RecvSequenceDropKind::Reordered)
    }
}

fn should_log_recv_sequence_drop(drop_count: u64) -> bool {
    drop_count == 1 || drop_count.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::{
        classify_recv_sequence_drop, should_log_recv_sequence_drop, GatewayUdpChannel,
        GatewayUdpCrypto, RecvSequenceDropKind,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::util::StopManager;

    #[test]
    fn recv_sequence_drop_classifies_duplicate_and_reordered_packets() {
        assert_eq!(classify_recv_sequence_drop(10, 11), None);
        assert_eq!(
            classify_recv_sequence_drop(10, 10),
            Some(RecvSequenceDropKind::Duplicate)
        );
        assert_eq!(
            classify_recv_sequence_drop(10, 9),
            Some(RecvSequenceDropKind::Reordered)
        );
    }

    #[test]
    fn recv_sequence_drop_counters_track_duplicate_and_reordered_packets_separately() {
        let mut crypto = GatewayUdpCrypto {
            session_id: 1,
            client_public_key: [0; 32],
            header_key: [0; 32],
            send_sequence: 0,
            last_recv_sequence: 10,
            duplicate_drop_count: 0,
            reordered_drop_count: 0,
            bootstrap_pending: false,
        };

        assert_eq!(
            crypto.record_recv_sequence_drop(RecvSequenceDropKind::Duplicate),
            1
        );
        assert_eq!(
            crypto.record_recv_sequence_drop(RecvSequenceDropKind::Duplicate),
            2
        );
        assert_eq!(
            crypto.record_recv_sequence_drop(RecvSequenceDropKind::Reordered),
            1
        );
        assert_eq!(crypto.duplicate_drop_count, 2);
        assert_eq!(crypto.reordered_drop_count, 1);
    }

    #[test]
    fn recv_sequence_drop_logging_is_sampled() {
        assert!(should_log_recv_sequence_drop(1));
        assert!(should_log_recv_sequence_drop(2));
        assert!(!should_log_recv_sequence_drop(3));
        assert!(should_log_recv_sequence_drop(4));
    }

    #[test]
    fn failed_start_can_be_retried() {
        let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242));
        let channel = GatewayUdpChannel::new(server_addr, [7; 32], "key-1".to_string(), 11)
            .expect("create gateway udp channel");
        let stopped_manager = StopManager::new(|| {});
        stopped_manager.stop();

        channel
            .start_named(
                stopped_manager,
                "gateway-udp-failed-start",
                Arc::new(|_, _| {}),
            )
            .expect_err("start with stopped manager");
        assert!(!channel.started.load(Ordering::Relaxed));

        let stop_manager = StopManager::new(|| {});
        channel
            .start_named(
                stop_manager.clone(),
                "gateway-udp-retry",
                Arc::new(|_, _| {}),
            )
            .expect("retry gateway UDP start");
        assert!(channel.started.load(Ordering::Relaxed));

        stop_manager.stop();
        assert!(stop_manager.wait_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn update_gateway_udp_auth_is_idempotent_for_unchanged_auth() {
        let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242));
        let gateway_udp_public_key = [7; 32];
        let gateway_udp_key_id = "key-1".to_string();
        let channel = GatewayUdpChannel::new(
            server_addr,
            gateway_udp_public_key,
            gateway_udp_key_id.clone(),
            11,
        )
        .expect("create gateway udp channel");

        {
            let mut crypto = channel.crypto.lock();
            crypto.send_sequence = 9;
            crypto.bootstrap_pending = false;
        }
        let initial_crypto = channel.crypto.lock().clone();

        channel
            .update_gateway_udp_auth(gateway_udp_public_key, gateway_udp_key_id, 11)
            .expect("update auth");

        let updated_crypto = channel.crypto.lock().clone();
        assert_eq!(
            updated_crypto.client_public_key,
            initial_crypto.client_public_key
        );
        assert_eq!(updated_crypto.header_key, initial_crypto.header_key);
        assert_eq!(updated_crypto.send_sequence, 9);
        assert!(!updated_crypto.bootstrap_pending);
    }

    #[test]
    fn mark_bootstrap_pending_resets_recv_sequence_for_fresh_bootstrap() {
        let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242));
        let channel = GatewayUdpChannel::new(server_addr, [7; 32], "key-1".to_string(), 11)
            .expect("create gateway udp channel");

        let initial_crypto = {
            let mut crypto = channel.crypto.lock();
            crypto.send_sequence = 9;
            crypto.last_recv_sequence = 5;
            crypto.duplicate_drop_count = 2;
            crypto.reordered_drop_count = 3;
            crypto.bootstrap_pending = false;
            crypto.clone()
        };

        channel.mark_bootstrap_pending();

        let updated_crypto = channel.crypto.lock().clone();
        assert_eq!(
            updated_crypto.client_public_key,
            initial_crypto.client_public_key
        );
        assert_eq!(updated_crypto.header_key, initial_crypto.header_key);
        assert_eq!(updated_crypto.send_sequence, 9);
        assert_eq!(updated_crypto.last_recv_sequence, 0);
        assert_eq!(updated_crypto.duplicate_drop_count, 0);
        assert_eq!(updated_crypto.reordered_drop_count, 0);
        assert!(updated_crypto.bootstrap_pending);
    }
}
