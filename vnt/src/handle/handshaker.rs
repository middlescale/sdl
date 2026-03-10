use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use protobuf::Message;

use crate::channel::context::ChannelContext;
use crate::handle::{CONTROL_VIP, SELF_IP};
use crate::proto::message::HandshakeRequest;
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};

const CAPABILITY_UDP_ENDPOINT_REPORT_V1: &str = "udp_endpoint_report_v1";
const CAPABILITY_PUNCH_COORD_V1: &str = "punch_coord_v1";
const CAPABILITY_GATEWAY_TICKET_V1: &str = "gateway_ticket_v1";

#[derive(Clone)]
pub struct Handshake {
    time: Arc<AtomicCell<Instant>>,
}
impl Handshake {
    pub fn new() -> Self {
        Handshake {
            time: Arc::new(AtomicCell::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or(Instant::now()),
            )),
        }
    }
    pub fn send(&self, context: &ChannelContext, secret: bool, addr: SocketAddr) -> io::Result<()> {
        let last = self.time.load();
        if last.elapsed() < Duration::from_secs(3) {
            return Ok(());
        }
        let request_packet = self.handshake_request_packet(secret)?;
        log::info!("发送握手请求,secret={},{:?}", secret, addr);
        context.send_default(&request_packet, addr)?;
        self.time.store(Instant::now());
        Ok(())
    }
    pub fn handshake_request_packet(&self, secret: bool) -> io::Result<NetPacket<Vec<u8>>> {
        let mut request = HandshakeRequest::new();
        request.secret = secret;
        request.version = crate::VNT_VERSION.to_string();
        request
            .capabilities
            .push(CAPABILITY_UDP_ENDPOINT_REPORT_V1.to_string());
        request
            .capabilities
            .push(CAPABILITY_PUNCH_COORD_V1.to_string());
        request
            .capabilities
            .push(CAPABILITY_GATEWAY_TICKET_V1.to_string());
        let bytes = request.write_to_bytes().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("handshake_request_packet {:?}", e),
            )
        })?;
        let buf = vec![0u8; 12 + bytes.len()];
        let mut net_packet = NetPacket::new(buf)?;
        net_packet.set_default_version();
        net_packet.set_destination(CONTROL_VIP);
        net_packet.set_source(SELF_IP);
        net_packet.set_protocol(Protocol::Service);
        net_packet.set_transport_protocol(service_packet::Protocol::HandshakeRequest.into());
        net_packet.set_initial_ttl(MAX_TTL);
        net_packet.set_payload(&bytes)?;
        Ok(net_packet)
    }
}
