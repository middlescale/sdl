use crate::channel::context::ChannelContext;
use crate::channel::sender::ConnectUtil;
use crate::channel::{ConnectProtocol, RouteKey};
use crate::handle::{now_time, CurrentDeviceInfo};
use crate::proto::message::{GatewayAccessGrant, GatewayConnectHello};
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};
use protobuf::Message;
use rand::RngCore;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::OnceLock;

#[derive(Clone, Default)]
struct GatewayRelayState {
    endpoint: Option<SocketAddr>,
    server_name: String,
    ticket: String,
    session_id: u64,
    ticket_expire_unix_ms: i64,
    device_id: String,
    authenticated: bool,
    last_hello_unix_ms: i64,
}

fn relay_state() -> &'static parking_lot::Mutex<GatewayRelayState> {
    static STATE: OnceLock<parking_lot::Mutex<GatewayRelayState>> = OnceLock::new();
    STATE.get_or_init(|| parking_lot::Mutex::new(GatewayRelayState::default()))
}

pub fn set_gateway_grant(grant: &GatewayAccessGrant, virtual_ip: std::net::Ipv4Addr, device_id: String) {
    let endpoint = grant
        .gateway_addrs
        .iter()
        .find_map(|addr| parse_transport_endpoint(addr).ok());
    let mut guard = relay_state().lock();
    guard.endpoint = endpoint;
    guard.server_name = grant.gateway_server_name.clone();
    guard.ticket = grant.ticket.clone();
    guard.session_id = grant.session_id;
    guard.ticket_expire_unix_ms = grant.ticket_expire_unix_ms;
    guard.device_id = device_id;
    guard.authenticated = false;
    guard.last_hello_unix_ms = 0;
    if endpoint.is_none() {
        log::info!("gateway relay disabled for virtual ip {virtual_ip}: no quic gateway addr");
    }
}

pub fn clear_gateway_grant() {
    let mut guard = relay_state().lock();
    *guard = GatewayRelayState::default();
}

pub fn relay_data_addr(default_addr: SocketAddr) -> SocketAddr {
    let guard = relay_state().lock();
    let now_ms = now_time() as i64;
    if guard.authenticated && now_ms <= guard.ticket_expire_unix_ms {
        if let Some(addr) = guard.endpoint {
            return addr;
        }
    }
    default_addr
}

pub fn is_gateway_addr(addr: SocketAddr) -> bool {
    let guard = relay_state().lock();
    guard.endpoint == Some(addr)
}

pub fn maintain_gateway_channel(
    context: &ChannelContext,
    connect_util: &ConnectUtil,
    current_device: &CurrentDeviceInfo,
) -> anyhow::Result<()> {
    let Some((packet, gateway_addr, server_name)) = maybe_build_connect_hello(current_device)? else {
        return Ok(());
    };
    let key = RouteKey::new(ConnectProtocol::QUIC, 0, gateway_addr);
    if context.send_by_key(&packet, key).is_err() {
        connect_util.try_connect_quic(packet.into_buffer(), server_name, gateway_addr);
    }
    Ok(())
}

pub fn send_relay<B: AsRef<[u8]>>(context: &ChannelContext, packet: &NetPacket<B>) -> io::Result<()> {
    let guard = relay_state().lock();
    let now_ms = now_time() as i64;
    if guard.authenticated && now_ms <= guard.ticket_expire_unix_ms {
        if let Some(gateway_addr) = guard.endpoint {
            return context.send_by_key(packet, RouteKey::new(ConnectProtocol::QUIC, 0, gateway_addr));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "gateway relay is not authenticated",
    ))
}

pub fn send_control<B: AsRef<[u8]>>(
    context: &ChannelContext,
    packet: &NetPacket<B>,
    control_addr: SocketAddr,
) -> io::Result<()> {
    context.send_default(packet, control_addr)
}

fn maybe_build_connect_hello(
    current_device: &CurrentDeviceInfo,
) -> anyhow::Result<Option<(NetPacket<Vec<u8>>, SocketAddr, String)>> {
    let mut guard = relay_state().lock();
    let now_ms = now_time() as i64;
    if guard.authenticated || now_ms > guard.ticket_expire_unix_ms {
        return Ok(None);
    }
    let gateway_addr = match guard.endpoint {
        Some(addr) => addr,
        None => return Ok(None),
    };
    let server_name = if guard.server_name.trim().is_empty() {
        gateway_addr.ip().to_string()
    } else {
        guard.server_name.clone()
    };
    if now_ms-guard.last_hello_unix_ms < 3_000 {
        return Ok(None);
    }
    guard.last_hello_unix_ms = now_ms;
    let mut nonce = vec![0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hello = GatewayConnectHello {
        device_id: guard.device_id.clone(),
        virtual_ip: u32::from(current_device.virtual_ip),
        session_id: guard.session_id,
        ticket: guard.ticket.clone(),
        nonce,
        client_time_unix_ms: now_ms,
        device_pub_key: vec![],
        device_pub_key_alg: String::new(),
        device_signature: vec![],
        ..Default::default()
    };
    let payload = hello.write_to_bytes()?;
    let mut packet = NetPacket::new(vec![0u8; 12 + payload.len()])?;
    packet.set_default_version();
    packet.set_source(current_device.virtual_ip);
    packet.set_destination(current_device.virtual_gateway);
    packet.set_protocol(Protocol::Service);
    packet.set_transport_protocol(service_packet::Protocol::GatewayConnectHello.into());
    packet.set_initial_ttl(MAX_TTL);
    packet.set_payload(&payload)?;
    Ok(Some((packet, gateway_addr, server_name)))
}

pub fn handle_connect_ack(from: SocketAddr, session_id: u64, ok: bool, reason: &str) {
    let mut guard = relay_state().lock();
    if guard.endpoint != Some(from) || guard.session_id != session_id {
        return;
    }
    guard.authenticated = ok;
    if ok {
        log::info!("gateway relay authenticated, session={session_id}, endpoint={from}");
    } else {
        log::warn!("gateway relay auth rejected, session={session_id}, reason={reason}");
    }
}

fn parse_transport_endpoint(addr: &str) -> anyhow::Result<SocketAddr> {
    let normalized = addr
        .strip_prefix("quic://")
        .unwrap_or(addr)
        .trim()
        .to_string();
    Ok(SocketAddr::from_str(&normalized)?)
}
