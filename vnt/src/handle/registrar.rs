use anyhow::anyhow;
use std::net::Ipv4Addr;

use protobuf::Message;

use crate::handle::{CONTROL_VIP, SELF_IP};
use crate::proto::message::{DeviceAuthProof, DeviceAuthRequest, RegistrationRequest};
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};

/// 注册数据
pub fn registration_request_packet(
    token: String,
    device_id: String,
    device_pub_key: Vec<u8>,
    online_kx_pub: Vec<u8>,
    name: String,
    ip: Option<Ipv4Addr>,
    is_fast: bool,
    allow_ip_change: bool,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut request = RegistrationRequest::new();
    request.token = token;
    request.device_id = device_id;
    request.device_pub_key = device_pub_key;
    request.online_kx_pub = online_kx_pub;
    request.name = name;
    if let Some(ip) = ip {
        request.virtual_ip = ip.into();
    }
    request.allow_ip_change = allow_ip_change;
    request.is_fast = is_fast;
    request.version = crate::VNT_VERSION.to_string();
    let bytes = request
        .write_to_bytes()
        .map_err(|e| anyhow!("RegistrationRequest {:?}", e))?;
    let buf = vec![0u8; 12 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_destination(CONTROL_VIP);
    net_packet.set_source(SELF_IP);
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::RegistrationRequest.into());
    net_packet.set_initial_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(net_packet)
}

pub fn device_auth_request_packet(
    user_id: String,
    group: String,
    device_id: String,
    ticket: String,
    device_pub_key: Vec<u8>,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut request = DeviceAuthRequest::new();
    request.user_id = user_id;
    request.group = group;
    request.device_id = device_id;
    request.ticket = ticket;
    request.device_pub_key = device_pub_key;
    let bytes = request
        .write_to_bytes()
        .map_err(|e| anyhow!("DeviceAuthRequest {:?}", e))?;
    let buf = vec![0u8; 12 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_destination(CONTROL_VIP);
    net_packet.set_source(SELF_IP);
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::DeviceAuthRequest.into());
    net_packet.set_initial_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(net_packet)
}

pub fn device_auth_proof_packet(
    challenge_id: String,
    device_id: String,
    device_pub_key: Vec<u8>,
    signature: Vec<u8>,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut request = DeviceAuthProof::new();
    request.challenge_id = challenge_id;
    request.device_id = device_id;
    request.device_pub_key = device_pub_key;
    request.signature = signature;
    let bytes = request
        .write_to_bytes()
        .map_err(|e| anyhow!("DeviceAuthProof {:?}", e))?;
    let buf = vec![0u8; 12 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_destination(CONTROL_VIP);
    net_packet.set_source(SELF_IP);
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::DeviceAuthProof.into());
    net_packet.set_initial_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(net_packet)
}
