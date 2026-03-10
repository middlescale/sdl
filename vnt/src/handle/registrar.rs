use anyhow::anyhow;
use std::net::Ipv4Addr;

use protobuf::Message;

use crate::handle::{CONTROL_VIP, SELF_IP};
use crate::proto::message::{DeviceAuthRequest, RegistrationRequest};
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};

/// 注册数据
pub fn registration_request_packet(
    token: String,
    device_id: String,
    device_pub_key: Vec<u8>,
    device_pub_key_alg: String,
    name: String,
    ip: Option<Ipv4Addr>,
    is_fast: bool,
    allow_ip_change: bool,
    client_secret_hash: Option<&[u8]>,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut request = RegistrationRequest::new();
    request.token = token;
    request.device_id = device_id;
    request.device_pub_key = device_pub_key;
    request.device_pub_key_alg = device_pub_key_alg;
    request.name = name;
    if let Some(ip) = ip {
        request.virtual_ip = ip.into();
    }
    request.allow_ip_change = allow_ip_change;
    request.is_fast = is_fast;
    request.version = crate::VNT_VERSION.to_string();
    if let Some(client_secret_hash) = client_secret_hash {
        request.client_secret = true;
        request
            .client_secret_hash
            .extend_from_slice(client_secret_hash);
    }
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
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut request = DeviceAuthRequest::new();
    request.user_id = user_id;
    request.group = group;
    request.device_id = device_id;
    request.ticket = ticket;
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
