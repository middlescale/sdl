mod auth;
mod debug;
mod device_list;
mod dns;
mod gateway;
mod punch;
mod registration;

use gateway::is_gateway_peer_ipturn_source;
use punch::PunchSessionTracker;

use anyhow::anyhow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use sdl_packet::icmp::{icmp, Kind};
use sdl_packet::ip::ipv4;
use sdl_packet::ip::ipv4::packet::IpV4Packet;

use crate::core::PeerInfo;
use crate::core::SdlContext;
use crate::data_plane::route::{Route, RouteKey};
use crate::handle::callback::{ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, SdlCallback};
use crate::handle::recv_data::PacketHandler;
use crate::handle::{ConnectStatus, CurrentDeviceInfo};
use crate::nat::punch::{NatInfo, NatType, PunchModel};
use crate::proto::message::{
    DebugCollectRequest, DebugCollectResponse, DebugWatchStartRequest, DebugWatchStartResponse,
    DebugWatchStopRequest, DebugWatchStopResponse, DeviceAuthAck, DeviceAuthChallenge,
    DeviceAuthErrorReason, DeviceList, DeviceRenameResponse, DnsQueryResponse, GatewayConnectAck,
    HandshakeResponse, PunchAck, PunchEndpoint, PunchResult, PunchResultCode, PunchSessionPhase,
    PunchStart, RefreshGatewayGrantResponse, RefreshGatewayGrantResult, RegistrationErrorReason,
    RegistrationResponse,
};
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{ip_turn_packet, service_packet, NetPacket, Protocol};
use crate::tun_tap_device::vnt_device::write_full_device;
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::icmp_debug::parse_icmp_echo_meta;
use crate::{proto, DnsProfile, PeerClientInfo};

const CAPABILITY_UDP_ENDPOINT_REPORT_V1: &str = "udp_endpoint_report_v1";
static UNAUTHORIZED_SERVER_SOURCE_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static UNAUTHORIZED_SERVER_SOURCE_DROP_LOG_LIMITER: OnceLock<
    crate::util::limit::ConcurrentRateLimiter,
> = OnceLock::new();

fn log_sampled_unauthorized_server_source_drop(route_key: RouteKey, control_addr: SocketAddr) {
    let count = UNAUTHORIZED_SERVER_SOURCE_DROP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if UNAUTHORIZED_SERVER_SOURCE_DROP_LOG_LIMITER
        .get_or_init(|| crate::util::limit::ConcurrentRateLimiter::new(1, 1))
        .try_acquire()
    {
        let sampled = UNAUTHORIZED_SERVER_SOURCE_DROP_COUNT.swap(0, Ordering::Relaxed);
        let total = sampled.max(count);
        log::debug!(
            "dropping packets from unauthorized control/gateway source (sample route_key={:?}, control_addr={}, count={})",
            route_key,
            control_addr,
            total
        );
    }
}

/// 处理来源于服务端的包
#[derive(Clone)]
pub struct ServerPacketHandler<Call, Device> {
    context: Arc<SdlContext>,
    device: Device,
    callback: Call,
    punch_sessions: PunchSessionTracker,
    // Keep device-list commit/apply in order with other peer_table epoch mutators.
    device_list_update_lock: Arc<Mutex<()>>,
    device_auth_ok: Arc<AtomicCell<bool>>,
}

struct DeviceListUpdate {
    previous_peers: HashMap<Ipv4Addr, PeerInfo>,
    ip_list: Vec<PeerInfo>,
}

struct PeerIdentityPlan {
    active_identities: HashSet<crate::core::PeerIdentity>,
    reset_identities: HashSet<crate::core::PeerIdentity>,
}

impl<Call, Device> ServerPacketHandler<Call, Device> {
    pub(crate) fn new(context: Arc<SdlContext>, device: Device, callback: Call) -> Self {
        Self {
            context,
            device,
            callback,
            punch_sessions: PunchSessionTracker::default(),
            device_list_update_lock: Arc::new(Mutex::new(())),
            device_auth_ok: Arc::new(AtomicCell::new(false)),
        }
    }
}

impl<Call: SdlCallback, Device: DeviceWrite> PacketHandler for ServerPacketHandler<Call, Device> {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        _extend: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        if !self
            .context
            .services
            .control_session
            .is_control_addr(route_key.addr)
            && !self
                .context
                .state
                .gateway
                .sessions
                .is_gateway_addr(route_key.addr)
        {
            log_sampled_unauthorized_server_source_drop(
                route_key,
                self.context.services.control_session.server_addr(),
            );
            return Ok(());
        }
        self.context
            .services
            .route_manager
            .touch_path(&net_packet.source(), &route_key);
        self.reconcile_punch_sessions(current_device)?;
        if net_packet.protocol() == Protocol::Error
            && net_packet.transport_protocol()
                == Into::<u8>::into(crate::protocol::error_packet::Protocol::NoKey)
        {
            return Ok(());
        } else if net_packet.protocol() == Protocol::Service
            && net_packet.transport_protocol()
                == Into::<u8>::into(service_packet::Protocol::HandshakeResponse)
        {
            let response = HandshakeResponse::parse_from_bytes(net_packet.payload())
                .map_err(|e| anyhow!("HandshakeResponse {:?}", e))?;
            log::info!("握手响应:{:?},{}", route_key, response);
            if !response
                .capabilities
                .iter()
                .any(|item| item == CAPABILITY_UDP_ENDPOINT_REPORT_V1)
            {
                return Err(anyhow!(
                    "control missing required capability {}",
                    CAPABILITY_UDP_ENDPOINT_REPORT_V1
                ));
            }
            self.context
                .services
                .control_session
                .set_negotiated_capabilities(&response.capabilities);
            let handshake_info =
                HandshakeInfo::new_no_secret(response.version, response.capabilities);
            if self.callback.handshake(handshake_info) {
                //没有加密，则发送注册请求
                self.register(current_device, route_key, false)?;
            }

            return Ok(());
        }
        match net_packet.protocol() {
            Protocol::Service => {
                self.service(current_device, net_packet, route_key)?;
            }
            Protocol::Error => {
                self.error(net_packet)?;
            }
            Protocol::Control => {
                self.control(net_packet, route_key)?;
            }
            Protocol::IpTurn => {
                match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                    ip_turn_packet::Protocol::Ipv4 => {
                        let source = net_packet.source();
                        let destination = net_packet.destination();
                        let from_gateway = self
                            .context
                            .state
                            .gateway
                            .sessions
                            .is_gateway_addr(route_key.addr);
                        let from_gateway_peer =
                            is_gateway_peer_ipturn_source(source, current_device, from_gateway);
                        if from_gateway_peer {
                            if let Some(peer) = self.context.state.peers.identity_for_vip(&source) {
                                self.context
                                    .state
                                    .gateway
                                    .sessions
                                    .remember_peer_ingress_gateway(peer, route_key.addr);
                            }
                        }
                        let mut gateway_echo_reply = None;
                        let mut peer_echo_reply = None;
                        let mut echo_meta = None;
                        {
                            let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
                            if ipv4.protocol() == ipv4::protocol::Protocol::Icmp
                                && ipv4.destination_ip() == destination
                            {
                                let icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
                                echo_meta = parse_icmp_echo_meta(&icmp_packet);
                                if from_gateway_peer && icmp_packet.kind() == Kind::EchoRequest {
                                    drop(icmp_packet);
                                    drop(ipv4);
                                    rewrite_peer_echo_request_as_reply(
                                        &mut net_packet,
                                        source,
                                        destination,
                                    )?;
                                    self.send_gateway_reply(
                                        &net_packet,
                                        current_device,
                                        route_key.addr,
                                    )?;
                                    return Ok(());
                                }
                                if icmp_packet.kind() == Kind::EchoReply {
                                    if source == current_device.virtual_gateway {
                                        gateway_echo_reply =
                                            Some((ipv4.source_ip(), ipv4.destination_ip()));
                                    } else if from_gateway_peer {
                                        peer_echo_reply =
                                            Some((ipv4.source_ip(), ipv4.destination_ip()));
                                    }
                                }
                            }
                        }
                        if let Some((icmp_source, icmp_destination)) = gateway_echo_reply {
                            self.context.state.debug_watch.emit(
                                "icmp",
                                "gateway_echo_reply_received",
                                serde_json::json!({
                                    "src": icmp_source.to_string(),
                                    "dst": icmp_destination.to_string(),
                                    "via": route_key.addr.to_string(),
                                    "bytes": net_packet.payload().len(),
                                    "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                    "icmp_id": echo_meta.map(|meta| meta.identifier),
                                    "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                    "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                }),
                            );
                            let written = write_full_device(
                                &self.device,
                                net_packet.payload(),
                                "gateway ip packet inject",
                            )?;
                            self.context.state.debug_watch.emit(
                                "icmp",
                                "gateway_echo_reply_injected",
                                serde_json::json!({
                                    "src": icmp_source.to_string(),
                                    "dst": icmp_destination.to_string(),
                                    "written_bytes": written,
                                    "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                    "icmp_id": echo_meta.map(|meta| meta.identifier),
                                    "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                    "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                }),
                            );
                            return Ok(());
                        }
                        if from_gateway_peer {
                            if let Some((icmp_source, icmp_destination)) = peer_echo_reply {
                                self.context.state.debug_watch.emit(
                                    "icmp",
                                    "peer_echo_reply_received",
                                    serde_json::json!({
                                        "src": icmp_source.to_string(),
                                        "dst": icmp_destination.to_string(),
                                        "via": route_key.addr.to_string(),
                                        "bytes": net_packet.payload().len(),
                                        "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                        "icmp_id": echo_meta.map(|meta| meta.identifier),
                                        "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                        "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                    }),
                                );
                            }
                            let written = write_full_device(
                                &self.device,
                                net_packet.payload(),
                                "gateway peer ip packet inject",
                            )?;
                            if let Some((icmp_source, icmp_destination)) = peer_echo_reply {
                                self.context.state.debug_watch.emit(
                                    "icmp",
                                    "peer_echo_reply_injected",
                                    serde_json::json!({
                                        "src": icmp_source.to_string(),
                                        "dst": icmp_destination.to_string(),
                                        "written_bytes": written,
                                        "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                        "icmp_id": echo_meta.map(|meta| meta.identifier),
                                        "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                        "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                    }),
                                );
                            }
                            return Ok(());
                        }
                    }
                    ip_turn_packet::Protocol::WGIpv4 => {}
                    ip_turn_packet::Protocol::Ipv4Broadcast => {}
                    ip_turn_packet::Protocol::Unknown(_) => {}
                }
            }
            Protocol::OtherTurn => {}
            Protocol::Unknown(_) => {}
        }
        Ok(())
    }
}

impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    fn send_gateway_reply<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
        current_device: &CurrentDeviceInfo,
        ingress_gateway: SocketAddr,
    ) -> anyhow::Result<()> {
        let packet_len = packet.buffer().len();
        let destination = packet.destination();
        self.context
            .state
            .data_plane_stats
            .record_logical_up(packet_len);
        self.context
            .state
            .gateway
            .sessions
            .send_relay_to_or_active(ingress_gateway, packet)?;
        self.context
            .state
            .data_plane_stats
            .record_gateway_up(packet_len);
        if destination != current_device.virtual_gateway {
            self.context
                .state
                .data_plane_stats
                .record_peer_up(destination, packet_len);
        }
        Ok(())
    }

    fn service(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        match service_packet::Protocol::from(net_packet.transport_protocol()) {
            service_packet::Protocol::RegistrationResponse => {
                self.handle_registration_response(current_device, net_packet, route_key)?
            }
            service_packet::Protocol::PushDeviceList => {
                self.handle_push_device_list(current_device, net_packet)?
            }
            service_packet::Protocol::DeviceAuthAck => {
                self.handle_device_auth_ack(current_device, net_packet, route_key)?
            }
            service_packet::Protocol::DeviceAuthChallenge => {
                self.handle_device_auth_challenge(net_packet)?
            }
            service_packet::Protocol::DeviceRenameResponse => {
                self.handle_device_rename_response(net_packet)?
            }
            service_packet::Protocol::DebugCollectRequest => {
                self.handle_debug_collect_request(current_device, net_packet)?
            }
            service_packet::Protocol::DebugWatchStartRequest => {
                self.handle_debug_watch_start_request(current_device, net_packet)?
            }
            service_packet::Protocol::DebugWatchStopRequest => {
                self.handle_debug_watch_stop_request(current_device, net_packet)?
            }
            service_packet::Protocol::DnsQueryResponse => {
                self.handle_dns_query_response(net_packet)?
            }
            service_packet::Protocol::PunchStart => {
                self.handle_punch_start(current_device, net_packet)?
            }
            service_packet::Protocol::RefreshGatewayGrantResponse => {
                self.handle_refresh_gateway_grant_response(current_device, net_packet)?
            }
            service_packet::Protocol::GatewayConnectAck => {
                self.handle_gateway_connect_ack(net_packet, route_key)?
            }
            _ => {
                log::warn!(
                    "service_packet::Protocol::Unknown = {:?}",
                    net_packet.head()
                );
            }
        }
        Ok(())
    }

    fn register(
        &self,
        current_device: &CurrentDeviceInfo,
        _route_key: RouteKey,
        allow_ip_change: bool,
    ) -> anyhow::Result<()> {
        if current_device.status.online() {
            log::info!("已连接的不需要注册，{:?}", self.context.config);
            return Ok(());
        }
        log::info!("发送注册请求，{:?}", self.context.config);
        self.context
            .services
            .control_session
            .send_registration_request(false, allow_ip_change)?;
        Ok(())
    }

    fn error(&self, net_packet: NetPacket<&mut [u8]>) -> io::Result<()> {
        match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            InErrorPacket::TokenError => {
                // token错误，可能是服务端设置了白名单
                let err = ErrorInfo::new(ErrorType::TokenError);
                self.callback.error(err);
            }
            InErrorPacket::Disconnect => {
                crate::handle::change_status(
                    &self.context.state.current_device,
                    ConnectStatus::Connecting,
                );
                let err = ErrorInfo::new(ErrorType::Disconnect);
                self.callback.error(err);
                let _device_list_update_guard = self.device_list_update_lock.lock();
                //掉线epoch要归零
                {
                    self.context.state.peers.reset_epoch();
                }
                self.context.state.peers.crypto.clear_all();
                self.context.services.control_session.send_handshake()?;
                // self.register(current_device, context, route_key)?;
            }
            InErrorPacket::AddressExhausted => {
                // 地址用尽
                let err = ErrorInfo::new(ErrorType::AddressExhausted);
                self.callback.error(err);
            }
            InErrorPacket::OtherError(e) => {
                let err = ErrorInfo::new_msg(ErrorType::Unknown, e.message()?);
                self.callback.error(err);
            }
            InErrorPacket::IpAlreadyExists => {
                let err = ErrorInfo::new(ErrorType::IpAlreadyExists);
                self.callback.error(err);
            }
            InErrorPacket::InvalidIp => {
                let err = ErrorInfo::new(ErrorType::InvalidIp);
                self.callback.error(err);
            }
            InErrorPacket::NoKey => {
                //这个类型最开头已经处理过，这里忽略
            }
        }
        Ok(())
    }

    fn control(&self, net_packet: NetPacket<&mut [u8]>, route_key: RouteKey) -> anyhow::Result<()> {
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PongPacket(pong_packet) => {
                // Gateway probes use the virtual gateway as their source, so receive
                // dispatch routes them to ServerPacketHandler rather than the normal
                // peer-side ClientPacketHandler. Consume a matching probe reply here
                // before treating it as a generic route-measurement Pong.
                if self
                    .context
                    .state
                    .gateway
                    .sessions
                    .handle_gateway_probe_pong(net_packet.source(), route_key, pong_packet.epoch())
                {
                    return Ok(());
                }
                let current_time = crate::handle::now_time() as u16;
                if current_time < pong_packet.time() {
                    return Ok(());
                }
                let metric = net_packet.origin_ttl() - net_packet.ttl() + 1;
                let from_control_or_gateway = self
                    .context
                    .services
                    .control_session
                    .is_control_addr(route_key.addr)
                    || self
                        .context
                        .state
                        .gateway
                        .sessions
                        .is_gateway_addr(route_key.addr);
                let learned_metric = if from_control_or_gateway {
                    metric.max(2)
                } else {
                    metric
                };
                let rt = (current_time - pong_packet.time()) as i64;
                let route = Route::from(route_key, learned_metric, rt);
                self.context
                    .services
                    .route_manager
                    .add_path(net_packet.source(), route);
                let epoch = self.context.state.peers.epoch();
                if pong_packet.epoch() != epoch {
                    //纪元不一致，可能有新客户端连接，向服务端拉取客户端列表
                    self.context
                        .services
                        .control_session
                        .send_service_header_only(service_packet::Protocol::PullDeviceList)?;
                }
            }
            ControlPacket::AddrResponse(addr_packet) => {
                //更新本地公网ipv4
                self.context
                    .services
                    .nat_test
                    .update_addr(addr_packet.ipv4(), addr_packet.port());
            }
            _ => {}
        }
        Ok(())
    }
}

fn rewrite_peer_echo_request_as_reply<B: AsRef<[u8]> + AsMut<[u8]>>(
    net_packet: &mut NetPacket<B>,
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> io::Result<()> {
    let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
    let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
    icmp_packet.set_kind(Kind::EchoReply);
    icmp_packet.update_checksum();
    ipv4.set_source_ip(destination);
    ipv4.set_destination_ip(source);
    ipv4.update_checksum();
    net_packet.set_source(destination);
    net_packet.set_destination(source);
    Ok(())
}

#[cfg(test)]
pub(super) mod test_util {
    use super::*;

    pub(super) fn build_icmp_echo_request_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> NetPacket<Vec<u8>> {
        let mut ipv4_payload = vec![0u8; 28];
        let ipv4_len = ipv4_payload.len() as u16;
        ipv4_payload[0] = 0x45;
        ipv4_payload[2..4].copy_from_slice(&ipv4_len.to_be_bytes());
        ipv4_payload[8] = 64;
        ipv4_payload[9] = 1;
        ipv4_payload[12..16].copy_from_slice(&source.octets());
        ipv4_payload[16..20].copy_from_slice(&destination.octets());
        ipv4_payload[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        ipv4_payload[26..28].copy_from_slice(&0x0001u16.to_be_bytes());
        {
            let mut ipv4 = IpV4Packet::new(&mut ipv4_payload).expect("ipv4 packet");
            let mut icmp = icmp::IcmpPacket::new(ipv4.payload_mut()).expect("icmp packet");
            icmp.set_kind(Kind::EchoRequest);
            icmp.update_checksum();
            ipv4.update_checksum();
        }

        let buffer = vec![0u8; 12 + ipv4_payload.len()];
        let mut packet = NetPacket::new0(buffer.len(), buffer).expect("net packet");
        packet.set_default_version();
        packet.set_protocol(Protocol::IpTurn);
        packet.set_transport_protocol_into(ip_turn_packet::Protocol::Ipv4);
        packet.set_initial_ttl(6);
        packet.set_source(source);
        packet.set_destination(destination);
        packet.set_payload(&ipv4_payload).expect("set payload");
        packet
    }

    pub(super) fn test_peer(
        vip: Ipv4Addr,
        device_pub_key_seed: u8,
        channel_mode: crate::proto::message::ChannelMode,
    ) -> PeerInfo {
        PeerInfo::new(
            vip,
            format!("peer-{device_pub_key_seed}"),
            1,
            format!("device-{device_pub_key_seed}"),
            vec![device_pub_key_seed; 32],
            vec![device_pub_key_seed.saturating_add(1); 32],
            channel_mode,
            false,
            false,
            false,
        )
    }

    pub(super) fn endpoint_fingerprint(ip: Ipv4Addr, port: u32) -> punch::PunchEndpointFingerprint {
        vec![(u32::from(ip), Vec::new(), port, false)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::connect_protocol::ConnectProtocol;
    use sdl_packet::icmp::icmp::IcmpPacket;

    #[test]
    fn rewrite_peer_echo_request_as_reply_swaps_inner_and_outer_ips() {
        let source = Ipv4Addr::new(10, 26, 0, 5);
        let destination = Ipv4Addr::new(10, 26, 0, 3);
        let mut packet = test_util::build_icmp_echo_request_packet(source, destination);

        rewrite_peer_echo_request_as_reply(&mut packet, source, destination)
            .expect("rewrite echo request");

        assert_eq!(packet.source(), destination);
        assert_eq!(packet.destination(), source);
        let ipv4 = IpV4Packet::new(packet.payload()).expect("ipv4");
        assert_eq!(ipv4.source_ip(), destination);
        assert_eq!(ipv4.destination_ip(), source);
        let icmp = IcmpPacket::new(ipv4.payload()).expect("icmp");
        assert_eq!(icmp.kind(), Kind::EchoReply);
    }

    #[test]
    fn unauthorized_server_source_drop_logger_is_callable() {
        log_sampled_unauthorized_server_source_drop(
            RouteKey::new(ConnectProtocol::UDP, "198.51.100.10:29901".parse().unwrap()),
            "203.0.113.10:4242".parse().unwrap(),
        );
    }
}
