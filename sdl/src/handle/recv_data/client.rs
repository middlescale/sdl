use anyhow::anyhow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

use protobuf::Message;

use sdl_packet::icmp::{icmp, Kind};
use sdl_packet::ip::ipv4;
use sdl_packet::ip::ipv4::packet::IpV4Packet;

use crate::core::SdlRuntime;
use crate::data_plane::route::{Route, RouteKey};
use crate::handle::extension::handle_extension_tail;
use crate::handle::recv_data::PacketHandler;
use crate::handle::CurrentDeviceInfo;
use crate::nat::punch::NatInfo;
use crate::proto::message::{PunchInfo, PunchNatType};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::{
    control_packet, ip_turn_packet, other_turn_packet, NetPacket, Protocol, MAX_TTL,
};
use crate::tun_tap_device::vnt_device::DeviceWrite;

static UNKNOWN_PEER_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static UNKNOWN_PEER_DROP_LOG_LIMITER: OnceLock<crate::util::limit::ConcurrentRateLimiter> =
    OnceLock::new();
static UNENCRYPTED_PEER_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static UNENCRYPTED_PEER_DROP_LOG_LIMITER: OnceLock<crate::util::limit::ConcurrentRateLimiter> =
    OnceLock::new();
static INVALID_CIPHER_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static INVALID_CIPHER_DROP_LOG_LIMITER: OnceLock<crate::util::limit::ConcurrentRateLimiter> =
    OnceLock::new();

fn log_sampled_drop(
    counter: &AtomicU64,
    limiter: &'static OnceLock<crate::util::limit::ConcurrentRateLimiter>,
    message: impl FnOnce(u64) -> String,
) {
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if limiter
        .get_or_init(|| crate::util::limit::ConcurrentRateLimiter::new(1, 1))
        .try_acquire()
    {
        let sampled = counter.swap(0, Ordering::Relaxed);
        let total = sampled.max(count);
        log::debug!("{}", message(total));
    }
}

fn should_bypass_peer_decrypt_for_gateway(
    source: Ipv4Addr,
    current_device: &CurrentDeviceInfo,
    via_gateway: bool,
) -> bool {
    via_gateway && source == current_device.virtual_gateway
}

/// 处理来源于客户端的包
#[derive(Clone)]
pub struct ClientPacketHandler<Device> {
    device: Device,
    runtime: Arc<SdlRuntime>,
}

impl<Device: DeviceWrite> ClientPacketHandler<Device> {
    pub fn new(runtime: Arc<SdlRuntime>, device: Device) -> Self {
        Self { device, runtime }
    }

    fn decrypt_by_route<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        route_key: RouteKey,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<bool> {
        if !net_packet.is_encrypt() {
            log_sampled_drop(
                &UNENCRYPTED_PEER_DROP_COUNT,
                &UNENCRYPTED_PEER_DROP_LOG_LIMITER,
                |count| {
                    format!(
                        "dropping unencrypted peer packets (sample via {:?}, peer={}, count={})",
                        route_key, peer_ip, count
                    )
                },
            );
            return Ok(false);
        }
        match self.runtime.peer_crypto.decrypt_ipv4(peer_ip, net_packet) {
            Ok(()) => Ok(true),
            Err(err) => {
                log_sampled_drop(
                    &INVALID_CIPHER_DROP_COUNT,
                    &INVALID_CIPHER_DROP_LOG_LIMITER,
                    |count| {
                        format!(
                            "dropping peer packets with invalid cipher (sample via {:?}, peer={}, err={:?}, count={})",
                            route_key, peer_ip, err, count
                        )
                    },
                );
                Ok(false)
            }
        }
    }

    fn encrypt_by_route<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        self.runtime
            .peer_crypto
            .send_cipher(peer_ip)?
            .encrypt_ipv4(net_packet)
    }

    fn send_reply_by_route<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        let packet_len = packet.buffer().as_ref().len();
        let destination = packet.destination();
        self.runtime.data_plane_stats.record_logical_up(packet_len);
        if self
            .runtime
            .gateway_sessions
            .is_gateway_addr(route_key.addr)
        {
            self.runtime.gateway_sessions.send_relay(packet)?;
            self.runtime.data_plane_stats.record_gateway_up(packet_len);
        } else if route_key.protocol().is_udp() {
            self.runtime
                .udp_channel
                .send_by_key(packet.buffer(), route_key)?;
        } else {
            return Err(anyhow!("unsupported reply route {:?}", route_key));
        }
        let gateway_vip = self.runtime.current_device.load().virtual_gateway;
        if destination != gateway_vip {
            self.runtime
                .data_plane_stats
                .record_peer_up(destination, packet_len);
        }
        Ok(())
    }
}

impl<Device: DeviceWrite> PacketHandler for ClientPacketHandler<Device> {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        mut extend: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        let source = net_packet.source();
        let via_gateway = self
            .runtime
            .gateway_sessions
            .is_gateway_addr(route_key.addr);
        if source != current_device.virtual_gateway && self.runtime.peer_info(&source).is_none() {
            log_sampled_drop(
                &UNKNOWN_PEER_DROP_COUNT,
                &UNKNOWN_PEER_DROP_LOG_LIMITER,
                |count| {
                    format!(
                        "dropping packets from unknown peer (sample via {:?}, peer={}, count={})",
                        route_key, source, count
                    )
                },
            );
            return Ok(());
        }
        if !should_bypass_peer_decrypt_for_gateway(source, current_device, via_gateway)
            && !self.decrypt_by_route(&source, route_key, &mut net_packet)?
        {
            return Ok(());
        }
        let packet_len = net_packet.buffer().as_ref().len();
        self.runtime
            .data_plane_stats
            .record_logical_down(packet_len);
        if source != current_device.virtual_gateway {
            self.runtime
                .data_plane_stats
                .record_peer_down(source, packet_len);
        }
        if via_gateway {
            self.runtime
                .data_plane_stats
                .record_gateway_down(packet_len);
        }
        if self
            .runtime
            .route_manager()
            .has_direct_path(&source, &route_key)
        {
            self.runtime.route_manager().touch_path(&source, &route_key);
        }
        //处理扩展
        let net_packet = if net_packet.is_extension() {
            //这样重用数组，减少一次数据拷贝
            if handle_extension_tail(&mut net_packet, &mut extend)? {
                extend
            } else {
                net_packet
            }
        } else {
            net_packet
        };
        match net_packet.protocol() {
            Protocol::Service => {}
            Protocol::Error => {}
            Protocol::Control => {
                self.control(current_device, net_packet, route_key)?;
            }
            Protocol::IpTurn => {
                self.ip_turn(net_packet, current_device, route_key)?;
            }
            Protocol::OtherTurn => {
                self.other_turn(current_device, net_packet, route_key)?;
            }
            Protocol::Unknown(_) => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::should_bypass_peer_decrypt_for_gateway;
    use crate::data_plane::route::RouteKey;
    use crate::handle::CurrentDeviceInfo;
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::net::Ipv4Addr;

    #[test]
    fn bypasses_peer_decrypt_for_virtual_gateway_packets_via_gateway() {
        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        let route_key = RouteKey::new(ConnectProtocol::UDP, "120.78.210.64:29901".parse().unwrap());
        assert!(should_bypass_peer_decrypt_for_gateway(
            current_device.virtual_gateway,
            &current_device,
            route_key.protocol().is_udp()
        ));
    }

    #[test]
    fn does_not_bypass_peer_decrypt_for_non_gateway_source() {
        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        assert!(!should_bypass_peer_decrypt_for_gateway(
            Ipv4Addr::new(10, 26, 0, 5),
            &current_device,
            true
        ));
    }

    #[test]
    fn does_not_bypass_peer_decrypt_for_gateway_source_on_non_gateway_route() {
        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );
        assert!(!should_bypass_peer_decrypt_for_gateway(
            current_device.virtual_gateway,
            &current_device,
            false
        ));
    }
}

impl<Device: DeviceWrite> ClientPacketHandler<Device> {
    fn ip_turn(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        current_device: &CurrentDeviceInfo,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        let destination = net_packet.destination();
        let source = net_packet.source();
        match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
            ip_turn_packet::Protocol::Ipv4 => {
                let mut log_peer_echo_reply = None;
                {
                    let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
                    if ipv4.protocol() == ipv4::protocol::Protocol::Icmp
                        && ipv4.destination_ip() == destination
                    {
                        let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
                        if icmp_packet.kind() == Kind::EchoRequest {
                            //开启ping
                            icmp_packet.set_kind(Kind::EchoReply);
                            icmp_packet.update_checksum();
                            ipv4.set_source_ip(destination);
                            ipv4.set_destination_ip(source);
                            ipv4.update_checksum();
                            net_packet.set_source(destination);
                            net_packet.set_destination(source);
                            self.encrypt_by_route(&source, &mut net_packet)?;
                            self.send_reply_by_route(&net_packet, route_key)?;
                            return Ok(());
                        } else if icmp_packet.kind() == Kind::EchoReply {
                            log_peer_echo_reply = Some((ipv4.source_ip(), ipv4.destination_ip()));
                        }
                    }
                    // ip代理只关心实际目标
                    let real_dest = ipv4.destination_ip();
                    if real_dest != destination
                        && !(real_dest.is_broadcast()
                            || real_dest.is_multicast()
                            || real_dest == current_device.broadcast_ip
                            || real_dest.is_unspecified())
                    {
                        if !self.runtime.out_external_route.allow(&real_dest) {
                            //拦截不符合的目标
                            return Ok(());
                        }
                        match ipv4.protocol() {
                            ipv4::protocol::Protocol::Tcp => {
                                let payload = ipv4.payload();
                                if payload.len() < 20 {
                                    return Ok(());
                                }
                                let _destination_port =
                                    u16::from_be_bytes(payload[2..4].try_into().unwrap());
                            }
                            ipv4::protocol::Protocol::Udp => {
                                let payload = ipv4.payload();
                                if payload.len() < 8 {
                                    return Ok(());
                                }
                                let destination_port =
                                    u16::from_be_bytes(payload[2..4].try_into().unwrap());
                                if self
                                    .runtime
                                    .nat_test
                                    .is_local_udp(real_dest, destination_port)
                                {
                                    return Ok(());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if let Some((icmp_source, icmp_destination)) = log_peer_echo_reply {
                    log::debug!(
                        "peer icmp echo reply received src={} dst={} via={} bytes={}",
                        icmp_source,
                        icmp_destination,
                        route_key.addr,
                        net_packet.payload().len()
                    );
                    self.runtime.debug_watch.emit(
                        "icmp",
                        "peer_echo_reply_received",
                        serde_json::json!({
                            "src": icmp_source.to_string(),
                            "dst": icmp_destination.to_string(),
                            "via": route_key.addr.to_string(),
                            "bytes": net_packet.payload().len(),
                        }),
                    );
                }
                let written = self.device.write(net_packet.payload())?;
                if let Some((icmp_source, icmp_destination)) = log_peer_echo_reply {
                    log::debug!(
                        "peer icmp echo reply injected into tun src={} dst={} written_bytes={}",
                        icmp_source,
                        icmp_destination,
                        written
                    );
                    self.runtime.debug_watch.emit(
                        "icmp",
                        "peer_echo_reply_injected",
                        serde_json::json!({
                            "src": icmp_source.to_string(),
                            "dst": icmp_destination.to_string(),
                            "written_bytes": written,
                        }),
                    );
                }
            }
            ip_turn_packet::Protocol::WGIpv4 => {
                // WG客户端的数据不会直接发过来，不用处理
            }
            ip_turn_packet::Protocol::Ipv4Broadcast => {
                //客户端不帮忙转发广播包，所以不会出现这种类型的数据
            }
            ip_turn_packet::Protocol::Unknown(_) => {}
        }
        Ok(())
    }
    fn control(
        &self,
        current_device: &CurrentDeviceInfo,
        mut net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        let metric = net_packet.origin_ttl() - net_packet.ttl() + 1;
        let source = net_packet.source();
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PingPacket(_) => {
                net_packet.set_transport_protocol(control_packet::Protocol::Pong.into());
                net_packet.set_source(current_device.virtual_ip);
                net_packet.set_destination(source);
                net_packet.set_initial_ttl(MAX_TTL);
                self.encrypt_by_route(&source, &mut net_packet)?;
                self.send_reply_by_route(&net_packet, route_key)?;
            }
            ControlPacket::PongPacket(pong_packet) => {
                let current_time = crate::handle::now_time() as u16;
                if current_time < pong_packet.time() {
                    return Ok(());
                }
                if !self.runtime.peer_probe_tracker.match_ping_response(
                    source,
                    route_key,
                    pong_packet.epoch(),
                ) {
                    return Ok(());
                }
                let rt = (current_time - pong_packet.time()) as i64;
                let route = Route::from(route_key, metric, rt);
                self.runtime.route_manager().add_path(source, route);
            }
            ControlPacket::PunchRequest => {
                log::info!("PunchRequest={:?},source={}", route_key, source);
                if self
                    .runtime
                    .route_manager
                    .use_channel_type()
                    .is_only_relay()
                {
                    return Ok(());
                }
                //忽略掉来源于自己的包
                if self
                    .runtime
                    .nat_test
                    .is_local_address(route_key.protocol().is_base_tcp(), route_key.addr)
                {
                    return Ok(());
                }

                //回应
                net_packet.set_transport_protocol(control_packet::Protocol::PunchResponse.into());
                net_packet.set_source(current_device.virtual_ip);
                net_packet.set_destination(source);
                net_packet.set_initial_ttl(1);
                self.encrypt_by_route(&source, &mut net_packet)?;
                self.send_reply_by_route(&net_packet, route_key)?;
                // 收到PunchRequest就添加路由，会导致单向通信的问题，删掉试试
                // let route = Route::from_default_rt(route_key, 1);
                // context.route_table.add_route_if_absent(source, route);
            }
            ControlPacket::PunchResponse => {
                log::info!("PunchResponse={:?},source={}", route_key, source);
                if self
                    .runtime
                    .route_manager
                    .use_channel_type()
                    .is_only_relay()
                {
                    return Ok(());
                }
                if self
                    .runtime
                    .nat_test
                    .is_local_address(route_key.protocol().is_base_tcp(), route_key.addr)
                {
                    return Ok(());
                }
                if !self
                    .runtime
                    .peer_probe_tracker
                    .match_punch_response(source, route_key.addr)
                {
                    return Ok(());
                }
                let route = Route::from_default_rt(route_key, metric);
                self.runtime
                    .route_manager()
                    .add_path_if_absent(source, route);
            }
            ControlPacket::AddrRequest => match route_key.addr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    let mut packet = NetPacket::new_encrypt([0; 12 + 6 + ENCRYPTION_RESERVED])?;
                    packet.set_default_version();
                    packet.set_protocol(Protocol::Control);
                    packet.set_transport_protocol(control_packet::Protocol::AddrResponse.into());
                    packet.set_initial_ttl(MAX_TTL);
                    packet.set_source(current_device.virtual_ip);
                    packet.set_destination(source);
                    let mut addr_packet = control_packet::AddrPacket::new(packet.payload_mut())?;
                    addr_packet.set_ipv4(ipv4);
                    addr_packet.set_port(route_key.addr.port());
                    self.encrypt_by_route(&source, &mut packet)?;
                    self.send_reply_by_route(&packet, route_key)?;
                }
                std::net::IpAddr::V6(_) => {}
            },
            ControlPacket::AddrResponse(_) => {}
        }
        Ok(())
    }
    fn other_turn(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        if self
            .runtime
            .route_manager
            .use_channel_type()
            .is_only_relay()
        {
            return Ok(());
        }
        let source = net_packet.source();
        match other_turn_packet::Protocol::from(net_packet.transport_protocol()) {
            other_turn_packet::Protocol::Punch => {
                let punch_info = PunchInfo::parse_from_bytes(net_packet.payload())
                    .map_err(|e| anyhow!("PunchInfo {:?}", e))?;
                let public_udp_endpoints: Vec<std::net::SocketAddr> = punch_info
                    .public_udp_endpoints
                    .iter()
                    .filter_map(|endpoint| {
                        if endpoint.port == 0 {
                            return None;
                        }
                        if endpoint.ip != 0 {
                            return Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                                Ipv4Addr::from(endpoint.ip),
                                endpoint.port as u16,
                            )));
                        }
                        if endpoint.ipv6.len() == 16 {
                            let ipv6: [u8; 16] = endpoint.ipv6.clone().try_into().ok()?;
                            return Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                                Ipv6Addr::from(ipv6),
                                endpoint.port as u16,
                                0,
                                0,
                            )));
                        }
                        None
                    })
                    .collect();
                let local_udp_endpoints: Vec<std::net::SocketAddr> = punch_info
                    .local_udp_endpoints
                    .iter()
                    .filter_map(|endpoint| {
                        if endpoint.port == 0 {
                            return None;
                        }
                        if endpoint.ip != 0 {
                            return Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                                Ipv4Addr::from(endpoint.ip),
                                endpoint.port as u16,
                            )));
                        }
                        if endpoint.ipv6.len() == 16 {
                            let ipv6: [u8; 16] = endpoint.ipv6.clone().try_into().ok()?;
                            return Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                                Ipv6Addr::from(ipv6),
                                endpoint.port as u16,
                                0,
                                0,
                            )));
                        }
                        None
                    })
                    .collect();
                let public_ips = public_udp_endpoints
                    .iter()
                    .filter_map(|addr| match addr {
                        std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
                        std::net::SocketAddr::V6(_) => None,
                    })
                    .collect();
                let public_ports = public_udp_endpoints
                    .iter()
                    .map(|addr| addr.port())
                    .collect();
                let local_ipv4 = local_udp_endpoints.iter().find_map(|addr| match addr {
                    std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
                    std::net::SocketAddr::V6(_) => None,
                });
                let ipv6 = local_udp_endpoints.iter().find_map(|addr| match addr {
                    std::net::SocketAddr::V4(_) => None,
                    std::net::SocketAddr::V6(addr) => Some(*addr.ip()),
                });
                let udp_ports = local_udp_endpoints.iter().map(|addr| addr.port()).collect();
                let peer_nat_info = NatInfo::new(
                    public_ips,
                    public_ports,
                    public_udp_endpoints,
                    punch_info.public_port_range as u16,
                    local_ipv4,
                    ipv6,
                    udp_ports,
                    punch_info.nat_type.enum_value_or_default().into(),
                    punch_info.punch_model.enum_value_or_default().into(),
                );
                {
                    let peer_nat_info = peer_nat_info.clone();
                    self.runtime
                        .peer_nat_info_map
                        .write()
                        .insert(source, peer_nat_info);
                }
                if !punch_info.reply {
                    let mut punch_reply = PunchInfo::new();
                    punch_reply.reply = true;
                    let nat_info = self.runtime.nat_test.nat_info();
                    punch_reply.public_port_range = nat_info.public_port_range as u32;
                    punch_reply.nat_type =
                        protobuf::EnumOrUnknown::new(PunchNatType::from(nat_info.nat_type));
                    punch_reply.punch_model =
                        protobuf::EnumOrUnknown::new(nat_info.punch_model.into());
                    punch_reply.public_udp_endpoints = nat_info
                        .public_udp_endpoints
                        .iter()
                        .map(|addr| {
                            let mut endpoint = crate::proto::message::PunchEndpoint::new();
                            endpoint.port = u32::from(addr.port());
                            match addr {
                                std::net::SocketAddr::V4(addr) => {
                                    endpoint.ip = u32::from(*addr.ip());
                                }
                                std::net::SocketAddr::V6(addr) => {
                                    endpoint.ipv6 = addr.ip().octets().to_vec();
                                }
                            }
                            endpoint
                        })
                        .collect();
                    punch_reply.local_udp_endpoints = nat_info
                        .local_udp_endpoints()
                        .into_iter()
                        .map(|addr| {
                            let mut endpoint = crate::proto::message::PunchEndpoint::new();
                            endpoint.port = u32::from(addr.port());
                            match addr {
                                std::net::SocketAddr::V4(addr) => {
                                    endpoint.ip = u32::from(*addr.ip());
                                }
                                std::net::SocketAddr::V6(addr) => {
                                    endpoint.ipv6 = addr.ip().octets().to_vec();
                                }
                            }
                            endpoint
                        })
                        .collect();
                    let bytes = punch_reply
                        .write_to_bytes()
                        .map_err(|e| anyhow!("punch_reply {:?}", e))?;
                    let mut punch_packet =
                        NetPacket::new_encrypt(vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED])?;
                    punch_packet.set_default_version();
                    punch_packet.set_protocol(Protocol::OtherTurn);
                    punch_packet.set_transport_protocol(other_turn_packet::Protocol::Punch.into());
                    punch_packet.set_initial_ttl(MAX_TTL);
                    punch_packet.set_source(current_device.virtual_ip());
                    punch_packet.set_destination(source);
                    punch_packet.set_payload(&bytes)?;
                    self.encrypt_by_route(&source, &mut punch_packet)?;
                    if self
                        .runtime
                        .punch_coordinator
                        .submit_from_peer(source, peer_nat_info)
                    {
                        self.runtime
                            .udp_channel
                            .send_by_key(punch_packet.buffer(), route_key)?;
                    }
                } else {
                    self.runtime
                        .punch_coordinator
                        .submit_local(source, peer_nat_info);
                }
            }
            other_turn_packet::Protocol::Unknown(e) => {
                log::warn!("不支持的转发协议 {:?},source:{:?}", e, source);
            }
        }
        Ok(())
    }
}
