use anyhow::anyhow;
use std::net::Ipv4Addr;
use std::sync::Arc;

use sdl_packet::icmp::{icmp, Kind};
use sdl_packet::ip::ipv4;
use sdl_packet::ip::ipv4::packet::IpV4Packet;

use crate::cipher::CipherModel;
use crate::core::SdlRuntime;
use crate::data_plane::route::{Route, RouteOrigin, RoutePath};
use crate::handle::extension::handle_extension_tail;
use crate::handle::recv_data::PacketHandler;
use crate::handle::CurrentDeviceInfo;
use crate::nat::punch::NatInfo;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::peer_discovery_packet::{
    DiscoverySessionId, EndpointInfoPayload, PeerDiscoveryPacket, DISCOVERY_SESSION_LEN,
};
use crate::protocol::{
    control_packet, ip_turn_packet, peer_discovery_packet, NetPacket, Protocol, MAX_TTL,
};
use crate::tun_tap_device::vnt_device::DeviceWrite;
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
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if !peer_packet_encryption_matches(
            self.runtime.config.cipher_model,
            net_packet.is_encrypt(),
        ) {
            anyhow::bail!(
                "unexpected peer packet encryption flag for cipher model {:?}",
                self.runtime.config.cipher_model
            );
        }
        if !net_packet.is_encrypt() {
            return Ok(());
        }
        if net_packet.protocol() == Protocol::PeerDiscovery {
            return self.discovery_cipher(peer_ip)?.decrypt_ipv4(net_packet);
        }
        self.runtime.peer_crypto.decrypt_ipv4(peer_ip, net_packet)
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

    fn matches_active_peer_discovery_session(
        &self,
        peer_ip: &Ipv4Addr,
        session_id: DiscoverySessionId,
        require_txid: bool,
    ) -> bool {
        let Some(session) = self.runtime.peer_discovery_session(peer_ip) else {
            return false;
        };
        let now_ms = crate::handle::now_time() as i64;
        if session.deadline_unix_ms > 0 && now_ms > session.deadline_unix_ms {
            self.runtime.clear_peer_discovery_session(peer_ip);
            return false;
        }
        if require_txid {
            session_id.same_transaction(&session.session_id)
        } else {
            session_id.same_attempt(&session.session_id)
        }
    }

    fn discovery_cipher(&self, peer_ip: &Ipv4Addr) -> anyhow::Result<crate::cipher::Cipher> {
        let peer_info = self
            .runtime
            .peer_info(peer_ip)
            .ok_or_else(|| anyhow!("missing peer identity for discovery {}", peer_ip))?;
        let key = crate::util::derive_peer_discovery_bootstrap_key(
            &self.runtime.device_signing_key,
            &peer_info.device_pub_key,
        )?;
        crate::cipher::Cipher::new_key(key)
    }

    fn encrypt_peer_discovery<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        peer_ip: &Ipv4Addr,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        self.discovery_cipher(peer_ip)?.encrypt_ipv4(net_packet)
    }

    fn send_reply_by_route<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
        route_key: RoutePath,
    ) -> anyhow::Result<()> {
        if self
            .runtime
            .gateway_sessions
            .is_gateway_addr(route_key.addr())
        {
            self.runtime.gateway_sessions.send_relay(packet)?;
        } else if route_key.protocol().is_udp() {
            self.runtime
                .udp_channel
                .send_by_key(packet.buffer(), route_key)?;
        } else {
            return Err(anyhow!("unsupported reply route {:?}", route_key));
        }
        Ok(())
    }
}

impl<Device: DeviceWrite> PacketHandler for ClientPacketHandler<Device> {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        mut extend: NetPacket<&mut [u8]>,
        route_path: RoutePath,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        let v_source = net_packet.source();
        let direct_owner = self
            .runtime
            .route_manager()
            .peer_for_direct_route(&route_path);
        if requires_unknown_route_ingress_limit(route_path, direct_owner)
            && !self
                .runtime
                .unknown_peer_ingress_limiter
                .allow(route_path.addr())
        {
            log::debug!(
                "drop rate-limited unknown-route peer packet source={} route_path={:?}",
                v_source,
                route_path
            );
            return Ok(());
        }
        if !peer_packet_encryption_matches(
            self.runtime.config.cipher_model,
            net_packet.is_encrypt(),
        ) {
            log::warn!(
                "drop peer packet with unexpected encryption flag source={} route_path={:?} encrypt={} cipher_model={:?}",
                v_source,
                route_path,
                net_packet.is_encrypt(),
                self.runtime.config.cipher_model
            );
            return Ok(());
        }
        if v_source != current_device.virtual_gateway && self.runtime.peer_info(&v_source).is_none()
        {
            log::debug!(
                "drop packet from unknown peer {} via {:?}",
                v_source,
                route_path
            );
            return Ok(());
        }
        if !should_accept_peer_packet(
            route_path,
            v_source,
            direct_owner,
            net_packet.protocol(),
            net_packet.transport_protocol(),
        ) {
            log::warn!(
                "drop peer packet source={} route_path={:?} protocol={:?}/{} direct_owner={:?}",
                v_source,
                route_path,
                net_packet.protocol(),
                net_packet.transport_protocol(),
                direct_owner
            );
            return Ok(());
        }
        if !matches_expected_unknown_route_setup_endpoint(
            route_path,
            direct_owner,
            v_source,
            net_packet.protocol(),
            net_packet.transport_protocol(),
            self.runtime.peer_nat_info_map.read().get(&v_source),
        ) {
            log::warn!(
                "drop peer setup from unexpected endpoint source={} route_path={:?} protocol={:?}/{}",
                v_source,
                route_path,
                net_packet.protocol(),
                net_packet.transport_protocol()
            );
            return Ok(());
        }
        if requires_unknown_route_setup_limit(
            route_path,
            direct_owner,
            net_packet.protocol(),
            net_packet.transport_protocol(),
        ) && !self
            .runtime
            .unknown_peer_setup_limiter
            .allow(route_path.addr())
        {
            log::warn!(
                "drop rate-limited setup packet source={} route_path={:?}",
                v_source,
                route_path
            );
            return Ok(());
        }
        if net_packet.is_encrypt()
            && !self.runtime.peer_replay_guard.check_and_remember(
                v_source,
                crate::util::PeerReplayId::from_aes_gcm_packet(&net_packet)?,
            )
        {
            log::warn!(
                "drop replayed peer packet source={} route_path={:?}",
                v_source,
                route_path
            );
            return Ok(());
        }
        self.decrypt_by_route(&v_source, &mut net_packet)?;
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
        if should_touch_path_on_receive(net_packet.protocol()) {
            self.runtime
                .route_manager()
                .touch_path(&v_source, &route_path);
        }
        match net_packet.protocol() {
            Protocol::Service => {}
            Protocol::Error => {}
            Protocol::Control => {
                self.control(current_device, net_packet, route_path)?;
            }
            Protocol::IpTurn => {
                self.ip_turn(net_packet, current_device, route_path)?;
            }
            Protocol::OtherTurn => {
                self.other_turn(current_device, net_packet, route_path)?;
            }
            Protocol::PeerDiscovery => {
                self.peer_discovery(current_device, net_packet, route_path)?;
            }
            Protocol::Unknown(_) => {}
        }
        Ok(())
    }
}

fn should_accept_peer_packet(
    route_path: RoutePath,
    source: Ipv4Addr,
    direct_owner: Option<Ipv4Addr>,
    protocol: Protocol,
    transport_protocol: u8,
) -> bool {
    if route_path.origin() != RouteOrigin::PeerUdp {
        return true;
    }
    match direct_owner {
        Some(owner) => owner == source,
        None => {
            protocol == Protocol::PeerDiscovery && allows_unknown_route_setup(transport_protocol)
        }
    }
}

fn requires_unknown_route_setup_limit(
    route_path: RoutePath,
    direct_owner: Option<Ipv4Addr>,
    protocol: Protocol,
    transport_protocol: u8,
) -> bool {
    route_path.origin() == RouteOrigin::PeerUdp
        && direct_owner.is_none()
        && protocol == Protocol::PeerDiscovery
        && allows_unknown_route_setup(transport_protocol)
}

fn requires_unknown_route_ingress_limit(
    route_path: RoutePath,
    direct_owner: Option<Ipv4Addr>,
) -> bool {
    route_path.origin() == RouteOrigin::PeerUdp && direct_owner.is_none()
}

fn matches_expected_unknown_route_setup_endpoint(
    route_path: RoutePath,
    direct_owner: Option<Ipv4Addr>,
    source: Ipv4Addr,
    protocol: Protocol,
    transport_protocol: u8,
    peer_nat_info: Option<&NatInfo>,
) -> bool {
    if !requires_unknown_route_setup_limit(route_path, direct_owner, protocol, transport_protocol) {
        return true;
    }
    let Some(peer_nat_info) = peer_nat_info else {
        log::debug!(
            "missing peer nat info for unknown-route setup source={} route_path={:?}",
            source,
            route_path
        );
        return false;
    };
    peer_nat_info.matches_candidate_endpoint(route_path.addr())
}

fn local_is_authoritative_discovery_initiator(local_vip: Ipv4Addr, peer_vip: Ipv4Addr) -> bool {
    u32::from(local_vip) < u32::from(peer_vip)
}

#[cfg(test)]
fn allows_unknown_route_control(transport_protocol: u8) -> bool {
    matches!(
        control_packet::Protocol::from(transport_protocol),
        control_packet::Protocol::Ping | control_packet::Protocol::Pong
    )
}

fn allows_unknown_route_setup(transport_protocol: u8) -> bool {
    matches!(
        peer_discovery_packet::Protocol::from(transport_protocol),
        peer_discovery_packet::Protocol::Hello
            | peer_discovery_packet::Protocol::HelloAck
            | peer_discovery_packet::Protocol::EndpointInfo
    )
}

fn peer_packet_encryption_matches(cipher_model: CipherModel, is_encrypt: bool) -> bool {
    match cipher_model {
        _ => is_encrypt,
    }
}

fn should_touch_path_on_receive(protocol: Protocol) -> bool {
    protocol != Protocol::PeerDiscovery
}

#[cfg(test)]
mod tests {
    use super::{
        allows_unknown_route_control, allows_unknown_route_setup,
        matches_expected_unknown_route_setup_endpoint, peer_packet_encryption_matches,
        requires_unknown_route_ingress_limit, requires_unknown_route_setup_limit,
        should_accept_peer_packet, should_touch_path_on_receive,
    };
    use crate::cipher::CipherModel;
    use crate::data_plane::route::{RouteOrigin, RoutePath};
    use crate::nat::punch::{NatInfo, NatType, PunchModel};
    use crate::protocol::{control_packet, peer_discovery_packet, Protocol};
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn peer_route_key() -> RoutePath {
        RoutePath::new_with_origin(
            ConnectProtocol::UDP,
            RouteOrigin::PeerUdp,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 4000)),
        )
    }

    fn peer_nat_info(endpoint: SocketAddr) -> NatInfo {
        NatInfo::new(
            vec![Ipv4Addr::new(198, 51, 100, 10)],
            vec![endpoint.port()],
            vec![endpoint],
            0,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            None,
            vec![endpoint.port()],
            NatType::Cone,
            PunchModel::IPv4Udp,
        )
    }

    #[test]
    fn unknown_peer_route_only_allows_peer_discovery_packets() {
        let source = Ipv4Addr::new(10, 0, 0, 9);
        let route_key = peer_route_key();

        assert!(should_accept_peer_packet(
            route_key,
            source,
            None,
            Protocol::PeerDiscovery,
            peer_discovery_packet::Protocol::Hello.into()
        ));
        assert!(!should_accept_peer_packet(
            route_key,
            source,
            None,
            Protocol::IpTurn,
            0
        ));
        assert!(!should_accept_peer_packet(
            route_key,
            source,
            None,
            Protocol::Control,
            control_packet::Protocol::Ping.into()
        ));
        assert!(!should_accept_peer_packet(
            route_key,
            source,
            None,
            Protocol::Control,
            control_packet::Protocol::AddrRequest.into()
        ));
    }

    #[test]
    fn direct_route_binding_rejects_packets_for_different_peer() {
        let route_key = peer_route_key();
        let source = Ipv4Addr::new(10, 0, 0, 9);
        let other_peer = Ipv4Addr::new(10, 0, 0, 10);

        assert!(should_accept_peer_packet(
            route_key,
            source,
            Some(source),
            Protocol::IpTurn,
            0
        ));
        assert!(!should_accept_peer_packet(
            route_key,
            source,
            Some(other_peer),
            Protocol::Control,
            0
        ));
    }

    #[test]
    fn non_peer_origins_skip_direct_route_gate() {
        let route_key = RoutePath::new_with_origin(
            ConnectProtocol::QUIC,
            RouteOrigin::GatewayQuic,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 11), 443)),
        );

        assert!(should_accept_peer_packet(
            route_key,
            Ipv4Addr::new(10, 0, 0, 9),
            None,
            Protocol::IpTurn,
            0
        ));
    }

    #[test]
    fn unknown_peer_route_setup_limiter_only_targets_setup_packets() {
        let route_key = peer_route_key();

        assert!(requires_unknown_route_setup_limit(
            route_key,
            None,
            Protocol::PeerDiscovery,
            peer_discovery_packet::Protocol::Hello.into()
        ));
        assert!(requires_unknown_route_setup_limit(
            route_key,
            None,
            Protocol::PeerDiscovery,
            peer_discovery_packet::Protocol::EndpointInfo.into()
        ));
        assert!(!requires_unknown_route_setup_limit(
            route_key,
            None,
            Protocol::IpTurn,
            0
        ));
        assert!(!requires_unknown_route_setup_limit(
            route_key,
            Some(Ipv4Addr::new(10, 0, 0, 9)),
            Protocol::Control,
            control_packet::Protocol::Ping.into()
        ));
        assert!(!requires_unknown_route_setup_limit(
            route_key,
            None,
            Protocol::Control,
            control_packet::Protocol::AddrRequest.into()
        ));
    }

    #[test]
    fn unknown_peer_route_ingress_limiter_targets_all_unknown_peer_udp_paths() {
        let route_key = peer_route_key();

        assert!(requires_unknown_route_ingress_limit(route_key, None));
        assert!(!requires_unknown_route_ingress_limit(
            route_key,
            Some(Ipv4Addr::new(10, 0, 0, 9))
        ));
        assert!(!requires_unknown_route_ingress_limit(
            RoutePath::new_with_origin(
                ConnectProtocol::QUIC,
                RouteOrigin::GatewayQuic,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 11), 443)),
            ),
            None
        ));
    }

    #[test]
    fn unknown_route_setup_requires_expected_candidate_endpoint() {
        let route_key = RoutePath::new_with_origin(
            ConnectProtocol::UDP,
            RouteOrigin::PeerUdp,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 4000)),
        );
        let source = Ipv4Addr::new(10, 0, 0, 9);
        let allowed = peer_nat_info(route_key.addr());
        let denied = peer_nat_info(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 1),
            4001,
        )));

        assert!(matches_expected_unknown_route_setup_endpoint(
            route_key,
            None,
            source,
            Protocol::PeerDiscovery,
            peer_discovery_packet::Protocol::Hello.into(),
            Some(&allowed),
        ));
        assert!(!matches_expected_unknown_route_setup_endpoint(
            route_key,
            None,
            source,
            Protocol::PeerDiscovery,
            peer_discovery_packet::Protocol::Hello.into(),
            Some(&denied),
        ));
        assert!(!matches_expected_unknown_route_setup_endpoint(
            route_key,
            None,
            source,
            Protocol::PeerDiscovery,
            peer_discovery_packet::Protocol::Hello.into(),
            None,
        ));
    }

    #[test]
    fn peer_packet_encryption_must_match_runtime_cipher_mode() {
        assert!(peer_packet_encryption_matches(CipherModel::AesGcm, true));
        assert!(!peer_packet_encryption_matches(CipherModel::AesGcm, false));
    }

    #[test]
    fn peer_discovery_packets_do_not_refresh_generic_route_activity() {
        assert!(!should_touch_path_on_receive(Protocol::PeerDiscovery));
        assert!(should_touch_path_on_receive(Protocol::IpTurn));
    }

    #[test]
    fn unknown_route_control_whitelist_excludes_addr_discovery_packets() {
        assert!(allows_unknown_route_control(
            control_packet::Protocol::Ping.into()
        ));
        assert!(!allows_unknown_route_control(
            control_packet::Protocol::AddrRequest.into()
        ));
        assert!(!allows_unknown_route_control(
            control_packet::Protocol::AddrResponse.into()
        ));
    }

    #[test]
    fn unknown_route_setup_whitelist_only_allows_peer_discovery_packets() {
        assert!(allows_unknown_route_setup(
            peer_discovery_packet::Protocol::Hello.into()
        ));
        assert!(allows_unknown_route_setup(
            peer_discovery_packet::Protocol::HelloAck.into()
        ));
        assert!(allows_unknown_route_setup(
            peer_discovery_packet::Protocol::EndpointInfo.into()
        ));
        assert!(!allows_unknown_route_setup(200));
    }
}

impl<Device: DeviceWrite> ClientPacketHandler<Device> {
    fn ip_turn(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        current_device: &CurrentDeviceInfo,
        route_key: RoutePath,
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
                        route_key.addr(),
                        net_packet.payload().len()
                    );
                    self.runtime.debug_watch.emit(
                        "icmp",
                        "peer_echo_reply_received",
                        serde_json::json!({
                            "src": icmp_source.to_string(),
                            "dst": icmp_destination.to_string(),
                            "via": route_key.addr().to_string(),
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
        route_key: RoutePath,
    ) -> anyhow::Result<()> {
        let metric = net_packet.origin_ttl() - net_packet.ttl() + 1;
        let source = net_packet.source();
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PingPacket(_) => {
                let route = Route::from_default_rt(route_key, metric);
                self.runtime
                    .route_manager()
                    .add_path_if_absent(source, route);
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
                let rt = (current_time - pong_packet.time()) as i64;
                let route = Route::from(route_key, metric, rt);
                self.runtime.route_manager().add_path(source, route);
            }
            ControlPacket::AddrRequest => match route_key.addr().ip() {
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
                    addr_packet.set_port(route_key.addr().port());
                    self.encrypt_by_route(&source, &mut packet)?;
                    self.send_reply_by_route(&packet, route_key)?;
                }
                std::net::IpAddr::V6(_) => {}
            },
            ControlPacket::AddrResponse(_) => {}
        }
        Ok(())
    }
    fn peer_discovery(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RoutePath,
    ) -> anyhow::Result<()> {
        let metric = net_packet.origin_ttl() - net_packet.ttl() + 1;
        let source = net_packet.source();
        match PeerDiscoveryPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            PeerDiscoveryPacket::Hello {
                session: session_id,
                payload,
            } => {
                if !self.matches_active_peer_discovery_session(&source, session_id, false) {
                    log::warn!(
                        "drop peer discovery hello without active session source={} route_key={:?} session_id={} attempt={} txid={}",
                        source,
                        route_key,
                        session_id.session_id(),
                        session_id.attempt(),
                        session_id.txid()
                    );
                    return Ok(());
                }
                log::info!(
                    "PeerDiscoveryHello route_key={:?},source={}",
                    route_key,
                    source
                );
                if self
                    .runtime
                    .nat_test
                    .is_local_address(route_key.protocol().is_base_tcp(), route_key.addr())
                {
                    return Ok(());
                }

                let Some(peer_info) = self.runtime.peer_info(&source) else {
                    log::warn!(
                        "drop peer discovery hello without peer identity source={}",
                        source
                    );
                    return Ok(());
                };
                let mut responder = match crate::util::build_peer_discovery_noise_responder(
                    &self.runtime.device_signing_key,
                    &peer_info.device_pub_key,
                    session_id,
                    source,
                    current_device.virtual_ip,
                ) {
                    Ok(responder) => responder,
                    Err(err) => {
                        log::warn!(
                            "drop peer discovery hello with invalid identity source={} err={:?}",
                            source,
                            err
                        );
                        return Ok(());
                    }
                };
                if let Err(err) = responder.read_hello(payload) {
                    log::warn!(
                        "drop peer discovery hello with invalid noise payload source={} err={:?}",
                        source,
                        err
                    );
                    return Ok(());
                }
                let hello_ack_payload = match responder.write_hello_ack(&[]) {
                    Ok(payload) => payload,
                    Err(err) => {
                        log::warn!(
                            "drop peer discovery hello when building ack source={} err={:?}",
                            source,
                            err
                        );
                        return Ok(());
                    }
                };
                let mut reply = NetPacket::new_encrypt(vec![
                    0u8;
                    12 + DISCOVERY_SESSION_LEN
                        + hello_ack_payload.len()
                        + ENCRYPTION_RESERVED
                ])?;
                reply.set_default_version();
                reply.set_protocol(Protocol::PeerDiscovery);
                reply.set_transport_protocol(peer_discovery_packet::Protocol::HelloAck.into());
                reply.set_source(current_device.virtual_ip);
                reply.set_destination(source);
                reply.set_initial_ttl(1);
                session_id.write(reply.payload_mut())?;
                reply.payload_mut()
                    [DISCOVERY_SESSION_LEN..DISCOVERY_SESSION_LEN + hello_ack_payload.len()]
                    .copy_from_slice(&hello_ack_payload);
                self.encrypt_peer_discovery(&source, &mut reply)?;
                self.send_reply_by_route(&reply, route_key)?;
                if responder.is_handshake_finished() {
                    let session_key = match responder.derived_session_key() {
                        Ok(session_key) => session_key,
                        Err(err) => {
                            log::warn!(
                                "drop peer discovery hello completed without exportable session key source={} err={:?}",
                                source,
                                err
                            );
                            return Ok(());
                        }
                    };
                    if !local_is_authoritative_discovery_initiator(
                        current_device.virtual_ip,
                        source,
                    ) {
                        let cipher = crate::cipher::Cipher::new_key(session_key)?;
                        self.runtime
                            .peer_crypto
                            .replace_current_cipher(source, cipher);
                        if !self
                            .runtime
                            .route_manager
                            .use_channel_type()
                            .is_only_relay()
                        {
                            let route = Route::from_default_rt(route_key, metric);
                            self.runtime
                                .route_manager()
                                .add_path_if_absent(source, route);
                        }
                    }
                }
            }
            PeerDiscoveryPacket::HelloAck {
                session: session_id,
                payload,
            } => {
                if !self.matches_active_peer_discovery_session(&source, session_id, true) {
                    log::warn!(
                        "drop peer discovery hello-ack without active session source={} route_key={:?} session_id={} attempt={} txid={}",
                        source,
                        route_key,
                        session_id.session_id(),
                        session_id.attempt(),
                        session_id.txid()
                    );
                    return Ok(());
                }
                log::info!(
                    "PeerDiscoveryHelloAck route_key={:?},source={}",
                    route_key,
                    source
                );
                if self
                    .runtime
                    .nat_test
                    .is_local_address(route_key.protocol().is_base_tcp(), route_key.addr())
                {
                    return Ok(());
                }
                let Some(handshake_result) =
                    self.runtime
                        .with_peer_discovery_initiator(&source, |initiator| {
                            initiator
                                .read_hello_ack(payload)
                                .map(|_| initiator.is_handshake_finished())
                        })
                else {
                    log::warn!(
                        "drop peer discovery hello-ack without initiator state source={} route_key={:?}",
                        source,
                        route_key
                    );
                    return Ok(());
                };
                match handshake_result {
                    Ok(true) => {
                        let Some(session_key_result) = self
                            .runtime
                            .with_peer_discovery_initiator(&source, |initiator| {
                                initiator.derived_session_key()
                            })
                        else {
                            log::warn!(
                                "drop peer discovery hello-ack without exportable initiator state source={} route_key={:?}",
                                source,
                                route_key
                            );
                            return Ok(());
                        };
                        let session_key = match session_key_result {
                            Ok(session_key) => session_key,
                            Err(err) => {
                                log::warn!(
                                    "drop peer discovery hello-ack without session key source={} route_key={:?} err={:?}",
                                    source,
                                    route_key,
                                    err
                                );
                                return Ok(());
                            }
                        };
                        self.runtime.clear_peer_discovery_initiator(&source);
                        if local_is_authoritative_discovery_initiator(
                            current_device.virtual_ip,
                            source,
                        ) {
                            let cipher = crate::cipher::Cipher::new_key(session_key)?;
                            self.runtime
                                .peer_crypto
                                .replace_current_cipher(source, cipher);
                            if !self
                                .runtime
                                .route_manager
                                .use_channel_type()
                                .is_only_relay()
                            {
                                let route = Route::from_default_rt(route_key, metric);
                                self.runtime
                                    .route_manager()
                                    .add_path_if_absent(source, route);
                                self.send_peer_discovery_info(
                                    current_device,
                                    source,
                                    route_key,
                                    session_id,
                                    false,
                                )?;
                            }
                        }
                    }
                    Ok(false) => {
                        log::warn!(
                            "drop peer discovery hello-ack before handshake completion source={} route_key={:?}",
                            source,
                            route_key
                        );
                    }
                    Err(err) => {
                        log::warn!(
                            "drop peer discovery hello-ack with invalid noise payload source={} route_key={:?} err={:?}",
                            source,
                            route_key,
                            err
                        );
                    }
                }
            }
            PeerDiscoveryPacket::EndpointInfo {
                session: session_id,
                payload,
            } => {
                if !self.matches_active_peer_discovery_session(&source, session_id, true) {
                    log::warn!(
                        "drop peer discovery info without active session source={} route_key={:?} session_id={} attempt={} txid={}",
                        source,
                        route_key,
                        session_id.session_id(),
                        session_id.attempt(),
                        session_id.txid()
                    );
                    return Ok(());
                }
                self.handle_peer_discovery_info(
                    current_device,
                    source,
                    route_key,
                    payload,
                    session_id,
                )?;
            }
        }
        Ok(())
    }
    fn other_turn(
        &self,
        _current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RoutePath,
    ) -> anyhow::Result<()> {
        let source = net_packet.source();
        log::warn!(
            "unsupported other-turn packet transport_protocol={} source={} route_key={:?}",
            net_packet.transport_protocol(),
            source,
            route_key
        );
        Ok(())
    }

    fn handle_peer_discovery_info(
        &self,
        current_device: &CurrentDeviceInfo,
        source: Ipv4Addr,
        route_key: RoutePath,
        payload: &[u8],
        session_id: DiscoverySessionId,
    ) -> anyhow::Result<()> {
        if self
            .runtime
            .route_manager
            .use_channel_type()
            .is_only_relay()
        {
            return Ok(());
        }
        let endpoint_info =
            EndpointInfoPayload::decode(payload).map_err(|e| anyhow!("EndpointInfo {:?}", e))?;
        let peer_nat_info = endpoint_info.clone().into_nat_info();
        {
            let peer_nat_info = peer_nat_info.clone();
            self.runtime
                .peer_nat_info_map
                .write()
                .insert(source, peer_nat_info);
        }
        if !endpoint_info.reply() {
            let punch_packet =
                self.build_peer_discovery_info_packet(current_device, source, session_id, true)?;
            if self
                .runtime
                .punch_coordinator
                .submit_from_peer(source, peer_nat_info, session_id)
            {
                self.runtime
                    .udp_channel
                    .send_by_key(punch_packet.buffer(), route_key)?;
            }
        } else {
            self.runtime
                .punch_coordinator
                .submit_local(source, peer_nat_info, session_id);
        }
        Ok(())
    }

    fn send_peer_discovery_info(
        &self,
        current_device: &CurrentDeviceInfo,
        peer_ip: Ipv4Addr,
        route_key: RoutePath,
        session_id: DiscoverySessionId,
        reply: bool,
    ) -> anyhow::Result<()> {
        let packet =
            self.build_peer_discovery_info_packet(current_device, peer_ip, session_id, reply)?;
        self.send_reply_by_route(&packet, route_key)
    }

    fn build_peer_discovery_info_packet(
        &self,
        current_device: &CurrentDeviceInfo,
        peer_ip: Ipv4Addr,
        session_id: DiscoverySessionId,
        reply: bool,
    ) -> anyhow::Result<NetPacket<Vec<u8>>> {
        let nat_info = self.runtime.nat_test.nat_info();
        let bytes = EndpointInfoPayload::from_nat_info(reply, &nat_info)
            .encode()
            .map_err(|e| anyhow!("EndpointInfo {:?}", e))?;
        let mut packet = NetPacket::new_encrypt(vec![
            0u8;
            12 + DISCOVERY_SESSION_LEN
                + bytes.len()
                + ENCRYPTION_RESERVED
        ])?;
        packet.set_default_version();
        packet.set_protocol(Protocol::PeerDiscovery);
        packet.set_transport_protocol(peer_discovery_packet::Protocol::EndpointInfo.into());
        packet.set_initial_ttl(MAX_TTL);
        packet.set_source(current_device.virtual_ip());
        packet.set_destination(peer_ip);
        session_id.write(packet.payload_mut())?;
        packet.payload_mut()[DISCOVERY_SESSION_LEN..DISCOVERY_SESSION_LEN + bytes.len()]
            .copy_from_slice(&bytes);
        self.encrypt_peer_discovery(&peer_ip, &mut packet)?;
        Ok(packet)
    }
}
