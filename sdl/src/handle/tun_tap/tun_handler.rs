use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;
use sdl_packet::icmp::icmp::IcmpPacket;
use sdl_packet::icmp::Kind;
use sdl_packet::ip::ipv4::packet::IpV4Packet;
use sdl_packet::ip::ipv4::protocol::Protocol;
use sdl_packet::udp::udp::UdpPacket;
use std::net::Ipv4Addr;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::{io, thread};
use tun_rs::SyncDevice;

use crate::compression::Compressor;
use crate::core::{ExitNodeRoute, ExitRouteDecision, SdlContext};
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route_state::RouteKind;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::CurrentDeviceInfo;
use crate::net::dns::local::LocalDnsResolution;
use crate::protocol;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{ip_turn_packet, NetPacket};
use crate::tun_tap_device::vnt_device::write_full_sync_device;
use crate::util::icmp_debug::parse_icmp_echo_meta;
use crate::util::StopManager;

const LOCAL_DNS_QUEUE_CAPACITY: usize = 64;
const LOCAL_DNS_WORKER_COUNT: usize = 4;

struct LocalDnsRequest {
    pending: crate::core::PendingDnsQuery,
    payload: Vec<u8>,
}

pub(crate) struct LocalDnsForwarder {
    tx: SyncSender<LocalDnsRequest>,
}

impl LocalDnsForwarder {
    pub(crate) fn new(device: Arc<SyncDevice>, context: Arc<SdlContext>) -> Self {
        let (tx, rx) = sync_channel::<LocalDnsRequest>(LOCAL_DNS_QUEUE_CAPACITY);
        let rx = Arc::new(Mutex::new(rx));
        for worker_index in 0..LOCAL_DNS_WORKER_COUNT {
            let worker_rx = rx.clone();
            let worker_device = device.clone();
            let worker_context = context.clone();
            if let Err(err) = thread::Builder::new()
                .name(format!("local-dns-worker-{worker_index}"))
                .spawn(move || loop {
                    let request = {
                        let receiver = worker_rx.lock().unwrap();
                        receiver.recv()
                    };
                    let Ok(request) = request else {
                        break;
                    };
                    let forward_result = match worker_context.local_dns_resolvers() {
                        Some(resolvers) => {
                            crate::net::dns::forward::forward_dns_query_to_resolvers(
                                &request.payload,
                                &resolvers,
                            )
                        }
                        None => crate::net::dns::forward::forward_dns_query_to_system_resolver(
                            &request.payload,
                        ),
                    };
                    let response = match forward_result {
                        Ok(response) => response,
                        Err(err) => {
                            log::warn!("local DNS forward failed: {err:?}");
                            continue;
                        }
                    };
                    match crate::net::dns::tunnel::build_dns_response_packet(
                        &request.pending,
                        &response,
                    )
                    .and_then(|packet| {
                        write_full_sync_device(
                            &worker_device,
                            &packet,
                            "local dns forward response",
                        )
                        .map(|_| ())
                        .map_err(io::Error::other)
                    }) {
                        Ok(()) => {}
                        Err(err) => log::warn!("local DNS response inject failed: {err:?}"),
                    }
                })
            {
                log::warn!("failed to start local DNS worker: {err:?}");
            }
        }
        Self { tx }
    }

    fn forward(&self, pending: crate::core::PendingDnsQuery, payload: Vec<u8>) -> io::Result<()> {
        self.tx
            .try_send(LocalDnsRequest { pending, payload })
            .map_err(|err| match err {
                TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "local DNS queue is full")
                }
                TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "local DNS worker is stopped")
                }
            })
    }
}
fn icmp(device_writer: &SyncDevice, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> anyhow::Result<()> {
    if ipv4_packet.protocol() == Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            write_full_sync_device(device_writer, ipv4_packet.buffer, "self icmp reply")?;
        }
    }
    Ok(())
}

pub fn start(
    stop_manager: StopManager,
    data_channel: DataChannel,
    device: Arc<SyncDevice>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    gateway_sessions: GatewaySessions,
    exit_node_route: ExitNodeRoute,
    peer_table: Arc<RwLock<crate::core::PeerTable>>,
    peer_crypto: Arc<PeerCryptoManager>,
    compressor: Compressor,
    device_stop: DeviceStop,
) -> io::Result<()> {
    thread::Builder::new()
        .name("tunHandlerS".into())
        .spawn(move || {
            if let Err(e) = crate::handle::tun_tap::start_simple(
                stop_manager,
                &data_channel,
                device,
                current_device,
                gateway_sessions,
                exit_node_route,
                peer_table,
                peer_crypto,
                compressor,
                device_stop,
            ) {
                log::warn!("stop:{}", e);
            }
        })?;

    Ok(())
}

fn broadcast(
    channel: &DataChannel,
    net_packet: &NetPacket<&mut [u8]>,
    current_device: &CurrentDeviceInfo,
    peer_table: &RwLock<crate::core::PeerTable>,
    peer_crypto: &PeerCryptoManager,
) -> anyhow::Result<()> {
    let list: Vec<(Ipv4Addr, crate::core::PeerIdentity)> = peer_table
        .read()
        .values()
        .filter(|info| info.status.is_online())
        .map(|info| (info.virtual_ip, info.identity()))
        .collect();
    if list.is_empty() {
        return Ok(());
    }
    if current_device.virtual_ip == Ipv4Addr::UNSPECIFIED {
        //未分配 VIP 时不转发
        return Ok(());
    }
    for (peer_ip, peer_identity) in list {
        let mut peer_buf = vec![0u8; net_packet.data_len() + ENCRYPTION_RESERVED];
        peer_buf[..net_packet.data_len()].copy_from_slice(net_packet.buffer());
        let mut peer_packet = NetPacket::new_encrypt(peer_buf)?;
        peer_packet.set_destination(peer_ip);
        let cipher = match peer_crypto.current_cipher(&peer_identity) {
            Ok(cipher) => cipher,
            Err(err) => {
                log::debug!(
                    "skip broadcast without peer session cipher for {}: {:?}",
                    peer_ip,
                    err
                );
                continue;
            }
        };
        cipher.encrypt_ipv4(&mut peer_packet)?;

        match channel.send_to_peer(&peer_packet, &peer_ip)? {
            RouteKind::P2p => {
                channel.record_logical_up_traffic(peer_packet.buffer().len());
                channel.record_peer_up_traffic(peer_ip, peer_packet.buffer().len());
            }
            RouteKind::GatewayRelay | RouteKind::Relay => {
                channel.record_logical_up_traffic(peer_packet.buffer().len());
                channel.record_gateway_up_traffic(peer_packet.buffer().len());
                channel.record_peer_up_traffic(peer_ip, peer_packet.buffer().len());
            }
        }
    }
    Ok(())
}

fn overlay_source_for_tun_packet(src_ip: Ipv4Addr, current_device: &CurrentDeviceInfo) -> Ipv4Addr {
    if current_device.contains_virtual_ip(src_ip) {
        src_ip
    } else {
        current_device.virtual_ip
    }
}

fn exit_next_hop(
    route: &ExitNodeRoute,
    destination: Ipv4Addr,
    peer_table: &RwLock<crate::core::PeerTable>,
) -> Option<Ipv4Addr> {
    match route.decision_for_external_destination(&destination) {
        ExitRouteDecision::Local => None,
        ExitRouteDecision::ExitNodeVip(vip) => Some(vip),
        ExitRouteDecision::ExitNodeDeviceId(device_id) => {
            peer_table.read().vip_for_device_id(&device_id)
        }
    }
}

fn exit_next_hop_for_decision(
    decision: ExitRouteDecision,
    peer_table: &RwLock<crate::core::PeerTable>,
) -> Option<Ipv4Addr> {
    match decision {
        ExitRouteDecision::Local => None,
        ExitRouteDecision::ExitNodeVip(vip) => Some(vip),
        ExitRouteDecision::ExitNodeDeviceId(device_id) => {
            let peer_table = peer_table.read();
            peer_table.vip_for_device_id(&device_id).and_then(|vip| {
                peer_table
                    .get(&vip)
                    .filter(|peer| peer.exit_node_usable())
                    .map(|_| vip)
            })
        }
    }
}

#[cfg(test)]
mod dns_policy_tests {
    use super::exit_next_hop_for_decision;
    use crate::core::{ExitRouteDecision, PeerInfo, PeerTable};
    use parking_lot::RwLock;
    use std::net::Ipv4Addr;

    #[test]
    fn dns_exit_target_requires_a_usable_exit_node() {
        let peer = PeerInfo::new(
            Ipv4Addr::new(10, 26, 0, 4),
            "hk".into(),
            0,
            "hk-device".into(),
            vec![],
            vec![],
            crate::proto::message::ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        );
        let peer_table = RwLock::new(PeerTable::new(
            1,
            std::collections::HashMap::from([(peer.virtual_ip(), peer)]),
        ));
        assert_eq!(
            exit_next_hop_for_decision(
                ExitRouteDecision::ExitNodeDeviceId("hk-device".into()),
                &peer_table,
            ),
            None
        );
    }
}

/// 接收tun数据，并且转发到udp上
/// 实现一个原地发送，必须保证是如下结构
/// |12字节开头|ip报文|至少1024字节结尾|
///
pub(crate) fn handle(
    data_channel: &DataChannel,
    buf: &mut [u8],
    data_len: usize, //数据总长度=12+ip包长度
    extend: &mut [u8],
    device_writer: &SyncDevice,
    current_device: CurrentDeviceInfo,
    gateway_sessions: &GatewaySessions,
    exit_node_route: &ExitNodeRoute,
    peer_table: &RwLock<crate::core::PeerTable>,
    peer_crypto: &PeerCryptoManager,
    compressor: &Compressor,
    local_dns: &LocalDnsForwarder,
) -> anyhow::Result<()> {
    //忽略掉结构不对的情况（ipv6数据、win tap会读到空数据），不然日志打印太多了
    let ipv4_packet = match IpV4Packet::new(&mut buf[12..data_len]) {
        Ok(packet) => packet,
        Err(_) => return Ok(()),
    };
    let src_ip = ipv4_packet.source_ip();
    let dest_ip = ipv4_packet.destination_ip();
    let protocol = ipv4_packet.protocol();
    if protocol == Protocol::Icmp {
        let icmp_meta = IcmpPacket::new(ipv4_packet.payload())
            .ok()
            .and_then(|packet| parse_icmp_echo_meta(&packet));
        data_channel.emit_debug_watch_event(
            "icmp",
            "tun_outbound",
            serde_json::json!({
                "src": src_ip.to_string(),
                "dst": dest_ip.to_string(),
                "bytes": data_len.saturating_sub(12),
                "icmp_kind": icmp_meta.map(|meta| meta.kind_label()),
                "icmp_id": icmp_meta.map(|meta| meta.identifier),
                "icmp_seq": icmp_meta.map(|meta| meta.sequence),
                "icmp_checksum_valid": icmp_meta.map(|meta| meta.checksum_valid),
            }),
        );
    }
    if src_ip == dest_ip {
        return icmp(device_writer, ipv4_packet);
    }
    let src_ip = ipv4_packet.source_ip();
    let overlay_src_ip = overlay_source_for_tun_packet(src_ip, &current_device);
    let mut dest_ip = ipv4_packet.destination_ip();
    if ipv4_packet.protocol() == Protocol::Udp {
        if data_channel.is_dns_service_ip(&dest_ip) {
            let udp_packet = UdpPacket::new(src_ip, dest_ip, ipv4_packet.payload())?;
            if udp_packet.destination_port() == 53
                && crate::net::dns::query::is_dns_query_payload(udp_packet.payload())
            {
                let dns_client_port = udp_packet.source_port();
                let dns_payload = udp_packet.payload().to_vec();
                if let Ok(context) = data_channel.context() {
                    let profile = context.dns.profile.read().clone();
                    let decision = {
                        let guard = peer_table.read();
                        crate::net::dns::local::resolve_local_query(
                            udp_packet.payload(),
                            profile.as_ref(),
                            guard.devices(),
                        )
                    };
                    if let LocalDnsResolution::Answered(dns_response_payload) = decision {
                        let pending = crate::core::PendingDnsQuery::new(
                            src_ip,
                            dest_ip,
                            udp_packet.source_port(),
                        );
                        if let Ok(response_packet) =
                            crate::net::dns::tunnel::build_dns_response_packet(
                                &pending,
                                &dns_response_payload,
                            )
                        {
                            write_full_sync_device(
                                device_writer,
                                &response_packet,
                                "local dns response",
                            )?;
                            return Ok(());
                        }
                    }
                }
                if let Some(query) = crate::net::dns::query::parse_dns_query(&dns_payload) {
                    if let Some(decision) =
                        exit_node_route.decision_for_dns_query(&query.domain, query.query_type)
                    {
                        match decision {
                            ExitRouteDecision::Local => {
                                // With a traffic policy active, the worker uses the
                                // physical resolver snapshot captured before DNS was
                                // redirected to SDL, so this cannot loop back to TUN.
                                local_dns.forward(
                                    crate::core::PendingDnsQuery::new(
                                        src_ip,
                                        dest_ip,
                                        dns_client_port,
                                    ),
                                    dns_payload,
                                )?;
                                return Ok(());
                            }
                            decision => {
                                if let Some(next_hop) =
                                    exit_next_hop_for_decision(decision, peer_table)
                                {
                                    dest_ip = next_hop;
                                } else {
                                    let pending = crate::core::PendingDnsQuery::new(
                                        src_ip,
                                        dest_ip,
                                        dns_client_port,
                                    );
                                    let response =
                                        crate::net::dns::tunnel::build_dns_servfail_packet(
                                            &pending,
                                            &dns_payload,
                                        )?;
                                    write_full_sync_device(
                                        device_writer,
                                        &response,
                                        "exit-node DNS SERVFAIL response",
                                    )?;
                                    return Ok(());
                                }
                            }
                        }
                    } else if let Some(next_hop) =
                        exit_next_hop(exit_node_route, dest_ip, peer_table)
                    {
                        dest_ip = next_hop;
                    } else {
                        local_dns.forward(
                            crate::core::PendingDnsQuery::new(src_ip, dest_ip, dns_client_port),
                            dns_payload,
                        )?;
                        return Ok(());
                    }
                } else if let Some(next_hop) = exit_next_hop(exit_node_route, dest_ip, peer_table) {
                    dest_ip = next_hop;
                } else {
                    local_dns.forward(
                        crate::core::PendingDnsQuery::new(src_ip, dest_ip, dns_client_port),
                        dns_payload,
                    )?;
                    return Ok(());
                }
            }
        }
    }
    let mut net_packet = NetPacket::new0(data_len, buf)?;
    let mut out = NetPacket::unchecked(extend);
    net_packet.set_default_version();
    net_packet.set_protocol(protocol::Protocol::IpTurn);
    net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
    net_packet.set_initial_ttl(6);
    net_packet.set_source(overlay_src_ip);
    net_packet.set_destination(dest_ip);
    if dest_ip == current_device.virtual_gateway {
        if protocol == Protocol::Icmp {
            data_channel.emit_debug_watch_event(
                "icmp",
                "gateway_relay_forward",
                serde_json::json!({
                    "src": src_ip.to_string(),
                    "dst": dest_ip.to_string(),
                    "bytes": data_len.saturating_sub(12),
                }),
            );
        }
        gateway_sessions.send_relay(&net_packet)?;
        data_channel.record_logical_up_traffic(net_packet.buffer().len());
        data_channel.record_gateway_up_traffic(net_packet.buffer().len());
        return Ok(());
    }
    if !Ipv4Addr::is_multicast(&dest_ip)
        && !dest_ip.is_broadcast()
        && current_device.broadcast_ip != dest_ip
        && current_device.is_outside_virtual_network(dest_ip)
    {
        if let Some(next_hop) = exit_next_hop(exit_node_route, dest_ip, peer_table) {
            //路由的目标不能是自己
            if next_hop == src_ip {
                return Ok(());
            }
            //需要修改目的地址
            dest_ip = next_hop;
            net_packet.set_destination(next_hop);
        } else {
            return Ok(());
        }
    }

    if dest_ip.is_multicast() {
        //当作广播处理
        dest_ip = Ipv4Addr::BROADCAST;
        net_packet.set_destination(Ipv4Addr::BROADCAST);
    }
    let is_broadcast = dest_ip.is_broadcast() || current_device.broadcast_ip == dest_ip;

    let mut net_packet = if compressor.compress(&net_packet, &mut out)? {
        out.set_default_version();
        out.set_protocol(protocol::Protocol::IpTurn);
        out.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
        out.set_initial_ttl(6);
        out.set_source(overlay_src_ip);
        out.set_destination(dest_ip);
        out
    } else {
        net_packet
    };
    if is_broadcast {
        // 广播 发送到直连目标
        broadcast(
            data_channel,
            &net_packet,
            &current_device,
            peer_table,
            peer_crypto,
        )?;
        return Ok(());
    }

    let peer_identity = peer_table
        .read()
        .identity_for_vip(&dest_ip)
        .ok_or_else(|| anyhow::anyhow!("missing peer identity for {}", dest_ip))?;
    let cipher = peer_crypto.current_cipher(&peer_identity)?;
    cipher.encrypt_ipv4(&mut net_packet)?;
    match data_channel.send_to_peer(&net_packet, &dest_ip) {
        Ok(RouteKind::P2p) => {
            data_channel.record_logical_up_traffic(net_packet.buffer().len());
            data_channel.record_peer_up_traffic(dest_ip, net_packet.buffer().len());
        }
        Ok(RouteKind::GatewayRelay | RouteKind::Relay) => {
            data_channel.record_logical_up_traffic(net_packet.buffer().len());
            data_channel.record_gateway_up_traffic(net_packet.buffer().len());
            data_channel.record_peer_up_traffic(dest_ip, net_packet.buffer().len());
        }
        Err(err) => {
            return Err(err.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::overlay_source_for_tun_packet;
    use crate::handle::CurrentDeviceInfo;
    use std::net::Ipv4Addr;

    fn current_device() -> CurrentDeviceInfo {
        CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        )
    }

    #[test]
    fn overlay_source_preserves_sdl_source_ip() {
        assert_eq!(
            overlay_source_for_tun_packet(Ipv4Addr::new(10, 26, 0, 3), &current_device()),
            Ipv4Addr::new(10, 26, 0, 3)
        );
    }

    #[test]
    fn overlay_source_uses_local_vip_for_forwarded_external_packets() {
        assert_eq!(
            overlay_source_for_tun_packet(Ipv4Addr::new(172, 31, 240, 10), &current_device()),
            Ipv4Addr::new(10, 26, 0, 3)
        );
    }
}
