use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use sdl_packet::icmp::icmp::IcmpPacket;
use sdl_packet::icmp::Kind;
use sdl_packet::ip::ipv4::packet::IpV4Packet;
use sdl_packet::ip::ipv4::protocol::Protocol;
use sdl_packet::udp::udp::UdpPacket;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{io, thread};
use tun_rs::SyncDevice;

use crate::compression::Compressor;
use crate::core::ExitNodeRoute;
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::route_state::RouteKind;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::CurrentDeviceInfo;
use crate::protocol;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{ip_turn_packet, NetPacket};
use crate::tun_tap_device::vnt_device::write_full_sync_device;
use crate::util::icmp_debug::parse_icmp_echo_meta;
use crate::util::local_dns::LocalDnsResolution;
use crate::util::{PeerCryptoManager, StopManager};
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
    peer_state: Arc<Mutex<crate::handle::PeerState>>,
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
                peer_state,
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
    peer_state: &Mutex<crate::handle::PeerState>,
    peer_crypto: &PeerCryptoManager,
) -> anyhow::Result<()> {
    let list: Vec<Ipv4Addr> = peer_state
        .lock()
        .devices
        .values()
        .filter(|info| info.status.is_online())
        .map(|info| info.virtual_ip)
        .collect();
    if list.is_empty() {
        return Ok(());
    }
    if current_device.virtual_ip == Ipv4Addr::UNSPECIFIED {
        //未分配 VIP 时不转发
        return Ok(());
    }
    for peer_ip in list {
        let mut peer_buf = vec![0u8; net_packet.data_len() + ENCRYPTION_RESERVED];
        peer_buf[..net_packet.data_len()].copy_from_slice(net_packet.buffer());
        let mut peer_packet = NetPacket::new_encrypt(peer_buf)?;
        peer_packet.set_destination(peer_ip);
        let cipher = match peer_crypto.send_cipher(&peer_ip) {
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
    peer_state: &Mutex<crate::handle::PeerState>,
    peer_crypto: &PeerCryptoManager,
    compressor: &Compressor,
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
        if data_channel.is_dns_service_ip(&dest_ip) || dest_ip == current_device.virtual_gateway {
            let udp_packet = UdpPacket::new(src_ip, dest_ip, ipv4_packet.payload())?;
            if udp_packet.destination_port() == 53 && !udp_packet.payload().is_empty() {
                if let Ok(runtime) = data_channel.runtime() {
                    let profile = runtime.dns_profile.read().clone();
                    let decision = {
                        let guard = peer_state.lock();
                        crate::util::local_dns::resolve_local_query(
                            udp_packet.payload(),
                            profile.as_ref(),
                            &guard.devices,
                        )
                    };
                    if let LocalDnsResolution::Answered(dns_response_payload) = decision {
                        let pending = crate::core::PendingDnsQuery {
                            client_ip: src_ip,
                            dns_server_ip: dest_ip,
                            client_port: udp_packet.source_port(),
                            created_at_ms: 0,
                        };
                        if let Ok(response_packet) =
                            crate::util::dns_tunnel::build_dns_response_packet(
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
                data_channel.proxy_dns_query(
                    src_ip,
                    dest_ip,
                    udp_packet.source_port(),
                    udp_packet.payload(),
                )?;
                return Ok(());
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
        if let Some(next_hop) = exit_node_route.next_hop_for_external_destination(&dest_ip) {
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
            peer_state,
            peer_crypto,
        )?;
        return Ok(());
    }

    let cipher = peer_crypto.send_cipher(&dest_ip)?;
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
