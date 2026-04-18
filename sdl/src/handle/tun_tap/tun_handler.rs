use crossbeam_utils::atomic::AtomicCell;
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
use crate::data_plane::data_channel::DataChannel;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::CurrentDeviceInfo;
use crate::protocol;
use crate::protocol::{ip_turn_packet, NetPacket};
use crate::util::StopManager;

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
            device_writer.send(ipv4_packet.buffer)?;
        }
    }
    Ok(())
}

pub fn start(
    stop_manager: StopManager,
    data_channel: DataChannel,
    device: Arc<SyncDevice>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
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
                ip_route,
                compressor,
                device_stop,
            ) {
                log::warn!("stop:{}", e);
            }
        })?;

    Ok(())
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
    ip_route: &ExternalRoute,
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
        log::debug!(
            "tun outbound icmp src={} dst={} bytes={}",
            src_ip,
            dest_ip,
            data_len.saturating_sub(12)
        );
        data_channel.emit_debug_watch_event(
            "icmp",
            "tun_outbound",
            serde_json::json!({
                "src": src_ip.to_string(),
                "dst": dest_ip.to_string(),
                "bytes": data_len.saturating_sub(12),
            }),
        );
    }
    if src_ip == dest_ip {
        return icmp(device_writer, ipv4_packet);
    }
    let src_ip = ipv4_packet.source_ip();
    let mut dest_ip = ipv4_packet.destination_ip();
    if ipv4_packet.protocol() == Protocol::Udp && data_channel.is_dns_service_ip(&dest_ip) {
        let udp_packet = UdpPacket::new(src_ip, dest_ip, ipv4_packet.payload())?;
        if udp_packet.destination_port() == 53 && !udp_packet.payload().is_empty() {
            data_channel.proxy_dns_query(
                src_ip,
                dest_ip,
                udp_packet.source_port(),
                udp_packet.payload(),
            )?;
            return Ok(());
        }
    }
    let mut net_packet = NetPacket::new0(data_len, buf)?;
    let mut out = NetPacket::unchecked(extend);
    net_packet.set_default_version();
    net_packet.set_protocol(protocol::Protocol::IpTurn);
    net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
    net_packet.set_initial_ttl(6);
    net_packet.set_source(src_ip);
    net_packet.set_destination(dest_ip);
    if dest_ip == current_device.virtual_gateway {
        if protocol == Protocol::Icmp {
            log::debug!(
                "forwarding outbound icmp to gateway relay src={} dst={} bytes={}",
                src_ip,
                dest_ip,
                data_len.saturating_sub(12)
            );
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
        data_channel.send_relay(&net_packet)?;
        return Ok(());
    }
    if !Ipv4Addr::is_multicast(&dest_ip)
        && !dest_ip.is_broadcast()
        && current_device.broadcast_ip != dest_ip
        && current_device.not_in_network(dest_ip)
    {
        if let Some(r_dest_ip) = ip_route.route(&dest_ip) {
            //路由的目标不能是自己
            if r_dest_ip == src_ip {
                return Ok(());
            }
            //需要修改目的地址
            dest_ip = r_dest_ip;
            net_packet.set_destination(r_dest_ip);
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
        out.set_source(src_ip);
        out.set_destination(dest_ip);
        out
    } else {
        net_packet
    };
    if is_broadcast {
        data_channel.broadcast_to_peers(&net_packet, &current_device)?;
        return Ok(());
    }

    data_channel.encrypt_and_send_to_peer(&mut net_packet, &dest_ip)?;
    Ok(())
}
