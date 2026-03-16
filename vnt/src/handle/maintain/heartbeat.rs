use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::core::VntRuntime;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{NetPacket, Protocol};
use crate::util::Scheduler;

/// 定时发送心跳包
pub fn heartbeat(scheduler: &Scheduler, context: ChannelContext, runtime: Arc<VntRuntime>) {
    heartbeat0(
        &context,
        &runtime.current_device.load(),
        &runtime.client_cipher,
    );
    // 心跳包 3秒发送一次
    let rs = scheduler.timeout(Duration::from_secs(3), |s| heartbeat(s, context, runtime));
    if !rs {
        log::info!("定时任务停止");
    }
}

fn heartbeat0(
    context: &ChannelContext,
    current_device: &CurrentDeviceInfo,
    client_cipher: &Cipher,
) {
    let channel_num = context.channel_num();

    let src_ip = current_device.virtual_ip;
    for (dest_ip, routes) in context.route_manager().heartbeat_targets(channel_num) {
        if current_device.is_gateway_vip(&dest_ip) {
            continue;
        }
        let net_packet = heartbeat_packet_client(client_cipher, src_ip, dest_ip);
        let net_packet = match net_packet {
            Ok(net_packet) => net_packet,
            Err(e) => {
                log::error!("heartbeat_packet err={:?}", e);
                continue;
            }
        };
        for route in routes.iter() {
            if let Err(e) = context.send_by_key(&net_packet, route.route_key()) {
                log::warn!("heartbeat err={:?}", e)
            }
        }
    }
}

/// 构建心跳包
fn heartbeat_packet(src: Ipv4Addr, dest: Ipv4Addr) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = NetPacket::new(vec![0u8; 12 + 4])?;
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
    net_packet.set_initial_ttl(5);
    net_packet.set_source(src);
    net_packet.set_destination(dest);
    let mut ping = PingPacket::new(net_packet.payload_mut())?;
    ping.set_time(crate::handle::now_time() as u16);
    Ok(net_packet)
}

fn heartbeat_packet_client(
    client_cipher: &Cipher,
    src: Ipv4Addr,
    dest: Ipv4Addr,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = heartbeat_packet(src, dest)?;
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}
