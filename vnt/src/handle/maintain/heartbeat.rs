use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::handle::maintain::route_maintenance;
use crate::handle::registrar;
use crate::handle::BaseConfigInfo;
use crate::handle::CONTROL_VIP;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{control_packet, NetPacket, Protocol};
use crate::util::Scheduler;

/// 定时发送心跳包
pub fn heartbeat(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    client_cipher: Cipher,
    config_info: BaseConfigInfo,
    gateway_ticket_expire_unix_ms: Arc<AtomicCell<i64>>,
) {
    heartbeat0(
        &context,
        &current_device_info.load(),
        &device_map,
        &client_cipher,
        &config_info,
        &gateway_ticket_expire_unix_ms,
    );
    // 心跳包 3秒发送一次
    let rs = scheduler.timeout(Duration::from_secs(3), |s| {
        heartbeat(
            s,
            context,
            current_device_info,
            device_map,
            client_cipher,
            config_info,
            gateway_ticket_expire_unix_ms,
        )
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn heartbeat0(
    context: &ChannelContext,
    current_device: &CurrentDeviceInfo,
    device_map: &Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>,
    client_cipher: &Cipher,
    config_info: &BaseConfigInfo,
    gateway_ticket_expire_unix_ms: &AtomicCell<i64>,
) {
    try_refresh_gateway_grant(
        context,
        current_device,
        config_info,
        gateway_ticket_expire_unix_ms,
    );

    let src_ip = current_device.virtual_ip;
    let channel_num = context.channel_num();

    // 通过 default/control 路径维持控制面活性（control 与 gateway 独立部署）。
    match heartbeat_packet_server(device_map, src_ip, CONTROL_VIP) {
        Ok(net_packet) => {
            if let Err(e) = context.send_default(&net_packet, current_device.control_server) {
                log::warn!("heartbeat err={:?}", e)
            }
        }
        Err(e) => {
            log::error!("heartbeat_packet err={:?}", e);
        }
    }

    for (dest_ip, routes) in context.route_table.route_table() {
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
        for (index, route) in routes.iter().enumerate() {
            let limit = if context.latency_first() {
                channel_num + 1
            } else {
                channel_num
            };
            if index >= limit {
                // 多余的通道不再发送心跳包,让它自动过期
                break;
            }
            if let Err(e) = context.send_by_key(&net_packet, route.route_key()) {
                log::warn!("heartbeat err={:?}", e)
            }
        }
    }

    let peer_list = { device_map.lock().1.clone() };
    for peer in peer_list.values() {
        if !route_maintenance::should_probe_peer(current_device, peer) {
            continue;
        }
        if context
            .route_table
            .get_first_route(&peer.virtual_ip)
            .is_none()
        {
            // 路由为空时尝试走 gateway relay。
            let net_packet = match heartbeat_packet_client(client_cipher, src_ip, peer.virtual_ip) {
                Ok(net_packet) => net_packet,
                Err(e) => {
                    log::error!("heartbeat_packet err={:?}", e);
                    continue;
                }
            };
            if let Err(e) = crate::handle::gateway_relay::send_relay(context, &net_packet) {
                log::debug!(
                    "heartbeat_packet relay unavailable for {}: {:?}",
                    peer.virtual_ip,
                    e
                );
            }
        }
    }
}

fn try_refresh_gateway_grant(
    context: &ChannelContext,
    current_device: &CurrentDeviceInfo,
    config_info: &BaseConfigInfo,
    gateway_ticket_expire_unix_ms: &AtomicCell<i64>,
) {
    if !current_device.status.online() {
        return;
    }
    let expire_unix_ms = gateway_ticket_expire_unix_ms.load();
    if expire_unix_ms <= 0 {
        return;
    }
    let now_ms = crate::handle::now_time() as i64;
    if expire_unix_ms - now_ms > 30_000 {
        return;
    }
    let mut ip = config_info.ip;
    if ip.is_none() {
        ip = Some(current_device.virtual_ip);
    }
    let packet = match registrar::registration_request_packet(
        config_info.token.clone(),
        config_info.device_id.clone(),
        config_info.device_pub_key.clone(),
        config_info.device_pub_key_alg.clone(),
        config_info.name.clone(),
        ip,
        false,
        false,
        config_info.client_secret_hash.as_ref().map(|v| v.as_ref()),
    ) {
        Ok(packet) => packet,
        Err(e) => {
            log::warn!("build registration refresh packet failed: {:?}", e);
            return;
        }
    };
    match context.send_default(&packet, current_device.control_server) {
        Ok(_) => {
            gateway_ticket_expire_unix_ms.store(0);
            log::info!("gateway grant nearing expiration, requested registration refresh");
        }
        Err(e) => log::warn!("gateway grant refresh send failed: {:?}", e),
    }
}

/// 构建心跳包
fn heartbeat_packet(src: Ipv4Addr, dest: Ipv4Addr) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = NetPacket::new(vec![0u8; 12 + 4])?;
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(control_packet::Protocol::Ping.into());
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

fn heartbeat_packet_server(
    device_map: &Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>,
    src: Ipv4Addr,
    dest: Ipv4Addr,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = heartbeat_packet(src, dest)?;
    let mut ping = PingPacket::new(net_packet.payload_mut())?;
    ping.set_epoch(device_map.lock().0);
    Ok(net_packet)
}
