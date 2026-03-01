use crate::channel::context::ChannelContext;
use crate::handle::CurrentDeviceInfo;
use crate::nat::NatTest;
use crate::proto::message::{ClientStatusInfo, PunchNatType, RouteItem};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{service_packet, NetPacket, Protocol, HEAD_LEN, MAX_TTL};
use crate::util::Scheduler;
use crossbeam_utils::atomic::AtomicCell;
use protobuf::Message;
use std::io;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// 上报状态给服务器
pub fn up_status(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
) {
    let _ = scheduler.timeout(Duration::from_secs(60), move |x| {
        up_status0(x, context, current_device_info, nat_test)
    });
}

/// 事件触发的即时上报（不影响周期上报）
pub fn trigger_up_status(
    context: &ChannelContext,
    current_device_info: &AtomicCell<CurrentDeviceInfo>,
    nat_test: &NatTest,
) {
    if let Err(e) = send_up_status_packet(context, current_device_info, nat_test) {
        log::warn!("{:?}", e)
    }
}

/// 事件触发上报：优先确保已有公网端点；若缺失则先发一次探测并短暂等待后再上报
pub fn trigger_up_status_with_nat_ready(
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
) {
    thread::Builder::new()
        .name("upStatusEvent".into())
        .spawn(move || {
            let nat_info = nat_test.nat_info();
            if !has_public_endpoints(&nat_info.public_ips, &nat_info.public_ports) {
                if let Ok((data, addr)) = nat_test.send_data() {
                    let _ = context.send_main_udp(0, &data, addr);
                }
                thread::sleep(Duration::from_secs(2));
            }
            if let Err(e) = send_up_status_packet(&context, &current_device_info, &nat_test) {
                log::warn!("{:?}", e)
            }
        })
        .expect("upStatusEvent");
}

fn has_public_endpoints(public_ips: &[std::net::Ipv4Addr], public_ports: &[u16]) -> bool {
    !public_ips.is_empty() && !public_ports.is_empty()
}

fn up_status0(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
) {
    if let Err(e) = send_up_status_packet(&context, &current_device_info, &nat_test) {
        log::warn!("{:?}", e)
    }
    let rs = scheduler.timeout(Duration::from_secs(10 * 60), move |x| {
        up_status0(x, context, current_device_info, nat_test)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn send_up_status_packet(
    context: &ChannelContext,
    current_device_info: &AtomicCell<CurrentDeviceInfo>,
    nat_test: &NatTest,
) -> io::Result<()> {
    let device_info = current_device_info.load();
    if device_info.status.offline() {
        return Ok(());
    }
    let routes = context.route_table.route_table_p2p();
    let mut message = ClientStatusInfo::new();
    message.source = device_info.virtual_ip.into();
    for (ip, _) in routes {
        let mut item = RouteItem::new();
        item.next_ip = ip.into();
        message.p2p_list.push(item);
    }
    message.up_stream = context.up_traffic_meter.as_ref().map_or(0, |v| v.total());
    message.down_stream = context.down_traffic_meter.as_ref().map_or(0, |v| v.total());
    message.nat_type = protobuf::EnumOrUnknown::new(if context.is_cone() {
        PunchNatType::Cone
    } else {
        PunchNatType::Symmetric
    });
    let nat_info = nat_test.nat_info();
    message.public_ip_list = nat_info
        .public_ips
        .iter()
        .map(|ip| u32::from(*ip))
        .collect();
    message.public_udp_ports = nat_info.public_ports.iter().map(|p| *p as u32).collect();
    message.local_udp_ports = nat_info.udp_ports.iter().map(|p| *p as u32).collect();
    let buf = message
        .write_to_bytes()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("up_status_packet {:?}", e)))?;
    let mut net_packet =
        NetPacket::new_encrypt(vec![0; HEAD_LEN + buf.len() + ENCRYPTION_RESERVED])?;
    net_packet.set_default_version();
    net_packet.set_gateway_flag(true);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol_into(service_packet::Protocol::ClientStatusInfo);
    net_packet.set_initial_ttl(MAX_TTL);
    net_packet.set_source(device_info.virtual_ip);
    net_packet.set_destination(device_info.virtual_gateway);
    net_packet.set_payload(&buf)?;
    context.send_default(&net_packet, device_info.connect_server)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::has_public_endpoints;
    use std::net::Ipv4Addr;

    #[test]
    fn has_public_endpoints_requires_both_ip_and_port() {
        assert!(!has_public_endpoints(&[], &[]));
        assert!(!has_public_endpoints(&[Ipv4Addr::new(1, 1, 1, 1)], &[]));
        assert!(!has_public_endpoints(&[], &[12345]));
        assert!(has_public_endpoints(&[Ipv4Addr::new(1, 1, 1, 1)], &[12345]));
    }
}
