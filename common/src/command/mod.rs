use std::collections::HashSet;
use vnt::core::Vnt;
use vnt::data_plane::use_channel_type::UseChannelType;
use vnt::transport::connect_protocol::ConnectProtocol;

use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};

pub mod client;
pub mod entity;
mod ipc;
pub mod server;
pub mod service_state;

pub fn command_route(vnt: &Vnt) -> Vec<RouteItem> {
    let route_table = vnt.route_table();
    let server_addr = vnt.config().server_address_str.clone();
    let mut route_list = Vec::with_capacity(route_table.len());
    for (destination, routes) in route_table {
        for route in routes {
            let next_hop = vnt
                .route_key(&route.route_key())
                .map_or(String::new(), |v| v.to_string());
            let metric = route.metric.to_string();
            let rt = if route.rt < 0 {
                "".to_string()
            } else {
                route.rt.to_string()
            };
            let interface = match route.protocol {
                ConnectProtocol::UDP => route.addr.to_string(),
                ConnectProtocol::TCP => {
                    format!("tcp@{}", route.addr)
                }
                ConnectProtocol::QUIC => {
                    format!("quic@{}", route.addr)
                }
                ConnectProtocol::WS | ConnectProtocol::WSS => server_addr.clone(),
            };

            let item = RouteItem {
                destination: destination.to_string(),
                next_hop,
                metric,
                rt,
                interface,
            };
            route_list.push(item);
        }
    }
    route_list
}

pub fn command_list(vnt: &Vnt) -> Vec<DeviceItem> {
    let info = vnt.current_device();
    let device_list = vnt.device_list();
    let mut list = Vec::new();
    for peer in device_list {
        let name = peer.name;
        let virtual_ip = peer.virtual_ip.to_string();
        let (nat_type, public_ips, local_ip, ipv6) =
            if let Some(nat_info) = vnt.peer_nat_info(&peer.virtual_ip) {
                let nat_type = format!("{:?}", nat_info.nat_type);
                let public_ips: Vec<String> =
                    nat_info.public_ips.iter().map(|v| v.to_string()).collect();
                let public_ips = public_ips.join(",");
                let local_ip = nat_info
                    .local_ipv4()
                    .map(|v| v.to_string())
                    .unwrap_or("None".to_string());
                let ipv6 = nat_info
                    .ipv6()
                    .map(|v| v.to_string())
                    .unwrap_or("None".to_string());
                (nat_type, public_ips, local_ip, ipv6)
            } else {
                (
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                )
            };
        let (nat_traversal_type, rt) = if let Some(route) = vnt.route(&peer.virtual_ip) {
            let next_hop = vnt.route_key(&route.route_key());
            let nat_traversal_type = if route.metric == 1 {
                if route.protocol.is_udp() {
                    "udp-p2p".to_string()
                } else {
                    format!("{:?}-p2p", route.protocol)
                }
            } else if let Some(next_hop) = next_hop {
                if info.is_gateway_vip(&next_hop) {
                    "gateway-relay".to_string()
                } else {
                    "client-relay".to_string()
                }
            } else {
                "gateway-relay".to_string()
            };
            let rt = if route.rt < 0 {
                "".to_string()
            } else {
                route.rt.to_string()
            };
            (nat_traversal_type, rt)
        } else {
            ("gateway-relay".to_string(), "".to_string())
        };
        let status = format!("{:?}", peer.status);
        let item = DeviceItem {
            name,
            virtual_ip,
            nat_type,
            public_ips,
            local_ip,
            ipv6,
            nat_traversal_type,
            rt,
            status,
            wire_guard: peer.wireguard,
        };
        list.push(item);
    }
    list
}

pub fn command_info(vnt: &Vnt) -> Info {
    let service_state = service_state::read_service_state().unwrap_or_default();
    let config = vnt.config();
    let current_device = vnt.current_device();
    let nat_info = vnt.nat_info();
    let name = vnt.name().to_string();
    let virtual_ip = current_device.virtual_ip().to_string();
    let virtual_gateway = current_device.virtual_gateway().to_string();
    let virtual_netmask = current_device.virtual_netmask.to_string();
    let connect_status = format!("{:?}", vnt.connection_status());
    let channel_policy = match vnt.use_channel_type() {
        UseChannelType::Relay => "relay".to_string(),
        UseChannelType::P2p => "p2p".to_string(),
        UseChannelType::All => "auto".to_string(),
    };
    let relay_server = if current_device.control_server.port() == 0 {
        config.server_address_str.clone()
    } else {
        current_device.control_server.to_string()
    };
    let nat_type = format!("{:?}", nat_info.nat_type);
    let public_ips: Vec<String> = nat_info.public_ips.iter().map(|v| v.to_string()).collect();
    let public_ips = public_ips.join(",");
    let local_addr = nat_info
        .local_ipv4()
        .map(|v| v.to_string())
        .unwrap_or("None".to_string());
    let ipv6_addr = nat_info
        .ipv6()
        .map(|v| v.to_string())
        .unwrap_or("None".to_string());
    #[cfg(feature = "port_mapping")]
    let port_mapping_list = vnt.config().port_mapping_list.clone();
    #[cfg(not(feature = "port_mapping"))]
    let port_mapping_list = vec![];
    let in_ips = vnt.config().in_ips.clone();
    let out_ips = vnt.config().out_ips.clone();
    let udp_listen_addr = nat_info
        .udp_ports
        .iter()
        .map(|port| format!("0.0.0.0:{}", port))
        .collect();
    let tcp_listen_addr = format!("0.0.0.0:{}", nat_info.tcp_port);
    Info {
        name,
        virtual_ip,
        virtual_gateway,
        virtual_netmask,
        connect_status,
        auth_pending: service_state.auth_pending,
        channel_policy,
        last_error: service_state.last_error,
        relay_server,
        nat_type,
        public_ips,
        local_addr,
        ipv6_addr,
        port_mapping_list,
        in_ips,
        out_ips,
        udp_listen_addr,
        tcp_listen_addr,
    }
}

pub fn command_chart_a(vnt: &Vnt) -> ChartA {
    let disable_stats = !vnt.config().enable_traffic;
    if disable_stats {
        let chart = ChartA {
            disable_stats: true,
            ..Default::default()
        };
        return chart;
    }
    let (up_total, up_map) = vnt.up_stream_all().unwrap_or_default();
    let (down_total, down_map) = vnt.down_stream_all().unwrap_or_default();
    ChartA {
        disable_stats,
        up_total,
        down_total,
        up_map,
        down_map,
    }
}

pub fn command_chart_b(vnt: &Vnt, input_str: &str) -> ChartB {
    let disable_stats = !vnt.config().enable_traffic;
    if disable_stats {
        let chart = ChartB {
            disable_stats: true,
            ..Default::default()
        };
        return chart;
    }
    let (_, up_map) = vnt.up_stream_history().unwrap_or_default();
    let (_, down_map) = vnt.down_stream_history().unwrap_or_default();
    let up_keys: HashSet<_> = up_map.keys().cloned().collect();
    let down_keys: HashSet<_> = down_map.keys().cloned().collect();
    let mut keys: Vec<usize> = up_keys.union(&down_keys).cloned().collect();
    keys.sort();
    if let Some(channel) = find_matching_channel(input_str, &keys) {
        let (up_total, up_list) = up_map.get(&channel).cloned().unwrap_or_default();
        let (down_total, down_list) = down_map.get(&channel).cloned().unwrap_or_default();
        ChartB {
            disable_stats,
            channel: Some(channel),
            up_total,
            up_list,
            down_total,
            down_list,
        }
    } else {
        ChartB::default()
    }
}

fn match_from_end(input_str: &str, ip: &str) -> bool {
    let mut input_chars = input_str.chars().rev();
    let mut ip_chars = ip.chars().rev();

    while let (Some(ic), Some(pc)) = (input_chars.next(), ip_chars.next()) {
        if ic != pc {
            return false;
        }
    }

    input_chars.next().is_none() // Ensure all input characters matched
}

fn find_matching_channel(input_str: &str, channels: &[usize]) -> Option<usize> {
    for &channel in channels {
        let channel_str = channel.to_string();
        if match_from_end(input_str, &channel_str) {
            return Some(channel);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{find_matching_channel, match_from_end};

    #[test]
    fn match_from_end_requires_full_suffix_match() {
        assert!(match_from_end("12", "ch-12"));
        assert!(!match_from_end("13", "ch-12"));
        assert!(!match_from_end("123", "12"));
    }

    #[test]
    fn find_matching_channel_matches_from_suffix() {
        let channels = [0, 1, 12, 21];
        assert_eq!(find_matching_channel("12", &channels), Some(12));
        assert_eq!(find_matching_channel("1", &channels), Some(1));
        assert_eq!(find_matching_channel("99", &channels), None);
    }
}
