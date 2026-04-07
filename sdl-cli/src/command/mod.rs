use sdl::core::Sdl;
use sdl::data_plane::gateway_session::GatewaySessionSummary;
use sdl::data_plane::route_state::RouteKind;
use sdl::data_plane::use_channel_type::UseChannelType;
use sdl::transport::connect_protocol::ConnectProtocol;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};

use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};

pub mod client;
pub mod entity;
mod ipc;
pub mod server;
pub mod service_state;

const CONTROL_DESTINATION: &str = "CONTROL";
const CONTROL_VIP_STR: &str = "0.0.0.1";

pub fn command_route(vnt: &Sdl) -> Vec<RouteItem> {
    let route_table = vnt.route_states();
    let current_device = vnt.current_device();
    let server_addr = vnt.config().server_address_str.clone();
    let gateway_summary = vnt.gateway_session_summary();
    let peer_names: std::collections::HashMap<Ipv4Addr, String> = vnt
        .device_list()
        .into_iter()
        .map(|peer| (peer.virtual_ip, peer.name))
        .collect();
    let mut route_list = Vec::with_capacity(route_table.len());
    let mut has_gateway_route = false;
    for (destination, routes) in route_table {
        if destination == current_device.virtual_gateway {
            has_gateway_route = true;
        }
        for route in routes {
            let next_hop = vnt
                .route_key(&route.route_key)
                .map_or(String::new(), |v| v.to_string());
            let metric = route.metric.to_string();
            let rt = if route.rt < 0 {
                "".to_string()
            } else {
                route.rt.to_string()
            };
            let interface = match route.kind {
                RouteKind::GatewayRelay => gateway_relay_interface(
                    &gateway_summary,
                    route.transport,
                    route.addr,
                    &server_addr,
                ),
                RouteKind::P2p | RouteKind::Relay => {
                    route_interface(route.transport, route.addr, &server_addr)
                }
            };

            let item = RouteItem {
                name: route_name(destination, current_device.virtual_gateway, &peer_names),
                destination: display_destination(destination),
                next_hop,
                metric,
                rt,
                interface,
            };
            route_list.push(item);
        }
    }
    if !has_gateway_route
        && gateway_summary.configured
        && !current_device.virtual_gateway.is_unspecified()
    {
        route_list.push(build_gateway_route_item(
            current_device.virtual_gateway,
            &gateway_summary,
            &route_list,
            &peer_names,
            &server_addr,
        ));
    }
    route_list
}

fn display_destination(destination: Ipv4Addr) -> String {
    if destination.to_string() == CONTROL_VIP_STR {
        CONTROL_DESTINATION.to_string()
    } else {
        destination.to_string()
    }
}

fn build_gateway_route_item(
    gateway_vip: Ipv4Addr,
    gateway_summary: &GatewaySessionSummary,
    route_list: &[RouteItem],
    peer_names: &std::collections::HashMap<Ipv4Addr, String>,
    server_addr: &str,
) -> RouteItem {
    let (metric, rt) = control_route_metric_rt(route_list);
    let fallback_addr = gateway_summary
        .endpoint
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    RouteItem {
        name: route_name(gateway_vip, gateway_vip, peer_names),
        destination: gateway_vip.to_string(),
        next_hop: String::new(),
        metric,
        rt,
        interface: gateway_relay_interface(
            gateway_summary,
            ConnectProtocol::QUIC,
            fallback_addr,
            server_addr,
        ),
    }
}

fn route_name(
    destination: Ipv4Addr,
    gateway_vip: Ipv4Addr,
    peer_names: &std::collections::HashMap<Ipv4Addr, String>,
) -> String {
    if destination.to_string() == CONTROL_VIP_STR {
        return "control".to_string();
    }
    if destination == gateway_vip {
        return "gateway".to_string();
    }
    peer_names.get(&destination).cloned().unwrap_or_default()
}

fn control_route_metric_rt(route_list: &[RouteItem]) -> (String, String) {
    if let Some(item) = route_list
        .iter()
        .find(|item| item.destination == CONTROL_DESTINATION)
    {
        (item.metric.clone(), item.rt.clone())
    } else {
        ("2".to_string(), String::new())
    }
}

fn route_interface(
    protocol: ConnectProtocol,
    addr: std::net::SocketAddr,
    server_addr: &str,
) -> String {
    match protocol {
        ConnectProtocol::UDP => addr.to_string(),
        ConnectProtocol::TCP => format!("tcp@{}", addr),
        ConnectProtocol::QUIC => format!("quic@{}", addr),
        ConnectProtocol::WS | ConnectProtocol::WSS => server_addr.to_string(),
    }
}

fn gateway_relay_interface(
    gateway_summary: &GatewaySessionSummary,
    fallback_protocol: ConnectProtocol,
    fallback_addr: std::net::SocketAddr,
    server_addr: &str,
) -> String {
    if let Some(endpoint) = gateway_summary.endpoint {
        let channel = if gateway_summary.channel_name.is_empty() {
            match fallback_protocol {
                ConnectProtocol::UDP => "udp".to_string(),
                ConnectProtocol::TCP => "tcp".to_string(),
                ConnectProtocol::QUIC => "quic".to_string(),
                ConnectProtocol::WS => "ws".to_string(),
                ConnectProtocol::WSS => "wss".to_string(),
            }
        } else {
            gateway_summary.channel_name.clone()
        };
        return format!("{}@{}", channel, endpoint);
    }
    route_interface(fallback_protocol, fallback_addr, server_addr)
}

pub fn command_list(vnt: &Sdl) -> Vec<DeviceItem> {
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

pub fn command_info(vnt: &Sdl) -> Info {
    let service_state = service_state::read_service_state().unwrap_or_default();
    let config = vnt.config();
    let current_device = vnt.current_device();
    let gateway_summary = vnt.gateway_session_summary();
    let nat_info = vnt.nat_info();
    let name = vnt.name().to_string();
    let virtual_ip = current_device.virtual_ip().to_string();
    let virtual_gateway = current_device.virtual_gateway().to_string();
    let virtual_netmask = current_device.virtual_netmask.to_string();
    let gateway_session_status = if !gateway_summary.configured {
        "not-configured".to_string()
    } else if gateway_summary.authenticated {
        if gateway_summary.reauth_required {
            "reauth-required".to_string()
        } else {
            "connected".to_string()
        }
    } else {
        "disconnected".to_string()
    };
    let gateway_endpoint = gateway_summary
        .endpoint
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_default();
    let gateway_channel = if gateway_summary.configured {
        gateway_summary.channel_name
    } else {
        String::new()
    };
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
        gateway_session_status,
        gateway_endpoint,
        gateway_channel,
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

pub fn command_chart_a(vnt: &Sdl) -> ChartA {
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

pub fn command_chart_b(vnt: &Sdl, input_str: &str) -> ChartB {
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
    use super::{
        control_route_metric_rt, display_destination, find_matching_channel, match_from_end,
        route_name, RouteItem, CONTROL_DESTINATION,
    };
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

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

    #[test]
    fn display_destination_relabels_control_vip() {
        assert_eq!(
            display_destination(Ipv4Addr::new(0, 0, 0, 1)),
            CONTROL_DESTINATION
        );
        assert_eq!(
            display_destination(Ipv4Addr::new(10, 26, 0, 1)),
            "10.26.0.1"
        );
    }

    #[test]
    fn control_route_metric_rt_prefers_control_row() {
        let route_list = vec![RouteItem {
            name: "control".to_string(),
            destination: CONTROL_DESTINATION.to_string(),
            next_hop: String::new(),
            metric: "2".to_string(),
            rt: "85".to_string(),
            interface: "quic@43.133.189.140:443".to_string(),
        }];
        assert_eq!(
            control_route_metric_rt(&route_list),
            ("2".to_string(), "85".to_string())
        );
        assert_eq!(
            control_route_metric_rt(&[]),
            ("2".to_string(), String::new())
        );
    }

    #[test]
    fn route_name_prefers_peer_and_special_labels() {
        let mut peer_names = HashMap::new();
        peer_names.insert(Ipv4Addr::new(10, 26, 0, 3), "aliyun-hk".to_string());
        assert_eq!(
            route_name(
                Ipv4Addr::new(0, 0, 0, 1),
                Ipv4Addr::new(10, 26, 0, 1),
                &peer_names
            ),
            "control"
        );
        assert_eq!(
            route_name(
                Ipv4Addr::new(10, 26, 0, 1),
                Ipv4Addr::new(10, 26, 0, 1),
                &peer_names
            ),
            "gateway"
        );
        assert_eq!(
            route_name(
                Ipv4Addr::new(10, 26, 0, 3),
                Ipv4Addr::new(10, 26, 0, 1),
                &peer_names
            ),
            "aliyun-hk"
        );
    }
}
