use sdl::core::Sdl;
use sdl::data_plane::gateway_session::GatewaySessionSummary;
use sdl::data_plane::route_state::RouteKind;
use sdl::data_plane::use_channel_type::UseChannelType;
use sdl::transport::connect_protocol::ConnectProtocol;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::command::entity::{
    DeviceItem, GatewayItem, Info, PeerTrafficItem, RouteItem, TrafficSummary, TransportTrafficItem,
};

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

pub fn command_list(sdl: &Sdl) -> Vec<DeviceItem> {
    let info = sdl.current_device();
    let device_list = sdl.device_list();
    let mut list = Vec::new();
    for peer in device_list {
        let name = peer.name;
        let virtual_ip = peer.virtual_ip.to_string();
        let (nat_type, public_ips, local_ip, ipv6) =
            if let Some(nat_info) = sdl.peer_nat_info(&peer.virtual_ip) {
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
        let (nat_traversal_type, rt) = if let Some(route) = sdl.route(&peer.virtual_ip) {
            let next_hop = sdl.route_key(&route.route_key());
            let nat_traversal_type = if route.is_p2p() {
                if route.is_udp() {
                    "udp-p2p".to_string()
                } else {
                    format!("{}-p2p", route.protocol_name())
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
    let name = config.name.clone();
    let runtime_name = vnt.name().to_string();
    let restart_required = runtime_name != name;
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
    let data_plane_status = if gateway_summary.authenticated {
        "gateway-available".to_string()
    } else if vnt
        .route_states()
        .into_iter()
        .any(|(_, routes)| routes.into_iter().any(|route| route.kind == RouteKind::P2p))
    {
        "p2p-available".to_string()
    } else {
        "limited".to_string()
    };
    let channel_policy = match vnt.use_channel_type() {
        UseChannelType::Relay => "relay".to_string(),
        UseChannelType::P2p => "p2p".to_string(),
        UseChannelType::All => "auto".to_string(),
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
    Info {
        name,
        runtime_name,
        restart_required,
        device_id: config.device_id.clone(),
        virtual_ip,
        virtual_gateway,
        virtual_netmask,
        gateway_session_status,
        gateway_endpoint,
        gateway_channel,
        connect_status,
        data_plane_status,
        auth_pending: service_state.auth_pending,
        channel_policy,
        last_error: service_state.last_error,
        nat_type,
        public_ips,
        local_addr,
        ipv6_addr,
        port_mapping_list,
        in_ips,
        out_ips,
        udp_listen_addr,
    }
}

pub fn command_gateway(vnt: &Sdl) -> Vec<GatewayItem> {
    vnt.gateway_session_summaries()
        .into_iter()
        .enumerate()
        .map(|(index, summary)| GatewayItem {
            gateway_id: if summary.gateway_id.is_empty() {
                format!("gateway-{}", index + 1)
            } else {
                summary.gateway_id
            },
            endpoint: summary
                .endpoint
                .map(|endpoint| endpoint.to_string())
                .unwrap_or_default(),
            channel: summary.channel_name,
            status: if !summary.configured {
                "not-configured".to_string()
            } else if summary.authenticated {
                if summary.reauth_required {
                    "reauth-required".to_string()
                } else {
                    "connected".to_string()
                }
            } else {
                "disconnected".to_string()
            },
            rt_ms: summary.rt_ms.map(|rt| rt.to_string()).unwrap_or_default(),
            active: summary.active,
        })
        .collect()
}

pub fn command_traffic(vnt: &Sdl) -> TrafficSummary {
    let disable_stats = !vnt.config().enable_traffic;
    if disable_stats {
        return TrafficSummary {
            disable_stats: true,
            ..Default::default()
        };
    }
    let gateway_vip = vnt.current_device().virtual_gateway;
    let gateway_summary = vnt.gateway_session_summary();
    let devices = vnt.device_list();
    let device_names: HashMap<Ipv4Addr, String> = devices
        .iter()
        .map(|device| (device.virtual_ip, device.name.clone()))
        .collect();
    let device_statuses: HashMap<Ipv4Addr, String> = devices
        .iter()
        .map(|device| (device.virtual_ip, format!("{:?}", device.status)))
        .collect();
    let peer_up_total = vnt.logical_up_stream();
    let peer_down_total = vnt.logical_down_stream();
    let (_, up_map) = vnt.up_stream_by_peer().unwrap_or_default();
    let (_, down_map) = vnt.down_stream_by_peer().unwrap_or_default();
    let mut vips = BTreeSet::new();
    vips.extend(
        device_names
            .keys()
            .copied()
            .filter(|vip| *vip != gateway_vip),
    );
    vips.extend(up_map.keys().copied());
    vips.extend(down_map.keys().copied());
    let mut peer_items: Vec<PeerTrafficItem> = vips
        .into_iter()
        .map(|vip| PeerTrafficItem {
            name: device_names.get(&vip).cloned().unwrap_or_default(),
            virtual_ip: vip.to_string(),
            status: device_statuses
                .get(&vip)
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string()),
            up_total: up_map.get(&vip).copied().unwrap_or_default(),
            down_total: down_map.get(&vip).copied().unwrap_or_default(),
        })
        .collect();
    if !gateway_vip.is_unspecified() || gateway_summary.configured {
        peer_items.push(PeerTrafficItem {
            name: "gateways".to_string(),
            virtual_ip: gateway_vip.to_string(),
            status: if !gateway_summary.configured {
                "not-configured".to_string()
            } else if gateway_summary.authenticated {
                "connected".to_string()
            } else {
                "disconnected".to_string()
            },
            up_total: vnt.gateway_up_stream(),
            down_total: vnt.gateway_down_stream(),
        });
    }
    let transport_up_total = vnt.transport_up_stream();
    let transport_down_total = vnt.transport_down_stream();
    let (_, transport_up_map) = vnt.up_stream_by_transport().unwrap_or_default();
    let (_, transport_down_map) = vnt.down_stream_by_transport().unwrap_or_default();
    let mut transport_ips = BTreeSet::<IpAddr>::new();
    transport_ips.extend(transport_up_map.keys().copied());
    transport_ips.extend(transport_down_map.keys().copied());
    let transport_items = transport_ips
        .into_iter()
        .map(|remote_ip| TransportTrafficItem {
            remote_ip: remote_ip.to_string(),
            up_total: transport_up_map
                .get(&remote_ip)
                .copied()
                .unwrap_or_default(),
            down_total: transport_down_map
                .get(&remote_ip)
                .copied()
                .unwrap_or_default(),
        })
        .collect();
    TrafficSummary {
        disable_stats,
        peer_up_total,
        peer_down_total,
        peer_items,
        transport_up_total,
        transport_down_total,
        transport_items,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        control_route_metric_rt, display_destination, route_name, RouteItem, CONTROL_DESTINATION,
    };
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

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
