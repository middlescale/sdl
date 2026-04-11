use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Serialize, Deserialize, Debug)]
pub struct Info {
    pub name: String,
    pub virtual_ip: String,
    pub virtual_gateway: String,
    pub virtual_netmask: String,
    pub gateway_session_status: String,
    pub gateway_endpoint: String,
    pub gateway_channel: String,
    pub connect_status: String,
    pub data_plane_status: String,
    pub auth_pending: bool,
    pub channel_policy: String,
    pub last_error: Option<String>,
    pub relay_server: String,
    pub nat_type: String,
    pub public_ips: String,
    pub local_addr: String,
    pub ipv6_addr: String,
    pub port_mapping_list: Vec<(bool, SocketAddr, String)>,
    pub in_ips: Vec<(u32, u32, Ipv4Addr)>,
    pub out_ips: Vec<(u32, u32)>,
    pub udp_listen_addr: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RouteItem {
    pub name: String,
    pub destination: String,
    pub next_hop: String,
    pub metric: String,
    pub rt: String,
    pub interface: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeviceItem {
    pub name: String,
    pub virtual_ip: String,
    pub nat_type: String,
    pub public_ips: String,
    pub local_ip: String,
    pub ipv6: String,
    pub nat_traversal_type: String,
    pub rt: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ChartA {
    pub disable_stats: bool,
    pub up_total: u64,
    pub down_total: u64,
    pub up_map: HashMap<usize, u64>,
    pub down_map: HashMap<usize, u64>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ChartB {
    pub disable_stats: bool,
    pub channel: Option<usize>,
    pub up_total: u64,
    pub up_list: Vec<usize>,
    pub down_total: u64,
    pub down_list: Vec<usize>,
}
