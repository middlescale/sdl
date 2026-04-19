use console::{style, Style};
use std::net::Ipv4Addr;

use crate::command::entity::{DeviceItem, Info, RouteItem, TrafficSummary};

pub mod table;

pub fn console_info(status: Info) {
    println!("Name: {}", style(status.name).green());
    if !status.runtime_name.is_empty() {
        if status.restart_required {
            println!(
                "Runtime name: {}",
                style(format!("{} (restart required)", status.runtime_name)).yellow()
            );
        } else {
            println!("Runtime name: {}", style(status.runtime_name).green());
        }
    }
    println!("Virtual ip: {}", style(status.virtual_ip).green());
    println!("Virtual gateway: {}", style(status.virtual_gateway).green());
    if status
        .gateway_session_status
        .eq_ignore_ascii_case("connected")
    {
        println!(
            "Gateway session: {}",
            style(status.gateway_session_status).green()
        );
    } else if status
        .gateway_session_status
        .eq_ignore_ascii_case("reauth-required")
    {
        println!(
            "Gateway session: {}",
            style(status.gateway_session_status).yellow()
        );
    } else {
        println!(
            "Gateway session: {}",
            style(status.gateway_session_status).red()
        );
    }
    if !status.gateway_endpoint.is_empty() {
        println!(
            "Gateway endpoint: {}",
            style(status.gateway_endpoint).green()
        );
    }
    if !status.gateway_channel.is_empty() {
        println!("Gateway channel: {}", style(status.gateway_channel).green());
    }
    println!("Virtual netmask: {}", style(status.virtual_netmask).green());
    if status.connect_status.eq_ignore_ascii_case("Connected") {
        println!("Control session: {}", style(status.connect_status).green());
    } else {
        println!("Control session: {}", style(status.connect_status).red());
    }
    if status
        .data_plane_status
        .eq_ignore_ascii_case("gateway-available")
        || status
            .data_plane_status
            .eq_ignore_ascii_case("p2p-available")
    {
        println!("Data plane: {}", style(status.data_plane_status).green());
    } else {
        println!("Data plane: {}", style(status.data_plane_status).yellow());
    }

    println!(
        "Auth pending: {}",
        if status.auth_pending {
            style("true").yellow()
        } else {
            style("false").green()
        }
    );
    println!("NAT type: {}", style(status.nat_type).green());
    println!("Channel policy: {}", style(status.channel_policy).green());
    if let Some(last_error) = &status.last_error {
        println!("Last error: {}", style(last_error).red());
    }
    println!("Relay server: {}", style(status.relay_server).green());
    println!(
        "Udp listen: {}",
        style(status.udp_listen_addr.join(", ")).green()
    );
    println!("Public ips: {}", style(status.public_ips).green());
    println!("Local addr: {}", style(status.local_addr).green());
    println!("IPv6: {}", style(status.ipv6_addr).green());

    if !status.port_mapping_list.is_empty() {
        println!("------------------------------------------");
        println!("Port mapping {}", status.port_mapping_list.len());
        for (is_tcp, addr, dest) in status.port_mapping_list {
            if is_tcp {
                println!("  TCP: {} -> {}", addr, dest)
            } else {
                println!("  UDP: {} -> {}", addr, dest)
            }
        }
    }
    if !status.in_ips.is_empty() || !status.out_ips.is_empty() {
        println!("------------------------------------------");
    }
    if !status.in_ips.is_empty() {
        println!("IP forwarding {}", status.in_ips.len());
        for (dest, mask, ip) in status.in_ips {
            println!(
                "  -- {} --> {}/{}",
                ip,
                Ipv4Addr::from(dest),
                mask.count_ones()
            )
        }
    }
    if !status.out_ips.is_empty() {
        println!("Allows network {}", status.out_ips.len());
        for (dest, mask) in status.out_ips {
            println!("  {}/{}", Ipv4Addr::from(dest), mask.count_ones())
        }
    }
}

fn convert(num: u64) -> String {
    let gigabytes = num / (1024 * 1024 * 1024);
    let remaining_bytes = num % (1024 * 1024 * 1024);
    let megabytes = remaining_bytes / (1024 * 1024);
    let remaining_bytes = remaining_bytes % (1024 * 1024);
    let kilobytes = remaining_bytes / 1024;
    let remaining_bytes = remaining_bytes % 1024;
    let mut s = String::new();
    if gigabytes > 0 {
        s.push_str(&format!("{} GB ", gigabytes));
    }
    if megabytes > 0 {
        s.push_str(&format!("{} MB ", megabytes));
    }
    if kilobytes > 0 {
        s.push_str(&format!("{} KB ", kilobytes));
    }
    if remaining_bytes > 0 {
        s.push_str(&format!("{} bytes", remaining_bytes));
    }
    if s.is_empty() {
        "0 bytes".to_string()
    } else {
        s
    }
}

pub fn console_route_table(mut list: Vec<RouteItem>) {
    if list.is_empty() {
        println!("No route found");
        return;
    }
    list.sort_by(|t1, t2| t1.destination.cmp(&t2.destination));
    let mut out_list = Vec::with_capacity(list.len());

    out_list.push(vec![
        ("Name".to_string(), Style::new()),
        ("Destination".to_string(), Style::new()),
        ("Next Hop".to_string(), Style::new()),
        ("Metric".to_string(), Style::new()),
        ("Rt".to_string(), Style::new()),
        ("Interface".to_string(), Style::new()),
    ]);
    for item in list {
        out_list.push(vec![
            (item.name, Style::new().green()),
            (item.destination, Style::new().green()),
            (item.next_hop, Style::new().green()),
            (item.metric, Style::new().green()),
            (item.rt, Style::new().green()),
            (item.interface, Style::new().green()),
        ]);
    }

    table::println_table(out_list)
}

pub fn console_device_list(mut list: Vec<DeviceItem>) {
    if list.is_empty() {
        println!("No other devices found");
        return;
    }
    list.sort_by(|t1, t2| t1.virtual_ip.cmp(&t2.virtual_ip));
    list.sort_by(|t1, t2| t1.status.cmp(&t2.status));
    let mut out_list = Vec::with_capacity(list.len());
    //表头
    out_list.push(vec![
        ("Name".to_string(), Style::new()),
        ("Virtual Ip".to_string(), Style::new()),
        ("Status".to_string(), Style::new()),
        ("P2P/Relay".to_string(), Style::new()),
        ("Rt".to_string(), Style::new()),
    ]);
    for item in list {
        let name = item.name;
        if &item.status == "Online" {
            if item.nat_traversal_type.contains("p2p") {
                out_list.push(vec![
                    (name, Style::new().green()),
                    (item.virtual_ip, Style::new().green()),
                    (item.status, Style::new().green()),
                    (item.nat_traversal_type, Style::new().green()),
                    (item.rt, Style::new().green()),
                ]);
            } else {
                out_list.push(vec![
                    (name, Style::new().yellow()),
                    (item.virtual_ip, Style::new().yellow()),
                    (item.status, Style::new().yellow()),
                    (item.nat_traversal_type, Style::new().yellow()),
                    (item.rt, Style::new().yellow()),
                ]);
            }
        } else {
            out_list.push(vec![
                (name, Style::new().color256(102)),
                (item.virtual_ip, Style::new().color256(102)),
                (item.status, Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
            ]);
        }
    }
    table::println_table(out_list)
}

pub fn console_device_list_all(mut list: Vec<DeviceItem>) {
    if list.is_empty() {
        println!("No other devices found");
        return;
    }
    list.sort_by(|t1, t2| t1.virtual_ip.cmp(&t2.virtual_ip));
    list.sort_by(|t1, t2| t1.status.cmp(&t2.status));
    let mut out_list = Vec::with_capacity(list.len());
    //表头
    out_list.push(vec![
        ("Name".to_string(), Style::new()),
        ("Virtual Ip".to_string(), Style::new()),
        ("Status".to_string(), Style::new()),
        ("P2P/Relay".to_string(), Style::new()),
        ("Rt".to_string(), Style::new()),
        ("NAT Type".to_string(), Style::new()),
        ("Public Ips".to_string(), Style::new()),
        ("Local Ip".to_string(), Style::new()),
        ("IPv6".to_string(), Style::new()),
    ]);
    for item in list {
        if &item.status == "Online" {
            if &item.nat_traversal_type == "p2p" {
                out_list.push(vec![
                    (item.name, Style::new().green()),
                    (item.virtual_ip, Style::new().green()),
                    (item.status, Style::new().green()),
                    (item.nat_traversal_type, Style::new().green()),
                    (item.rt, Style::new().green()),
                    (item.nat_type, Style::new().green()),
                    (item.public_ips, Style::new().green()),
                    (item.local_ip, Style::new().green()),
                    (item.ipv6, Style::new().green()),
                ]);
            } else {
                out_list.push(vec![
                    (item.name, Style::new().yellow()),
                    (item.virtual_ip, Style::new().yellow()),
                    (item.status, Style::new().yellow()),
                    (item.nat_traversal_type, Style::new().yellow()),
                    (item.rt, Style::new().yellow()),
                    (item.nat_type, Style::new().yellow()),
                    (item.public_ips, Style::new().yellow()),
                    (item.local_ip, Style::new().yellow()),
                    (item.ipv6, Style::new().yellow()),
                ]);
            }
        } else {
            out_list.push(vec![
                (item.name, Style::new().color256(102)),
                (item.virtual_ip, Style::new().color256(102)),
                (item.status, Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
            ]);
        }
    }
    table::println_table(out_list)
}

pub fn console_traffic(mut summary: TrafficSummary) {
    if summary.disable_stats {
        println!("Traffic stats disabled");
        return;
    }
    if summary.peer_items.is_empty() && summary.transport_items.is_empty() {
        println!("No traffic data");
        return;
    }
    summary
        .peer_items
        .sort_by(|a, b| a.virtual_ip.cmp(&b.virtual_ip));
    println!("Peer traffic");
    let mut peer_list = Vec::with_capacity(summary.peer_items.len() + 2);
    peer_list.push(vec![
        ("Name".to_string(), Style::new()),
        ("Virtual Ip".to_string(), Style::new()),
        ("Status".to_string(), Style::new()),
        ("Up".to_string(), Style::new()),
        ("Down".to_string(), Style::new()),
    ]);
    for item in summary.peer_items {
        peer_list.push(vec![
            (item.name, Style::new().green()),
            (item.virtual_ip, Style::new().green()),
            (item.status, Style::new().green()),
            (convert(item.up_total), Style::new().green()),
            (convert(item.down_total), Style::new().green()),
        ]);
    }
    peer_list.push(vec![
        ("total".to_string(), Style::new().yellow()),
        ("".to_string(), Style::new().yellow()),
        ("".to_string(), Style::new().yellow()),
        (convert(summary.peer_up_total), Style::new().yellow()),
        (convert(summary.peer_down_total), Style::new().yellow()),
    ]);
    table::println_table(peer_list);

    println!();
    println!("Transport traffic");
    summary
        .transport_items
        .sort_by(|a, b| a.remote_ip.cmp(&b.remote_ip));
    let mut transport_list = Vec::with_capacity(summary.transport_items.len() + 2);
    transport_list.push(vec![
        ("Remote Ip".to_string(), Style::new()),
        ("Up".to_string(), Style::new()),
        ("Down".to_string(), Style::new()),
    ]);
    for item in summary.transport_items {
        transport_list.push(vec![
            (item.remote_ip, Style::new().green()),
            (convert(item.up_total), Style::new().green()),
            (convert(item.down_total), Style::new().green()),
        ]);
    }
    transport_list.push(vec![
        ("total".to_string(), Style::new().yellow()),
        (convert(summary.transport_up_total), Style::new().yellow()),
        (convert(summary.transport_down_total), Style::new().yellow()),
    ]);
    table::println_table(transport_list)
}
