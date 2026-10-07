//! linux route operations.
use super::super::excludes::{
    normalize_route_target, normalized_route_target_addr, route_exclude_diff,
};
use super::super::{
    command_available, command_stdout, run_command, run_shell, validate_iface_name,
};
use super::{
    parse_tcp_connection_remote_ipv4s, preflight_remote_management_excludes,
    route_preflight_warning, validate_default_route_interface,
};
use std::net::Ipv4Addr;

pub fn setup_server_routing(egress_interface: &str, tun_name: &str) -> anyhow::Result<String> {
    validate_iface_name(egress_interface, "egress interface")?;
    validate_iface_name(tun_name, "tun name")?;

    let forwarding_note = enable_ipv4_forwarding()?;
    run_shell(&format!(
        "iptables -t nat -C POSTROUTING -o {egress_interface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o {egress_interface} -j MASQUERADE"
    ))?;
    run_shell(&format!(
        "iptables -C FORWARD -i {tun_name} -o {egress_interface} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {tun_name} -o {egress_interface} -j ACCEPT"
    ))?;
    run_shell(&format!(
        "iptables -C FORWARD -i {egress_interface} -o {tun_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {egress_interface} -o {tun_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    ))?;

    Ok(format!(
        "exit-node routing configured: tun={} egress={}; {}",
        tun_name, egress_interface, forwarding_note
    ))
}

pub fn teardown_server_routing(egress_interface: &str, tun_name: &str) -> anyhow::Result<String> {
    validate_iface_name(egress_interface, "egress interface")?;
    validate_iface_name(tun_name, "tun name")?;

    run_shell(&format!(
        "iptables -t nat -D POSTROUTING -o {egress_interface} -j MASQUERADE 2>/dev/null || true"
    ))?;
    run_shell(&format!(
        "iptables -D FORWARD -i {tun_name} -o {egress_interface} -j ACCEPT 2>/dev/null || true"
    ))?;
    run_shell(&format!(
        "iptables -D FORWARD -i {egress_interface} -o {tun_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true"
    ))?;

    Ok(format!(
        "exit-node routing removed: tun={} egress={}; IPv4 forwarding was not disabled because it may be used by Docker, VPN, router, or other services",
        tun_name, egress_interface
    ))
}

pub fn setup_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    preflight_client_routing(tun_name)?;
    preflight_remote_management_excludes(excludes)?;
    run_shell(&format!(
        "ip route del 0.0.0.0/1 dev {tun_name} 2>/dev/null || true"
    ))?;
    run_shell(&format!(
        "ip route del 128.0.0.0/1 dev {tun_name} 2>/dev/null || true"
    ))?;
    for exclude in excludes {
        let exclude = normalize_route_target(exclude)?;
        let addr = normalized_route_target_addr(&exclude)?;
        run_shell(&format!(
            "ip route del {exclude} 2>/dev/null || true; route=$(ip route get {addr} | head -n 1 | sed 's/ uid [0-9].*//; s/ cache.*//; s/^[^ ]* //'); [ -n \"$route\" ] && ip route replace {exclude} $route"
        ))?;
    }
    run_command("ip", &["route", "replace", "0.0.0.0/1", "dev", tun_name])?;
    run_command("ip", &["route", "replace", "128.0.0.0/1", "dev", tun_name])?;
    let exclude_note = if excludes.is_empty() {
        String::new()
    } else {
        format!("; excluded {}", excludes.join(","))
    };
    Ok(format!(
        "exit-node client routing configured: default IPv4 split routes via {}{}",
        tun_name, exclude_note
    ))
}

pub fn teardown_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    for exclude in excludes {
        let exclude = normalize_route_target(exclude)?;
        run_shell(&format!("ip route del {exclude} 2>/dev/null || true"))?;
    }
    run_shell(&format!(
        "ip route del 0.0.0.0/1 dev {tun_name} 2>/dev/null || true"
    ))?;
    run_shell(&format!(
        "ip route del 128.0.0.0/1 dev {tun_name} 2>/dev/null || true"
    ))?;
    Ok(format!(
        "exit-node client routing removed: default IPv4 split routes via {}",
        tun_name
    ))
}

pub fn refresh_client_routing_excludes(
    tun_name: &str,
    previous_excludes: &[String],
    next_excludes: &[String],
) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    preflight_remote_management_excludes(next_excludes)?;
    let (removed, added) = route_exclude_diff(previous_excludes, next_excludes)?;
    for exclude in &removed {
        run_shell(&format!("ip route del {exclude} 2>/dev/null || true"))?;
    }
    for exclude in &added {
        run_shell(&format!(
            "ip route del {exclude} 2>/dev/null || true; route=$(ip route show default | head -n 1 | sed 's/^default //'); [ -n \"$route\" ] || exit 1; ip route replace {exclude} $route"
        ))?;
    }
    Ok(format!(
        "removed {} excludes, added {} excludes; default split routes unchanged via {}",
        removed.len(),
        added.len(),
        tun_name
    ))
}

fn enable_ipv4_forwarding() -> anyhow::Result<String> {
    let current = command_stdout("sysctl", &["-n", "net.ipv4.ip_forward"])?;
    if current.trim() == "1" {
        return Ok("IPv4 forwarding was already enabled".to_string());
    }
    run_command("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    Ok(
        "IPv4 forwarding was enabled for exit-node routing and will not be disabled automatically"
            .to_string(),
    )
}

pub(super) fn active_remote_management_ipv4s() -> Vec<Ipv4Addr> {
    if command_available("ss") {
        match command_stdout("ss", &["-Htn", "state", "established"]) {
            Ok(output) => return parse_tcp_connection_remote_ipv4s(&output),
            Err(err) => log::warn!(
                "failed to inspect active TCP connections with ss: {:?}",
                err
            ),
        }
    }
    match command_stdout("netstat", &["-tn"]) {
        Ok(output) => parse_tcp_connection_remote_ipv4s(&output),
        Err(err) => {
            log::warn!(
                "failed to inspect active TCP connections with netstat: {:?}",
                err
            );
            Vec::new()
        }
    }
}

fn preflight_client_routing(tun_name: &str) -> anyhow::Result<()> {
    for target in ["0.0.0.0/1", "128.0.0.0/1"] {
        let route = command_stdout("ip", &["route", "show", target])?;
        if let Some(iface) = linux_route_iface(&route) {
            if iface != tun_name {
                anyhow::bail!(
                    "{}",
                    route_preflight_warning(&format!(
                        "split default route {} already exists on interface '{}'",
                        target, iface
                    ))
                );
            }
        }
    }
    let default_route = command_stdout("ip", &["route", "show", "default"])?;
    if let Some(iface) = linux_route_iface(&default_route) {
        validate_default_route_interface(tun_name, iface)?;
    }
    Ok(())
}

fn linux_route_iface(route: &str) -> Option<&str> {
    let mut fields = route.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "dev" {
            return fields.next();
        }
    }
    None
}
