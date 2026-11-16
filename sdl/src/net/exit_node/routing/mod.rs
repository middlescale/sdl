//! Platform routing and guards against disrupting existing VPN/management paths.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use super::excludes::route_targets_cover_ip;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    all(test, target_os = "windows")
))]
use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
use linux::active_remote_management_ipv4s;
#[cfg(target_os = "macos")]
use macos::active_remote_management_ipv4s;
#[cfg(target_os = "windows")]
use windows::active_remote_management_ipv4s;

#[cfg(target_os = "linux")]
pub use linux::{
    client_bypasses_active, client_routing_active, refresh_client_routing_excludes,
    repair_client_routing_excludes, restore_client_split_routes, setup_client_routing,
    setup_server_routing, teardown_client_routing, teardown_server_routing,
};
#[cfg(target_os = "macos")]
pub use macos::{
    client_bypasses_active, client_routing_active, refresh_client_routing_excludes,
    setup_client_routing, setup_server_routing, teardown_client_routing, teardown_server_routing,
};
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use unsupported::{
    refresh_client_routing_excludes, setup_client_routing, setup_server_routing,
    teardown_client_routing, teardown_server_routing,
};
#[cfg(target_os = "windows")]
pub use windows::{
    client_bypasses_active, client_routing_active, refresh_client_routing_excludes,
    setup_client_routing, setup_server_routing, teardown_client_routing, teardown_server_routing,
};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn is_vpn_like_interface(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    [
        "tun",
        "tap",
        "utun",
        "wg",
        "tailscale",
        "zt",
        "zerotier",
        "ppp",
        "ipsec",
        "vpn",
        "clash",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_default_route_interface(tun_name: &str, iface: &str) -> anyhow::Result<()> {
    if iface == tun_name {
        return Ok(());
    }
    if is_vpn_like_interface(iface) {
        anyhow::bail!(
            "{}",
            route_preflight_warning(&format!(
                "default route already uses VPN/TUN-like interface '{}'",
                iface
            ))
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn route_preflight_warning(reason: &str) -> String {
    format!(
        "warning: exit-node route preflight failed: {reason}; SDL did not change system routes. Disable the existing VPN/full-tunnel route first, then retry `sdl exit-node use`."
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn remote_management_warning(ip: Ipv4Addr) -> String {
    format!(
        "warning: active public remote management connection from {ip} is not excluded; SDL did not change system routes because this could disconnect the current SSH/RDP session. SSH to this machine through its SDL virtual IP and retry, or add `--exclude {ip}` to `sdl exit-node use` if you understand the route change."
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn preflight_remote_management_excludes(excludes: &[String]) -> anyhow::Result<()> {
    let active_remotes = active_remote_management_ipv4s();
    for remote in active_remotes {
        if is_remote_management_ip_safe_without_exclude(remote) {
            continue;
        }
        if !route_targets_cover_ip(excludes, remote) {
            anyhow::bail!("{}", remote_management_warning(remote));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn is_remote_management_ip_safe_without_exclude(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local() || is_cgnat_ipv4(ip)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn is_cgnat_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    let base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    let mask = u32::MAX << 22;
    value & mask == base & mask
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const REMOTE_MANAGEMENT_PORTS: &[u16] = &[22, 3389, 5900, 5985, 5986];

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    all(test, target_os = "windows")
))]
fn parse_tcp_connection_remote_ipv4s(output: &str) -> Vec<Ipv4Addr> {
    let mut remotes = BTreeSet::new();
    for line in output.lines() {
        let endpoints = line
            .split_whitespace()
            .filter_map(parse_tcp_endpoint)
            .collect::<Vec<_>>();
        for pair in endpoints.windows(2) {
            let (local_ip, local_port) = pair[0];
            let (remote_ip, _remote_port) = pair[1];
            if REMOTE_MANAGEMENT_PORTS.contains(&local_port)
                && !remote_ip.is_loopback()
                && !remote_ip.is_unspecified()
                && local_ip != remote_ip
            {
                remotes.insert(remote_ip);
            }
        }
    }
    remotes.into_iter().collect()
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    all(test, target_os = "windows")
))]
fn parse_tcp_endpoint(token: &str) -> Option<(Ipv4Addr, u16)> {
    let token = token.trim_matches(|c| c == '[' || c == ']');
    if token.is_empty() || token == "*" || token == "*.*" {
        return None;
    }
    if let Some((addr, port)) = token.rsplit_once(':') {
        if let (Ok(addr), Ok(port)) = (addr.parse::<Ipv4Addr>(), port.parse::<u16>()) {
            return Some((addr, port));
        }
    }
    if let Some((addr, port)) = token.rsplit_once('.') {
        if let (Ok(addr), Ok(port)) = (addr.parse::<Ipv4Addr>(), port.parse::<u16>()) {
            return Some((addr, port));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn server_routing_is_explicitly_unsupported_without_running_commands() {
        assert_eq!(
            setup_server_routing("", "").unwrap_err().to_string(),
            "exit-node routing setup is currently supported only on Linux"
        );
        assert_eq!(
            teardown_server_routing("", "").unwrap_err().to_string(),
            "exit-node routing teardown is currently supported only on Linux"
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn remote_management_detection_parses_linux_ss_output() {
        let output = r#"
0      0      10.0.0.2:22        223.74.148.12:53124
0      0      10.0.0.2:443       8.8.8.8:53125
"#;
        assert_eq!(
            parse_tcp_connection_remote_ipv4s(output),
            vec![Ipv4Addr::new(223, 74, 148, 12)]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn remote_management_detection_parses_macos_netstat_output() {
        let output = r#"
tcp4       0      0  192.168.31.82.22       223.74.148.12.53124    ESTABLISHED
tcp4       0      0  192.168.31.82.443      8.8.8.8.53125          ESTABLISHED
"#;
        assert_eq!(
            parse_tcp_connection_remote_ipv4s(output),
            vec![Ipv4Addr::new(223, 74, 148, 12)]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn remote_management_public_ip_requires_exclude_but_sdl_vip_does_not() {
        assert!(!is_remote_management_ip_safe_without_exclude(
            Ipv4Addr::new(223, 74, 148, 12)
        ));
        assert!(is_remote_management_ip_safe_without_exclude(Ipv4Addr::new(
            10, 26, 0, 5
        )));
        assert!(is_remote_management_ip_safe_without_exclude(Ipv4Addr::new(
            100, 104, 205, 73
        )));
    }
}
