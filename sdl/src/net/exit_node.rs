use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::Command;

use anyhow::Context;

use crate::core::Sdl;

pub fn local_ready(enabled: bool, egress_interface: &Option<String>) -> bool {
    enabled
        && cfg!(target_os = "linux")
        && egress_interface
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
}

pub fn merge_excludes(
    runtime: &Sdl,
    selected_device_id: Option<&str>,
    user_excludes: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut excludes = BTreeSet::new();
    for exclude in collect_auto_excludes(runtime, selected_device_id) {
        excludes.insert(normalize_route_target(&exclude)?);
    }
    for exclude in user_excludes {
        excludes.insert(normalize_route_target(exclude)?);
    }
    Ok(excludes.into_iter().collect())
}

pub fn setup_server_routing(egress_interface: &str, tun_name: &str) -> anyhow::Result<String> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!("exit-node routing setup is currently supported only on Linux");
    }
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
    if !cfg!(target_os = "linux") {
        anyhow::bail!("exit-node routing teardown is currently supported only on Linux");
    }
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

#[cfg(target_os = "linux")]
pub fn setup_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    preflight_client_routing(tun_name)?;
    for exclude in excludes {
        let exclude = normalize_route_target(exclude)?;
        run_shell(&format!(
            "default_route=$(ip route show default | head -n 1 | sed 's/^default //'); [ -n \"$default_route\" ] && ip route replace {exclude} $default_route"
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

#[cfg(target_os = "linux")]
pub fn teardown_client_routing(tun_name: &str) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
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

#[cfg(target_os = "macos")]
pub fn setup_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    preflight_client_routing(tun_name)?;
    let gateway = macos_default_gateway()?;
    for exclude in excludes {
        let (addr, mask) = route_target_addr_mask(exclude)?;
        run_shell(&format!(
            "route -n delete -net {addr} -netmask {mask} 2>/dev/null || true; route -n add -net {addr} -netmask {mask} {gateway}"
        ))?;
    }
    run_shell(&format!(
        "route -n delete -net 0.0.0.0 -netmask 128.0.0.0 2>/dev/null || true; route -n add -net 0.0.0.0 -netmask 128.0.0.0 -interface {tun_name}"
    ))?;
    run_shell(&format!(
        "route -n delete -net 128.0.0.0 -netmask 128.0.0.0 2>/dev/null || true; route -n add -net 128.0.0.0 -netmask 128.0.0.0 -interface {tun_name}"
    ))?;
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

#[cfg(target_os = "macos")]
pub fn teardown_client_routing(tun_name: &str) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    run_shell("route -n delete -net 0.0.0.0 -netmask 128.0.0.0 2>/dev/null || true")?;
    run_shell("route -n delete -net 128.0.0.0 -netmask 128.0.0.0 2>/dev/null || true")?;
    Ok(format!(
        "exit-node client routing removed: default IPv4 split routes via {}",
        tun_name
    ))
}

#[cfg(target_os = "windows")]
pub fn setup_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    preflight_client_routing(tun_name)?;
    let if_index = windows_interface_index(tun_name)?;
    let gateway = windows_default_gateway()?;
    for exclude in excludes {
        let (addr, mask) = route_target_addr_mask(exclude)?;
        let _ = run_command(
            "route.exe",
            &["DELETE", &addr.to_string(), "MASK", &mask.to_string()],
        );
        run_command(
            "route.exe",
            &[
                "ADD",
                &addr.to_string(),
                "MASK",
                &mask.to_string(),
                &gateway,
                "METRIC",
                "1",
            ],
        )?;
    }
    let _ = run_command("route.exe", &["DELETE", "0.0.0.0", "MASK", "128.0.0.0"]);
    run_command(
        "route.exe",
        &[
            "ADD",
            "0.0.0.0",
            "MASK",
            "128.0.0.0",
            "0.0.0.0",
            "METRIC",
            "1",
            "IF",
            &if_index,
        ],
    )?;
    let _ = run_command("route.exe", &["DELETE", "128.0.0.0", "MASK", "128.0.0.0"]);
    run_command(
        "route.exe",
        &[
            "ADD",
            "128.0.0.0",
            "MASK",
            "128.0.0.0",
            "0.0.0.0",
            "METRIC",
            "1",
            "IF",
            &if_index,
        ],
    )?;
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

#[cfg(target_os = "windows")]
pub fn teardown_client_routing(tun_name: &str) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    let _ = run_command("route.exe", &["DELETE", "0.0.0.0", "MASK", "128.0.0.0"]);
    let _ = run_command("route.exe", &["DELETE", "128.0.0.0", "MASK", "128.0.0.0"]);
    Ok(format!(
        "exit-node client routing removed: default IPv4 split routes via {}",
        tun_name
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn setup_client_routing(_tun_name: &str, _excludes: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("exit-node client routing setup is supported only on Linux, macOS, and Windows")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn teardown_client_routing(_tun_name: &str) -> anyhow::Result<String> {
    anyhow::bail!(
        "exit-node client routing teardown is supported only on Linux, macOS, and Windows"
    )
}

fn collect_auto_excludes(runtime: &Sdl, selected_device_id: Option<&str>) -> Vec<String> {
    let mut excludes = BTreeSet::new();
    add_socket_addr_exclude(&mut excludes, runtime.control_server_addr());
    if let Some((host, port)) = parse_control_authority(&runtime.config().server_address_str) {
        add_resolved_host_excludes(&mut excludes, &host, port);
    }
    for summary in runtime.gateway_session_summaries() {
        if let Some(endpoint) = summary.endpoint {
            add_socket_addr_exclude(&mut excludes, endpoint);
        }
    }
    for (_peer_ip, routes) in runtime.route_table() {
        for route in routes {
            if route.is_p2p() {
                add_socket_addr_exclude(&mut excludes, route.addr);
            }
        }
    }
    if let Some(peer_ip) = selected_exit_node_peer_ip(runtime, selected_device_id) {
        if let Some(route) = runtime.route(&peer_ip) {
            if route.is_p2p() {
                add_socket_addr_exclude(&mut excludes, route.addr);
            }
        }
    }
    excludes.into_iter().collect()
}

fn selected_exit_node_peer_ip(runtime: &Sdl, selected_device_id: Option<&str>) -> Option<Ipv4Addr> {
    let selected_device_id = selected_device_id?.trim();
    if selected_device_id.is_empty() {
        return None;
    }
    runtime
        .device_list()
        .into_iter()
        .find(|peer| peer.device_id == selected_device_id)
        .map(|peer| peer.virtual_ip)
}

fn validate_iface_name(value: &str, label: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    if value.len() > 64 {
        anyhow::bail!("{label} too long");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'))
    {
        anyhow::bail!("{label} contains invalid characters");
    }
    Ok(())
}

fn run_command(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if output.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "{} {} failed: {}{}",
        program,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
}

fn run_shell(command: &str) -> anyhow::Result<()> {
    run_command("sh", &["-c", command])
}

#[cfg(target_os = "linux")]
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

#[cfg(not(target_os = "linux"))]
fn enable_ipv4_forwarding() -> anyhow::Result<String> {
    anyhow::bail!("IPv4 forwarding setup is supported only on Linux")
}

fn command_stdout(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "{} {} failed: {}{}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn normalize_route_target(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("route target cannot be empty");
    }
    if value.contains('/') {
        let Some((addr, prefix)) = value.split_once('/') else {
            anyhow::bail!("invalid IPv4 CIDR route target '{value}'");
        };
        addr.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 CIDR address '{value}'"))?;
        let prefix = prefix
            .parse::<u8>()
            .with_context(|| format!("invalid IPv4 CIDR prefix '{value}'"))?;
        if prefix > 32 {
            anyhow::bail!("invalid IPv4 CIDR prefix '{value}': must be <= 32");
        }
        return Ok(value.to_string());
    }
    value
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 route target '{value}'"))?;
    Ok(format!("{value}/32"))
}

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

fn route_preflight_warning(reason: &str) -> String {
    format!(
        "warning: exit-node route preflight failed: {reason}; SDL did not change system routes. Disable the existing VPN/full-tunnel route first, then retry `sdl exit-node use`."
    )
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn linux_route_iface(route: &str) -> Option<&str> {
    let mut fields = route.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "dev" {
            return fields.next();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn preflight_client_routing(tun_name: &str) -> anyhow::Result<()> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("netstat -rn -f inet 2>/dev/null || true")
        .output()
        .context("failed to query macOS route table")?;
    let route_table = String::from_utf8_lossy(&output.stdout);
    for target in ["0/1", "0.0.0.0/1", "128.0/1", "128.0.0.0/1"] {
        if let Some(iface) = macos_netstat_route_iface(&route_table, target) {
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
    let output = Command::new("sh")
        .arg("-c")
        .arg("route -n get default 2>/dev/null || true")
        .output()
        .context("failed to query macOS default route")?;
    let default_route = String::from_utf8_lossy(&output.stdout);
    if let Some(iface) = macos_route_interface(&default_route) {
        validate_default_route_interface(tun_name, iface)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_route_interface(route: &str) -> Option<&str> {
    route.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("interface:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

#[cfg(target_os = "macos")]
fn macos_netstat_route_iface<'a>(route_table: &'a str, destination: &str) -> Option<&'a str> {
    route_table.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != destination {
            return None;
        }
        fields.nth(2)
    })
}

#[cfg(target_os = "windows")]
fn preflight_client_routing(tun_name: &str) -> anyhow::Result<()> {
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        let command = format!(
            "$route = Get-NetRoute -DestinationPrefix '{}' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if ($route) {{ (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop).Name }}",
            prefix
        );
        let iface = run_powershell(&command)?;
        if !iface.trim().is_empty() && iface.trim() != tun_name {
            anyhow::bail!(
                "{}",
                route_preflight_warning(&format!(
                    "split default route {} already exists on interface '{}'",
                    prefix,
                    iface.trim()
                ))
            );
        }
    }
    let default_iface = run_powershell(
        "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if ($route) { (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop).Name }",
    )?;
    if !default_iface.trim().is_empty() {
        validate_default_route_interface(tun_name, default_iface.trim())?;
    }
    Ok(())
}

fn ipv4_host_route(ip: Ipv4Addr) -> String {
    format!("{ip}/32")
}

fn add_socket_addr_exclude(excludes: &mut BTreeSet<String>, addr: SocketAddr) {
    if let IpAddr::V4(ip) = addr.ip() {
        excludes.insert(ipv4_host_route(ip));
    }
}

fn add_resolved_host_excludes(excludes: &mut BTreeSet<String>, host: &str, port: u16) {
    if let Ok(addrs) = (host, port).to_socket_addrs() {
        for addr in addrs {
            add_socket_addr_exclude(excludes, addr);
        }
    }
}

fn parse_control_authority(value: &str) -> Option<(String, u16)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (scheme, rest) = trimmed.split_once("://").unwrap_or(("https", trimmed));
    let default_port = match scheme {
        "http" | "ws" => 80,
        "https" | "wss" | "tcp" | "udp" => 443,
        _ => 443,
    };
    let authority = rest.split('/').next().unwrap_or(rest).trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }
    let mut parts = authority.rsplitn(2, ':');
    let last = parts.next().unwrap_or(authority);
    let maybe_host = parts.next();
    if let Some(host) = maybe_host {
        if let Ok(port) = last.parse::<u16>() {
            return Some((host.to_string(), port));
        }
    }
    Some((authority.to_string(), default_port))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn ipv4_mask_from_prefix(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix)))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn route_target_addr_mask(value: &str) -> anyhow::Result<(Ipv4Addr, Ipv4Addr)> {
    let normalized = normalize_route_target(value)?;
    let (addr, prefix) = normalized
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid route target '{value}'"))?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 route address '{value}'"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid IPv4 route prefix '{value}'"))?;
    Ok((addr, ipv4_mask_from_prefix(prefix)))
}

#[cfg(target_os = "macos")]
fn macos_default_gateway() -> anyhow::Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("route -n get default | awk '/gateway:/{print $2; exit}'")
        .output()
        .context("failed to query macOS default gateway")?;
    if !output.status.success() {
        anyhow::bail!(
            "route -n get default failed: {}{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let gateway = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if gateway.is_empty() {
        anyhow::bail!("macOS default gateway not found");
    }
    Ok(gateway)
}

#[cfg(target_os = "windows")]
fn run_powershell(command: &str) -> anyhow::Result<String> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .with_context(|| format!("failed to execute PowerShell command: {command}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }
    anyhow::bail!(
        "PowerShell command failed: {}; {}{}",
        command,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
}

#[cfg(target_os = "windows")]
fn windows_interface_index(tun_name: &str) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    let index = run_powershell(&format!(
        "(Get-NetAdapter -Name '{}' -ErrorAction Stop).ifIndex",
        tun_name
    ))?;
    if index.is_empty() {
        anyhow::bail!("Windows interface '{}' not found", tun_name);
    }
    Ok(index)
}

#[cfg(target_os = "windows")]
fn windows_default_gateway() -> anyhow::Result<String> {
    let gateway = run_powershell(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1).NextHop",
    )?;
    if gateway.is_empty() {
        anyhow::bail!("Windows default gateway not found");
    }
    Ok(gateway)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::macos_netstat_route_iface;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_split_route_detection_ignores_plain_default_route() {
        let route_table = r#"
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.31.1       UGScg                 en0
default            link#24            UCSIg               utun5
10.26/24           10.26.0.5          UGSc                utun0
"#;
        assert_eq!(macos_netstat_route_iface(route_table, "0/1"), None);
        assert_eq!(macos_netstat_route_iface(route_table, "128.0/1"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_split_route_detection_finds_exact_split_route() {
        let route_table = r#"
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                link#23            USc                 utun0
128.0/1            link#23            USc                 utun0
"#;
        assert_eq!(macos_netstat_route_iface(route_table, "0/1"), Some("utun0"));
        assert_eq!(
            macos_netstat_route_iface(route_table, "128.0/1"),
            Some("utun0")
        );
    }
}
