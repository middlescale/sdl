//! macos route operations.

use super::super::excludes::{route_exclude_diff, route_target_addr_mask};
use super::super::{command_stdout, run_shell, validate_iface_name};
use super::{
    parse_tcp_connection_remote_ipv4s, preflight_remote_management_excludes,
    route_preflight_warning, validate_default_route_interface,
};
use anyhow::Context;
use std::net::Ipv4Addr;
use std::process::Command;

pub fn setup_server_routing(_egress_interface: &str, _tun_name: &str) -> anyhow::Result<String> {
    anyhow::bail!("exit-node routing setup is currently supported only on Linux")
}

pub fn teardown_server_routing(_egress_interface: &str, _tun_name: &str) -> anyhow::Result<String> {
    anyhow::bail!("exit-node routing teardown is currently supported only on Linux")
}

pub fn setup_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    preflight_client_routing(tun_name)?;
    preflight_remote_management_excludes(excludes)?;
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

pub fn teardown_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    for exclude in excludes {
        let (addr, mask) = route_target_addr_mask(exclude)?;
        run_shell(&format!(
            "route -n delete -net {addr} -netmask {mask} 2>/dev/null || true"
        ))?;
    }
    run_shell("route -n delete -net 0.0.0.0 -netmask 128.0.0.0 2>/dev/null || true")?;
    run_shell("route -n delete -net 128.0.0.0 -netmask 128.0.0.0 2>/dev/null || true")?;
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
    let gateway = macos_default_gateway()?;
    let (removed, added) = route_exclude_diff(previous_excludes, next_excludes)?;
    for exclude in &removed {
        let (addr, mask) = route_target_addr_mask(exclude)?;
        run_shell(&format!(
            "route -n delete -net {addr} -netmask {mask} 2>/dev/null || true"
        ))?;
    }
    for exclude in &added {
        let (addr, mask) = route_target_addr_mask(exclude)?;
        run_shell(&format!(
            "route -n delete -net {addr} -netmask {mask} 2>/dev/null || true; route -n add -net {addr} -netmask {mask} {gateway}"
        ))?;
    }
    Ok(format!(
        "removed {} excludes, added {} excludes; default split routes unchanged via {}",
        removed.len(),
        added.len(),
        tun_name
    ))
}

pub(super) fn active_remote_management_ipv4s() -> Vec<Ipv4Addr> {
    match command_stdout("netstat", &["-an", "-p", "tcp"]) {
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

fn macos_route_interface(route: &str) -> Option<&str> {
    route.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("interface:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn macos_netstat_route_iface<'a>(route_table: &'a str, destination: &str) -> Option<&'a str> {
    route_table.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != destination {
            return None;
        }
        fields.nth(2)
    })
}

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

#[cfg(test)]
mod tests {
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
