//! windows route operations.

use super::super::excludes::{route_exclude_diff, route_target_addr_mask};
use super::super::{run_command, run_powershell, validate_iface_name};
use super::{
    preflight_remote_management_excludes, route_preflight_warning,
    validate_default_route_interface, REMOTE_MANAGEMENT_PORTS,
};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub fn setup_server_routing(_egress_interface: &str, _tun_name: &str) -> anyhow::Result<String> {
    anyhow::bail!("exit-node routing setup is currently supported only on Linux")
}

pub fn teardown_server_routing(_egress_interface: &str, _tun_name: &str) -> anyhow::Result<String> {
    anyhow::bail!("exit-node routing teardown is currently supported only on Linux")
}

pub fn setup_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    preflight_client_routing(tun_name)?;
    preflight_remote_management_excludes(excludes)?;
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

pub fn teardown_client_routing(tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
    validate_iface_name(tun_name, "tun name")?;
    for exclude in excludes {
        let (addr, mask) = route_target_addr_mask(exclude)?;
        let _ = run_command(
            "route.exe",
            &["DELETE", &addr.to_string(), "MASK", &mask.to_string()],
        );
    }
    let _ = run_command("route.exe", &["DELETE", "0.0.0.0", "MASK", "128.0.0.0"]);
    let _ = run_command("route.exe", &["DELETE", "128.0.0.0", "MASK", "128.0.0.0"]);
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
    let gateway = windows_default_gateway()?;
    let (removed, added) = route_exclude_diff(previous_excludes, next_excludes)?;
    for exclude in &removed {
        let (addr, mask) = route_target_addr_mask(exclude)?;
        let _ = run_command(
            "route.exe",
            &["DELETE", &addr.to_string(), "MASK", &mask.to_string()],
        );
    }
    for exclude in &added {
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
    Ok(format!(
        "removed {} excludes, added {} excludes; default split routes unchanged via {}",
        removed.len(),
        added.len(),
        tun_name
    ))
}

pub(super) fn active_remote_management_ipv4s() -> Vec<Ipv4Addr> {
    let ports = REMOTE_MANAGEMENT_PORTS
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let command = format!(
        "$ports = @({ports}); Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {{ $ports -contains $_.LocalPort }} | Select-Object -ExpandProperty RemoteAddress"
    );
    match run_powershell(&command) {
        Ok(output) => output
            .lines()
            .filter_map(|line| line.trim().parse::<Ipv4Addr>().ok())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        Err(err) => {
            log::warn!(
                "failed to inspect active TCP connections with PowerShell: {:?}",
                err
            );
            Vec::new()
        }
    }
}

fn preflight_client_routing(tun_name: &str) -> anyhow::Result<()> {
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        let command = format!(
            "$route = Get-NetRoute -DestinationPrefix '{}' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if ($null -eq $route) {{ exit 0 }}; (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop).Name",
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
        "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if ($null -eq $route) { exit 0 }; (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop).Name",
    )?;
    if !default_iface.trim().is_empty() {
        validate_default_route_interface(tun_name, default_iface.trim())?;
    }
    Ok(())
}

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

fn windows_default_gateway() -> anyhow::Result<String> {
    let gateway = run_powershell(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1).NextHop",
    )?;
    if gateway.is_empty() {
        anyhow::bail!("Windows default gateway not found");
    }
    Ok(gateway)
}
