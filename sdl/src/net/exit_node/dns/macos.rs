//! macos DNS operations.
use super::super::{command_stdout, run_command};
use super::{ClientDnsServiceState, ClientDnsState};
use anyhow::Context;
use std::net::Ipv4Addr;
use std::process::Command;

pub(super) fn setup_client_dns_platform(
    _tun_name: &str,
    dns_service_ip: Ipv4Addr,
    previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    let default_iface = macos_default_interface()?;
    let default_service = macos_network_service_for_device(&default_iface)?;
    let services = macos_dns_target_services(&default_service)?;
    let previous_services = previous_state
        .map(|state| state.to_vec())
        .unwrap_or_default();
    let mut restore_services = Vec::new();
    let mut configured_services = Vec::new();
    let dns_server = dns_service_ip.to_string();
    for service in services {
        let mut restore_servers = previous_services
            .iter()
            .find(|state| state.service == service)
            .map(|state| state.restore_servers.clone())
            .unwrap_or_else(|| macos_dns_servers(&service).unwrap_or_default());
        restore_servers.retain(|server| server.trim() != dns_server);
        if let Err(err) = macos_set_dns_servers(&service, std::slice::from_ref(&dns_server)) {
            log::warn!("failed to configure macOS DNS on {}: {:?}", service, err);
            continue;
        }
        restore_services.push(ClientDnsServiceState {
            service: service.clone(),
            restore_servers,
            restore_metric: None,
            restore_automatic_metric: None,
        });
        configured_services.push(service);
    }
    if configured_services.is_empty() {
        anyhow::bail!("failed to configure macOS DNS on any network service");
    }
    macos_flush_dns_cache();
    Ok((
        Some(restore_services),
        format!(
            "exit-node DNS configured on {} via SDL DNS {}",
            configured_services.join(","),
            dns_service_ip
        ),
    ))
}

pub(super) fn teardown_client_dns_platform(
    state: Option<&ClientDnsState>,
) -> anyhow::Result<String> {
    let Some(state) = state else {
        return Ok("exit-node DNS unchanged: no saved DNS state".to_string());
    };
    let services = state.to_vec();
    if services.is_empty() {
        return Ok("exit-node DNS unchanged: no saved network service".to_string());
    };
    let mut restored = Vec::new();
    for state in services {
        if state.restore_servers.is_empty() {
            run_command("networksetup", &["-setdnsservers", &state.service, "Empty"])?;
        } else {
            let mut args = vec!["-setdnsservers", state.service.as_str()];
            for server in &state.restore_servers {
                args.push(server.as_str());
            }
            run_command("networksetup", &args)?;
        }
        restored.push(state.service);
    }
    macos_flush_dns_cache();
    Ok(format!("exit-node DNS restored on {}", restored.join(",")))
}

fn macos_default_interface() -> anyhow::Result<String> {
    let output = crate::net::command_timeout::output(
        Command::new("sh")
            .arg("-c")
            .arg("route -n get default | awk '/interface:/{print $2; exit}'"),
        crate::net::command_timeout::NETWORK_COMMAND_TIMEOUT,
    )
    .context("failed to query macOS default interface")?;
    if !output.status.success() {
        anyhow::bail!(
            "route -n get default failed: {}{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let iface = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if iface.is_empty() {
        anyhow::bail!("macOS default interface not found");
    }
    Ok(iface)
}

fn macos_network_service_for_device(device: &str) -> anyhow::Result<String> {
    let output = command_stdout("networksetup", &["-listallhardwareports"])?;
    parse_macos_network_service_for_device(&output, device)
        .ok_or_else(|| anyhow::anyhow!("macOS network service for device '{}' not found", device))
}

fn macos_dns_target_services(default_service: &str) -> anyhow::Result<Vec<String>> {
    let default_service = default_service.trim();
    if default_service.is_empty() {
        anyhow::bail!("macOS default network service not found");
    }
    Ok(vec![default_service.to_string()])
}

fn parse_macos_network_service_for_device(output: &str, device: &str) -> Option<String> {
    let mut current_service: Option<String> = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(service) = line.strip_prefix("Hardware Port:") {
            current_service = Some(service.trim().to_string());
            continue;
        }
        if let Some(candidate) = line.strip_prefix("Device:") {
            if candidate.trim() == device {
                return current_service;
            }
        }
    }
    None
}

fn macos_dns_servers(service: &str) -> anyhow::Result<Vec<String>> {
    let output = command_stdout("networksetup", &["-getdnsservers", service])?;
    Ok(parse_macos_dns_servers(&output))
}

fn parse_macos_dns_servers(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("There aren't any DNS Servers"))
        .map(str::to_string)
        .collect()
}

fn macos_set_dns_servers(service: &str, servers: &[String]) -> anyhow::Result<()> {
    let mut args = vec!["-setdnsservers", service];
    for server in servers {
        args.push(server.as_str());
    }
    run_command("networksetup", &args)
}

fn macos_flush_dns_cache() {
    if let Err(err) = run_command("dscacheutil", &["-flushcache"]) {
        log::warn!("failed to flush macOS DNS cache: {:?}", err);
    }
    if let Err(err) = run_command("killall", &["-HUP", "mDNSResponder"]) {
        log::warn!("failed to notify mDNSResponder: {:?}", err);
    }
}
