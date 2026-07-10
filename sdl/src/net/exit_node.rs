use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::Command;

use anyhow::Context;

use crate::core::Sdl;

pub type ClientDnsState = Vec<ClientDnsServiceState>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientDnsServiceState {
    pub service: String,
    pub restore_servers: Vec<String>,
    pub restore_metric: Option<u32>,
    pub restore_automatic_metric: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct ClientRouteDnsSnapshot {
    pub client_active: bool,
    pub tun_name: String,
    pub applied_route_excludes: Vec<String>,
    pub dns_state: Option<ClientDnsState>,
}

#[derive(Clone, Debug)]
pub struct ClientRouteDnsSelection {
    pub tun_name: String,
    pub applied_route_excludes: Vec<String>,
    pub dns_service_ip: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct ClientRouteDnsApplyResult {
    pub route_note: String,
    pub dns_note: String,
    pub dns_state: Option<ClientDnsState>,
}

#[derive(Clone, Debug)]
pub struct ClientRouteDnsApplyError {
    message: String,
    rollback_failed: bool,
}

impl ClientRouteDnsApplyError {
    pub fn rollback_failed(&self) -> bool {
        self.rollback_failed
    }
}

impl std::fmt::Display for ClientRouteDnsApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ClientRouteDnsApplyError {}

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

pub fn apply_client_route_dns_selection(
    previous: &ClientRouteDnsSnapshot,
    next: &ClientRouteDnsSelection,
) -> Result<ClientRouteDnsApplyResult, ClientRouteDnsApplyError> {
    if previous.client_active || !previous.applied_route_excludes.is_empty() {
        teardown_client_routing(&previous.tun_name, &previous.applied_route_excludes).map_err(
            |err| ClientRouteDnsApplyError {
                message: format!("exit-node previous route cleanup failed: {err:?}"),
                rollback_failed: false,
            },
        )?;
    }

    let route_note = match setup_client_routing(&next.tun_name, &next.applied_route_excludes) {
        Ok(note) => note,
        Err(err) => {
            return Err(rollback_client_route_dns_selection(
                previous,
                next.dns_service_ip,
                format!("exit-node route setup failed: {err:?}"),
            ));
        }
    };

    match setup_client_dns(
        &next.tun_name,
        next.dns_service_ip,
        previous.dns_state.as_ref(),
    ) {
        Ok((dns_state, dns_note)) => Ok(ClientRouteDnsApplyResult {
            route_note,
            dns_note,
            dns_state,
        }),
        Err(err) => {
            let new_route_cleanup =
                teardown_client_routing(&next.tun_name, &next.applied_route_excludes);
            Err(rollback_client_route_dns_selection(
                previous,
                next.dns_service_ip,
                format!(
                    "exit-node DNS setup failed: {err:?}; new route cleanup={new_route_cleanup:?}"
                ),
            ))
        }
    }
}

pub fn refresh_client_route_excludes(
    tun_name: &str,
    previous_excludes: &[String],
    next_excludes: &[String],
) -> Result<String, ClientRouteDnsApplyError> {
    if previous_excludes == next_excludes {
        return Ok("exit-node route excludes unchanged".to_string());
    }
    match refresh_client_routing_excludes(tun_name, previous_excludes, next_excludes) {
        Ok(note) => Ok(format!("exit-node route excludes refreshed: {note}")),
        Err(err) => {
            let rollback =
                refresh_client_routing_excludes(tun_name, next_excludes, previous_excludes);
            let rollback_failed = rollback.is_err();
            Err(ClientRouteDnsApplyError {
                message: match rollback {
                    Ok(note) => format!(
                        "exit-node route exclude refresh failed: {err:?}; restored previous routes: {note}"
                    ),
                    Err(rollback_err) => format!(
                        "exit-node route exclude refresh failed: {err:?}; rollback failed: {rollback_err:?}"
                    ),
                },
                rollback_failed,
            })
        }
    }
}

fn rollback_client_route_dns_selection(
    previous: &ClientRouteDnsSnapshot,
    dns_service_ip: Ipv4Addr,
    context: String,
) -> ClientRouteDnsApplyError {
    match restore_client_route_dns_snapshot(previous, dns_service_ip) {
        Ok(note) => ClientRouteDnsApplyError {
            message: format!("{context}; previous exit-node selection was restored: {note}"),
            rollback_failed: false,
        },
        Err(rollback_err) => ClientRouteDnsApplyError {
            message: format!(
                "{context}; rollback failed: {rollback_err:?}; exit-node should be marked inactive for later cleanup"
            ),
            rollback_failed: true,
        },
    }
}

fn restore_client_route_dns_snapshot(
    snapshot: &ClientRouteDnsSnapshot,
    dns_service_ip: Ipv4Addr,
) -> anyhow::Result<String> {
    if !snapshot.client_active {
        return Ok("no previous active exit-node selection".to_string());
    }
    setup_client_routing(&snapshot.tun_name, &snapshot.applied_route_excludes).and_then(
        |route_note| {
            setup_client_dns(
                &snapshot.tun_name,
                dns_service_ip,
                snapshot.dns_state.as_ref(),
            )
            .map(|(_, dns_note)| format!("{route_note}; {dns_note}"))
        },
    )
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

pub fn setup_client_dns(
    tun_name: &str,
    dns_service_ip: Ipv4Addr,
    previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    validate_iface_name(tun_name, "tun name")?;
    setup_client_dns_platform(tun_name, dns_service_ip, previous_state)
}

pub fn teardown_client_dns(state: Option<&ClientDnsState>) -> anyhow::Result<String> {
    teardown_client_dns_platform(state)
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

fn route_exclude_diff(
    previous: &[String],
    next: &[String],
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let previous = previous
        .iter()
        .map(|exclude| normalize_route_target(exclude))
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    let next = next
        .iter()
        .map(|exclude| normalize_route_target(exclude))
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    let removed = previous.difference(&next).cloned().collect();
    let added = next.difference(&previous).cloned().collect();
    Ok((removed, added))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
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

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn setup_client_routing(_tun_name: &str, _excludes: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("exit-node client routing setup is supported only on Linux, macOS, and Windows")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn teardown_client_routing(_tun_name: &str, _excludes: &[String]) -> anyhow::Result<String> {
    anyhow::bail!(
        "exit-node client routing teardown is supported only on Linux, macOS, and Windows"
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn refresh_client_routing_excludes(
    _tun_name: &str,
    _previous_excludes: &[String],
    _next_excludes: &[String],
) -> anyhow::Result<String> {
    anyhow::bail!(
        "exit-node client route exclude refresh is supported only on Linux, macOS, and Windows"
    )
}

#[cfg(target_os = "linux")]
fn setup_client_dns_platform(
    tun_name: &str,
    dns_service_ip: Ipv4Addr,
    _previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    if !command_available("resolvectl") {
        return Ok((
            None,
            "exit-node DNS unchanged: resolvectl is not available".to_string(),
        ));
    }
    run_command(
        "resolvectl",
        &["dns", tun_name, &dns_service_ip.to_string()],
    )?;
    run_command("resolvectl", &["domain", tun_name, "~."])?;
    run_command("resolvectl", &["default-route", tun_name, "true"])?;
    Ok((
        Some(vec![ClientDnsServiceState {
            service: tun_name.to_string(),
            restore_servers: Vec::new(),
            restore_metric: None,
            restore_automatic_metric: None,
        }]),
        format!(
            "exit-node DNS configured on {} via SDL DNS {}",
            tun_name, dns_service_ip
        ),
    ))
}

#[cfg(target_os = "linux")]
fn teardown_client_dns_platform(state: Option<&ClientDnsState>) -> anyhow::Result<String> {
    if !command_available("resolvectl") {
        return Ok("exit-node DNS unchanged: resolvectl is not available".to_string());
    }
    let service = state
        .and_then(|state| state.first())
        .map(|state| state.service.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("sdl-tun");
    run_command("resolvectl", &["revert", service]).or_else(|err| {
        log::warn!("failed to revert {} DNS: {:?}", service, err);
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(format!("exit-node DNS reverted on {}", service))
}

#[cfg(target_os = "macos")]
fn setup_client_dns_platform(
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

#[cfg(target_os = "macos")]
fn teardown_client_dns_platform(state: Option<&ClientDnsState>) -> anyhow::Result<String> {
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

#[cfg(target_os = "windows")]
fn setup_client_dns_platform(
    tun_name: &str,
    dns_service_ip: Ipv4Addr,
    previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    let restore_state = previous_state
        .and_then(|state| {
            state
                .iter()
                .find(|entry| entry.service == tun_name)
                .cloned()
        })
        .unwrap_or_else(|| windows_current_dns_service_state(tun_name));
    let script = format!(
        "$ErrorActionPreference='Stop'; \
Set-DnsClientServerAddress -InterfaceAlias {} -ServerAddresses @({}); \
Set-NetIPInterface -InterfaceAlias {} -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1",
        ps_string(tun_name),
        ps_string(&dns_service_ip.to_string()),
        ps_string(tun_name),
    );
    run_powershell(&script)?;
    Ok((
        Some(vec![ClientDnsServiceState {
            service: tun_name.to_string(),
            restore_servers: restore_state.restore_servers,
            restore_metric: restore_state.restore_metric,
            restore_automatic_metric: restore_state.restore_automatic_metric,
        }]),
        format!(
            "exit-node DNS configured on {} via SDL DNS {}",
            tun_name, dns_service_ip
        ),
    ))
}

#[cfg(target_os = "windows")]
fn teardown_client_dns_platform(state: Option<&ClientDnsState>) -> anyhow::Result<String> {
    let service = state
        .and_then(|state| state.first())
        .cloned()
        .unwrap_or_else(|| ClientDnsServiceState {
            service: "sdl-tun".to_string(),
            restore_servers: Vec::new(),
            restore_metric: None,
            restore_automatic_metric: None,
        });
    let service_name = service.service.as_str();
    let dns_script = if service.restore_servers.is_empty() {
        format!(
            "Set-DnsClientServerAddress -InterfaceAlias {} -ResetServerAddresses",
            ps_string(service_name)
        )
    } else {
        let servers = service
            .restore_servers
            .iter()
            .map(|server| ps_string(server))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Set-DnsClientServerAddress -InterfaceAlias {} -ServerAddresses @({})",
            ps_string(service_name),
            servers
        )
    };
    let metric_script = match (service.restore_automatic_metric, service.restore_metric) {
        (Some(true), _) => format!(
            "Set-NetIPInterface -InterfaceAlias {} -AddressFamily IPv4 -AutomaticMetric Enabled",
            ps_string(service_name)
        ),
        (Some(false), Some(metric)) | (None, Some(metric)) => format!(
            "Set-NetIPInterface -InterfaceAlias {} -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric {}",
            ps_string(service_name),
            metric
        ),
        _ => String::new(),
    };
    let script = if metric_script.is_empty() {
        format!("$ErrorActionPreference='Stop'; {dns_script}")
    } else {
        format!("$ErrorActionPreference='Stop'; {dns_script}; {metric_script}")
    };
    run_powershell(&script)?;
    Ok(format!("exit-node DNS restored on {}", service_name))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn setup_client_dns_platform(
    _tun_name: &str,
    _dns_service_ip: Ipv4Addr,
    _previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    Ok((
        None,
        "exit-node DNS unchanged: unsupported platform".to_string(),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn teardown_client_dns_platform(_state: Option<&ClientDnsState>) -> anyhow::Result<String> {
    Ok("exit-node DNS unchanged: unsupported platform".to_string())
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
    for peer in runtime.device_list() {
        if let Some(nat_info) = runtime.peer_nat_info(&peer.virtual_ip) {
            for endpoint in &nat_info.public_udp_endpoints {
                add_socket_addr_exclude(&mut excludes, *endpoint);
            }
            for endpoint in nat_info.local_udp_endpoints() {
                add_socket_addr_exclude(&mut excludes, endpoint);
            }
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

#[cfg(target_os = "linux")]
fn command_available(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "command -v {} >/dev/null 2>&1",
            shell_quote(program)
        ))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

#[cfg(target_os = "linux")]
fn active_remote_management_ipv4s() -> Vec<Ipv4Addr> {
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

#[cfg(target_os = "macos")]
fn active_remote_management_ipv4s() -> Vec<Ipv4Addr> {
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

#[cfg(target_os = "windows")]
fn active_remote_management_ipv4s() -> Vec<Ipv4Addr> {
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn route_targets_cover_ip(excludes: &[String], ip: Ipv4Addr) -> bool {
    excludes.iter().any(|exclude| {
        normalize_route_target(exclude)
            .ok()
            .and_then(|target| route_target_contains_ip(&target, ip).ok())
            .unwrap_or(false)
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn route_target_contains_ip(target: &str, ip: Ipv4Addr) -> anyhow::Result<bool> {
    let normalized = normalize_route_target(target)?;
    let (addr, prefix) = normalized
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid route target '{target}'"))?;
    let addr = u32::from(
        addr.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 route address '{target}'"))?,
    );
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid IPv4 route prefix '{target}'"))?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ok((u32::from(ip) & mask) == (addr & mask))
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

fn normalized_route_target_addr(value: &str) -> anyhow::Result<Ipv4Addr> {
    let (addr, _) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid route target '{value}'"))?;
    addr.parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 route address '{value}'"))
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

#[cfg(target_os = "macos")]
fn macos_default_interface() -> anyhow::Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("route -n get default | awk '/interface:/{print $2; exit}'")
        .output()
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

#[cfg(target_os = "macos")]
fn macos_network_service_for_device(device: &str) -> anyhow::Result<String> {
    let output = command_stdout("networksetup", &["-listallhardwareports"])?;
    parse_macos_network_service_for_device(&output, device)
        .ok_or_else(|| anyhow::anyhow!("macOS network service for device '{}' not found", device))
}

#[cfg(target_os = "macos")]
fn macos_dns_target_services(default_service: &str) -> anyhow::Result<Vec<String>> {
    let default_service = default_service.trim();
    if default_service.is_empty() {
        anyhow::bail!("macOS default network service not found");
    }
    Ok(vec![default_service.to_string()])
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn macos_dns_servers(service: &str) -> anyhow::Result<Vec<String>> {
    let output = command_stdout("networksetup", &["-getdnsservers", service])?;
    Ok(parse_macos_dns_servers(&output))
}

#[cfg(target_os = "macos")]
fn parse_macos_dns_servers(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("There aren't any DNS Servers"))
        .map(str::to_string)
        .collect()
}

#[cfg(target_os = "macos")]
fn macos_set_dns_servers(service: &str, servers: &[String]) -> anyhow::Result<()> {
    let mut args = vec!["-setdnsservers", service];
    for server in servers {
        args.push(server.as_str());
    }
    run_command("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn macos_flush_dns_cache() {
    if let Err(err) = run_command("dscacheutil", &["-flushcache"]) {
        log::warn!("failed to flush macOS DNS cache: {:?}", err);
    }
    if let Err(err) = run_command("killall", &["-HUP", "mDNSResponder"]) {
        log::warn!("failed to notify mDNSResponder: {:?}", err);
    }
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
fn ps_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(target_os = "windows")]
fn windows_current_dns_service_state(tun_name: &str) -> ClientDnsServiceState {
    let servers = run_powershell(&format!(
        "$servers = (Get-DnsClientServerAddress -InterfaceAlias {} -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses; \
if ($servers) {{ $servers -join \"`n\" }}",
        ps_string(tun_name)
    ))
    .map(|output| {
        output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_else(|err| {
        log::warn!("failed to read Windows DNS servers for {}: {:?}", tun_name, err);
        Vec::new()
    });
    let metric_info = run_powershell(&format!(
        "$iface = Get-NetIPInterface -InterfaceAlias {} -AddressFamily IPv4 -ErrorAction Stop; \
Write-Output $iface.InterfaceMetric; Write-Output $iface.AutomaticMetric",
        ps_string(tun_name)
    ))
    .unwrap_or_else(|err| {
        log::warn!(
            "failed to read Windows interface metric for {}: {:?}",
            tun_name,
            err
        );
        String::new()
    });
    let mut lines = metric_info
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let restore_metric = lines.next().and_then(|line| line.parse::<u32>().ok());
    let restore_automatic_metric = lines.next().and_then(|line| line.parse::<bool>().ok());
    ClientDnsServiceState {
        service: tun_name.to_string(),
        restore_servers: servers,
        restore_metric,
        restore_automatic_metric,
    }
}

#[cfg(target_os = "linux")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
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
    use std::net::Ipv4Addr;

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    use super::{
        is_remote_management_ip_safe_without_exclude, parse_tcp_connection_remote_ipv4s,
        route_targets_cover_ip,
    };

    #[cfg(target_os = "macos")]
    use super::macos_netstat_route_iface;

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

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn route_targets_cover_ip_matches_host_and_cidr_excludes() {
        assert!(route_targets_cover_ip(
            &["223.74.148.12".to_string()],
            Ipv4Addr::new(223, 74, 148, 12)
        ));
        assert!(route_targets_cover_ip(
            &["223.74.148.0/24".to_string()],
            Ipv4Addr::new(223, 74, 148, 12)
        ));
        assert!(!route_targets_cover_ip(
            &["223.74.149.0/24".to_string()],
            Ipv4Addr::new(223, 74, 148, 12)
        ));
    }

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
