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

/// Check kernel routes, not the persisted list of routes SDL previously installed.
pub fn client_routing_active(tun_name: &str) -> anyhow::Result<bool> {
    validate_iface_name(tun_name, "tun name")?;
    for target in ["0.0.0.0/1", "128.0.0.0/1"] {
        let route = command_stdout("ip", &["-4", "route", "show", "exact", target])?;
        if !split_route_matches(&route, target, tun_name) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn split_route_matches(routes: &str, target: &str, tun_name: &str) -> bool {
    routes.lines().next().is_some_and(|line| {
        line.split_whitespace().next() == Some(target) && linux_route_iface(line) == Some(tun_name)
    })
}

pub fn client_bypasses_active(tun_name: &str, excludes: &[String]) -> anyhow::Result<bool> {
    validate_iface_name(tun_name, "tun name")?;
    for exclude in excludes {
        let target = normalize_route_target(exclude)?;
        let addr = normalized_route_target_addr(&target)?;
        let effective = command_stdout("ip", &["-4", "route", "get", &addr.to_string()])?;
        let iface = linux_route_iface(&effective)
            .ok_or_else(|| anyhow::anyhow!("cannot determine route interface for {exclude}"))?;
        if iface == tun_name {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Repair missing underlay bypasses without replacing routes owned by another manager.
pub fn repair_client_routing_excludes(tun_name: &str, excludes: &[String]) -> anyhow::Result<bool> {
    validate_iface_name(tun_name, "tun name")?;
    // A single snapshot keeps the healthy-path check cheap when many peers exist.
    let routes = command_stdout("ip", &["-4", "route", "show", "table", "main"])?;
    let default = routes
        .lines()
        .find(|line| line.split_whitespace().next() == Some("default"))
        .ok_or_else(|| anyhow::anyhow!("physical default route is unavailable"))?;
    let iface = linux_route_iface(default)
        .ok_or_else(|| anyhow::anyhow!("physical default route has no interface"))?;
    if iface == tun_name {
        anyhow::bail!("default route points to SDL tunnel");
    }
    validate_default_route_interface(tun_name, iface)?;
    for exclude in excludes {
        let target = normalize_route_target(exclude)?;
        let addr = normalized_route_target_addr(&target)?;
        let existing = routes.lines().find(|line| {
            line.split_whitespace()
                .next()
                .and_then(|prefix| normalize_route_target(prefix).ok())
                .is_some_and(|prefix| prefix == target)
        });
        if let Some(existing) = existing {
            if linux_route_iface(existing) == Some(tun_name) {
                anyhow::bail!("cannot restore bypass {target}: conflicting route {existing}");
            }
            continue;
        }
        let effective = command_stdout("ip", &["-4", "route", "get", &addr.to_string()]).ok();
        let route = effective
            .as_deref()
            .and_then(|output| output.lines().next())
            .filter(|line| linux_route_iface(line).is_some_and(|name| name != tun_name));
        if route.is_some_and(|line| line.starts_with("local ") || line.starts_with("broadcast ")) {
            continue;
        }
        let source = route.unwrap_or(default);
        let parts = bypass_route_arguments(source)?;
        let mut args = vec!["-4", "route", "add", target.as_str()];
        args.extend(parts);
        run_command("ip", &args)?;
    }
    Ok(["0.0.0.0/1", "128.0.0.0/1"].iter().all(|target| {
        routes
            .lines()
            .any(|line| split_route_matches(line, target, tun_name))
    }))
}

fn bypass_route_arguments(route: &str) -> anyhow::Result<Vec<&str>> {
    let mut words = route.split_whitespace().skip(1);
    let mut args = Vec::new();
    while let Some(word) = words.next() {
        if matches!(word, "via" | "dev" | "src" | "metric") {
            let value = words
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing {word} in route: {route}"))?;
            args.extend([word, value]);
        }
    }
    if !args.contains(&"dev") {
        anyhow::bail!("cannot determine route interface: {route}");
    }
    Ok(args)
}

/// Restore missing split routes only after the control path has been restored.
pub fn restore_client_split_routes(tun_name: &str, excludes: &[String]) -> anyhow::Result<()> {
    validate_iface_name(tun_name, "tun name")?;
    preflight_remote_management_excludes(excludes)?;
    let mut missing = Vec::new();
    for target in ["0.0.0.0/1", "128.0.0.0/1"] {
        let route = command_stdout("ip", &["-4", "route", "show", "exact", target])?;
        if split_route_matches(&route, target, tun_name) {
            continue;
        }
        if !route.trim().is_empty() {
            anyhow::bail!("cannot restore {target}: conflicting route {route}");
        }
        missing.push(target);
    }
    let mut installed = Vec::new();
    for target in missing {
        if let Err(err) = run_command("ip", &["-4", "route", "add", target, "dev", tun_name]) {
            for added in installed {
                if let Err(rollback) =
                    run_command("ip", &["-4", "route", "del", added, "dev", tun_name])
                {
                    log::warn!("failed to roll back exit-node route {added}: {rollback}");
                }
            }
            return Err(err);
        }
        installed.push(target);
    }
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::{bypass_route_arguments, split_route_matches};

    #[test]
    fn bypass_arguments_only_include_supported_route_attributes() {
        assert_eq!(
            bypass_route_arguments(
                "1.2.3.4 via 192.0.2.1 dev eth0 src 192.0.2.2 uid 1000 cache metric 10"
            )
            .unwrap(),
            [
                "via",
                "192.0.2.1",
                "dev",
                "eth0",
                "src",
                "192.0.2.2",
                "metric",
                "10"
            ]
        );
        assert!(bypass_route_arguments("default via 192.0.2.1").is_err());
        assert!(bypass_route_arguments("default dev").is_err());
    }

    #[test]
    fn split_route_must_exist_on_the_selected_tun() {
        assert!(split_route_matches(
            "0.0.0.0/1 dev sdl-tun scope link\n",
            "0.0.0.0/1",
            "sdl-tun"
        ));
        assert!(!split_route_matches("", "0.0.0.0/1", "sdl-tun"));
        assert!(!split_route_matches(
            "0.0.0.0/1 dev other-tun scope link\n",
            "0.0.0.0/1",
            "sdl-tun"
        ));
        assert!(!split_route_matches(
            "128.0.0.0/1 dev sdl-tun scope link\n",
            "0.0.0.0/1",
            "sdl-tun"
        ));
    }
}
