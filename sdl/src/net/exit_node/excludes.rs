//! Collect underlay bypasses and normalize/diff IPv4 route exclusions.
use crate::core::{PeerIdentity, Sdl};
use anyhow::Context;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

pub fn merge_excludes(
    runtime: &Sdl,
    selected_identity: Option<&PeerIdentity>,
    user_excludes: &[String],
) -> anyhow::Result<Vec<String>> {
    merge_route_targets(
        &collect_auto_excludes(runtime, selected_identity),
        user_excludes,
    )
}

fn merge_route_targets(automatic: &[String], user: &[String]) -> anyhow::Result<Vec<String>> {
    let mut excludes = BTreeSet::new();
    for exclude in automatic.iter().chain(user) {
        excludes.insert(normalize_route_target(exclude)?);
    }
    Ok(excludes.into_iter().collect())
}

#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(super) fn route_exclude_diff(
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

fn collect_auto_excludes(runtime: &Sdl, selected_identity: Option<&PeerIdentity>) -> Vec<String> {
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
    for (_peer_ip, routes) in runtime.route_snapshot() {
        for route in routes {
            if route.is_p2p() {
                add_socket_addr_exclude(&mut excludes, route.endpoint.addr);
            }
        }
    }
    if let Some(peer_ip) = selected_exit_node_peer_ip(runtime, selected_identity) {
        if let Some(route) = runtime.route(&peer_ip) {
            if route.is_p2p() {
                add_socket_addr_exclude(&mut excludes, route.endpoint.addr);
            }
        }
    }
    excludes.into_iter().collect()
}

fn selected_exit_node_peer_ip(
    runtime: &Sdl,
    selected_identity: Option<&PeerIdentity>,
) -> Option<Ipv4Addr> {
    runtime.peer_vip_for_identity(selected_identity?)
}

pub(super) fn normalize_route_target(value: &str) -> anyhow::Result<String> {
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(super) fn route_targets_cover_ip(excludes: &[String], ip: Ipv4Addr) -> bool {
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

#[cfg(target_os = "linux")]
pub(super) fn normalized_route_target_addr(value: &str) -> anyhow::Result<Ipv4Addr> {
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
pub(super) fn route_target_addr_mask(value: &str) -> anyhow::Result<(Ipv4Addr, Ipv4Addr)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn normalization_trims_hosts_and_preserves_explicit_prefixes() {
        assert_eq!(
            normalize_route_target(" 192.0.2.1 ").unwrap(),
            "192.0.2.1/32"
        );
        assert_eq!(
            normalize_route_target(" 192.0.2.123/24 ").unwrap(),
            "192.0.2.123/24"
        );
        assert_eq!(normalize_route_target("0.0.0.0/0").unwrap(), "0.0.0.0/0");
        assert_eq!(
            normalize_route_target("255.255.255.255/32").unwrap(),
            "255.255.255.255/32"
        );
    }

    #[test]
    fn normalization_rejects_invalid_ipv4_targets_and_prefixes() {
        for value in [
            "",
            " ",
            "example.net",
            "::1",
            "256.0.0.1",
            "192.0.2.1/33",
            "192.0.2.1/-1",
            "192.0.2.1/",
            "192.0.2.1/24/1",
            "192.0.2.1; echo unsafe",
        ] {
            assert!(normalize_route_target(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn merging_normalizes_deduplicates_and_sorts_both_sources() {
        assert_eq!(
            merge_route_targets(
                &targets(&["192.0.2.2", "192.0.2.1/32", "192.0.2.2"]),
                &targets(&["192.0.2.1", " 198.51.100.0/24 "]),
            )
            .unwrap(),
            targets(&["192.0.2.1/32", "192.0.2.2/32", "198.51.100.0/24"])
        );
        assert!(merge_route_targets(&[], &[]).unwrap().is_empty());
    }

    #[test]
    fn merging_rejects_invalid_targets_from_either_source() {
        assert!(merge_route_targets(&targets(&["bad"]), &[]).is_err());
        assert!(merge_route_targets(&[], &targets(&["bad"])).is_err());
    }

    #[test]
    fn exclusion_diff_normalizes_hosts_and_ignores_order_and_duplicates() {
        let (removed, added) = route_exclude_diff(
            &targets(&["192.0.2.2", "192.0.2.1", "192.0.2.1/32"]),
            &targets(&["192.0.2.3", "192.0.2.1/32"]),
        )
        .unwrap();
        assert_eq!(removed, targets(&["192.0.2.2/32"]));
        assert_eq!(added, targets(&["192.0.2.3/32"]));
        assert_eq!(
            route_exclude_diff(
                &targets(&["192.0.2.1", "192.0.2.2"]),
                &targets(&["192.0.2.2/32", "192.0.2.1/32"])
            )
            .unwrap(),
            (vec![], vec![])
        );
        assert!(route_exclude_diff(&targets(&["bad"]), &[]).is_err());
        assert!(route_exclude_diff(&[], &targets(&["bad"])).is_err());
    }

    #[test]
    fn control_authority_preserves_ports_and_bracketed_ipv6() {
        for (input, host, port) in [
            ("control.example/control", "control.example", 443),
            ("http://control.example/control", "control.example", 80),
            (
                "https://control.example:8443/control",
                "control.example",
                8443,
            ),
            ("https://[2001:db8::1]:8443/control", "2001:db8::1", 8443),
        ] {
            assert_eq!(parse_control_authority(input), Some((host.into(), port)));
        }
        assert!(parse_control_authority("").is_none());
        assert!(parse_control_authority("https:///control").is_none());
    }

    #[test]
    fn socket_excludes_use_ipv4_hosts_and_ignore_ipv6() {
        let mut excludes = BTreeSet::new();
        add_socket_addr_exclude(&mut excludes, "192.0.2.1:443".parse().unwrap());
        add_socket_addr_exclude(&mut excludes, "192.0.2.1:8443".parse().unwrap());
        add_socket_addr_exclude(&mut excludes, "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(
            excludes.into_iter().collect::<Vec<_>>(),
            targets(&["192.0.2.1/32"])
        );
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
}
