use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use crate::tun_tap_device::create_device::{add_route, delete_route, exe_cmd};
use crate::DnsProfile;

const DNS_ROUTE_READY_TIMEOUT: Duration = Duration::from_secs(4);
const DNS_ROUTE_READY_RETRY_INTERVAL: Duration = Duration::from_millis(200);

pub(crate) fn apply_split_dns(
    interface_name: &str,
    previous_profile: Option<&DnsProfile>,
    profile: &DnsProfile,
) -> io::Result<()> {
    if profile.servers.is_empty() || profile.match_domains.is_empty() {
        return Ok(());
    }
    wait_interface_up(interface_name, DNS_ROUTE_READY_TIMEOUT)?;
    if let Err(err) = reconcile_dns_routes(interface_name, previous_profile, Some(profile)) {
        return rollback_apply_failure(interface_name, previous_profile, profile, err);
    }
    if !resolvectl_available() {
        return Ok(());
    }
    if let Err(err) = exe_cmd(&build_apply_command(interface_name, profile)) {
        return rollback_apply_failure(interface_name, previous_profile, profile, err);
    }
    Ok(())
}

pub(crate) fn revert_split_dns(
    interface_name: &str,
    previous_profile: Option<&DnsProfile>,
) -> io::Result<()> {
    reconcile_dns_routes(interface_name, previous_profile, None)?;
    if !resolvectl_available() {
        return Ok(());
    }
    exe_cmd(&build_revert_command(interface_name))?;
    Ok(())
}

fn reconcile_dns_routes(
    interface_name: &str,
    previous_profile: Option<&DnsProfile>,
    profile: Option<&DnsProfile>,
) -> io::Result<()> {
    let previous_servers = dns_server_set(previous_profile)?;
    let current_servers = dns_server_set(profile)?;

    for server_ip in current_servers.difference(&previous_servers) {
        add_route(interface_name, *server_ip, Ipv4Addr::BROADCAST)?;
    }
    for server_ip in previous_servers.difference(&current_servers) {
        if let Err(err) = delete_route(interface_name, *server_ip, Ipv4Addr::BROADCAST) {
            log::warn!(
                "failed to delete dns route interface={} server={}: {:?}",
                interface_name,
                server_ip,
                err
            );
        }
    }
    Ok(())
}

fn rollback_apply_failure(
    interface_name: &str,
    previous_profile: Option<&DnsProfile>,
    profile: &DnsProfile,
    err: io::Error,
) -> io::Result<()> {
    let kind = err.kind();
    let err_msg = err.to_string();
    match reconcile_dns_routes(interface_name, Some(profile), previous_profile) {
        Ok(()) => Err(io::Error::new(kind, err_msg)),
        Err(rollback_err) => Err(io::Error::new(
            kind,
            format!("{err_msg}; rollback to previous dns routes failed: {rollback_err}"),
        )),
    }
}

fn dns_server_set(profile: Option<&DnsProfile>) -> io::Result<BTreeSet<Ipv4Addr>> {
    let mut servers = BTreeSet::new();
    let Some(profile) = profile else {
        return Ok(servers);
    };
    for server in &profile.servers {
        let server_ip = server.parse::<Ipv4Addr>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid dns server ip {server}: {err}"),
            )
        })?;
        servers.insert(server_ip);
    }
    Ok(servers)
}

fn wait_interface_up(interface_name: &str, timeout: Duration) -> io::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if interface_is_up(interface_name)? {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("interface {interface_name} did not become ready within {timeout:?}"),
            ));
        }
        thread::sleep(DNS_ROUTE_READY_RETRY_INTERVAL);
    }
}

fn interface_is_up(interface_name: &str) -> io::Result<bool> {
    let path = format!("/sys/class/net/{interface_name}/flags");
    let Ok(raw) = fs::read_to_string(&path) else {
        return Ok(false);
    };
    let raw = raw.trim();
    let raw = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let flags = u32::from_str_radix(raw, 16).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid interface flags for {interface_name}: {err}"),
        )
    })?;
    Ok(flags & 0x1 != 0)
}

fn resolvectl_available() -> bool {
    std::process::Command::new("sh")
        .arg("-lc")
        .arg("command -v resolvectl >/dev/null 2>&1")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn build_apply_command(interface_name: &str, profile: &DnsProfile) -> String {
    let servers = profile.servers.join(" ");
    let domains = profile
        .match_domains
        .iter()
        .map(|domain| {
            if domain.starts_with('~') {
                domain.clone()
            } else {
                format!("~{}", domain)
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "resolvectl dns {interface_name} {servers} && resolvectl domain {interface_name} {domains} && resolvectl default-route {interface_name} false"
    )
}

fn build_revert_command(interface_name: &str) -> String {
    format!("resolvectl revert {interface_name}")
}

#[cfg(test)]
mod tests {
    use super::{build_apply_command, build_revert_command, dns_server_set};
    use crate::DnsProfile;
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    #[test]
    fn build_apply_command_prefixes_match_domains() {
        let profile = DnsProfile {
            servers: vec!["10.26.0.1".into(), "10.26.0.2".into()],
            match_domains: vec!["ms.net".into(), "~corp.ms.net".into()],
            peer_name_domain: "corp.ms.net".into(),
        };
        let command = build_apply_command("sdl-tun", &profile);
        assert_eq!(
            command,
            "resolvectl dns sdl-tun 10.26.0.1 10.26.0.2 && resolvectl domain sdl-tun ~ms.net ~corp.ms.net && resolvectl default-route sdl-tun false"
        );
    }

    #[test]
    fn build_revert_command_targets_interface() {
        assert_eq!(build_revert_command("sdl-tun"), "resolvectl revert sdl-tun");
    }

    #[test]
    fn dns_server_set_deduplicates_servers() {
        let profile = DnsProfile {
            servers: vec!["10.26.0.1".into(), "10.26.0.1".into(), "10.26.0.2".into()],
            match_domains: vec!["ms.net".into()],
            peer_name_domain: "ms.net".into(),
        };
        assert_eq!(
            dns_server_set(Some(&profile)).unwrap(),
            BTreeSet::from([Ipv4Addr::new(10, 26, 0, 1), Ipv4Addr::new(10, 26, 0, 2)])
        );
    }
}
