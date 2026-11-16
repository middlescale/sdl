//! linux DNS operations.
use super::super::{command_available, command_stdout, run_command};
use super::{ClientDnsServiceState, ClientDnsState};
use std::net::Ipv4Addr;

/// `None` means the host does not provide resolvectl, so DNS cannot be verified.
pub fn client_exit_dns_active(tun_name: &str, dns_ip: Ipv4Addr) -> anyhow::Result<Option<bool>> {
    if !command_available("resolvectl")? {
        return Ok(None);
    }
    let servers = command_stdout("resolvectl", &["dns", tun_name])?;
    let domains = command_stdout("resolvectl", &["domain", tun_name])?;
    Ok(Some(exit_dns_matches(&servers, &domains, dns_ip)))
}

fn exit_dns_matches(servers: &str, domains: &str, dns_ip: Ipv4Addr) -> bool {
    let server = dns_ip.to_string();
    servers.split_whitespace().any(|word| word == server)
        && domains.split_whitespace().any(|word| word == "~.")
}

#[cfg(test)]
mod tests {
    use super::exit_dns_matches;
    use std::net::Ipv4Addr;

    #[test]
    fn exit_dns_requires_both_server_and_root_routing_domain() {
        let ip = Ipv4Addr::new(10, 26, 0, 53);
        assert!(exit_dns_matches(
            "Link 7 (sdl-tun): 10.26.0.53",
            "Link 7 (sdl-tun): ~.",
            ip
        ));
        assert!(!exit_dns_matches(
            "Link 7 (sdl-tun): 10.26.0.53",
            "Link 7 (sdl-tun): ~default.ms.net",
            ip
        ));
        assert!(!exit_dns_matches(
            "Link 7 (sdl-tun): 10.26.0.54",
            "Link 7 (sdl-tun): ~.",
            ip
        ));
    }
}

pub(super) fn setup_client_dns_platform(
    tun_name: &str,
    dns_service_ip: Ipv4Addr,
    _previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    if !command_available("resolvectl")? {
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

pub(super) fn teardown_client_dns_platform(
    state: Option<&ClientDnsState>,
) -> anyhow::Result<String> {
    if !command_available("resolvectl")? {
        return Ok("exit-node DNS unchanged: resolvectl is not available".to_string());
    }
    let service = state
        .and_then(|state| state.first())
        .map(|state| state.service.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("sdl-tun");
    run_command("resolvectl", &["revert", service])?;
    Ok(format!("exit-node DNS reverted on {}", service))
}
