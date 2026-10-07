//! linux DNS operations.
use super::super::{command_available, run_command};
use super::{ClientDnsServiceState, ClientDnsState};
use std::net::Ipv4Addr;

pub(super) fn setup_client_dns_platform(
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

pub(super) fn teardown_client_dns_platform(
    state: Option<&ClientDnsState>,
) -> anyhow::Result<String> {
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
