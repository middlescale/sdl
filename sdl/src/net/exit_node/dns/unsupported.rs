//! unsupported DNS operations.
use super::ClientDnsState;
use std::net::Ipv4Addr;

pub(super) fn setup_client_dns_platform(
    _tun_name: &str,
    _dns_service_ip: Ipv4Addr,
    _previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    Ok((
        None,
        "exit-node DNS unchanged: unsupported platform".to_string(),
    ))
}

pub(super) fn teardown_client_dns_platform(
    _state: Option<&ClientDnsState>,
) -> anyhow::Result<String> {
    Ok("exit-node DNS unchanged: unsupported platform".to_string())
}
