//! windows DNS operations.
use super::super::{ps_string, run_powershell};
use super::{ClientDnsServiceState, ClientDnsState};
use std::net::Ipv4Addr;

pub(super) fn setup_client_dns_platform(
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

pub(super) fn teardown_client_dns_platform(
    state: Option<&ClientDnsState>,
) -> anyhow::Result<String> {
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
