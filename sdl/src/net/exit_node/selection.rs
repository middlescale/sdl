//! Apply a selection and restore the previous route/DNS state on failure.
use super::{
    refresh_client_routing_excludes, setup_client_dns, setup_client_routing,
    teardown_client_routing, ClientDnsState,
};
use std::net::Ipv4Addr;

#[cfg(test)]
mod tests;

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

/// Narrow, statically dispatched boundary for testing transaction ordering and
/// failure recovery without executing host routing/DNS commands.
trait RouteDnsOperations {
    fn setup_routes(&self, tun_name: &str, excludes: &[String]) -> anyhow::Result<String>;
    fn teardown_routes(&self, tun_name: &str, excludes: &[String]) -> anyhow::Result<String>;
    fn setup_dns(
        &self,
        tun_name: &str,
        dns_service_ip: Ipv4Addr,
        previous_state: Option<&ClientDnsState>,
    ) -> anyhow::Result<(Option<ClientDnsState>, String)>;
    fn refresh_excludes(
        &self,
        tun_name: &str,
        previous: &[String],
        next: &[String],
    ) -> anyhow::Result<String>;
}

struct SystemRouteDnsOperations;

impl RouteDnsOperations for SystemRouteDnsOperations {
    fn setup_routes(&self, tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
        setup_client_routing(tun_name, excludes)
    }

    fn teardown_routes(&self, tun_name: &str, excludes: &[String]) -> anyhow::Result<String> {
        teardown_client_routing(tun_name, excludes)
    }

    fn setup_dns(
        &self,
        tun_name: &str,
        dns_service_ip: Ipv4Addr,
        previous_state: Option<&ClientDnsState>,
    ) -> anyhow::Result<(Option<ClientDnsState>, String)> {
        setup_client_dns(tun_name, dns_service_ip, previous_state)
    }

    fn refresh_excludes(
        &self,
        tun_name: &str,
        previous: &[String],
        next: &[String],
    ) -> anyhow::Result<String> {
        refresh_client_routing_excludes(tun_name, previous, next)
    }
}

pub fn apply_client_route_dns_selection(
    previous: &ClientRouteDnsSnapshot,
    next: &ClientRouteDnsSelection,
) -> Result<ClientRouteDnsApplyResult, ClientRouteDnsApplyError> {
    apply_selection_with(&SystemRouteDnsOperations, previous, next)
}

fn apply_selection_with(
    operations: &impl RouteDnsOperations,
    previous: &ClientRouteDnsSnapshot,
    next: &ClientRouteDnsSelection,
) -> Result<ClientRouteDnsApplyResult, ClientRouteDnsApplyError> {
    if previous.client_active || !previous.applied_route_excludes.is_empty() {
        operations
            .teardown_routes(&previous.tun_name, &previous.applied_route_excludes)
            .map_err(|err| ClientRouteDnsApplyError {
                message: format!("exit-node previous route cleanup failed: {err:?}"),
                rollback_failed: false,
            })?;
    }

    let route_note = match operations.setup_routes(&next.tun_name, &next.applied_route_excludes) {
        Ok(note) => note,
        Err(err) => {
            return Err(rollback_client_route_dns_selection(
                operations,
                previous,
                next.dns_service_ip,
                format!("exit-node route setup failed: {err:?}"),
            ));
        }
    };

    match operations.setup_dns(
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
                operations.teardown_routes(&next.tun_name, &next.applied_route_excludes);
            Err(rollback_client_route_dns_selection(
                operations,
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
    refresh_excludes_with(
        &SystemRouteDnsOperations,
        tun_name,
        previous_excludes,
        next_excludes,
    )
}

fn refresh_excludes_with(
    operations: &impl RouteDnsOperations,
    tun_name: &str,
    previous_excludes: &[String],
    next_excludes: &[String],
) -> Result<String, ClientRouteDnsApplyError> {
    if previous_excludes == next_excludes {
        return Ok("exit-node route excludes unchanged".to_string());
    }
    match operations.refresh_excludes(tun_name, previous_excludes, next_excludes) {
        Ok(note) => Ok(format!("exit-node route excludes refreshed: {note}")),
        Err(err) => {
            let rollback = operations.refresh_excludes(tun_name, next_excludes, previous_excludes);
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
    operations: &impl RouteDnsOperations,
    previous: &ClientRouteDnsSnapshot,
    dns_service_ip: Ipv4Addr,
    context: String,
) -> ClientRouteDnsApplyError {
    match restore_client_route_dns_snapshot(operations, previous, dns_service_ip) {
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
    operations: &impl RouteDnsOperations,
    snapshot: &ClientRouteDnsSnapshot,
    dns_service_ip: Ipv4Addr,
) -> anyhow::Result<String> {
    if !snapshot.client_active {
        return Ok("no previous active exit-node selection".to_string());
    }
    operations
        .setup_routes(&snapshot.tun_name, &snapshot.applied_route_excludes)
        .and_then(|route_note| {
            operations
                .setup_dns(
                    &snapshot.tun_name,
                    dns_service_ip,
                    snapshot.dns_state.as_ref(),
                )
                .map(|(_, dns_note)| format!("{route_note}; {dns_note}"))
        })
}
