use std::cell::RefCell;

use super::super::ClientDnsServiceState;
use super::*;

#[derive(Debug, PartialEq)]
enum Operation {
    SetupRoutes(String, Vec<String>),
    TeardownRoutes(String, Vec<String>),
    SetupDns(String, Ipv4Addr, Option<ClientDnsState>),
    RefreshExcludes(String, Vec<String>, Vec<String>),
}

#[derive(Default)]
struct FakeOperations {
    calls: RefCell<Vec<Operation>>,
    fail_at: Vec<usize>,
}

impl FakeOperations {
    fn failing_at(calls: &[usize]) -> Self {
        Self {
            fail_at: calls.to_vec(),
            ..Default::default()
        }
    }

    fn record(&self, operation: Operation) -> anyhow::Result<String> {
        let mut calls = self.calls.borrow_mut();
        calls.push(operation);
        let index = calls.len();
        if self.fail_at.contains(&index) {
            anyhow::bail!("injected failure at operation {index}");
        }
        Ok(format!("operation {index}"))
    }
}

impl RouteDnsOperations for FakeOperations {
    fn setup_routes(&self, tun: &str, excludes: &[String]) -> anyhow::Result<String> {
        self.record(Operation::SetupRoutes(tun.into(), excludes.to_vec()))
    }

    fn teardown_routes(&self, tun: &str, excludes: &[String]) -> anyhow::Result<String> {
        self.record(Operation::TeardownRoutes(tun.into(), excludes.to_vec()))
    }

    fn setup_dns(
        &self,
        tun: &str,
        ip: Ipv4Addr,
        previous: Option<&ClientDnsState>,
    ) -> anyhow::Result<(Option<ClientDnsState>, String)> {
        let note = self.record(Operation::SetupDns(tun.into(), ip, previous.cloned()))?;
        Ok((
            Some(vec![ClientDnsServiceState {
                service: tun.into(),
                ..Default::default()
            }]),
            note,
        ))
    }

    fn refresh_excludes(
        &self,
        tun: &str,
        previous: &[String],
        next: &[String],
    ) -> anyhow::Result<String> {
        self.record(Operation::RefreshExcludes(
            tun.into(),
            previous.to_vec(),
            next.to_vec(),
        ))
    }
}

fn selections() -> (ClientRouteDnsSnapshot, ClientRouteDnsSelection) {
    (
        ClientRouteDnsSnapshot {
            client_active: true,
            tun_name: "old-tun".into(),
            applied_route_excludes: vec!["192.0.2.1/32".into()],
            dns_state: Some(vec![ClientDnsServiceState {
                service: "saved-service".into(),
                restore_servers: vec!["192.0.2.53".into()],
                restore_metric: Some(50),
                restore_automatic_metric: Some(false),
            }]),
        },
        ClientRouteDnsSelection {
            tun_name: "new-tun".into(),
            applied_route_excludes: vec!["198.51.100.1/32".into()],
            dns_service_ip: Ipv4Addr::new(10, 26, 0, 1),
        },
    )
}

fn old_cleanup(previous: &ClientRouteDnsSnapshot) -> Operation {
    Operation::TeardownRoutes(
        previous.tun_name.clone(),
        previous.applied_route_excludes.clone(),
    )
}

fn new_setup(next: &ClientRouteDnsSelection) -> Operation {
    Operation::SetupRoutes(next.tun_name.clone(), next.applied_route_excludes.clone())
}

fn old_restore(
    previous: &ClientRouteDnsSnapshot,
    next: &ClientRouteDnsSelection,
) -> Vec<Operation> {
    vec![
        Operation::SetupRoutes(
            previous.tun_name.clone(),
            previous.applied_route_excludes.clone(),
        ),
        Operation::SetupDns(
            previous.tun_name.clone(),
            next.dns_service_ip,
            previous.dns_state.clone(),
        ),
    ]
}

#[test]
fn applying_selection_orders_route_cleanup_setup_and_dns_and_preserves_restore_state() {
    let operations = FakeOperations::default();
    let (previous, next) = selections();
    let result = apply_selection_with(&operations, &previous, &next).unwrap();
    assert_eq!(
        *operations.calls.borrow(),
        vec![
            old_cleanup(&previous),
            new_setup(&next),
            Operation::SetupDns(
                next.tun_name.clone(),
                next.dns_service_ip,
                previous.dns_state.clone()
            ),
        ]
    );
    assert_eq!(result.route_note, "operation 2");
    assert_eq!(result.dns_note, "operation 3");
    assert_eq!(result.dns_state.unwrap()[0].service, next.tun_name);
}

#[test]
fn initial_selection_does_not_clean_up_nonexistent_routes() {
    let operations = FakeOperations::default();
    let (_, next) = selections();
    apply_selection_with(&operations, &ClientRouteDnsSnapshot::default(), &next).unwrap();
    assert_eq!(
        *operations.calls.borrow(),
        vec![
            new_setup(&next),
            Operation::SetupDns(next.tun_name.clone(), next.dns_service_ip, None),
        ]
    );
}

#[test]
fn failure_to_clean_up_previous_routes_stops_before_new_setup() {
    let operations = FakeOperations::failing_at(&[1]);
    let (previous, next) = selections();
    let error = apply_selection_with(&operations, &previous, &next).unwrap_err();
    assert!(!error.rollback_failed());
    assert!(error.to_string().contains("previous route cleanup failed"));
    assert_eq!(*operations.calls.borrow(), vec![old_cleanup(&previous)]);
}

#[test]
fn route_setup_failure_restores_previous_routes_then_dns() {
    let operations = FakeOperations::failing_at(&[2]);
    let (previous, next) = selections();
    let error = apply_selection_with(&operations, &previous, &next).unwrap_err();
    assert!(!error.rollback_failed());
    assert!(error.to_string().contains("route setup failed"));
    let mut expected = vec![old_cleanup(&previous), new_setup(&next)];
    expected.extend(old_restore(&previous, &next));
    assert_eq!(*operations.calls.borrow(), expected);
}

#[test]
fn dns_failure_cleans_up_new_routes_before_restoring_previous_selection() {
    for cleanup_fails in [false, true] {
        let failures = if cleanup_fails { vec![3, 4] } else { vec![3] };
        let operations = FakeOperations::failing_at(&failures);
        let (previous, next) = selections();
        let error = apply_selection_with(&operations, &previous, &next).unwrap_err();
        assert!(!error.rollback_failed());
        assert!(error.to_string().contains("DNS setup failed"));
        if cleanup_fails {
            assert!(error
                .to_string()
                .contains("injected failure at operation 4"));
        }
        let mut expected = vec![
            old_cleanup(&previous),
            new_setup(&next),
            Operation::SetupDns(
                next.tun_name.clone(),
                next.dns_service_ip,
                previous.dns_state.clone(),
            ),
            Operation::TeardownRoutes(next.tun_name.clone(), next.applied_route_excludes.clone()),
        ];
        expected.extend(old_restore(&previous, &next));
        assert_eq!(*operations.calls.borrow(), expected);
    }
}

#[test]
fn rollback_route_or_dns_failure_marks_selection_for_later_cleanup() {
    let (previous, next) = selections();
    for (failures, count) in [
        (vec![2, 3], 3),
        (vec![2, 4], 4),
        (vec![3, 5], 5),
        (vec![3, 6], 6),
    ] {
        let operations = FakeOperations::failing_at(&failures);
        let error = apply_selection_with(&operations, &previous, &next).unwrap_err();
        assert!(error.rollback_failed());
        assert!(error.to_string().contains("rollback failed"));
        assert_eq!(operations.calls.borrow().len(), count);
    }
}

#[test]
fn initial_route_setup_failure_has_no_previous_selection_to_restore() {
    let operations = FakeOperations::failing_at(&[1]);
    let (_, next) = selections();
    let error =
        apply_selection_with(&operations, &ClientRouteDnsSnapshot::default(), &next).unwrap_err();
    assert!(!error.rollback_failed());
    assert_eq!(*operations.calls.borrow(), vec![new_setup(&next)]);
}

#[test]
fn inactive_previous_selection_still_cleans_up_residual_excludes() {
    let operations = FakeOperations::failing_at(&[2]);
    let (mut previous, next) = selections();
    previous.client_active = false;
    let error = apply_selection_with(&operations, &previous, &next).unwrap_err();
    assert!(!error.rollback_failed());
    assert_eq!(
        *operations.calls.borrow(),
        vec![old_cleanup(&previous), new_setup(&next)]
    );
}

#[test]
fn unchanged_excludes_do_not_run_system_operations() {
    let operations = FakeOperations::failing_at(&[1]);
    let (previous, _) = selections();
    assert_eq!(
        refresh_excludes_with(
            &operations,
            &previous.tun_name,
            &previous.applied_route_excludes,
            &previous.applied_route_excludes
        )
        .unwrap(),
        "exit-node route excludes unchanged"
    );
    assert!(operations.calls.borrow().is_empty());
}

#[test]
fn refreshing_excludes_changes_only_excludes() {
    let operations = FakeOperations::default();
    let (previous, next) = selections();
    let note = refresh_excludes_with(
        &operations,
        &previous.tun_name,
        &previous.applied_route_excludes,
        &next.applied_route_excludes,
    )
    .unwrap();
    assert!(note.contains("refreshed"));
    assert_eq!(
        *operations.calls.borrow(),
        vec![Operation::RefreshExcludes(
            previous.tun_name,
            previous.applied_route_excludes,
            next.applied_route_excludes
        )]
    );
}

#[test]
fn failed_exclude_refresh_reverses_arguments_and_reports_rollback_failure() {
    for rollback_fails in [false, true] {
        let failures = if rollback_fails { vec![1, 2] } else { vec![1] };
        let operations = FakeOperations::failing_at(&failures);
        let (previous, next) = selections();
        let error = refresh_excludes_with(
            &operations,
            &previous.tun_name,
            &previous.applied_route_excludes,
            &next.applied_route_excludes,
        )
        .unwrap_err();
        assert_eq!(error.rollback_failed(), rollback_fails);
        assert!(error.to_string().contains("route exclude refresh failed"));
        assert_eq!(
            *operations.calls.borrow(),
            vec![
                Operation::RefreshExcludes(
                    previous.tun_name.clone(),
                    previous.applied_route_excludes.clone(),
                    next.applied_route_excludes.clone()
                ),
                Operation::RefreshExcludes(
                    previous.tun_name,
                    next.applied_route_excludes,
                    previous.applied_route_excludes
                ),
            ]
        );
    }
}
