//! Exit-node route/DNS orchestration and platform operations.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use anyhow::Context;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::process::Command;

mod dns;
mod excludes;
mod routing;
mod selection;

pub use dns::{setup_client_dns, teardown_client_dns, ClientDnsServiceState, ClientDnsState};
pub use excludes::merge_excludes;
pub use routing::{
    refresh_client_routing_excludes, setup_client_routing, setup_server_routing,
    teardown_client_routing, teardown_server_routing,
};
pub use selection::{
    apply_client_route_dns_selection, refresh_client_route_excludes, ClientRouteDnsApplyError,
    ClientRouteDnsApplyResult, ClientRouteDnsSelection, ClientRouteDnsSnapshot,
};

pub fn local_ready(enabled: bool, egress_interface: &Option<String>) -> bool {
    enabled
        && cfg!(target_os = "linux")
        && egress_interface
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_shell(command: &str) -> anyhow::Result<()> {
    run_command("sh", &["-c", command])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(target_os = "linux")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
