use std::io;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::process::Command;

use crate::DnsProfile;

const MANAGED_COMMENT: &str = "managed by sdl";

pub(crate) fn apply_split_dns(
    _interface_name: &str,
    previous_profile: Option<&DnsProfile>,
    profile: &DnsProfile,
) -> io::Result<Vec<String>> {
    if profile.servers.is_empty() || profile.match_domains.is_empty() {
        return Ok(Vec::new());
    }
    let domains = normalize_match_domains(&profile.match_domains);
    if domains.is_empty() {
        return Ok(Vec::new());
    }
    if let Err(err) = reconcile_nrpt_rules(previous_profile, Some(profile)) {
        return rollback_apply_failure(previous_profile, profile, err);
    }
    Ok(domains)
}

pub(crate) fn revert_split_dns(previous_profile: Option<&DnsProfile>) -> io::Result<()> {
    reconcile_nrpt_rules(previous_profile, None)
}

fn exec_powershell(script: &str) -> io::Result<()> {
    println!(
        "exe cmd: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <script>"
    );
    let mut command = Command::new("powershell");
    command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script);
    #[cfg(target_os = "windows")]
    {
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    let out = command.output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "powershell failed: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

fn build_apply_script(domains: &[String], servers: &[String]) -> String {
    let namespaces = domains
        .iter()
        .map(|domain| ps_string(&format!(".{domain}")))
        .collect::<Vec<_>>()
        .join(", ");
    let nameservers = servers
        .iter()
        .map(|server| ps_string(server))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "$ErrorActionPreference = 'Stop'; \
$comment = {comment}; \
$namespaces = @({namespaces}); \
$nameServers = @({nameservers}); \
foreach ($namespace in $namespaces) {{ \
  Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains $namespace -and $_.Comment -eq $comment }} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}; \
  Add-DnsClientNrptRule -Namespace $namespace -NameServers $nameServers -Comment $comment | Out-Null; \
}}",
        comment = ps_string(MANAGED_COMMENT),
        namespaces = namespaces,
        nameservers = nameservers
    )
}

fn reconcile_nrpt_rules(
    previous_profile: Option<&DnsProfile>,
    profile: Option<&DnsProfile>,
) -> io::Result<()> {
    let previous_domains = normalized_profile_domains(previous_profile);
    let current_domains = normalized_profile_domains(profile);

    if let Some(profile) = profile {
        if !current_domains.is_empty() && !profile.servers.is_empty() {
            exec_powershell(&build_apply_script(&current_domains, &profile.servers))?;
        }
    }

    let removed = removed_domains(&previous_domains, &current_domains);
    if !removed.is_empty() {
        exec_powershell(&build_revert_script(&removed))?;
    }
    Ok(())
}

fn rollback_apply_failure(
    previous_profile: Option<&DnsProfile>,
    profile: &DnsProfile,
    err: io::Error,
) -> io::Result<Vec<String>> {
    let kind = err.kind();
    let err_msg = err.to_string();
    match reconcile_nrpt_rules(Some(profile), previous_profile) {
        Ok(()) => Err(io::Error::new(kind, err_msg)),
        Err(rollback_err) => Err(io::Error::new(
            kind,
            format!("{err_msg}; rollback to previous split DNS state failed: {rollback_err}"),
        )),
    }
}

fn build_revert_script(domains: &[String]) -> String {
    let namespaces = domains
        .iter()
        .map(|domain| ps_string(&format!(".{domain}")))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "$ErrorActionPreference = 'Stop'; \
$comment = {comment}; \
$namespaces = @({namespaces}); \
foreach ($namespace in $namespaces) {{ \
  Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains $namespace -and $_.Comment -eq $comment }} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}; \
}}",
        comment = ps_string(MANAGED_COMMENT),
        namespaces = namespaces
    )
}

fn normalize_match_domains(domains: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain = domain.trim().trim_start_matches('~').trim_end_matches('.');
        if domain.is_empty() {
            continue;
        }
        let domain = domain.to_ascii_lowercase();
        if normalized.iter().all(|existing| existing != &domain) {
            normalized.push(domain);
        }
    }
    normalized
}

fn normalized_profile_domains(profile: Option<&DnsProfile>) -> Vec<String> {
    profile
        .map(|profile| normalize_match_domains(&profile.match_domains))
        .unwrap_or_default()
}

fn removed_domains(previous_domains: &[String], current_domains: &[String]) -> Vec<String> {
    previous_domains
        .iter()
        .filter(|domain| !current_domains.contains(domain))
        .cloned()
        .collect()
}

fn ps_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::{
        build_apply_script, build_revert_script, normalize_match_domains, removed_domains,
    };

    #[test]
    fn normalize_match_domains_dedups_and_trims() {
        let domains = normalize_match_domains(&[
            "~MS.NET".into(),
            "sales.ms.net.".into(),
            "sales.ms.net".into(),
            "".into(),
        ]);
        assert_eq!(domains, vec!["ms.net", "sales.ms.net"]);
    }

    #[test]
    fn build_apply_script_uses_nrpt_rules() {
        let script = build_apply_script(
            &["ms.net".into(), "sales.ms.net".into()],
            &["10.26.0.53".into(), "10.26.0.54".into()],
        );
        assert!(script.contains("Add-DnsClientNrptRule"));
        assert!(script.contains("Remove-DnsClientNrptRule"));
        assert!(script.contains("'.ms.net'"));
        assert!(script.contains("'.sales.ms.net'"));
        assert!(script.contains("'10.26.0.53'"));
        assert!(script.contains("'10.26.0.54'"));
        assert!(script.contains("'managed by sdl'"));
    }

    #[test]
    fn build_revert_script_targets_managed_namespaces() {
        let script = build_revert_script(&["ms.net".into()]);
        assert!(script.contains("Remove-DnsClientNrptRule"));
        assert!(script.contains("'.ms.net'"));
        assert!(script.contains("'managed by sdl'"));
    }

    #[test]
    fn removed_domains_only_keeps_stale_namespaces() {
        let removed = removed_domains(
            &["ms.net".into(), "sales.ms.net".into()],
            &["sales.ms.net".into(), "corp.ms.net".into()],
        );
        assert_eq!(removed, vec!["ms.net"]);
    }
}
