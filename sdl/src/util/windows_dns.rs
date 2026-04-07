use std::io;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::process::Command;

use crate::DnsProfile;

const MANAGED_COMMENT: &str = "managed by sdl";

pub(crate) fn apply_split_dns(
    _interface_name: &str,
    profile: &DnsProfile,
) -> io::Result<Vec<String>> {
    if profile.servers.is_empty() || profile.match_domains.is_empty() {
        return Ok(Vec::new());
    }
    let domains = normalize_match_domains(&profile.match_domains);
    if domains.is_empty() {
        return Ok(Vec::new());
    }
    exec_powershell(&build_apply_script(&domains, &profile.servers))?;
    Ok(domains)
}

pub(crate) fn revert_split_dns(domains: &[String]) -> io::Result<()> {
    let domains = normalize_match_domains(domains);
    if domains.is_empty() {
        return Ok(());
    }
    exec_powershell(&build_revert_script(&domains))?;
    Ok(())
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

fn ps_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::{build_apply_script, build_revert_script, normalize_match_domains};

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
}
