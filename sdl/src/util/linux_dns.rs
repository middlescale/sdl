use std::io;

use crate::tun_tap_device::create_device::exe_cmd;
use crate::DnsProfile;

pub(crate) fn apply_split_dns(interface_name: &str, profile: &DnsProfile) -> io::Result<()> {
    if profile.servers.is_empty() || profile.match_domains.is_empty() {
        return Ok(());
    }
    exe_cmd(&build_apply_command(interface_name, profile))?;
    Ok(())
}

pub(crate) fn revert_split_dns(interface_name: &str) -> io::Result<()> {
    exe_cmd(&build_revert_command(interface_name))?;
    Ok(())
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
    use super::{build_apply_command, build_revert_command};
    use crate::DnsProfile;

    #[test]
    fn build_apply_command_prefixes_match_domains() {
        let profile = DnsProfile {
            servers: vec!["10.26.0.1".into(), "10.26.0.2".into()],
            match_domains: vec!["ms.net".into(), "~corp.ms.net".into()],
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
}
