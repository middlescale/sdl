use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::DnsProfile;

const MANAGED_HEADER: &str = "# managed by sdl\n";

pub(crate) fn apply_split_dns(
    _interface_name: &str,
    previous_profile: Option<&DnsProfile>,
    profile: &DnsProfile,
) -> io::Result<Vec<String>> {
    apply_split_dns_in_dir(&resolver_dir(), previous_profile, profile)
}

pub(crate) fn revert_split_dns(previous_profile: Option<&DnsProfile>) -> io::Result<()> {
    revert_split_dns_in_dir(&resolver_dir(), previous_profile)
}

fn apply_split_dns_in_dir(
    resolver_dir: &Path,
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
    if let Err(err) = reconcile_resolver_files_in_dir(resolver_dir, previous_profile, Some(profile))
    {
        return rollback_apply_failure_in_dir(resolver_dir, previous_profile, profile, err);
    }
    Ok(domains)
}

fn revert_split_dns_in_dir(
    resolver_dir: &Path,
    previous_profile: Option<&DnsProfile>,
) -> io::Result<()> {
    reconcile_resolver_files_in_dir(resolver_dir, previous_profile, None)
}

fn reconcile_resolver_files_in_dir(
    resolver_dir: &Path,
    previous_profile: Option<&DnsProfile>,
    profile: Option<&DnsProfile>,
) -> io::Result<()> {
    let previous_domains = normalized_profile_domains(previous_profile);
    let current_domains = normalized_profile_domains(profile);

    if !current_domains.is_empty() {
        fs::create_dir_all(resolver_dir)?;
        let content =
            build_resolver_contents(profile.expect("profile required when domains exist"));
        for domain in &current_domains {
            let path = resolver_path(resolver_dir, domain);
            if path.exists() && !is_managed_resolver_file(&path)? {
                return Err(io::Error::other(format!(
                    "refuse to overwrite unmanaged resolver file {}",
                    path.display()
                )));
            }
            fs::write(path, &content)?;
        }
    }

    if !resolver_dir.exists() {
        return Ok(());
    }
    for domain in removed_domains(&previous_domains, &current_domains) {
        let path = resolver_path(resolver_dir, &domain);
        if !path.exists() {
            continue;
        }
        if is_managed_resolver_file(&path)? {
            fs::remove_file(path)?;
        } else {
            log::warn!("skip unmanaged resolver file {}", path.display());
        }
    }
    Ok(())
}

fn rollback_apply_failure_in_dir(
    resolver_dir: &Path,
    previous_profile: Option<&DnsProfile>,
    profile: &DnsProfile,
    err: io::Error,
) -> io::Result<Vec<String>> {
    let kind = err.kind();
    let err_msg = err.to_string();
    match reconcile_resolver_files_in_dir(resolver_dir, Some(profile), previous_profile) {
        Ok(()) => Err(io::Error::new(kind, err_msg)),
        Err(rollback_err) => Err(io::Error::new(
            kind,
            format!("{err_msg}; rollback to previous split DNS state failed: {rollback_err}"),
        )),
    }
}

fn resolver_dir() -> PathBuf {
    std::env::var_os("SDL_MACOS_RESOLVER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/resolver"))
}

fn resolver_path(resolver_dir: &Path, domain: &str) -> PathBuf {
    resolver_dir.join(domain)
}

fn build_resolver_contents(profile: &DnsProfile) -> String {
    let mut content = String::from(MANAGED_HEADER);
    for server in &profile.servers {
        content.push_str("nameserver ");
        content.push_str(server);
        content.push('\n');
    }
    content
}

fn is_managed_resolver_file(path: &Path) -> io::Result<bool> {
    let content = fs::read_to_string(path)?;
    Ok(content.starts_with(MANAGED_HEADER))
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

#[cfg(test)]
mod tests {
    use super::{
        apply_split_dns_in_dir, build_resolver_contents, normalize_match_domains,
        revert_split_dns_in_dir,
    };
    use crate::DnsProfile;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_resolver_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sdl-macos-dns-test-{nanos}"))
    }

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
    fn build_resolver_contents_lists_nameservers() {
        let content = build_resolver_contents(&DnsProfile {
            servers: vec!["10.26.0.53".into(), "10.26.0.54".into()],
            match_domains: vec!["ms.net".into()],
            peer_name_domain: "ms.net".into(),
        });
        assert_eq!(
            content,
            "# managed by sdl\nnameserver 10.26.0.53\nnameserver 10.26.0.54\n"
        );
    }

    #[test]
    fn apply_and_revert_split_dns_manage_resolver_files() {
        let resolver_dir = temp_resolver_dir();
        let profile = DnsProfile {
            servers: vec!["10.26.0.53".into()],
            match_domains: vec!["~ms.net".into(), "sales.ms.net".into()],
            peer_name_domain: "sales.ms.net".into(),
        };

        let domains = apply_split_dns_in_dir(&resolver_dir, None, &profile).unwrap();
        assert_eq!(domains, vec!["ms.net", "sales.ms.net"]);
        assert_eq!(
            fs::read_to_string(resolver_dir.join("ms.net")).unwrap(),
            "# managed by sdl\nnameserver 10.26.0.53\n"
        );

        revert_split_dns_in_dir(&resolver_dir, Some(&profile)).unwrap();
        assert!(!resolver_dir.join("ms.net").exists());
        assert!(!resolver_dir.join("sales.ms.net").exists());

        let _ = fs::remove_dir_all(&resolver_dir);
    }

    #[test]
    fn apply_split_dns_rejects_unmanaged_file() {
        let resolver_dir = temp_resolver_dir();
        fs::create_dir_all(&resolver_dir).unwrap();
        fs::write(resolver_dir.join("ms.net"), "nameserver 1.1.1.1\n").unwrap();

        let err = apply_split_dns_in_dir(
            &resolver_dir,
            None,
            &DnsProfile {
                servers: vec!["10.26.0.53".into()],
                match_domains: vec!["ms.net".into()],
                peer_name_domain: "ms.net".into(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unmanaged resolver file"));

        let _ = fs::remove_dir_all(&resolver_dir);
    }

    #[test]
    fn apply_split_dns_rolls_back_to_previous_profile_on_failure() {
        let resolver_dir = temp_resolver_dir();
        fs::create_dir_all(&resolver_dir).unwrap();

        let previous_profile = DnsProfile {
            servers: vec!["10.26.0.53".into()],
            match_domains: vec!["ms.net".into()],
            peer_name_domain: "ms.net".into(),
        };
        let next_profile = DnsProfile {
            servers: vec!["10.26.0.54".into()],
            match_domains: vec!["ms.net".into(), "sales.ms.net".into()],
            peer_name_domain: "sales.ms.net".into(),
        };

        apply_split_dns_in_dir(&resolver_dir, None, &previous_profile).unwrap();
        fs::write(resolver_dir.join("sales.ms.net"), "nameserver 1.1.1.1\n").unwrap();

        let err = apply_split_dns_in_dir(&resolver_dir, Some(&previous_profile), &next_profile)
            .unwrap_err();
        assert!(err.to_string().contains("unmanaged resolver file"));
        assert_eq!(
            fs::read_to_string(resolver_dir.join("ms.net")).unwrap(),
            "# managed by sdl\nnameserver 10.26.0.53\n"
        );
        assert_eq!(
            fs::read_to_string(resolver_dir.join("sales.ms.net")).unwrap(),
            "nameserver 1.1.1.1\n"
        );

        let _ = fs::remove_dir_all(&resolver_dir);
    }
}
