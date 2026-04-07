use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::DnsProfile;

const MANAGED_HEADER: &str = "# managed by sdl\n";

pub(crate) fn apply_split_dns(
    _interface_name: &str,
    profile: &DnsProfile,
) -> io::Result<Vec<String>> {
    apply_split_dns_in_dir(&resolver_dir(), profile)
}

pub(crate) fn revert_split_dns(domains: &[String]) -> io::Result<()> {
    revert_split_dns_in_dir(&resolver_dir(), domains)
}

fn apply_split_dns_in_dir(resolver_dir: &Path, profile: &DnsProfile) -> io::Result<Vec<String>> {
    if profile.servers.is_empty() || profile.match_domains.is_empty() {
        return Ok(Vec::new());
    }
    let domains = normalize_match_domains(&profile.match_domains);
    if domains.is_empty() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(resolver_dir)?;
    let content = build_resolver_contents(profile);
    for domain in &domains {
        let path = resolver_path(resolver_dir, domain);
        if path.exists() && !is_managed_resolver_file(&path)? {
            return Err(io::Error::other(format!(
                "refuse to overwrite unmanaged resolver file {}",
                path.display()
            )));
        }
        fs::write(path, &content)?;
    }
    Ok(domains)
}

fn revert_split_dns_in_dir(resolver_dir: &Path, domains: &[String]) -> io::Result<()> {
    if domains.is_empty() {
        return Ok(());
    }
    if !resolver_dir.exists() {
        return Ok(());
    }
    for domain in normalize_match_domains(domains) {
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
        };

        let domains = apply_split_dns_in_dir(&resolver_dir, &profile).unwrap();
        assert_eq!(domains, vec!["ms.net", "sales.ms.net"]);
        assert_eq!(
            fs::read_to_string(resolver_dir.join("ms.net")).unwrap(),
            "# managed by sdl\nnameserver 10.26.0.53\n"
        );

        revert_split_dns_in_dir(&resolver_dir, &domains).unwrap();
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
            &DnsProfile {
                servers: vec!["10.26.0.53".into()],
                match_domains: vec!["ms.net".into()],
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unmanaged resolver file"));

        let _ = fs::remove_dir_all(&resolver_dir);
    }
}
