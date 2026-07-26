use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
#[cfg(target_os = "windows")]
use std::process::Command;
use std::time::Duration;

const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_RESPONSE_SIZE: usize = 4096;

pub(crate) fn forward_dns_query_to_system_resolver(query: &[u8]) -> io::Result<Vec<u8>> {
    forward_dns_query_to_resolvers(query, &system_resolvers())
}

pub(crate) fn forward_dns_query_to_resolvers(
    query: &[u8],
    resolvers: &[SocketAddr],
) -> io::Result<Vec<u8>> {
    if resolvers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "system DNS resolver not found",
        ));
    }
    let mut last_error = None;
    for &resolver in resolvers {
        match forward_dns_query(query, resolver) {
            Ok(response) => return Ok(response),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "system DNS resolver not found")
    }))
}

fn forward_dns_query(query: &[u8], resolver: SocketAddr) -> io::Result<Vec<u8>> {
    let bind_addr = if resolver.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(DNS_FORWARD_TIMEOUT))?;
    socket.set_write_timeout(Some(DNS_FORWARD_TIMEOUT))?;
    socket.connect(resolver)?;
    socket.send(query)?;
    let mut response = vec![0u8; MAX_DNS_RESPONSE_SIZE];
    let len = socket.recv(&mut response)?;
    response.truncate(len);
    Ok(response)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn system_resolvers() -> Vec<SocketAddr> {
    parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
}

#[cfg(target_os = "windows")]
pub(crate) fn system_resolvers() -> Vec<SocketAddr> {
    // Windows does not maintain /etc/resolv.conf. Query the configured adapter
    // DNS servers directly instead of falling back to the control plane.
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Select-Object -ExpandProperty ServerAddresses",
        ])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let mut resolvers = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|value| value.trim_matches(['[', ']', ',']).parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect::<Vec<_>>();
    resolvers.sort_unstable();
    resolvers.dedup();
    resolvers
}

fn parse_resolv_conf(contents: &str) -> Vec<SocketAddr> {
    let mut resolvers = Vec::new();
    for line in contents.lines() {
        let line = line.split_once('#').map(|(left, _)| left).unwrap_or(line);
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(addr) = parts.next() else {
            continue;
        };
        let addr = addr.trim_matches(['[', ']']);
        if let Ok(ip) = addr.parse::<IpAddr>() {
            resolvers.push(SocketAddr::new(ip, 53));
        }
    }
    resolvers
}

#[cfg(test)]
mod tests {
    use super::parse_resolv_conf;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn parses_resolv_conf_nameservers() {
        let resolvers = parse_resolv_conf(
            r#"
nameserver 192.168.1.1
nameserver 2001:4860:4860::8888 # comment
search lan
"#,
        );
        assert_eq!(
            resolvers,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53),
                SocketAddr::new(
                    IpAddr::V6("2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap()),
                    53
                ),
            ]
        );
    }

    #[test]
    fn ignores_invalid_resolvers() {
        let resolvers = parse_resolv_conf(
            r#"
nameserver invalid
nameserver
options edns0
"#,
        );
        assert!(resolvers.is_empty());
    }
}
