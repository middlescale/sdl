use anyhow::Context;
use http::Uri;

pub const DEFAULT_CONTROL_PATH: &str = "/control";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlAddress {
    authority: String,
    server_name: String,
    request_uri: String,
}

impl ControlAddress {
    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn request_uri(&self) -> &str {
        &self.request_uri
    }
}

pub fn parse_control_address(raw: &str) -> anyhow::Result<ControlAddress> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("control address is empty");
    }

    let canonical_input = if trimmed.contains("://") {
        if let Some(rest) = trimmed.strip_prefix("quic://") {
            format!("https://{}", rest)
        } else {
            trimmed.to_string()
        }
    } else {
        format!("https://{}", trimmed)
    };

    let uri: Uri = canonical_input
        .parse()
        .with_context(|| format!("invalid control address: {}", raw))?;
    if uri.scheme_str() != Some("https") {
        anyhow::bail!("control address must use https://");
    }

    let host = uri
        .host()
        .with_context(|| format!("control address missing host: {}", raw))?;
    let port = uri.port_u16().unwrap_or(443);
    let authority = format_authority(host, port);
    let path = match uri.path_and_query().map(|value| value.as_str()) {
        Some("/") | None => DEFAULT_CONTROL_PATH.to_string(),
        Some(path) if path.is_empty() => DEFAULT_CONTROL_PATH.to_string(),
        Some(path) => path.to_string(),
    };

    Ok(ControlAddress {
        authority: authority.clone(),
        server_name: host.to_string(),
        request_uri: format!("https://{}{}", authority, path),
    })
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_control_address, DEFAULT_CONTROL_PATH};

    #[test]
    fn parses_https_control_url() {
        let addr = parse_control_address("https://control.example.com/control").unwrap();
        assert_eq!(addr.authority(), "control.example.com:443");
        assert_eq!(addr.server_name(), "control.example.com");
        assert_eq!(
            addr.request_uri(),
            "https://control.example.com:443/control"
        );
    }

    #[test]
    fn defaults_to_control_path_for_bare_authority() {
        let addr = parse_control_address("control.example.com:4433").unwrap();
        assert_eq!(addr.authority(), "control.example.com:4433");
        assert_eq!(
            addr.request_uri(),
            format!("https://control.example.com:4433{}", DEFAULT_CONTROL_PATH)
        );
    }

    #[test]
    fn accepts_legacy_quic_scheme_as_h3_authority() {
        let addr = parse_control_address("quic://127.0.0.1:4433").unwrap();
        assert_eq!(addr.authority(), "127.0.0.1:4433");
        assert_eq!(addr.server_name(), "127.0.0.1");
        assert_eq!(addr.request_uri(), "https://127.0.0.1:4433/control");
    }
}
