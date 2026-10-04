//! Resolve protocol-specific gateway transport endpoints.

use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use http::Uri;

use crate::proto::message::GatewayChannelKind;

#[derive(Clone)]
pub(super) struct ResolvedGatewayChannel {
    pub(super) endpoint: SocketAddr,
    pub(super) kind: GatewayChannelKind,
    pub(super) server_name: String,
    pub(super) request_uri: Option<String>,
}

#[derive(Debug)]
pub(super) struct HttpsTransportTarget {
    pub(super) endpoint: SocketAddr,
    pub(super) server_name: String,
    pub(super) request_uri: String,
}

pub(super) fn parse_transport_endpoint(addr: &str) -> anyhow::Result<SocketAddr> {
    let normalized = addr
        .strip_prefix("quic://")
        .or_else(|| addr.strip_prefix("udp://"))
        .unwrap_or(addr)
        .trim()
        .to_string();
    if let Ok(socket_addr) = SocketAddr::from_str(&normalized) {
        return Ok(socket_addr);
    }
    normalized
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no socket address resolved for {normalized}"))
}

pub(super) fn resolve_gateway_channel(
    channel: &crate::proto::message::GatewayChannel,
) -> anyhow::Result<ResolvedGatewayChannel> {
    let kind = channel
        .kind
        .enum_value()
        .map_err(|value| anyhow::anyhow!("unknown gateway channel kind {value}"))?;
    if kind == GatewayChannelKind::GATEWAY_CHANNEL_UNKNOWN {
        anyhow::bail!("gateway channel kind is unspecified");
    }
    match kind {
        GatewayChannelKind::GATEWAY_CHANNEL_HTTPS => {
            let target = parse_https_transport_target(&channel.addr)?;
            Ok(ResolvedGatewayChannel {
                endpoint: target.endpoint,
                kind,
                server_name: if channel.server_name.is_empty() {
                    target.server_name
                } else {
                    channel.server_name.clone()
                },
                request_uri: Some(target.request_uri),
            })
        }
        _ => {
            let endpoint = parse_transport_endpoint(&channel.addr)?;
            Ok(ResolvedGatewayChannel {
                endpoint,
                kind,
                server_name: if channel.server_name.is_empty() {
                    endpoint.ip().to_string()
                } else {
                    channel.server_name.clone()
                },
                request_uri: None,
            })
        }
    }
}

pub(super) fn parse_https_transport_target(addr: &str) -> anyhow::Result<HttpsTransportTarget> {
    let uri: Uri = addr.trim().parse()?;
    if uri.scheme_str() != Some("https") {
        anyhow::bail!("gateway https addr must use https://");
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("gateway https addr missing host: {addr}"))?;
    let port = uri.port_u16().unwrap_or(443);
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let endpoint = authority
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no socket address resolved for {authority}"))?;
    let path = match uri.path_and_query().map(|value| value.as_str()) {
        Some("/") | None => "/gateway".to_string(),
        Some("") => "/gateway".to_string(),
        Some("/gateway") => "/gateway".to_string(),
        Some(path) => {
            anyhow::bail!("gateway https addr path must be /gateway or empty, got {path}")
        }
    };
    Ok(HttpsTransportTarget {
        endpoint,
        server_name: host.to_string(),
        request_uri: format!("https://{}{}", authority, path),
    })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use protobuf::EnumOrUnknown;

    use crate::proto::message::GatewayChannel;

    use super::super::Ipv4Addr;
    use super::{parse_https_transport_target, parse_transport_endpoint, resolve_gateway_channel};

    #[test]
    fn parse_transport_endpoint_accepts_socket_addr() {
        let endpoint = parse_transport_endpoint("quic://127.0.0.1:29900").unwrap();
        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.port(), 29900);
    }

    #[test]
    fn parse_transport_endpoint_accepts_udp_scheme() {
        let endpoint = parse_transport_endpoint("udp://127.0.0.1:29901").unwrap();
        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.port(), 29901);
    }

    #[test]
    fn parse_transport_endpoint_resolves_hostname() {
        let endpoint = parse_transport_endpoint("quic://localhost:29900").unwrap();
        assert_eq!(endpoint.port(), 29900);
        assert!(endpoint.ip().is_loopback());
    }

    #[test]
    fn parse_https_transport_target_defaults_gateway_path() {
        let target = parse_https_transport_target("https://127.0.0.1:443").unwrap();
        assert_eq!(target.endpoint.port(), 443);
        assert_eq!(target.request_uri, "https://127.0.0.1:443/gateway");
    }

    #[test]
    fn parse_https_transport_target_rejects_non_gateway_path() {
        let err = parse_https_transport_target("https://127.0.0.1:443/custom").unwrap_err();
        assert!(
            err.to_string()
                .contains("gateway https addr path must be /gateway or empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_gateway_channel_kind_is_rejected() {
        let channel = GatewayChannel {
            kind: EnumOrUnknown::from_i32(99),
            addr: "quic://127.0.0.1:29900".into(),
            ..Default::default()
        };

        let err = resolve_gateway_channel(&channel)
            .err()
            .expect("unknown channel kind");
        assert!(err.to_string().contains("unknown gateway channel kind 99"));
    }
}
