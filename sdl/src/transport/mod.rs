pub mod control_addr;
pub mod gateway_udp_channel;
pub mod gateway_udp_envelope;
pub mod http2_channel;
pub mod http3_channel;
pub mod quic_channel;
pub mod socket;
pub mod udp_channel;

use std::net::SocketAddr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConnectProtocol {
    UDP,
    TCP,
    QUIC,
    WS,
    WSS,
}

impl ConnectProtocol {
    #[inline]
    pub fn is_tcp(&self) -> bool {
        self == &ConnectProtocol::TCP
    }
    #[inline]
    pub fn is_quic(&self) -> bool {
        self == &ConnectProtocol::QUIC
    }
    #[inline]
    pub fn is_udp(&self) -> bool {
        self == &ConnectProtocol::UDP
    }
    #[inline]
    pub fn is_ws(&self) -> bool {
        self == &ConnectProtocol::WS
    }
    #[inline]
    pub fn is_wss(&self) -> bool {
        self == &ConnectProtocol::WSS
    }
    pub fn is_transport(&self) -> bool {
        self.is_tcp() || self.is_udp() || self.is_quic()
    }
    pub fn is_base_tcp(&self) -> bool {
        self.is_tcp() || self.is_quic() || self.is_ws() || self.is_wss()
    }
}

/// A transport protocol and remote address, independent of routing policy or
/// measurements. Multiple overlay peers may share an endpoint (e.g. a gateway),
/// so peer-specific state must still be keyed by `(peer_ip, endpoint)`.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TransportEndpoint {
    pub protocol: ConnectProtocol,
    pub addr: SocketAddr,
}

impl TransportEndpoint {
    pub const fn new(protocol: ConnectProtocol, addr: SocketAddr) -> Self {
        Self { protocol, addr }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn endpoint_identity_includes_protocol_and_address() {
        let addr = ([127, 0, 0, 1], 29873).into();
        let udp = TransportEndpoint::new(ConnectProtocol::UDP, addr);
        let copy = udp;
        assert_eq!(copy, TransportEndpoint::new(ConnectProtocol::UDP, addr));
        let tcp = TransportEndpoint::new(ConnectProtocol::TCP, addr);
        let other = TransportEndpoint::new(ConnectProtocol::UDP, ([127, 0, 0, 1], 29874).into());
        assert_eq!(HashSet::from([udp, copy, tcp, other]).len(), 3);
        assert!(udp < tcp);
        assert!(udp < other);
    }

    #[test]
    fn peer_specific_keys_distinguish_peers_sharing_an_endpoint() {
        let endpoint = TransportEndpoint::new(ConnectProtocol::UDP, ([127, 0, 0, 1], 29901).into());
        let peers = HashSet::from([
            (std::net::Ipv4Addr::new(10, 26, 0, 2), endpoint),
            (std::net::Ipv4Addr::new(10, 26, 0, 3), endpoint),
        ]);
        assert_eq!(peers.len(), 2);
    }
}
