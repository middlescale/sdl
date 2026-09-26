use std::io;
use std::net::Ipv4Addr;

use crate::core::PeerIdentity;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route::{Route, RouteKey};
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::use_channel_type::UseChannelType;
use crate::nat::punch_workers::PunchCoordinator;
use crate::protocol::NetPacket;
use crate::transport::udp_channel::UdpChannel;

// Active data-plane components that own transport, path maintenance, or
// probing behavior. They are kept outside core runtime state so packet
// execution remains a data-plane concern.
#[derive(Clone)]
pub(crate) struct DataPlaneRuntime {
    pub(crate) route_manager: RouteManager,
    pub(crate) udp_channel: UdpChannel,
    pub(crate) gateway_sessions: GatewaySessions,
    pub(crate) punch_coordinator: PunchCoordinator,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PayloadPath {
    P2pUdp(RouteKey),
    GatewayRelay,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct PayloadRoutePlan {
    pub(crate) path: Option<PayloadPath>,
    pub(crate) direct_recovery_requested: bool,
    pub(crate) allows_gateway_relay: bool,
}

impl DataPlaneRuntime {
    pub(crate) fn prepare_peer_payload_route(
        &self,
        vip: &Ipv4Addr,
        is_gateway_vip: bool,
        peer_channel_mode: Option<crate::proto::message::ChannelMode>,
    ) -> PayloadRoutePlan {
        let (measured_direct_route, direct_recovery_requested) = if is_gateway_vip {
            (None, false)
        } else {
            self.route_manager.activate_peer(vip);
            let (route, has_direct_route) = self.route_manager.payload_route_read(vip);
            let direct_recovery_requested = !self.route_manager.use_channel_type().is_only_relay()
                && self
                    .route_manager
                    .take_direct_recovery_request(vip, has_direct_route);
            (route, direct_recovery_requested)
        };
        let use_channel_type =
            if peer_channel_mode == Some(crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY) {
                UseChannelType::Relay
            } else {
                self.route_manager.use_channel_type()
            };
        PayloadRoutePlan {
            path: select_payload_path(is_gateway_vip, use_channel_type, measured_direct_route),
            direct_recovery_requested,
            allows_gateway_relay: !use_channel_type.is_only_p2p(),
        }
    }

    pub(crate) fn send_p2p<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        self.udp_channel.send_by_key(packet.buffer(), route_key)
    }

    pub(crate) fn mark_p2p_path_failed(&self, vip: &Ipv4Addr, route_key: RouteKey) {
        self.route_manager.mark_path_failed(vip, route_key);
    }

    pub(crate) fn send_peer_relay<B: AsRef<[u8]>>(
        &self,
        vip: Ipv4Addr,
        peer_identity: Option<&PeerIdentity>,
        peer_crypto: &PeerCryptoManager,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        self.gateway_sessions
            .maybe_send_peer_relay_probe(vip, peer_identity, peer_crypto);
        self.gateway_sessions
            .send_relay_for_peer(peer_identity, packet)
    }

    pub(crate) fn send_gateway_relay<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
    ) -> io::Result<()> {
        self.gateway_sessions.send_relay(packet)
    }

    pub(crate) fn send_reply_by_route<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
        route_key: RouteKey,
    ) -> io::Result<bool> {
        if self.gateway_sessions.is_gateway_addr(route_key.addr) {
            self.gateway_sessions
                .send_relay_to_or_active(route_key.addr, packet)?;
            Ok(true)
        } else if route_key.protocol().is_udp() {
            self.send_p2p(packet, route_key)?;
            Ok(false)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported reply route {route_key:?}"),
            ))
        }
    }
}

pub(crate) fn is_definitive_p2p_path_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

fn select_payload_path(
    is_gateway_vip: bool,
    use_channel_type: UseChannelType,
    direct_route: Option<Route>,
) -> Option<PayloadPath> {
    if is_gateway_vip {
        return Some(PayloadPath::GatewayRelay);
    }
    match use_channel_type {
        UseChannelType::Relay => Some(PayloadPath::GatewayRelay),
        UseChannelType::P2p => direct_route.map(|route| PayloadPath::P2pUdp(route.route_key())),
        UseChannelType::Auto => Some(match direct_route {
            Some(route) => PayloadPath::P2pUdp(route.route_key()),
            None => PayloadPath::GatewayRelay,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::{is_definitive_p2p_path_error, select_payload_path, PayloadPath};
    use crate::data_plane::route::Route;
    use crate::data_plane::use_channel_type::UseChannelType;
    use crate::transport::connect_protocol::ConnectProtocol;

    fn sample_route() -> Route {
        Route::new(
            ConnectProtocol::UDP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 3000)),
            1,
            10,
        )
    }

    #[test]
    fn payload_path_prefers_direct_udp_when_available() {
        let route = sample_route();
        assert_eq!(
            select_payload_path(false, UseChannelType::Auto, Some(route)),
            Some(PayloadPath::P2pUdp(route.route_key()))
        );
    }

    #[test]
    fn payload_path_falls_back_to_relay_for_auto_mode() {
        assert_eq!(
            select_payload_path(false, UseChannelType::Auto, None),
            Some(PayloadPath::GatewayRelay)
        );
    }

    #[test]
    fn payload_path_requires_direct_route_for_p2p_only_mode() {
        assert_eq!(select_payload_path(false, UseChannelType::P2p, None), None);
    }

    #[test]
    fn auto_policy_keeps_measured_p2p_even_with_high_rt() {
        let route = Route::new(
            ConnectProtocol::UDP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 3000)),
            1,
            900,
        );
        assert_eq!(
            select_payload_path(false, UseChannelType::Auto, Some(route)),
            Some(PayloadPath::P2pUdp(route.route_key()))
        );
    }

    #[test]
    fn auto_policy_ignores_historical_p2p_loss() {
        let route = sample_route();
        assert_eq!(
            select_payload_path(false, UseChannelType::Auto, Some(route)),
            Some(PayloadPath::P2pUdp(route.route_key()))
        );
    }

    #[test]
    fn gateway_always_uses_gateway_relay_in_p2p_mode() {
        assert_eq!(
            select_payload_path(true, UseChannelType::P2p, None),
            Some(PayloadPath::GatewayRelay)
        );
    }

    #[test]
    fn only_unreachable_errors_invalidate_a_p2p_route() {
        assert!(is_definitive_p2p_path_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )));
        assert!(is_definitive_p2p_path_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        )));
        assert!(is_definitive_p2p_path_error(&std::io::Error::from(
            std::io::ErrorKind::HostUnreachable,
        )));
        assert!(is_definitive_p2p_path_error(&std::io::Error::from(
            std::io::ErrorKind::NetworkUnreachable,
        )));
        assert!(!is_definitive_p2p_path_error(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock,
        )));
        assert!(!is_definitive_p2p_path_error(&std::io::Error::from(
            std::io::ErrorKind::Other,
        )));
    }
}
