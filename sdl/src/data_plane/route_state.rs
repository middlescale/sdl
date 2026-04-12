use std::net::{Ipv4Addr, SocketAddr};

use crate::data_plane::route::{Route, RouteKey};
use crate::transport::connect_protocol::ConnectProtocol;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RouteKind {
    P2p,
    GatewayRelay,
    Relay,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteState {
    pub peer_ip: Ipv4Addr,
    pub route_key: RouteKey,
    pub transport: ConnectProtocol,
    pub addr: SocketAddr,
    pub kind: RouteKind,
    pub metric: u8,
    pub rt: i64,
}

impl RouteState {
    pub fn from_route(peer_ip: Ipv4Addr, route: Route, virtual_gateway: Ipv4Addr) -> Self {
        let kind = if route.is_p2p() {
            RouteKind::P2p
        } else if peer_ip == virtual_gateway {
            RouteKind::GatewayRelay
        } else {
            RouteKind::Relay
        };
        Self {
            peer_ip,
            route_key: route.route_key(),
            transport: route.protocol(),
            addr: route.addr(),
            kind,
            metric: route.metric(),
            rt: route.rt(),
        }
    }

    pub fn route(&self) -> Route {
        Route::new_with_origin(
            self.transport,
            self.route_key.origin(),
            self.addr,
            self.metric,
            self.rt,
        )
    }

    pub fn is_p2p(&self) -> bool {
        self.kind == RouteKind::P2p
    }
}
