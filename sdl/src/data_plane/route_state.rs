use std::net::Ipv4Addr;

use crate::data_plane::route::Route;
use crate::transport::TransportEndpoint;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RouteKind {
    P2p,
    GatewayRelay,
    Relay,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteState {
    pub peer_ip: Ipv4Addr,
    pub endpoint: TransportEndpoint,
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
            endpoint: route.endpoint,
            kind,
            metric: route.metric,
            rt: route.rt,
        }
    }

    pub fn route(&self) -> Route {
        Route::new(self.endpoint, self.metric, self.rt)
    }

    pub fn is_p2p(&self) -> bool {
        self.kind == RouteKind::P2p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ConnectProtocol;

    #[test]
    fn route_state_round_trip_preserves_endpoint_and_route_metrics() {
        let peer_ip = Ipv4Addr::new(10, 26, 0, 2);
        let gateway_ip = Ipv4Addr::new(10, 26, 0, 1);
        let endpoint = TransportEndpoint::new(ConnectProtocol::UDP, ([127, 0, 0, 1], 29873).into());
        let state = RouteState::from_route(peer_ip, Route::new(endpoint, 1, 42), gateway_ip);

        assert_eq!(state.endpoint, endpoint);
        assert_eq!(state.peer_ip, peer_ip);
        assert_eq!(state.kind, RouteKind::P2p);
        let route = state.route();
        assert_eq!(route.endpoint, endpoint);
        assert_eq!(route.metric, 1);
        assert_eq!(route.rt, 42);
    }
}
