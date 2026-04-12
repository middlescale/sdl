use std::net::Ipv4Addr;

use crate::data_plane::route::Route;

#[derive(Copy, Clone, Debug)]
pub struct RouteSnapshot {
    peer_ip: Ipv4Addr,
    route: Route,
}

impl RouteSnapshot {
    pub fn new(peer_ip: Ipv4Addr, route: Route) -> Self {
        Self { peer_ip, route }
    }

    pub fn is_p2p(&self) -> bool {
        self.route.is_p2p()
    }

    pub fn peer_ip(&self) -> Ipv4Addr {
        self.peer_ip
    }

    pub fn route(&self) -> Route {
        self.route
    }
}
