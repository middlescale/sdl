use std::net::SocketAddr;

use crate::transport::connect_protocol::ConnectProtocol;

#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub protocol: ConnectProtocol,
    pub addr: SocketAddr,
    pub(crate) metric: u8,
    pub rt: i64,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteSortKey {
    pub(crate) metric: u8,
    pub rt: i64,
}

pub(crate) const DEFAULT_RT: i64 = 9999;

impl Route {
    pub fn new(protocol: ConnectProtocol, addr: SocketAddr, metric: u8, rt: i64) -> Self {
        Self {
            protocol,
            addr,
            metric,
            rt,
        }
    }

    pub fn from(route_key: RouteKey, metric: u8, rt: i64) -> Self {
        Self {
            protocol: route_key.protocol,
            addr: route_key.addr,
            metric,
            rt,
        }
    }

    pub fn from_default_rt(route_key: RouteKey, metric: u8) -> Self {
        Self {
            protocol: route_key.protocol,
            addr: route_key.addr,
            metric,
            rt: DEFAULT_RT,
        }
    }

    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            protocol: self.protocol,
            addr: self.addr,
        }
    }

    pub fn sort_key(&self) -> RouteSortKey {
        RouteSortKey {
            metric: self.metric,
            rt: self.rt,
        }
    }

    pub fn is_p2p(&self) -> bool {
        self.metric == 1
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    protocol: ConnectProtocol,
    pub addr: SocketAddr,
}

impl RouteKey {
    pub(crate) const fn new(protocol: ConnectProtocol, addr: SocketAddr) -> Self {
        Self { protocol, addr }
    }

    #[inline]
    pub fn protocol(&self) -> ConnectProtocol {
        self.protocol
    }
}
