use std::net::SocketAddr;

use crate::transport::connect_protocol::ConnectProtocol;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum RouteOrigin {
    PeerUdp,
    ControlHttp3,
    GatewayQuic,
    GatewayUdp,
}

#[derive(Copy, Clone, Debug)]
pub struct Route {
    protocol: ConnectProtocol,
    origin: RouteOrigin,
    addr: SocketAddr,
    metric: u8,
    rt: i64,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteSortKey {
    pub(crate) metric: u8,
    pub rt: i64,
}

pub(crate) const DEFAULT_RT: i64 = 9999;

impl Route {
    pub fn new_with_origin(
        protocol: ConnectProtocol,
        origin: RouteOrigin,
        addr: SocketAddr,
        metric: u8,
        rt: i64,
    ) -> Self {
        Self {
            protocol,
            origin,
            addr,
            metric,
            rt,
        }
    }

    pub fn from(route_key: RoutePath, metric: u8, rt: i64) -> Self {
        Self {
            protocol: route_key.protocol,
            origin: route_key.origin,
            addr: route_key.addr,
            metric,
            rt,
        }
    }

    pub fn from_default_rt(route_key: RoutePath, metric: u8) -> Self {
        Self {
            protocol: route_key.protocol,
            origin: route_key.origin,
            addr: route_key.addr,
            metric,
            rt: DEFAULT_RT,
        }
    }

    pub fn route_path(&self) -> RoutePath {
        RoutePath {
            protocol: self.protocol,
            origin: self.origin,
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

    pub fn is_udp(&self) -> bool {
        self.protocol.is_udp()
    }

    pub fn protocol(&self) -> ConnectProtocol {
        self.protocol
    }

    pub fn origin(&self) -> RouteOrigin {
        self.origin
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn metric(&self) -> u8 {
        self.metric
    }

    pub fn rt(&self) -> i64 {
        self.rt
    }

    /// Returns a short name for the transport protocol (e.g. "Udp", "Tcp", "Quic").
    pub fn protocol_name(&self) -> String {
        format!("{:?}", self.protocol)
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RoutePath {
    protocol: ConnectProtocol,
    origin: RouteOrigin,
    addr: SocketAddr,
}

impl RoutePath {
    pub(crate) const fn new_with_origin(
        protocol: ConnectProtocol,
        origin: RouteOrigin,
        addr: SocketAddr,
    ) -> Self {
        Self {
            protocol,
            origin,
            addr,
        }
    }

    #[inline]
    pub fn protocol(&self) -> ConnectProtocol {
        self.protocol
    }

    #[inline]
    pub fn origin(&self) -> RouteOrigin {
        self.origin
    }

    #[inline]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[inline]
    pub fn is_trusted_server_path(&self) -> bool {
        matches!(
            self.origin,
            RouteOrigin::ControlHttp3 | RouteOrigin::GatewayQuic | RouteOrigin::GatewayUdp
        )
    }

    #[inline]
    pub fn is_gateway_path(&self) -> bool {
        matches!(
            self.origin,
            RouteOrigin::GatewayQuic | RouteOrigin::GatewayUdp
        )
    }
}
