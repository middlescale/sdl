use std::net::SocketAddr;
use std::str::FromStr;

pub mod notify;
pub mod punch;
pub mod punch_workers;

pub const BUFFER_SIZE: usize = 1024 * 64;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum UseChannelType {
    Relay,
    P2p,
    All,
}

impl UseChannelType {
    pub fn is_only_relay(&self) -> bool {
        self == &UseChannelType::Relay
    }
    pub fn is_only_p2p(&self) -> bool {
        self == &UseChannelType::P2p
    }
    pub fn is_all(&self) -> bool {
        self == &UseChannelType::All
    }
}

impl FromStr for UseChannelType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "relay" => Ok(UseChannelType::Relay),
            "p2p" => Ok(UseChannelType::P2p),
            "all" => Ok(UseChannelType::All),
            _ => Err(format!("not match '{}', enum: relay/p2p/all", s)),
        }
    }
}

impl Default for UseChannelType {
    fn default() -> Self {
        UseChannelType::All
    }
}

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

#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub protocol: ConnectProtocol,
    index: usize,
    pub addr: SocketAddr,
    pub metric: u8,
    pub rt: i64,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteSortKey {
    pub metric: u8,
    pub rt: i64,
}

pub(crate) const DEFAULT_RT: i64 = 9999;

impl Route {
    pub fn new(
        protocol: ConnectProtocol,
        index: usize,
        addr: SocketAddr,
        metric: u8,
        rt: i64,
    ) -> Self {
        Self {
            protocol,
            index,
            addr,
            metric,
            rt,
        }
    }
    pub fn from(route_key: RouteKey, metric: u8, rt: i64) -> Self {
        Self {
            protocol: route_key.protocol,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt,
        }
    }
    pub fn from_default_rt(route_key: RouteKey, metric: u8) -> Self {
        Self {
            protocol: route_key.protocol,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt: DEFAULT_RT,
        }
    }
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            protocol: self.protocol,
            index: self.index,
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
    index: usize,
    pub addr: SocketAddr,
}

impl RouteKey {
    pub(crate) const fn new(protocol: ConnectProtocol, index: usize, addr: SocketAddr) -> Self {
        Self {
            protocol,
            index,
            addr,
        }
    }
    #[inline]
    pub fn protocol(&self) -> ConnectProtocol {
        self.protocol
    }
    #[inline]
    pub fn index(&self) -> usize {
        self.index
    }
}
