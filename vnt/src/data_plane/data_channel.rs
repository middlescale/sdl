use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Weak};

use crate::channel::{Route, RouteKey, UseChannelType};
use crate::core::VntRuntime;

#[derive(Clone)]
pub struct DataChannel {
    runtime: Weak<VntRuntime>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum DataPath {
    P2pUdp(RouteKey),
    GatewayRelay,
}

impl DataChannel {
    pub fn new(runtime: Weak<VntRuntime>) -> Self {
        Self { runtime }
    }

    pub fn direct_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        let runtime = self.runtime.upgrade()?;
        if runtime.route_manager().use_channel_type().is_only_relay() {
            None
        } else {
            runtime.route_manager().direct_route(vip)
        }
    }

    pub fn send_to_peer<B: AsRef<[u8]>>(
        &self,
        buf: &crate::protocol::NetPacket<B>,
        vip: &Ipv4Addr,
    ) -> io::Result<()> {
        let runtime = self.runtime()?;
        match self.select_path(runtime.as_ref(), vip) {
            Some(DataPath::P2pUdp(route_key)) => self.send_udp(runtime.as_ref(), buf, route_key),
            Some(DataPath::GatewayRelay) => runtime.gateway_sessions.send_relay(buf),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("peer route not found: {}", vip),
            )),
        }
    }

    pub fn send_p2p_route<B: AsRef<[u8]>>(
        &self,
        buf: &crate::protocol::NetPacket<B>,
        route: Route,
    ) -> io::Result<()> {
        let runtime = self.runtime()?;
        self.send_udp(runtime.as_ref(), buf, route.route_key())
    }

    fn select_path(&self, runtime: &VntRuntime, vip: &Ipv4Addr) -> Option<DataPath> {
        select_data_path(
            runtime.route_manager().use_channel_type(),
            runtime.route_manager().direct_route(vip),
        )
    }

    fn send_udp<B: AsRef<[u8]>>(
        &self,
        runtime: &VntRuntime,
        buf: &crate::protocol::NetPacket<B>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        runtime.udp_channel.send_by_key(buf.buffer(), route_key)
    }

    fn runtime(&self) -> io::Result<Arc<VntRuntime>> {
        self.runtime.upgrade().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "data channel runtime dropped")
        })
    }
}

fn select_data_path(
    use_channel_type: UseChannelType,
    direct_route: Option<Route>,
) -> Option<DataPath> {
    match use_channel_type {
        UseChannelType::Relay => Some(DataPath::GatewayRelay),
        UseChannelType::P2p => direct_route.map(|route| DataPath::P2pUdp(route.route_key())),
        UseChannelType::All => direct_route
            .map(|route| DataPath::P2pUdp(route.route_key()))
            .or(Some(DataPath::GatewayRelay)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::{select_data_path, DataPath};
    use crate::channel::{ConnectProtocol, Route, UseChannelType};

    fn sample_route() -> Route {
        Route::new(
            ConnectProtocol::UDP,
            0,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 3000)),
            1,
            10,
        )
    }

    #[test]
    fn select_data_path_prefers_direct_udp_when_available() {
        let route = sample_route();
        let path = select_data_path(UseChannelType::All, Some(route));
        assert_eq!(path, Some(DataPath::P2pUdp(route.route_key())));
    }

    #[test]
    fn select_data_path_falls_back_to_relay_for_all_mode() {
        let path = select_data_path(UseChannelType::All, None);
        assert_eq!(path, Some(DataPath::GatewayRelay));
    }

    #[test]
    fn select_data_path_requires_direct_route_for_p2p_only_mode() {
        let path = select_data_path(UseChannelType::P2p, None);
        assert_eq!(path, None);
    }
}
