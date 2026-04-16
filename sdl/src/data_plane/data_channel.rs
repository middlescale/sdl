use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Weak};

use serde_json::Value;

use crate::core::SdlRuntime;
use crate::data_plane::route::{Route, RoutePath};
use crate::util::PeerSessionTransport;

#[derive(Clone)]
pub struct DataChannel {
    runtime: Weak<SdlRuntime>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum DataPath {
    P2pUdp(RoutePath),
    GatewayRelay,
}

impl DataChannel {
    pub fn new(runtime: Weak<SdlRuntime>) -> Self {
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

    pub fn allows_gateway_relay(&self) -> bool {
        self.runtime
            .upgrade()
            .map(|runtime| !runtime.route_manager().use_channel_type().is_only_p2p())
            .unwrap_or(false)
    }

    pub fn is_dns_service_ip(&self, vip: &Ipv4Addr) -> bool {
        self.runtime
            .upgrade()
            .map(|runtime| runtime.is_dns_service_ip(*vip))
            .unwrap_or(false)
    }

    pub fn send_to_peer<B: AsRef<[u8]>>(
        &self,
        buf: &crate::protocol::NetPacket<B>,
        vip: &Ipv4Addr,
    ) -> io::Result<()> {
        self.send_to_peer_with_context(buf, vip, false)
    }

    pub fn send_to_peer_during_recovery<B: AsRef<[u8]>>(
        &self,
        buf: &crate::protocol::NetPacket<B>,
        vip: &Ipv4Addr,
    ) -> io::Result<()> {
        self.send_to_peer_with_context(buf, vip, true)
    }

    fn send_to_peer_with_context<B: AsRef<[u8]>>(
        &self,
        buf: &crate::protocol::NetPacket<B>,
        vip: &Ipv4Addr,
        allow_recovering: bool,
    ) -> io::Result<()> {
        let runtime = self.runtime()?;
        match self.select_path(runtime.as_ref(), vip, allow_recovering) {
            Some(DataPath::P2pUdp(route_key)) => self.send_udp(runtime.as_ref(), buf, route_key),
            Some(DataPath::GatewayRelay) => runtime.gateway_sessions.send_relay(buf),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("peer session not ready: {}", vip),
            )),
        }
    }

    pub fn send_p2p_route<B: AsRef<[u8]>>(
        &self,
        buf: &crate::protocol::NetPacket<B>,
        route: Route,
    ) -> io::Result<()> {
        let runtime = self.runtime()?;
        self.send_udp(runtime.as_ref(), buf, route.route_path())
    }

    pub fn proxy_dns_query(
        &self,
        client_ip: Ipv4Addr,
        dns_server_ip: Ipv4Addr,
        client_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        let runtime = self.runtime()?;
        let request_id = runtime.remember_dns_query(client_ip, dns_server_ip, client_port);
        let query_payload =
            match crate::util::dns_tunnel::build_dns_query_payload(request_id, payload) {
                Ok(payload) => payload,
                Err(err) => {
                    runtime.forget_dns_query(request_id);
                    return Err(err);
                }
            };
        if let Err(err) = runtime.control_session.send_service_payload(
            crate::protocol::service_packet::Protocol::DnsQueryRequest,
            &query_payload,
        ) {
            runtime.forget_dns_query(request_id);
            return Err(io::Error::other(err));
        }
        Ok(())
    }

    pub fn emit_debug_watch_event(&self, section: &str, event_type: &str, payload: Value) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.debug_watch.emit(section, event_type, payload);
        }
    }

    fn select_path(
        &self,
        runtime: &SdlRuntime,
        vip: &Ipv4Addr,
        allow_recovering: bool,
    ) -> Option<DataPath> {
        let direct_route = runtime.route_manager().direct_route(vip);
        let transport = runtime.peer_sessions.preferred_transport(
            vip,
            runtime.route_manager().use_channel_type(),
            direct_route,
            allow_recovering,
        )?;
        match transport {
            PeerSessionTransport::Direct => {
                direct_route.map(|route| DataPath::P2pUdp(route.route_path()))
            }
            PeerSessionTransport::Relay => Some(DataPath::GatewayRelay),
        }
    }

    fn send_udp<B: AsRef<[u8]>>(
        &self,
        runtime: &SdlRuntime,
        buf: &crate::protocol::NetPacket<B>,
        route_key: RoutePath,
    ) -> io::Result<()> {
        runtime.udp_channel.send_to_path(buf.buffer(), route_key)
    }

    fn runtime(&self) -> io::Result<Arc<SdlRuntime>> {
        self.runtime.upgrade().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "data channel runtime dropped")
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::DataPath;
    use crate::data_plane::route::{Route, RouteOrigin};
    use crate::transport::connect_protocol::ConnectProtocol;

    fn sample_route() -> Route {
        Route::new_with_origin(
            ConnectProtocol::UDP,
            RouteOrigin::PeerUdp,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 3000)),
            1,
            10,
        )
    }

    #[test]
    fn data_path_wraps_direct_route() {
        let route = sample_route();
        let path = DataPath::P2pUdp(route.route_path());
        assert_eq!(path, DataPath::P2pUdp(route.route_path()));
    }
}
