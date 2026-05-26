use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Weak};

use serde_json::Value;

use crate::core::SdlRuntime;
use crate::data_plane::route::{Route, RouteKey};
use crate::data_plane::route_state::RouteKind;
use crate::data_plane::use_channel_type::UseChannelType;

#[derive(Clone)]
pub struct DataChannel {
    runtime: Weak<SdlRuntime>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum DataPath {
    P2pUdp(RouteKey),
    GatewayRelay,
}

impl DataChannel {
    pub fn new(runtime: Weak<SdlRuntime>) -> Self {
        Self { runtime }
    }

    pub fn direct_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        let runtime = self.runtime.upgrade()?;
        if let Some(peer) = runtime.peer_state.lock().devices.get(vip) {
            if peer.preferred_channel_mode == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY {
                return None;
            }
        }
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
    ) -> io::Result<RouteKind> {
        let runtime = self.runtime()?;
        match self.select_path(runtime.as_ref(), vip) {
            Some(DataPath::P2pUdp(route_key)) => match self.send_udp(runtime.as_ref(), buf, route_key) {
                Ok(()) => Ok(RouteKind::P2p),
                Err(err) => {
                    runtime.route_manager().mark_path_failed(vip, route_key);
                    if self.allows_gateway_relay() {
                        log::warn!(
                            "p2p send failed for {}, removed route {:?}, falling back to relay: {:?}",
                            vip,
                            route_key,
                            err
                        );
                        runtime.gateway_sessions.send_relay(buf)?;
                        Ok(RouteKind::GatewayRelay)
                    } else {
                        log::warn!(
                            "p2p send failed for {}, removed route {:?}, relay fallback unavailable: {:?}",
                            vip,
                            route_key,
                            err
                        );
                        Err(err)
                    }
                }
            },
            Some(DataPath::GatewayRelay) => {
                runtime.gateway_sessions.send_relay(buf)?;
                Ok(RouteKind::GatewayRelay)
            }
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

    pub fn record_peer_up_traffic(&self, vip: Ipv4Addr, len: usize) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.data_plane_stats.record_peer_up(vip, len);
        }
    }

    pub fn record_peer_down_traffic(&self, vip: Ipv4Addr, len: usize) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.data_plane_stats.record_peer_down(vip, len);
        }
    }

    pub fn record_logical_up_traffic(&self, len: usize) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.data_plane_stats.record_logical_up(len);
        }
    }

    pub fn record_logical_down_traffic(&self, len: usize) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.data_plane_stats.record_logical_down(len);
        }
    }

    pub fn record_gateway_up_traffic(&self, len: usize) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.data_plane_stats.record_gateway_up(len);
        }
    }

    pub fn record_gateway_down_traffic(&self, len: usize) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.data_plane_stats.record_gateway_down(len);
        }
    }

    fn select_path(&self, runtime: &SdlRuntime, vip: &Ipv4Addr) -> Option<DataPath> {
        let use_channel_type = {
            if let Some(peer) = runtime.peer_state.lock().devices.get(vip) {
                if peer.preferred_channel_mode == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY {
                    UseChannelType::Relay
                } else {
                    runtime.route_manager().use_channel_type()
                }
            } else {
                runtime.route_manager().use_channel_type()
            }
        };
        select_data_path(
            use_channel_type,
            runtime.route_manager().direct_route(vip),
        )
    }

    fn send_udp<B: AsRef<[u8]>>(
        &self,
        runtime: &SdlRuntime,
        buf: &crate::protocol::NetPacket<B>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        runtime.udp_channel.send_by_key(buf.buffer(), route_key)
    }

    pub(crate) fn runtime(&self) -> io::Result<Arc<SdlRuntime>> {
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
