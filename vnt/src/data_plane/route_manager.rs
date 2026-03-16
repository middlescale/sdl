use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::channel::context::ChannelContext;
use crate::channel::{Route, RouteKey, UseChannelType};
use crate::cipher::Cipher;
use crate::data_plane::route_state::RouteState;
use crate::data_plane::route_table::RouteTable;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{NetPacket, Protocol};
use crate::util::StopManager;
use crossbeam_utils::atomic::AtomicCell;

const ROUTE_MAINTENANCE_START_DELAY: Duration = Duration::from_secs(3);
const ROUTE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct RouteManager {
    route_table: Arc<RouteTable>,
}

pub enum StaleDirectRoute {
    Timeout(Ipv4Addr, Route),
    Sleep(Duration),
    None,
}

pub struct StaleDirectRouteCleanup {
    pub delay: Duration,
}

impl RouteManager {
    pub fn new(route_table: Arc<RouteTable>) -> Self {
        Self { route_table }
    }

    pub fn start_maintenance(
        &self,
        stop_manager: StopManager,
        context: ChannelContext,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        client_cipher: Cipher,
    ) -> anyhow::Result<()> {
        self.start_heartbeat_loop(
            stop_manager.clone(),
            context.clone(),
            current_device.clone(),
            client_cipher,
        )?;
        self.start_stale_direct_route_cleanup_loop(stop_manager)
    }

    pub fn use_channel_type(&self) -> UseChannelType {
        self.route_table.use_channel_type
    }

    pub fn latency_first(&self) -> bool {
        self.route_table.latency_first
    }

    pub fn select_route(&self, index: usize, vip: &Ipv4Addr) -> io::Result<Route> {
        self.route_table.get_route(index, vip)
    }

    pub fn add_path_if_absent(&self, vip: Ipv4Addr, route: Route) {
        self.route_table.add_route_if_absent(vip, route)
    }

    pub fn add_path(&self, vip: Ipv4Addr, route: Route) {
        self.route_table.add_route(vip, route)
    }

    pub fn best_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table.get_first_route(vip)
    }

    pub fn direct_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table.get_one_p2p_route(vip)
    }

    pub fn peer_for_direct_route(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        self.route_table.get_one_p2p_ip(route_key)
    }

    pub fn direct_path_count(&self, vip: &Ipv4Addr) -> usize {
        self.route_table.p2p_num(vip)
    }

    pub fn has_enough_direct_paths(&self, vip: &Ipv4Addr) -> bool {
        self.route_table.no_need_punch(vip)
    }

    pub fn snapshot_routes(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.route_table.route_table()
    }

    pub fn snapshot_direct_routes(&self) -> Vec<(Ipv4Addr, Route)> {
        self.route_table.route_table_one_p2p()
    }

    pub fn has_any_route(&self, vip: &Ipv4Addr) -> bool {
        self.best_route(vip).is_some()
    }

    pub fn heartbeat_targets(&self, channel_num: usize) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.snapshot_routes()
            .into_iter()
            .filter_map(|(peer_ip, routes)| {
                let routes = self.limit_heartbeat_routes(routes, channel_num);
                if routes.is_empty() {
                    None
                } else {
                    Some((peer_ip, routes))
                }
            })
            .collect()
    }

    pub fn missing_route_peers<'b, I>(&self, peers: I) -> Vec<Ipv4Addr>
    where
        I: IntoIterator<Item = &'b Ipv4Addr>,
    {
        peers
            .into_iter()
            .filter(|peer_ip| !self.has_any_route(peer_ip))
            .copied()
            .collect()
    }

    pub fn snapshot_route_states(
        &self,
        virtual_gateway: Ipv4Addr,
    ) -> Vec<(Ipv4Addr, Vec<RouteState>)> {
        self.route_table
            .route_table()
            .into_iter()
            .map(|(peer_ip, routes)| {
                let states = routes
                    .into_iter()
                    .map(|route| RouteState::from_route(peer_ip, route, virtual_gateway))
                    .collect();
                (peer_ip, states)
            })
            .collect()
    }

    pub fn remove_path(&self, vip: &Ipv4Addr, route_key: RouteKey) {
        self.route_table.remove_route(vip, route_key)
    }

    pub fn touch_path(&self, vip: &Ipv4Addr, route_key: &RouteKey) {
        self.route_table.update_read_time(vip, route_key)
    }

    pub fn next_stale_direct_route(&self, read_idle: Duration) -> StaleDirectRoute {
        let mut max = Duration::from_secs(0);
        let read_guard = self.route_table.route_table.read();
        let mut has_p2p = false;
        for (ip, routes) in read_guard.iter() {
            for (route, time) in routes {
                if !route.is_p2p() {
                    continue;
                }
                has_p2p = true;
                let last_read = time.load().elapsed();
                if last_read >= read_idle {
                    return StaleDirectRoute::Timeout(*ip, *route);
                } else if max < last_read {
                    max = last_read;
                }
            }
        }
        if !has_p2p {
            return StaleDirectRoute::None;
        }
        let sleep_time = read_idle.checked_sub(max).unwrap_or_default();
        StaleDirectRoute::Sleep(sleep_time)
    }

    pub fn send_heartbeats(
        &self,
        context: &ChannelContext,
        current_device: CurrentDeviceInfo,
        client_cipher: &Cipher,
    ) {
        let channel_num = context.channel_num();
        let src_ip = current_device.virtual_ip;
        for (dest_ip, routes) in self.heartbeat_targets(channel_num) {
            if current_device.is_gateway_vip(&dest_ip) {
                continue;
            }
            let net_packet = match heartbeat_packet_client(client_cipher, src_ip, dest_ip) {
                Ok(net_packet) => net_packet,
                Err(e) => {
                    log::error!("heartbeat_packet err={:?}", e);
                    continue;
                }
            };
            for route in &routes {
                if let Err(e) = context.send_by_key(&net_packet, route.route_key()) {
                    log::warn!("heartbeat err={:?}", e)
                }
            }
        }
    }

    pub fn cleanup_stale_direct_routes(&self, read_idle: Duration) -> StaleDirectRouteCleanup {
        match self.next_stale_direct_route(read_idle) {
            StaleDirectRoute::Timeout(ip, route) => {
                log::info!("route Timeout {:?},{:?}", ip, route);
                self.remove_path(&ip, route.route_key());
                StaleDirectRouteCleanup {
                    delay: Duration::from_millis(100),
                }
            }
            StaleDirectRoute::Sleep(duration) => StaleDirectRouteCleanup { delay: duration },
            StaleDirectRoute::None => StaleDirectRouteCleanup {
                delay: Duration::from_millis(3000),
            },
        }
    }

    fn limit_heartbeat_routes(&self, routes: Vec<Route>, channel_num: usize) -> Vec<Route> {
        let limit = if self.latency_first() {
            channel_num + 1
        } else {
            channel_num
        };
        routes.into_iter().take(limit).collect()
    }
}

impl RouteManager {
    fn start_heartbeat_loop(
        &self,
        stop_manager: StopManager,
        context: ChannelContext,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        client_cipher: Cipher,
    ) -> anyhow::Result<()> {
        let route_manager = self.clone();
        thread::Builder::new()
            .name("routeHeartbeat".into())
            .spawn(move || {
                let current = thread::current();
                let worker = match stop_manager.add_listener("routeHeartbeat".into(), move || {
                    current.unpark();
                }) {
                    Ok(worker) => worker,
                    Err(e) => {
                        log::error!("{:?}", e);
                        return;
                    }
                };
                if wait_for_stop(&stop_manager, ROUTE_MAINTENANCE_START_DELAY) {
                    worker.stop_all();
                    return;
                }
                while !stop_manager.is_stopped() {
                    route_manager.send_heartbeats(&context, current_device.load(), &client_cipher);
                    if wait_for_stop(&stop_manager, ROUTE_HEARTBEAT_INTERVAL) {
                        break;
                    }
                }
                worker.stop_all();
            })?;
        Ok(())
    }

    fn start_stale_direct_route_cleanup_loop(
        &self,
        stop_manager: StopManager,
    ) -> anyhow::Result<()> {
        let route_manager = self.clone();
        thread::Builder::new()
            .name("routeStaleDirectCleanup".into())
            .spawn(move || {
                let current = thread::current();
                let worker =
                    match stop_manager.add_listener("routeStaleDirectCleanup".into(), move || {
                        current.unpark();
                    }) {
                        Ok(worker) => worker,
                        Err(e) => {
                            log::error!("{:?}", e);
                            return;
                        }
                    };
                if wait_for_stop(&stop_manager, ROUTE_MAINTENANCE_START_DELAY) {
                    worker.stop_all();
                    return;
                }
                while !stop_manager.is_stopped() {
                    let result = route_manager.cleanup_stale_direct_routes(Duration::from_secs(10));
                    if wait_for_stop(&stop_manager, result.delay) {
                        break;
                    }
                }
                worker.stop_all();
            })?;
        Ok(())
    }
}

fn wait_for_stop(stop_manager: &StopManager, duration: Duration) -> bool {
    if stop_manager.is_stopped() {
        return true;
    }
    thread::park_timeout(duration);
    stop_manager.is_stopped()
}

fn heartbeat_packet(src: Ipv4Addr, dest: Ipv4Addr) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = NetPacket::new(vec![0u8; 12 + 4])?;
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
    net_packet.set_initial_ttl(5);
    net_packet.set_source(src);
    net_packet.set_destination(dest);
    let mut ping = PingPacket::new(net_packet.payload_mut())?;
    ping.set_time(crate::handle::now_time() as u16);
    Ok(net_packet)
}

fn heartbeat_packet_client(
    client_cipher: &Cipher,
    src: Ipv4Addr,
    dest: Ipv4Addr,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = heartbeat_packet(src, dest)?;
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}

#[cfg(test)]
mod tests {
    use super::{RouteManager, StaleDirectRoute};
    use crate::channel::{ConnectProtocol, Route, UseChannelType};
    use crate::data_plane::route_table::RouteTable;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    fn route(metric: u8, port: u16) -> Route {
        Route::new(
            ConnectProtocol::UDP,
            0,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            metric,
            10,
        )
    }

    #[test]
    fn next_stale_direct_route_ignores_stale_relay_routes() {
        let table = Arc::new(RouteTable::new(UseChannelType::All, false, 1));
        let manager = RouteManager::new(table.clone());
        table.add_route(Ipv4Addr::new(10, 0, 0, 2), route(2, 2000));
        thread::sleep(Duration::from_millis(15));

        assert!(matches!(
            manager.next_stale_direct_route(Duration::from_millis(5)),
            StaleDirectRoute::None
        ));
    }

    #[test]
    fn next_stale_direct_route_times_out_stale_p2p_routes() {
        let table = Arc::new(RouteTable::new(UseChannelType::All, false, 1));
        let manager = RouteManager::new(table.clone());
        let peer = Ipv4Addr::new(10, 0, 0, 3);
        let route = route(1, 2001);
        table.add_route(peer, route);
        thread::sleep(Duration::from_millis(15));

        match manager.next_stale_direct_route(Duration::from_millis(5)) {
            StaleDirectRoute::Timeout(ip, timed_out) => {
                assert_eq!(ip, peer);
                assert_eq!(timed_out.route_key(), route.route_key());
            }
            other => panic!("expected timeout, got {:?}", kind_name(&other)),
        }
    }

    #[test]
    fn cleanup_stale_direct_routes_only_removes_stale_p2p_routes() {
        let table = Arc::new(RouteTable::new(UseChannelType::All, false, 1));
        let manager = RouteManager::new(table.clone());
        let relay_peer = Ipv4Addr::new(10, 0, 0, 4);
        let p2p_peer = Ipv4Addr::new(10, 0, 0, 5);
        let relay = route(2, 2002);
        let p2p = route(1, 2003);
        table.add_route(relay_peer, relay);
        table.add_route(p2p_peer, p2p);
        thread::sleep(Duration::from_millis(15));

        let _ = manager.cleanup_stale_direct_routes(Duration::from_millis(5));
        assert!(table.get_routes(&p2p_peer).is_none());
        let relay_routes = table.get_routes(&relay_peer).expect("relay routes");
        assert_eq!(relay_routes.len(), 1);
        assert_eq!(relay_routes[0].route_key(), relay.route_key());
    }

    fn kind_name(idle: &StaleDirectRoute) -> &'static str {
        match idle {
            StaleDirectRoute::Timeout(_, _) => "timeout",
            StaleDirectRoute::Sleep(_) => "sleep",
            StaleDirectRoute::None => "none",
        }
    }
}
