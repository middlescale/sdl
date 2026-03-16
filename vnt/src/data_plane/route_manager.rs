use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::channel::route_table::RouteTable;
use crate::channel::{Route, RouteKey, UseChannelType};
use crate::data_plane::route_state::RouteState;

pub struct RouteManager<'a> {
    route_table: &'a RouteTable,
}

pub enum RouteIdle {
    Timeout(Ipv4Addr, Route),
    Sleep(Duration),
    None,
}

impl<'a> RouteManager<'a> {
    pub fn new(route_table: &'a RouteTable) -> Self {
        Self { route_table }
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

    pub fn next_idle(&self, read_idle: Duration) -> RouteIdle {
        let mut max = Duration::from_secs(0);
        let read_guard = self.route_table.route_table.read();
        if read_guard.is_empty() {
            return RouteIdle::None;
        }
        for (ip, routes) in read_guard.iter() {
            for (route, time) in routes {
                let last_read = time.load().elapsed();
                if last_read >= read_idle {
                    return RouteIdle::Timeout(*ip, *route);
                } else if max < last_read {
                    max = last_read;
                }
            }
        }
        let sleep_time = read_idle.checked_sub(max).unwrap_or_default();
        RouteIdle::Sleep(sleep_time)
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
