use fnv::FnvHashMap;
use std::io;
use std::net::Ipv4Addr;
use std::time::Instant;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;

use crate::channel::{Route, RouteKey, UseChannelType, DEFAULT_RT};

type RouteLiveness = AtomicCell<Instant>;
type RouteMap = FnvHashMap<Ipv4Addr, Vec<(Route, RouteLiveness)>>;

pub struct RouteTable {
    pub(crate) route_table: RwLock<RouteMap>,
    pub(crate) latency_first: bool,
    pub(crate) channel_num: usize,
    pub(crate) use_channel_type: UseChannelType,
}

impl RouteTable {
    pub(crate) fn new(
        use_channel_type: UseChannelType,
        latency_first: bool,
        channel_num: usize,
    ) -> Self {
        Self {
            route_table: RwLock::new(FnvHashMap::with_capacity_and_hasher(64, Default::default())),
            use_channel_type,
            latency_first,
            channel_num,
        }
    }

    pub(crate) fn get_route(&self, index: usize, vip: &Ipv4Addr) -> io::Result<Route> {
        if let Some(v) = self.route_table.read().get(vip) {
            if self.latency_first {
                if let Some((route, _)) = v.first() {
                    return Ok(*route);
                }
            } else {
                let len = v.len();
                if len != 0 {
                    let route = &v[index % len].0;
                    if route.rt != DEFAULT_RT {
                        return Ok(*route);
                    }
                    for (route, _) in v {
                        if route.rt != DEFAULT_RT {
                            return Ok(*route);
                        }
                    }
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "route not found"))
    }

    pub fn add_route_if_absent(&self, vip: Ipv4Addr, route: Route) {
        self.add_route_(vip, route, true)
    }

    pub fn add_route(&self, vip: Ipv4Addr, route: Route) {
        self.add_route_(vip, route, false)
    }

    fn add_route_(&self, vip: Ipv4Addr, route: Route, only_if_absent: bool) {
        match self.use_channel_type {
            UseChannelType::Relay if route.is_p2p() => return,
            UseChannelType::P2p if !route.is_p2p() => return,
            UseChannelType::Relay | UseChannelType::P2p | UseChannelType::All => {}
        }
        let key = route.route_key();
        if only_if_absent {
            if let Some(list) = self.route_table.read().get(&vip) {
                for (x, _) in list {
                    if x.route_key() == key {
                        return;
                    }
                }
            }
        }
        let mut route_table = self.route_table.write();
        let list = route_table
            .entry(vip)
            .or_insert_with(|| Vec::with_capacity(4));
        let mut exist = false;
        for (x, time) in list.iter_mut() {
            if x.metric < route.metric && !self.latency_first {
                return;
            }
            if x.route_key() == key {
                if only_if_absent {
                    return;
                }
                x.metric = route.metric;
                x.rt = route.rt;
                exist = true;
                time.store(Instant::now());
                break;
            }
        }
        if exist {
            list.sort_by_key(|(k, _)| k.rt);
        } else {
            if !self.latency_first && route.is_p2p() {
                list.retain(|(k, _)| k.is_p2p());
            }
            list.sort_by_key(|(k, _)| k.rt);
            list.push((route, AtomicCell::new(Instant::now())));
        }
    }

    pub fn get_routes(&self, vip: &Ipv4Addr) -> Option<Vec<Route>> {
        self.route_table
            .read()
            .get(vip)
            .map(|v| v.iter().map(|(i, _)| *i).collect())
    }

    pub fn get_first_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table
            .read()
            .get(vip)
            .and_then(|v| v.first().map(|(i, _)| *i))
    }

    pub fn get_one_p2p_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table
            .read()
            .get(vip)
            .and_then(|v| v.iter().find_map(|(i, _)| i.is_p2p().then_some(*i)))
    }

    pub fn get_one_p2p_ip(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        let table = self.route_table.read();
        for (k, v) in table.iter() {
            for (route, _) in v {
                if &route.route_key() == route_key && route.is_p2p() {
                    return Some(*k);
                }
            }
        }
        None
    }

    pub fn no_need_punch(&self, vip: &Ipv4Addr) -> bool {
        self.route_table
            .read()
            .get(vip)
            .map(|v| v.iter().filter(|(k, _)| k.is_p2p()).count() >= self.channel_num)
            .unwrap_or(false)
    }

    pub fn p2p_num(&self, vip: &Ipv4Addr) -> usize {
        self.route_table
            .read()
            .get(vip)
            .map(|v| v.iter().filter(|(k, _)| k.is_p2p()).count())
            .unwrap_or(0)
    }

    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.route_table
            .read()
            .iter()
            .map(|(k, v)| (*k, v.iter().map(|(i, _)| *i).collect()))
            .collect()
    }

    pub fn route_table_one_p2p(&self) -> Vec<(Ipv4Addr, Route)> {
        let table = self.route_table.read();
        let mut list = Vec::with_capacity(8);
        for (ip, routes) in table.iter() {
            for (route, _) in routes.iter() {
                if route.is_p2p() {
                    list.push((*ip, *route));
                    break;
                }
            }
        }
        list
    }

    pub fn route_table_one(&self) -> Vec<(Ipv4Addr, Route)> {
        self.route_table
            .read()
            .iter()
            .filter_map(|(k, v)| v.first().map(|(route, _)| (*k, *route)))
            .collect()
    }

    pub fn remove_route(&self, vip: &Ipv4Addr, route_key: RouteKey) {
        let mut write_guard = self.route_table.write();
        if let Some(routes) = write_guard.get_mut(vip) {
            routes.retain(|(x, _)| x.route_key() != route_key);
            if routes.is_empty() {
                write_guard.remove(vip);
            }
        }
    }

    pub fn update_read_time(&self, vip: &Ipv4Addr, route_key: &RouteKey) {
        if let Some(routes) = self.route_table.read().get(vip) {
            for (route, time) in routes {
                if &route.route_key() == route_key {
                    time.store(Instant::now());
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RouteTable;
    use crate::channel::{ConnectProtocol, Route, RouteKey, UseChannelType};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn route_key(port: u16) -> RouteKey {
        RouteKey::new(
            ConnectProtocol::UDP,
            0,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)),
        )
    }

    #[test]
    fn relay_mode_rejects_direct_routes() {
        let table = RouteTable::new(UseChannelType::Relay, false, 1);
        let vip = Ipv4Addr::new(10, 0, 0, 2);
        table.add_route(vip, Route::from_default_rt(route_key(1000), 1));
        assert!(table.get_first_route(&vip).is_none());
    }

    #[test]
    fn p2p_mode_rejects_relay_routes() {
        let table = RouteTable::new(UseChannelType::P2p, false, 1);
        let vip = Ipv4Addr::new(10, 0, 0, 3);
        table.add_route(vip, Route::from_default_rt(route_key(1001), 2));
        assert!(table.get_first_route(&vip).is_none());
    }

    #[test]
    fn direct_routes_replace_relay_routes_when_not_latency_first() {
        let table = RouteTable::new(UseChannelType::All, false, 1);
        let vip = Ipv4Addr::new(10, 0, 0, 4);
        table.add_route(vip, Route::from_default_rt(route_key(1002), 2));
        table.add_route(vip, Route::from_default_rt(route_key(1003), 1));

        let routes = table.get_routes(&vip).unwrap();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].is_p2p());
    }
}
