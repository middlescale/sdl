use fnv::{FnvHashMap, FnvHashSet};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Instant;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;

use crate::data_plane::route::{Route, RouteKey};
use crate::data_plane::use_channel_type::UseChannelType;

type RouteLiveness = AtomicCell<Instant>;
type RouteMap = FnvHashMap<Ipv4Addr, Vec<(Route, RouteLiveness)>>;

pub struct RouteTable {
    pub(crate) route_table: RwLock<RouteMap>,
    direct_route_keys: RwLock<FnvHashSet<RouteKey>>,
    pub(crate) latency_first: bool,
    pub(crate) use_channel_type: AtomicCell<UseChannelType>,
}

impl RouteTable {
    pub(crate) fn new(use_channel_type: UseChannelType, latency_first: bool) -> Self {
        Self {
            route_table: RwLock::new(FnvHashMap::with_capacity_and_hasher(64, Default::default())),
            direct_route_keys: RwLock::new(FnvHashSet::with_capacity_and_hasher(
                64,
                Default::default(),
            )),
            use_channel_type: AtomicCell::new(use_channel_type),
            latency_first,
        }
    }

    pub fn use_channel_type(&self) -> UseChannelType {
        self.use_channel_type.load()
    }

    pub fn set_use_channel_type(&self, use_channel_type: UseChannelType) {
        self.use_channel_type.store(use_channel_type);
        let mut route_table = self.route_table.write();
        for routes in route_table.values_mut() {
            routes.retain(|(route, _)| match use_channel_type {
                UseChannelType::Relay => !route.is_p2p(),
                UseChannelType::P2p => route.is_p2p(),
                UseChannelType::All => true,
            });
        }
        route_table.retain(|_, routes| !routes.is_empty());
        Self::rebuild_direct_route_keys(&route_table, &mut self.direct_route_keys.write());
    }

    pub fn add_route_if_absent(&self, vip: Ipv4Addr, route: Route) {
        self.add_route_(vip, route, true)
    }

    pub fn add_route(&self, vip: Ipv4Addr, route: Route) {
        self.add_route_(vip, route, false)
    }

    fn add_route_(&self, vip: Ipv4Addr, route: Route, only_if_absent: bool) {
        match self.use_channel_type() {
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
        Self::rebuild_direct_route_keys(&route_table, &mut self.direct_route_keys.write());
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

    pub fn has_direct_route_key(&self, route_key: &RouteKey) -> bool {
        self.direct_route_keys.read().contains(route_key)
    }

    pub fn no_need_punch(&self, vip: &Ipv4Addr) -> bool {
        self.route_table
            .read()
            .get(vip)
            .map(|v| v.iter().any(|(k, _)| k.is_p2p()))
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
        Self::rebuild_direct_route_keys(&write_guard, &mut self.direct_route_keys.write());
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

    pub fn clear_peer(&self, vip: &Ipv4Addr) {
        let mut route_table = self.route_table.write();
        route_table.remove(vip);
        Self::rebuild_direct_route_keys(&route_table, &mut self.direct_route_keys.write());
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        let mut route_table = self.route_table.write();
        route_table.retain(|vip, _| valid_peers.contains(vip));
        Self::rebuild_direct_route_keys(&route_table, &mut self.direct_route_keys.write());
    }

    fn rebuild_direct_route_keys(
        route_table: &RouteMap,
        direct_route_keys: &mut FnvHashSet<RouteKey>,
    ) {
        direct_route_keys.clear();
        for routes in route_table.values() {
            for (route, _) in routes {
                if route.is_p2p() {
                    direct_route_keys.insert(route.route_key());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RouteTable;
    use crate::data_plane::route::{Route, RouteKey};
    use crate::data_plane::use_channel_type::UseChannelType;
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn route_key(port: u16) -> RouteKey {
        RouteKey::new(
            ConnectProtocol::UDP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)),
        )
    }

    #[test]
    fn relay_mode_rejects_direct_routes() {
        let table = RouteTable::new(UseChannelType::Relay, false);
        let vip = Ipv4Addr::new(10, 0, 0, 2);
        table.add_route(vip, Route::from_default_rt(route_key(1000), 1));
        assert!(table.get_first_route(&vip).is_none());
    }

    #[test]
    fn p2p_mode_rejects_relay_routes() {
        let table = RouteTable::new(UseChannelType::P2p, false);
        let vip = Ipv4Addr::new(10, 0, 0, 3);
        table.add_route(vip, Route::from_default_rt(route_key(1001), 2));
        assert!(table.get_first_route(&vip).is_none());
    }

    #[test]
    fn direct_routes_replace_relay_routes_when_not_latency_first() {
        let table = RouteTable::new(UseChannelType::All, false);
        let vip = Ipv4Addr::new(10, 0, 0, 4);
        table.add_route(vip, Route::from_default_rt(route_key(1002), 2));
        table.add_route(vip, Route::from_default_rt(route_key(1003), 1));

        let routes = table.get_routes(&vip).unwrap();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].is_p2p());
    }

    #[test]
    fn retain_peers_drops_stale_routes() {
        let table = RouteTable::new(UseChannelType::All, false);
        let vip1 = Ipv4Addr::new(10, 0, 0, 4);
        let vip2 = Ipv4Addr::new(10, 0, 0, 5);
        table.add_route(vip1, Route::from_default_rt(route_key(1002), 2));
        table.add_route(vip2, Route::from_default_rt(route_key(1003), 2));

        table.retain_peers(&HashSet::from([vip2]));

        assert!(table.get_first_route(&vip1).is_none());
        assert!(table.get_first_route(&vip2).is_some());
    }

    #[test]
    fn direct_route_key_index_tracks_route_lifecycle() {
        let table = RouteTable::new(UseChannelType::All, false);
        let vip = Ipv4Addr::new(10, 0, 0, 6);
        let direct = route_key(1006);
        let relay = RouteKey::new(
            ConnectProtocol::TCP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 2006)),
        );

        table.add_route(vip, Route::from_default_rt(direct, 1));
        table.add_route(vip, Route::from_default_rt(relay, 2));
        assert!(table.has_direct_route_key(&direct));
        assert!(!table.has_direct_route_key(&relay));

        table.set_use_channel_type(UseChannelType::Relay);
        assert!(!table.has_direct_route_key(&direct));

        table.set_use_channel_type(UseChannelType::All);
        table.add_route(vip, Route::from_default_rt(direct, 1));
        assert!(table.has_direct_route_key(&direct));

        table.remove_route(&vip, direct);
        assert!(!table.has_direct_route_key(&direct));
    }
}
