use fnv::{FnvHashMap, FnvHashSet};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;

use crate::data_plane::route::{Route, RouteKey};
use crate::data_plane::use_channel_type::UseChannelType;

type RouteLiveness = AtomicCell<Instant>;
type RouteMap = FnvHashMap<Ipv4Addr, Vec<(Route, RouteLiveness)>>;
type PeerActivityMap = FnvHashMap<Ipv4Addr, PeerActivity>;

// Payloads can be much more frequent than the idle window needs.  Updating at
// this cadence keeps a busy peer active without serialising every packet on a
// map write lock.
const PEER_ACTIVITY_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

pub struct RouteTable {
    pub(crate) route_table: RwLock<RouteMap>,
    peer_activity: RwLock<PeerActivityMap>,
    direct_route_keys: RwLock<FnvHashSet<RouteKey>>,
    pub(crate) latency_first: bool,
    pub(crate) use_channel_type: AtomicCell<UseChannelType>,
}

struct PeerActivity {
    last_payload: AtomicCell<Instant>,
    direct_recovery_requested: AtomicCell<bool>,
}

impl PeerActivity {
    fn new(now: Instant) -> Self {
        Self {
            last_payload: AtomicCell::new(now),
            direct_recovery_requested: AtomicCell::new(false),
        }
    }
}

impl RouteTable {
    pub(crate) fn new(use_channel_type: UseChannelType, latency_first: bool) -> Self {
        Self {
            route_table: RwLock::new(FnvHashMap::with_capacity_and_hasher(64, Default::default())),
            peer_activity: RwLock::new(FnvHashMap::with_capacity_and_hasher(
                64,
                Default::default(),
            )),
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
                UseChannelType::Auto => true,
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
            UseChannelType::Relay | UseChannelType::P2p | UseChannelType::Auto => {}
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
                x.loss_rate = route.loss_rate;
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
        drop(route_table);
        if route.is_p2p() {
            self.reset_direct_recovery_request(&vip);
        }
    }

    pub fn get_routes(&self, vip: &Ipv4Addr) -> Option<Vec<Route>> {
        self.route_table
            .read()
            .get(vip)
            .map(|v| v.iter().map(|(i, _)| *i).collect())
    }

    pub fn get_first_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table.read().get(vip).and_then(|routes| {
            routes
                .iter()
                // A negative RTT marks a direct route that is being
                // re-measured. It must not be used by forwarding or the
                // public route/CLI view before its Pong is received.
                .find_map(|(route, _)| (route.rt >= 0).then_some(*route))
        })
    }

    /// Like `get_first_route`, but never exposes a direct route whose
    /// liveness has already expired. This keeps forwarding and the public
    /// route view aligned with payload selection while cleanup catches up.
    pub fn get_first_live_route(&self, vip: &Ipv4Addr, stale_timeout: Duration) -> Option<Route> {
        self.route_table.read().get(vip).and_then(|routes| {
            routes.iter().find_map(|(route, liveness)| {
                (route.rt >= 0 && (!route.is_p2p() || liveness.load().elapsed() < stale_timeout))
                    .then_some(*route)
            })
        })
    }

    pub fn get_one_p2p_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table
            .read()
            .get(vip)
            .and_then(|v| v.iter().find_map(|(i, _)| i.is_p2p().then_some(*i)))
    }

    pub fn get_one_measured_p2p_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table.read().get(vip).and_then(|v| {
            v.iter()
                .find_map(|(i, _)| (i.is_p2p() && i.has_measured_rt()).then_some(*i))
        })
    }

    /// Returns the measured, live direct route usable for this payload and
    /// whether a live direct route exists.  A route that has outlived the
    /// maintenance window is treated as absent immediately, rather than
    /// waiting for the cleanup worker to remove it.
    pub fn payload_route_read(
        &self,
        vip: &Ipv4Addr,
        stale_timeout: Duration,
    ) -> (Option<Route>, bool) {
        let route_table = self.route_table.read();
        let Some(routes) = route_table.get(vip) else {
            return (None, false);
        };
        let mut measured_direct = None;
        let mut has_direct = false;
        for (route, liveness) in routes {
            if route.is_p2p() && liveness.load().elapsed() < stale_timeout {
                has_direct = true;
                if measured_direct.is_none() && route.has_measured_rt() {
                    measured_direct = Some(*route);
                }
            }
        }
        (measured_direct, has_direct)
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

    pub fn has_direct_path(&self, vip: &Ipv4Addr, route_key: &RouteKey) -> bool {
        self.route_table
            .read()
            .get(vip)
            .map(|routes| {
                routes
                    .iter()
                    .any(|(route, _)| route.is_p2p() && &route.route_key() == route_key)
            })
            .unwrap_or(false)
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

    /// Records application payload traffic for the UI activity state. Route
    /// health is maintained independently by the route heartbeat and stale
    /// cleanup loops.
    pub fn activate_peer(&self, vip: &Ipv4Addr, idle_timeout: std::time::Duration) -> bool {
        let now = Instant::now();
        if let Some(activity) = self.peer_activity.read().get(vip) {
            let previous = activity.last_payload.load();
            let elapsed = now.saturating_duration_since(previous);
            if elapsed >= idle_timeout {
                if activity
                    .last_payload
                    .compare_exchange(previous, now)
                    .is_ok()
                {
                    return true;
                }
                return false;
            }
            if elapsed >= PEER_ACTIVITY_REFRESH_INTERVAL {
                let _ = activity.last_payload.compare_exchange(previous, now);
            }
            return false;
        }

        // Only the thread that inserts this first activity marker reports the
        // first activation. Concurrent payload handlers see the marker.
        let mut activity = self.peer_activity.write();
        if activity.contains_key(vip) {
            return false;
        }
        activity.insert(*vip, PeerActivity::new(now));
        drop(activity);
        true
    }

    pub fn is_peer_active(&self, vip: &Ipv4Addr, idle_timeout: std::time::Duration) -> bool {
        self.peer_activity
            .read()
            .get(vip)
            .is_some_and(|activity| activity.last_payload.load().elapsed() < idle_timeout)
    }

    /// Claims the one immediate control-plane recovery request permitted while
    /// a peer has traffic but no direct route. A new direct route resets it.
    pub fn take_direct_recovery_request(&self, vip: &Ipv4Addr, has_direct_route: bool) -> bool {
        if has_direct_route {
            return false;
        }
        self.peer_activity.read().get(vip).is_some_and(|activity| {
            activity
                .direct_recovery_requested
                .compare_exchange(false, true)
                .is_ok()
        })
    }

    fn reset_direct_recovery_request(&self, vip: &Ipv4Addr) {
        if let Some(activity) = self.peer_activity.read().get(vip) {
            activity.direct_recovery_requested.store(false);
        }
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
        let has_direct_route = write_guard
            .get(vip)
            .is_some_and(|routes| routes.iter().any(|(route, _)| route.is_p2p()));
        drop(write_guard);
        if !has_direct_route {
            self.reset_direct_recovery_request(vip);
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

    pub fn clear_peer(&self, vip: &Ipv4Addr) {
        let mut route_table = self.route_table.write();
        route_table.remove(vip);
        Self::rebuild_direct_route_keys(&route_table, &mut self.direct_route_keys.write());
        drop(route_table);
        self.peer_activity.write().remove(vip);
    }

    pub fn clear_all(&self) {
        self.route_table.write().clear();
        self.direct_route_keys.write().clear();
        self.peer_activity.write().clear();
    }

    /// Drops only direct P2P paths while retaining relay paths as an immediate
    /// fallback after the local underlay has changed.
    pub fn clear_direct_routes(&self) -> Vec<Ipv4Addr> {
        let mut route_table = self.route_table.write();
        let mut affected_peers = Vec::new();
        route_table.retain(|vip, routes| {
            let before = routes.len();
            routes.retain(|(route, _)| !route.is_p2p());
            if routes.len() != before {
                affected_peers.push(*vip);
            }
            !routes.is_empty()
        });
        Self::rebuild_direct_route_keys(&route_table, &mut self.direct_route_keys.write());
        drop(route_table);
        for vip in &affected_peers {
            self.reset_direct_recovery_request(vip);
        }
        affected_peers
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        let mut route_table = self.route_table.write();
        route_table.retain(|vip, _| valid_peers.contains(vip));
        Self::rebuild_direct_route_keys(&route_table, &mut self.direct_route_keys.write());
        drop(route_table);
        self.peer_activity
            .write()
            .retain(|vip, _| valid_peers.contains(vip));
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
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

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
        let table = RouteTable::new(UseChannelType::Auto, false);
        let vip = Ipv4Addr::new(10, 0, 0, 4);
        table.add_route(vip, Route::from_default_rt(route_key(1002), 2));
        table.add_route(vip, Route::from_default_rt(route_key(1003), 1));

        let routes = table.get_routes(&vip).unwrap();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].is_p2p());
    }

    #[test]
    fn measured_p2p_route_excludes_default_rt_routes() {
        let table = RouteTable::new(UseChannelType::Auto, false);
        let vip = Ipv4Addr::new(10, 0, 0, 4);
        let default_rt = route_key(1003);
        table.add_route(vip, Route::from_default_rt(default_rt, 1));
        assert!(table.get_one_p2p_route(&vip).is_some());
        assert!(table.get_one_measured_p2p_route(&vip).is_none());

        table.add_route(vip, Route::from(default_rt, 1, 42));
        assert_eq!(table.get_one_measured_p2p_route(&vip).unwrap().rt, 42);
    }

    #[test]
    fn payload_route_read_treats_stale_direct_routes_as_absent() {
        let table = RouteTable::new(UseChannelType::Auto, false);
        let vip = Ipv4Addr::new(10, 0, 0, 22);
        table.add_route(
            vip,
            Route::new(ConnectProtocol::UDP, route_key(2022).addr, 1, 7),
        );

        assert!(table
            .payload_route_read(&vip, Duration::from_secs(1))
            .0
            .is_some());
        thread::sleep(Duration::from_millis(5));
        let (route, has_direct) = table.payload_route_read(&vip, Duration::from_millis(1));
        assert!(route.is_none());
        assert!(!has_direct);
    }

    #[test]
    fn live_route_view_falls_back_when_direct_route_is_stale() {
        let table = RouteTable::new(UseChannelType::Auto, true);
        let vip = Ipv4Addr::new(10, 0, 0, 23);
        let direct = Route::new(ConnectProtocol::UDP, route_key(2023).addr, 1, 1);
        let relay = Route::new(
            ConnectProtocol::TCP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2024)),
            2,
            10,
        );
        table.add_route(vip, direct);
        table.add_route(vip, relay);

        thread::sleep(Duration::from_millis(5));
        assert_eq!(
            table
                .get_first_live_route(&vip, Duration::from_millis(1))
                .unwrap()
                .route_key(),
            relay.route_key()
        );
    }

    #[test]
    fn retain_peers_drops_stale_routes() {
        let table = RouteTable::new(UseChannelType::Auto, false);
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
        let table = RouteTable::new(UseChannelType::Auto, false);
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

        table.set_use_channel_type(UseChannelType::Auto);
        table.add_route(vip, Route::from_default_rt(direct, 1));
        assert!(table.has_direct_route_key(&direct));

        table.remove_route(&vip, direct);
        assert!(!table.has_direct_route_key(&direct));
    }

    #[test]
    fn clear_all_drops_routes_and_direct_route_index() {
        let table = RouteTable::new(UseChannelType::Auto, false);
        let vip = Ipv4Addr::new(10, 0, 0, 7);
        let direct = route_key(1007);

        table.add_route(vip, Route::from_default_rt(direct, 1));
        assert!(table.get_first_route(&vip).is_some());
        assert!(table.has_direct_route_key(&direct));

        table.clear_all();

        assert!(table.get_first_route(&vip).is_none());
        assert!(!table.has_direct_route_key(&direct));
        assert!(table.route_table().is_empty());
    }

    #[test]
    fn clear_direct_routes_preserves_relay_fallback() {
        let table = RouteTable::new(UseChannelType::Auto, true);
        let vip = Ipv4Addr::new(10, 0, 0, 8);
        let direct = route_key(1008);
        let relay = RouteKey::new(
            ConnectProtocol::TCP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 2008)),
        );
        table.add_route(vip, Route::from_default_rt(direct, 1));
        table.add_route(vip, Route::from_default_rt(relay, 2));

        assert_eq!(table.clear_direct_routes(), vec![vip]);

        assert!(table.get_one_p2p_route(&vip).is_none());
        assert_eq!(table.get_first_route(&vip).unwrap().route_key(), relay);
        assert!(!table.has_direct_route_key(&direct));
    }

    #[test]
    fn unmeasured_direct_route_does_not_outrank_relay() {
        let table = RouteTable::new(UseChannelType::Auto, true);
        let vip = Ipv4Addr::new(10, 0, 0, 13);
        let direct = Route::new(ConnectProtocol::UDP, route_key(1013).addr, 1, -1);
        let relay = Route::new(
            ConnectProtocol::TCP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2013)),
            2,
            10,
        );
        table.add_route(vip, direct);
        table.add_route(vip, relay);

        assert_eq!(
            table.get_first_route(&vip).unwrap().route_key(),
            relay.route_key()
        );
    }

    #[test]
    fn learning_a_direct_route_does_not_mark_the_peer_active() {
        let table = RouteTable::new(UseChannelType::Auto, false);
        let vip = Ipv4Addr::new(10, 0, 0, 9);
        table.add_route(vip, Route::from_default_rt(route_key(1009), 1));

        assert!(!table.is_peer_active(&vip, Duration::from_secs(30)));
    }

    #[test]
    fn peer_activity_reactivation_preserves_route_measurement() {
        let table = RouteTable::new(UseChannelType::Auto, false);
        let vip = Ipv4Addr::new(10, 0, 0, 10);
        let direct = Route::new(ConnectProtocol::UDP, route_key(1010).addr, 1, 42);
        table.add_route(vip, direct);
        assert!(table.get_one_measured_p2p_route(&vip).is_some());

        assert!(table.activate_peer(&vip, Duration::from_secs(1)));
        assert!(table.get_one_measured_p2p_route(&vip).is_some());
        assert!(table.is_peer_active(&vip, Duration::from_secs(1)));
        assert!(!table.activate_peer(&vip, Duration::from_secs(1)));

        thread::sleep(Duration::from_millis(5));
        assert!(!table.is_peer_active(&vip, Duration::from_millis(1)));
        assert!(table.activate_peer(&vip, Duration::from_millis(1)));
        assert_eq!(
            table.get_one_measured_p2p_route(&vip).unwrap().route_key(),
            direct.route_key()
        );
    }

    #[test]
    fn concurrent_peer_activity_reactivation_reports_one_activation() {
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, false));
        let vip = Ipv4Addr::new(10, 0, 0, 11);
        table.add_route(vip, Route::from_default_rt(route_key(1011), 1));
        let _ = table.activate_peer(&vip, Duration::from_millis(1));
        thread::sleep(Duration::from_millis(5));

        let barrier = Arc::new(Barrier::new(3));
        let workers = (0..2)
            .map(|_| {
                let table = table.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    usize::from(table.activate_peer(&vip, Duration::from_millis(1)))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();

        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum::<usize>(),
            1
        );
    }

    #[test]
    fn traffic_after_direct_routes_are_cleared_requests_one_recovery() {
        let table = RouteTable::new(UseChannelType::Auto, false);
        let vip = Ipv4Addr::new(10, 0, 0, 12);
        let direct = Route::from_default_rt(route_key(1012), 1);
        table.add_route(vip, direct);
        let _ = table.activate_peer(&vip, Duration::from_secs(30));

        assert!(!table.take_direct_recovery_request(&vip, true));
        assert_eq!(table.clear_direct_routes(), vec![vip]);
        assert!(table.take_direct_recovery_request(&vip, false));
        assert!(!table.take_direct_recovery_request(&vip, false));

        table.add_route(vip, direct);
        table.remove_route(&vip, direct.route_key());
        assert!(table.take_direct_recovery_request(&vip, false));
    }
}
