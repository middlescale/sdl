//! One deadline-driven owner for stale expiry and post-underlay revalidation.
//! Lock order is maintenance -> route table -> recovery/activity markers. No
//! external handler runs under these locks; payload reads never take maintenance.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use crate::data_plane::route::{Route, RouteKey};
use crate::data_plane::route_table::StaleRouteCandidate;
use crate::util::StopManager;

use super::RouteManager;

type DirectPath = (Ipv4Addr, RouteKey);

#[derive(Clone, Copy, PartialEq, Eq)]
struct Revalidation {
    generation: u64,
    started_at: Instant,
    deadline: Instant,
}

#[derive(Default)]
pub(super) struct RouteMaintenance {
    pending: HashMap<DirectPath, Revalidation>,
    generation: u64,
    worker: Option<Thread>,
}

struct MaintenanceBatch {
    stale: Vec<StaleRouteCandidate>,
    revalidations: Vec<(DirectPath, Revalidation)>,
}

impl RouteManager {
    pub(super) fn wake_maintenance(&self) {
        if let Some(worker) = &self.maintenance.lock().worker {
            // unpark retains a token even if the worker has not parked yet.
            worker.unpark();
        }
    }

    /// Preserves endpoints but requires a fresh measurement after an underlay
    /// transition. Installing the generation and invalidating routes are one
    /// consistency boundary with expiry, so an older batch cannot delete these.
    pub fn begin_underlay_revalidation(&self, timeout: Duration) -> Vec<(Ipv4Addr, Route)> {
        self.begin_underlay_revalidation_at(Instant::now(), timeout)
    }

    fn begin_underlay_revalidation_at(
        &self,
        now: Instant,
        timeout: Duration,
    ) -> Vec<(Ipv4Addr, Route)> {
        let mut maintenance = self.maintenance.lock();
        let routes = self
            .route_table
            .invalidate_direct_routes_for_revalidation_at(now);
        maintenance.generation += 1;
        let pending = Revalidation {
            generation: maintenance.generation,
            started_at: now,
            deadline: now + timeout,
        };
        // A new transition replaces the entire preceding route generation.
        maintenance.pending.clear();
        for (peer, route) in &routes {
            maintenance
                .pending
                .insert((*peer, route.route_key()), pending);
        }
        drop(maintenance);
        self.wake_maintenance();
        let affected: HashSet<_> = routes.iter().map(|(peer, _)| *peer).collect();
        for peer in affected {
            self.notify_direct_route_update(peer);
        }
        routes
    }

    fn due_revalidations_at(&self, now: Instant) -> Vec<(DirectPath, Revalidation)> {
        self.maintenance
            .lock()
            .pending
            .iter()
            .filter_map(|(path, pending)| (pending.deadline <= now).then_some((*path, *pending)))
            .collect()
    }

    fn collect_maintenance_at(&self, now: Instant, stale_timeout: Duration) -> MaintenanceBatch {
        MaintenanceBatch {
            stale: self
                .route_table
                .maintenance_snapshot_at(now, stale_timeout)
                .expired,
            revalidations: self.due_revalidations_at(now),
        }
    }

    fn apply_maintenance_batch_at(
        &self,
        batch: MaintenanceBatch,
        now: Instant,
        stale_timeout: Duration,
    ) -> Vec<Ipv4Addr> {
        let mut changed = HashSet::new();
        {
            let mut maintenance = self.maintenance.lock();
            for ((peer, key), pending) in batch.revalidations {
                if maintenance.pending.get(&(peer, key)) != Some(&pending) || pending.deadline > now
                {
                    continue;
                }
                maintenance.pending.remove(&(peer, key));
                if self
                    .route_table
                    .remove_revalidation_route(&peer, key, pending.started_at)
                {
                    changed.insert(peer);
                }
            }
            for candidate in batch.stale {
                if self
                    .route_table
                    .remove_stale_direct_route_at(&candidate, now, stale_timeout)
                {
                    changed.insert(candidate.peer_ip);
                }
            }
        }
        // Drain the whole due set before any recovery callback. The latch below
        // is shared with payload recovery and synchronous mark_path_failed.
        let mut recovery = Vec::new();
        for peer in changed {
            self.notify_direct_route_update(peer);
            if self.fire_direct_route_timeout_if_last(peer) {
                recovery.push(peer);
            }
        }
        recovery.sort_unstable();
        recovery
    }

    /// Sole callback entry point for all three expiry/error sources. RouteTable
    /// owns the per-peer recovery latch, shared with payload requests. Removal
    /// does not rearm it; a newly learned direct route does. Handler invocation
    /// is deliberately outside the table/maintenance/handler locks.
    pub(super) fn fire_direct_route_timeout_if_last(&self, peer: Ipv4Addr) -> bool {
        let handler = self.direct_route_timeout_handler.lock().clone();
        let Some(handler) = handler else {
            return false;
        };
        if !self.route_table.take_direct_timeout_request(&peer) {
            return false;
        }
        handler(peer);
        true
    }

    fn next_maintenance_deadline_at(
        &self,
        now: Instant,
        stale_timeout: Duration,
    ) -> Option<Instant> {
        let maintenance = self.maintenance.lock();
        self.route_table
            .maintenance_snapshot_at(now, stale_timeout)
            .next_deadline
            .into_iter()
            .chain(maintenance.pending.values().map(|pending| pending.deadline))
            .min()
    }

    fn maintain_routes_at(&self, now: Instant) {
        let batch = self.collect_maintenance_at(now, self.stale_direct_timeout);
        let expired = self.apply_maintenance_batch_at(batch, now, self.stale_direct_timeout);
        if !expired.is_empty() {
            log::info!(
                "route maintenance expired final direct paths for peers {:?}",
                expired
            );
        }
    }

    pub(super) fn start_route_maintenance_loop(
        &self,
        stop_manager: StopManager,
    ) -> anyhow::Result<()> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop_flag = cancelled.clone();
        let wake_manager = self.clone();
        let worker = stop_manager.add_listener("routeMaintenance".into(), move || {
            stop_flag.store(true, Ordering::Release);
            wake_manager.wake_maintenance();
        })?;
        let manager = self.clone();
        thread::Builder::new()
            .name("routeMaintenance".into())
            .spawn(move || {
                manager.maintenance.lock().worker = Some(thread::current());
                while !cancelled.load(Ordering::Acquire) {
                    manager.maintain_routes_at(Instant::now());
                    // Compute from a fresh clock after callbacks, which can take
                    // time or add routes. Any earlier concurrent notification has
                    // left an unpark token, so the following wait cannot lose it.
                    let now = Instant::now();
                    let deadline =
                        manager.next_maintenance_deadline_at(now, manager.stale_direct_timeout);
                    if cancelled.load(Ordering::Acquire) {
                        break;
                    }
                    match deadline {
                        Some(deadline) => {
                            thread::park_timeout(deadline.saturating_duration_since(now))
                        }
                        None => thread::park(),
                    }
                }
                manager.maintenance.lock().worker = None;
                worker.stop_self();
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::route_table::RouteTable;
    use crate::data_plane::use_channel_type::UseChannelType;
    use crate::transport::connect_protocol::ConnectProtocol;
    use parking_lot::Mutex;
    use std::sync::{mpsc, Barrier};

    const STALE: Duration = Duration::from_secs(30);
    const GRACE: Duration = Duration::from_secs(3);

    fn peer(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, n)
    }

    fn direct(port: u16) -> Route {
        Route::new(ConnectProtocol::UDP, ([127, 0, 0, 1], port).into(), 1, 7)
    }

    fn manager() -> (RouteManager, Arc<Mutex<Vec<Ipv4Addr>>>) {
        let manager =
            RouteManager::new_detached(Arc::new(RouteTable::new(UseChannelType::Auto, true)));
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        manager.set_direct_route_timeout_handler(Arc::new(move |peer| captured.lock().push(peer)));
        (manager, events)
    }

    fn add_at(manager: &RouteManager, peer: Ipv4Addr, route: Route, now: Instant) {
        manager.add_path(peer, route);
        manager
            .route_table
            .update_read_time_at(&peer, &route.route_key(), now);
    }

    #[test]
    fn only_new_direct_deadlines_need_an_insertion_wake() {
        let (manager, _) = manager();
        let route = direct(1001);
        let relay = Route::from(route.route_key(), 2, 10);
        assert!(!manager.route_table.add_route(peer(1), relay));
        // Promoting the same endpoint from relay to direct introduces a timer.
        assert!(manager.route_table.add_route(peer(1), route));
        assert!(!manager.route_table.add_route(peer(1), route));
        assert!(!manager.route_table.add_route_if_absent(peer(1), route));
        assert!(manager
            .route_table
            .add_route_if_absent(peer(1), direct(1002)));
    }

    #[test]
    fn maintenance_snapshot_ignores_stale_relay_routes() {
        let (manager, _) = manager();
        let now = Instant::now();
        add_at(
            &manager,
            peer(1),
            Route::from(direct(1001).route_key(), 2, 10),
            now - STALE,
        );
        let snapshot = manager.route_table.maintenance_snapshot_at(now, STALE);
        assert!(snapshot.expired.is_empty());
        assert_eq!(snapshot.next_deadline, None);
    }

    #[test]
    fn maintenance_snapshot_collects_direct_routes_at_the_exact_deadline() {
        let (manager, _) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now - STALE);
        let snapshot = manager.route_table.maintenance_snapshot_at(now, STALE);
        assert_eq!(snapshot.expired.len(), 1);
        assert_eq!(snapshot.expired[0].peer_ip, peer(1));
        assert_eq!(snapshot.expired[0].route.route_key(), route.route_key());
        assert_eq!(snapshot.next_deadline, Some(now));
    }

    #[test]
    fn payload_activity_does_not_protect_a_stale_route() {
        for active in [false, true] {
            let (manager, _) = manager();
            let now = Instant::now();
            add_at(&manager, peer(1), direct(1001), now - STALE);
            if active {
                manager.activate_peer(&peer(1));
            }
            assert_eq!(manager.is_peer_active(&peer(1)), active);
            manager.maintain_routes_at(now);
            assert_eq!(manager.direct_path_count(&peer(1)), 0);
        }
    }

    #[test]
    fn maintenance_removes_stale_direct_routes_without_a_handler() {
        let manager =
            RouteManager::new_detached(Arc::new(RouteTable::new(UseChannelType::Auto, true)));
        let now = Instant::now();
        let relay = Route::from(direct(1002).route_key(), 2, 10);
        add_at(&manager, peer(1), direct(1001), now - STALE);
        add_at(&manager, peer(2), relay, now - STALE);
        manager.maintain_routes_at(now);
        assert!(manager.route_table.get_routes(&peer(1)).is_none());
        let remaining = manager.route_table.get_routes(&peer(2)).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].route_key(), relay.route_key());
        manager.activate_peer(&peer(1));
        assert!(manager.take_direct_recovery_request(&peer(1), false));
    }

    #[test]
    fn stale_expiry_fires_recovery_for_the_last_direct_route() {
        let (manager, events) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now - STALE);
        manager.maintain_routes_at(now);
        assert_eq!(*events.lock(), vec![peer(1)]);
        assert_eq!(manager.direct_path_count(&peer(1)), 0);
    }

    #[test]
    fn underlay_probe_invalidates_measurement_then_expires_unconfirmed_path() {
        let (manager, events) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now);
        let probes = manager.begin_underlay_revalidation_at(now, GRACE);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].0, peer(1));
        assert_eq!(probes[0].1.route_key(), route.route_key());
        assert_eq!(probes[0].1.rt, -1);
        assert!(manager.measured_direct_route(&peer(1)).is_none());
        manager.maintain_routes_at(now + GRACE);
        assert_eq!(*events.lock(), vec![peer(1)]);
        assert_eq!(manager.direct_path_count(&peer(1)), 0);
    }

    #[test]
    fn underlay_probe_preserves_measurement_received_before_expiry() {
        let (manager, events) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now);
        manager.begin_underlay_revalidation_at(now, GRACE);
        add_at(&manager, peer(1), route, now + GRACE);
        manager.maintain_routes_at(now + GRACE);
        assert_eq!(
            manager.measured_direct_route(&peer(1)).unwrap().rt,
            route.rt
        );
        assert!(events.lock().is_empty());
    }

    #[test]
    fn fresh_direct_route_prevents_recovery_when_another_route_is_stale() {
        let (manager, events) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now - STALE);
        add_at(&manager, peer(1), direct(1002), now);
        manager.maintain_routes_at(now);
        assert_eq!(manager.direct_path_count(&peer(1)), 1);
        assert!(events.lock().is_empty());
    }

    #[test]
    fn clearing_direct_paths_does_not_rearm_an_inflight_recovery() {
        let (manager, events) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now - STALE);
        manager.activate_peer(&peer(1));
        assert!(manager.take_direct_recovery_request(&peer(1), false));
        assert_eq!(manager.clear_direct_paths(), 1);
        assert!(!manager.take_direct_recovery_request(&peer(1), false));
        assert!(events.lock().is_empty());
        // Learning a path, not clearing it, rearms the next recovery cycle.
        add_at(&manager, peer(1), route, now);
        assert_eq!(manager.clear_direct_paths(), 1);
        assert!(manager.take_direct_recovery_request(&peer(1), false));
    }

    #[test]
    fn deadline_is_minimum_of_both_sources_and_empty_worker_can_park() {
        let (manager, _) = manager();
        let now = Instant::now();
        assert_eq!(manager.next_maintenance_deadline_at(now, STALE), None);
        add_at(&manager, peer(1), direct(1001), now);
        assert_eq!(
            manager.next_maintenance_deadline_at(now, STALE),
            Some(now + STALE)
        );
        manager.begin_underlay_revalidation_at(now, GRACE);
        assert_eq!(
            manager.next_maintenance_deadline_at(now, STALE),
            Some(now + GRACE)
        );
        assert!(manager
            .due_revalidations_at(now + GRACE - Duration::from_nanos(1))
            .is_empty());
        assert_eq!(manager.due_revalidations_at(now + GRACE).len(), 1);
    }

    #[test]
    fn one_pass_drains_all_due_routes_and_fires_once_per_peer() {
        let (manager, events) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now);
        add_at(&manager, peer(1), direct(1002), now);
        manager.begin_underlay_revalidation_at(now, GRACE);
        add_at(&manager, peer(2), direct(1003), now - STALE);
        let relay = Route::new(ConnectProtocol::UDP, ([127, 0, 0, 1], 1004).into(), 2, 10);
        add_at(&manager, peer(2), relay, now - STALE);

        let batch = manager.collect_maintenance_at(now + GRACE, STALE);
        assert_eq!(batch.stale.len(), 1);
        assert_eq!(batch.revalidations.len(), 2);
        assert_eq!(
            manager.apply_maintenance_batch_at(batch, now + GRACE, STALE),
            vec![peer(1), peer(2)]
        );
        assert_eq!(events.lock().len(), 2);
        assert_eq!(manager.direct_path_count(&peer(1)), 0);
        let surviving = manager.route_table.get_routes(&peer(2)).unwrap();
        assert_eq!(surviving.len(), 1);
        assert_eq!(surviving[0].route_key(), relay.route_key());
        assert_eq!(
            manager.next_maintenance_deadline_at(now + GRACE, STALE),
            None
        );
        manager.maintain_routes_at(now + STALE);
        assert_eq!(events.lock().len(), 2);
    }

    #[test]
    fn pong_between_stale_scan_and_delete_preserves_route() {
        let (manager, events) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now - STALE);
        let batch = manager.collect_maintenance_at(now, STALE);
        assert_eq!(batch.stale.len(), 1);
        manager
            .route_table
            .update_read_time_at(&peer(1), &route.route_key(), now);
        manager.apply_maintenance_batch_at(batch, now, STALE);
        assert_eq!(manager.direct_path_count(&peer(1)), 1);
        assert!(events.lock().is_empty());
    }

    #[test]
    fn pong_between_revalidation_scan_and_delete_preserves_route() {
        let (manager, events) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now);
        manager.begin_underlay_revalidation_at(now, GRACE);
        let batch = manager.collect_maintenance_at(now + GRACE, STALE);
        add_at(&manager, peer(1), route, now + GRACE);
        manager.apply_maintenance_batch_at(batch, now + GRACE, STALE);
        assert_eq!(manager.direct_path_count(&peer(1)), 1);
        assert!(manager.maintenance.lock().pending.is_empty());
        assert!(events.lock().is_empty());
    }

    #[test]
    fn old_expiry_batch_cannot_remove_a_new_underlay_generation() {
        let (manager, events) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now);
        manager.begin_underlay_revalidation_at(now, GRACE);
        let batch = manager.collect_maintenance_at(now + GRACE, STALE);
        manager.begin_underlay_revalidation_at(now + GRACE, GRACE);
        manager.apply_maintenance_batch_at(batch, now + GRACE, STALE);
        assert_eq!(manager.direct_path_count(&peer(1)), 1);
        assert_eq!(manager.maintenance.lock().pending.len(), 1);
        assert!(events.lock().is_empty());
        manager.maintain_routes_at(now + GRACE + GRACE);
        assert_eq!(*events.lock(), vec![peer(1)]);
        assert_eq!(manager.direct_path_count(&peer(1)), 0);
    }

    #[test]
    fn underlay_invalidation_refreshes_liveness_after_stale_scan() {
        let (manager, events) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now - STALE);
        let batch = manager.collect_maintenance_at(now, STALE);
        manager.begin_underlay_revalidation_at(now, GRACE);
        manager.apply_maintenance_batch_at(batch, now, STALE);
        assert_eq!(manager.direct_path_count(&peer(1)), 1);
        assert!(events.lock().is_empty());
    }

    #[test]
    fn any_surviving_direct_path_prevents_peer_recovery() {
        let (manager, events) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now);
        add_at(&manager, peer(1), direct(1002), now);
        manager.begin_underlay_revalidation_at(now, GRACE);
        add_at(&manager, peer(1), direct(1002), now + GRACE);
        manager.maintain_routes_at(now + GRACE);
        assert_eq!(manager.direct_path_count(&peer(1)), 1);
        assert!(events.lock().is_empty());
    }

    #[test]
    fn expiry_send_error_and_payload_share_one_claim_until_a_new_route() {
        let (manager, events) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now);
        manager.begin_underlay_revalidation_at(now, GRACE);
        let batch = manager.collect_maintenance_at(now + STALE, STALE);
        // Both deadline sources and the synchronous send error target this path.
        assert_eq!(batch.stale.len(), 1);
        assert_eq!(batch.revalidations.len(), 1);
        manager.mark_path_failed(&peer(1), route.route_key());
        manager.apply_maintenance_batch_at(batch, now + STALE, STALE);
        manager.mark_path_failed(&peer(1), route.route_key());
        assert_eq!(*events.lock(), vec![peer(1)]);
        // A timeout-only marker must not change the idle display or suppress the
        // first payload activation, but it must suppress a second recovery request.
        assert!(!manager.is_peer_active(&peer(1)));
        assert!(manager.activate_peer(&peer(1)));
        assert!(!manager.take_direct_recovery_request(&peer(1), false));
        add_at(&manager, peer(1), route, now);
        manager.mark_path_failed(&peer(1), route.route_key());
        assert_eq!(*events.lock(), vec![peer(1), peer(1)]);
    }

    #[test]
    fn payload_claim_before_stale_cleanup_suppresses_timeout_callback() {
        let (manager, events) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now - STALE);
        manager.activate_peer(&peer(1));
        assert!(manager.take_direct_recovery_request(&peer(1), false));
        let batch = manager.collect_maintenance_at(now, STALE);
        manager.apply_maintenance_batch_at(batch, now, STALE);
        assert_eq!(manager.direct_path_count(&peer(1)), 0);
        assert!(events.lock().is_empty());
    }

    #[test]
    fn concurrent_send_error_and_expiry_fire_once() {
        let (manager, events) = manager();
        let now = Instant::now();
        let route = direct(1001);
        add_at(&manager, peer(1), route, now - STALE);
        let batch = manager.collect_maintenance_at(now, STALE);
        let barrier = Arc::new(Barrier::new(2));
        let sender = manager.clone();
        let gate = barrier.clone();
        let thread = thread::spawn(move || {
            gate.wait();
            sender.mark_path_failed(&peer(1), route.route_key());
        });
        barrier.wait();
        manager.apply_maintenance_batch_at(batch, now, STALE);
        thread.join().unwrap();
        assert_eq!(*events.lock(), vec![peer(1)]);
    }

    #[test]
    fn timeout_callback_runs_outside_all_internal_locks() {
        let (manager, _) = manager();
        let now = Instant::now();
        add_at(&manager, peer(1), direct(1001), now - STALE);
        let inside = manager.clone();
        manager.set_direct_route_timeout_handler(Arc::new(move |ip| {
            assert!(inside.maintenance.try_lock().is_some());
            assert!(inside.direct_route_timeout_handler.try_lock().is_some());
            assert_eq!(inside.direct_path_count(&ip), 0);
        }));
        let batch = manager.collect_maintenance_at(now, STALE);
        assert_eq!(
            manager.apply_maintenance_batch_at(batch, now, STALE),
            vec![peer(1)]
        );
        *manager.direct_route_timeout_handler.lock() = None;
    }

    #[test]
    fn worker_wakes_for_new_routes_earlier_deadlines_and_stop() {
        let (manager, _) = manager();
        let stop = StopManager::new(|| {});
        let (send, recv) = mpsc::channel();
        manager.set_direct_route_timeout_handler(Arc::new(move |ip| {
            send.send(ip).unwrap();
        }));
        manager.start_route_maintenance_loop(stop.clone()).unwrap();
        // Covers notifications even before worker registration/park, as well as
        // interrupting a stale deadline with an immediate revalidation deadline.
        manager.add_path(peer(1), direct(1001));
        manager.begin_underlay_revalidation(Duration::ZERO);
        let result = recv.recv_timeout(Duration::from_secs(2));
        stop.stop();
        assert!(stop.wait_timeout(Duration::from_secs(2)));
        assert_eq!(result.unwrap(), peer(1));
    }

    #[test]
    fn empty_worker_can_be_stopped_without_a_timer_tick() {
        let (manager, _) = manager();
        let stop = StopManager::new(|| {});
        manager.start_route_maintenance_loop(stop.clone()).unwrap();
        stop.stop();
        assert!(stop.wait_timeout(Duration::from_secs(2)));
    }

    fn device() -> Arc<crossbeam_utils::atomic::AtomicCell<crate::handle::CurrentDeviceInfo>> {
        Arc::new(crossbeam_utils::atomic::AtomicCell::new(
            crate::handle::CurrentDeviceInfo::new0(),
        ))
    }

    #[test]
    fn constructor_extracts_config_and_shares_peer_handles_without_starting_workers() {
        use crate::core::{runtime::PeerSubsystem, Config};
        use crate::data_plane::peer_crypto::PeerCryptoManager;
        use crate::data_plane::stats::DataPlaneStats;
        use crate::transport::udp_channel::UdpChannel;
        use crate::util::PeerProbeTracker;
        use parking_lot::RwLock;

        let mut config = Config::with_defaults(
            "route-manager-test".into(),
            "test".into(),
            "127.0.0.1:4242".into(),
            None,
            Some(vec![0]),
            None,
        )
        .unwrap();
        config.use_channel_type = UseChannelType::P2p;
        config.latency_first = true;
        config.p2p_heartbeat_interval_sec = 13;
        config.p2p_route_idle_timeout_sec = 52;
        let peers = PeerSubsystem {
            table: Arc::new(RwLock::new(Default::default())),
            nat_info_map: Arc::new(RwLock::new(Default::default())),
            crypto: Arc::new(PeerCryptoManager::new(0)),
            probe_tracker: Arc::new(PeerProbeTracker::new(0)),
        };
        let udp = UdpChannel::bind(&config, DataPlaneStats::new(false)).unwrap();
        let manager = RouteManager::new(&config, udp, &peers);
        assert_eq!(manager.use_channel_type(), UseChannelType::P2p);
        assert!(manager.latency_first());
        assert_eq!(manager.heartbeat_interval, Duration::from_secs(13));
        assert_eq!(manager.stale_direct_timeout, Duration::from_secs(52));
        assert!(Arc::ptr_eq(
            manager.peer_table.as_ref().unwrap(),
            &peers.table
        ));
        assert!(Arc::ptr_eq(&manager.peer_crypto, &peers.crypto));
        assert!(Arc::ptr_eq(
            &manager.peer_probe_tracker,
            &peers.probe_tracker
        ));
        assert!(!manager.started.load(Ordering::Acquire));
        assert!(manager.maintenance.lock().worker.is_none());
    }

    #[test]
    fn start_is_shared_across_clones_and_stop_interrupts_initial_heartbeat_wait() {
        let (manager, _) = manager();
        let stop = StopManager::new(|| {});
        manager.start(stop.clone(), device()).unwrap();
        let duplicate = manager.clone().start(stop.clone(), device());
        stop.stop();
        assert!(stop.wait_timeout(Duration::from_secs(2)));
        assert!(duplicate
            .unwrap_err()
            .to_string()
            .contains("already attempted"));
    }

    #[test]
    fn concurrent_start_has_exactly_one_winner() {
        let (manager, _) = manager();
        let stop = StopManager::new(|| {});
        let barrier = Arc::new(Barrier::new(2));
        let other = manager.clone();
        let other_stop = stop.clone();
        let gate = barrier.clone();
        let thread = thread::spawn(move || {
            gate.wait();
            other.start(other_stop, device()).is_ok()
        });
        barrier.wait();
        let first = manager.start(stop.clone(), device()).is_ok();
        let second = thread.join().unwrap();
        stop.stop();
        assert!(stop.wait_timeout(Duration::from_secs(2)));
        assert_ne!(first, second);
    }

    #[test]
    fn failed_start_cannot_be_retried_with_another_stop_manager() {
        let (manager, _) = manager();
        let stopped = StopManager::new(|| {});
        stopped.stop();
        assert!(manager.start(stopped, device()).is_err());
        let fresh = StopManager::new(|| {});
        assert!(manager.clone().start(fresh.clone(), device()).is_err());
        assert!(fresh.is_stopped());
    }

    #[test]
    fn partial_start_failure_stops_the_already_started_heartbeat() {
        let (manager, _) = manager();
        let stop = StopManager::new(|| {});
        // Force the second worker's synchronous registration to fail after
        // heartbeat startup, without relying on OS thread-spawn failures.
        let (send, recv) = mpsc::channel();
        let blocker = stop
            .add_listener("routeMaintenance".into(), move || {
                send.send(()).unwrap();
            })
            .unwrap();
        let result = manager.start(stop.clone(), device());
        let cancelled = recv.try_recv();
        blocker.stop_self();
        assert!(stop.wait_timeout(Duration::from_secs(2)));
        assert!(result.is_err());
        assert!(cancelled.is_ok());
        assert!(manager.start(StopManager::new(|| {}), device()).is_err());
    }
}
