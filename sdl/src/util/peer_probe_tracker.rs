use crate::data_plane::route::RouteKey;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const PING_PROBE_TTL: Duration = Duration::from_secs(15);
const PUNCH_PROBE_TTL: Duration = Duration::from_secs(15);
const PROBE_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_PENDING_PINGS_PER_PEER: usize = 8;
const MAX_PENDING_PUNCHES_PER_PEER: usize = 1024;
const MIN_PING_PROBES_FOR_LOSS_RATE: u32 = 5;
const MAX_PING_PROBE_STATS_SAMPLES: u32 = 64;

#[derive(Clone, Debug)]
struct PendingPingProbe {
    route_key: RouteKey,
    epoch: u16,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
struct PendingPunchProbe {
    addr: SocketAddr,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct PingProbeStats {
    sent: u32,
    acked: u32,
}

impl PingProbeStats {
    fn record_sent(&mut self) {
        if self.sent >= MAX_PING_PROBE_STATS_SAMPLES {
            self.sent = (self.sent / 2).max(self.acked);
            self.acked /= 2;
        }
        self.sent = self.sent.saturating_add(1);
    }

    fn record_acked(&mut self) {
        self.acked = self.acked.saturating_add(1).min(self.sent);
    }

    fn loss_rate(&self) -> Option<f32> {
        if self.sent < MIN_PING_PROBES_FOR_LOSS_RATE {
            return None;
        }
        Some((self.sent.saturating_sub(self.acked)) as f32 / self.sent as f32)
    }
}

pub struct PeerProbeTracker {
    next_epoch: AtomicCell<u16>,
    last_cleanup_at: AtomicCell<Instant>,
    pending_pings: Mutex<HashMap<Ipv4Addr, Vec<PendingPingProbe>>>,
    pending_punches: Mutex<HashMap<Ipv4Addr, Vec<PendingPunchProbe>>>,
    ping_probe_stats: Mutex<HashMap<(Ipv4Addr, RouteKey), PingProbeStats>>,
}

impl PeerProbeTracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            next_epoch: AtomicCell::new(1),
            last_cleanup_at: AtomicCell::new(Instant::now()),
            pending_pings: Mutex::new(HashMap::with_capacity(capacity)),
            pending_punches: Mutex::new(HashMap::with_capacity(capacity)),
            ping_probe_stats: Mutex::new(HashMap::with_capacity(capacity)),
        }
    }

    pub fn record_ping_probe(&self, peer_ip: Ipv4Addr, route_key: RouteKey) -> u16 {
        self.maybe_cleanup();
        let epoch = {
            let mut pending = self.pending_pings.lock();
            self.record_ping_probe_locked(&mut pending, peer_ip, route_key)
        };
        self.record_ping_probe_sent(peer_ip, route_key);
        epoch
    }

    /// Registers a ping probe only when the same peer and route do not already
    /// have an outstanding measurement.
    pub fn try_record_ping_probe(&self, peer_ip: Ipv4Addr, route_key: RouteKey) -> Option<u16> {
        self.maybe_cleanup();
        let epoch = {
            let mut pending = self.pending_pings.lock();
            if pending.get(&peer_ip).is_some_and(|probes| {
                probes
                    .iter()
                    .any(|probe| probe.route_key == route_key && probe.expires_at > Instant::now())
            }) {
                return None;
            }
            self.record_ping_probe_locked(&mut pending, peer_ip, route_key)
        };
        self.record_ping_probe_sent(peer_ip, route_key);
        Some(epoch)
    }

    fn record_ping_probe_locked(
        &self,
        pending: &mut HashMap<Ipv4Addr, Vec<PendingPingProbe>>,
        peer_ip: Ipv4Addr,
        route_key: RouteKey,
    ) -> u16 {
        let epoch = self.next_probe_epoch();
        let probes = pending.entry(peer_ip).or_default();
        probes.retain(|probe| {
            probe.expires_at > Instant::now()
                && !(probe.route_key == route_key && probe.epoch == epoch)
        });
        probes.push(PendingPingProbe {
            route_key,
            epoch,
            expires_at: Instant::now() + PING_PROBE_TTL,
        });
        if probes.len() > MAX_PENDING_PINGS_PER_PEER {
            let drop_count = probes.len() - MAX_PENDING_PINGS_PER_PEER;
            probes.drain(..drop_count);
        }
        epoch
    }

    fn record_ping_probe_sent(&self, peer_ip: Ipv4Addr, route_key: RouteKey) {
        self.ping_probe_stats
            .lock()
            .entry((peer_ip, route_key))
            .or_default()
            .record_sent();
    }

    pub fn match_ping_response(&self, peer_ip: Ipv4Addr, route_key: RouteKey, epoch: u16) -> bool {
        if epoch == 0 {
            return false;
        }
        self.maybe_cleanup();
        let matched = {
            let mut pending = self.pending_pings.lock();
            let Some(probes) = pending.get_mut(&peer_ip) else {
                return false;
            };
            probes.retain(|probe| probe.expires_at > Instant::now());
            if let Some(index) = probes
                .iter()
                .position(|probe| probe.route_key == route_key && probe.epoch == epoch)
            {
                probes.swap_remove(index);
                if probes.is_empty() {
                    pending.remove(&peer_ip);
                }
                true
            } else {
                false
            }
        };
        if matched {
            self.ping_probe_stats
                .lock()
                .entry((peer_ip, route_key))
                .or_default()
                .record_acked();
        }
        matched
    }

    pub fn ping_loss_rate(&self, peer_ip: Ipv4Addr, route_key: RouteKey) -> Option<f32> {
        self.ping_probe_stats
            .lock()
            .get(&(peer_ip, route_key))
            .and_then(PingProbeStats::loss_rate)
    }

    pub fn record_punch_probe(&self, peer_ip: Ipv4Addr, addr: SocketAddr) {
        self.maybe_cleanup();
        let mut pending = self.pending_punches.lock();
        let probes = pending.entry(peer_ip).or_default();
        probes.retain(|probe| probe.expires_at > Instant::now() && probe.addr != addr);
        probes.push(PendingPunchProbe {
            addr,
            expires_at: Instant::now() + PUNCH_PROBE_TTL,
        });
        if probes.len() > MAX_PENDING_PUNCHES_PER_PEER {
            let drop_count = probes.len() - MAX_PENDING_PUNCHES_PER_PEER;
            probes.drain(..drop_count);
        }
    }

    pub fn match_punch_response(&self, peer_ip: Ipv4Addr, addr: SocketAddr) -> bool {
        self.maybe_cleanup();
        let mut pending = self.pending_punches.lock();
        let Some(probes) = pending.get_mut(&peer_ip) else {
            return false;
        };
        probes.retain(|probe| probe.expires_at > Instant::now());
        if let Some(index) = probes.iter().position(|probe| probe.addr == addr) {
            probes.swap_remove(index);
            if probes.is_empty() {
                pending.remove(&peer_ip);
            }
            true
        } else {
            false
        }
    }

    fn next_probe_epoch(&self) -> u16 {
        let current = self.next_epoch.load();
        let next = if current == u16::MAX { 1 } else { current + 1 };
        self.next_epoch.store(next);
        current
    }

    fn maybe_cleanup(&self) {
        let last = self.last_cleanup_at.load();
        if last.elapsed() < PROBE_CLEANUP_INTERVAL {
            return;
        }
        self.last_cleanup_at.store(Instant::now());
        self.pending_pings.lock().retain(|_, probes| {
            probes.retain(|probe| probe.expires_at > Instant::now());
            !probes.is_empty()
        });
        self.pending_punches.lock().retain(|_, probes| {
            probes.retain(|probe| probe.expires_at > Instant::now());
            !probes.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::PeerProbeTracker;
    use crate::data_plane::route::RouteKey;
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn ping_probe_must_match_epoch_and_route() {
        let tracker = PeerProbeTracker::new(4);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        let route_key = RouteKey::new(
            ConnectProtocol::UDP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 3000)),
        );
        let epoch = tracker.record_ping_probe(peer, route_key);

        assert!(!tracker.match_ping_response(peer, route_key, epoch.wrapping_add(1)));
        assert!(tracker.match_ping_response(peer, route_key, epoch));
        assert!(!tracker.match_ping_response(peer, route_key, epoch));
    }

    #[test]
    fn immediate_ping_probe_is_deduplicated_by_peer_and_route() {
        let tracker = PeerProbeTracker::new(4);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        let route_key = RouteKey::new(
            ConnectProtocol::UDP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 3000)),
        );

        assert!(tracker.try_record_ping_probe(peer, route_key).is_some());
        assert!(tracker.try_record_ping_probe(peer, route_key).is_none());
    }

    #[test]
    fn ping_loss_rate_uses_recent_ping_probe_results() {
        let tracker = PeerProbeTracker::new(4);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        let route_key = RouteKey::new(
            ConnectProtocol::UDP,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 3000)),
        );
        for i in 0..5 {
            let epoch = tracker.record_ping_probe(peer, route_key);
            if i < 3 {
                assert!(tracker.match_ping_response(peer, route_key, epoch));
            }
        }

        let loss = tracker
            .ping_loss_rate(peer, route_key)
            .expect("loss rate after enough samples");
        assert!((loss - 0.4).abs() < f32::EPSILON);
    }

    #[test]
    fn punch_probe_must_match_addr() {
        let tracker = PeerProbeTracker::new(4);
        let peer = Ipv4Addr::new(10, 0, 0, 3);
        let addr: SocketAddr = "203.0.113.10:4000".parse().unwrap();
        tracker.record_punch_probe(peer, addr);

        assert!(!tracker.match_punch_response(peer, "203.0.113.10:4001".parse().unwrap()));
        assert!(tracker.match_punch_response(peer, addr));
        assert!(!tracker.match_punch_response(peer, addr));
    }
}
