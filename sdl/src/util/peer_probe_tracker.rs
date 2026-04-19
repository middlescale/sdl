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

pub struct PeerProbeTracker {
    next_epoch: AtomicCell<u16>,
    last_cleanup_at: AtomicCell<Instant>,
    pending_pings: Mutex<HashMap<Ipv4Addr, Vec<PendingPingProbe>>>,
    pending_punches: Mutex<HashMap<Ipv4Addr, Vec<PendingPunchProbe>>>,
}

impl PeerProbeTracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            next_epoch: AtomicCell::new(1),
            last_cleanup_at: AtomicCell::new(Instant::now()),
            pending_pings: Mutex::new(HashMap::with_capacity(capacity)),
            pending_punches: Mutex::new(HashMap::with_capacity(capacity)),
        }
    }

    pub fn record_ping_probe(&self, peer_ip: Ipv4Addr, route_key: RouteKey) -> u16 {
        self.maybe_cleanup();
        let epoch = self.next_probe_epoch();
        let mut pending = self.pending_pings.lock();
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

    pub fn match_ping_response(&self, peer_ip: Ipv4Addr, route_key: RouteKey, epoch: u16) -> bool {
        if epoch == 0 {
            return false;
        }
        self.maybe_cleanup();
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
