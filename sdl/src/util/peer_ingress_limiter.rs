use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::util::limit::RateLimiter;

const INGRESS_BURST: usize = 512;
const INGRESS_REFILL_PER_SEC: usize = 512;
const ENTRY_IDLE_TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct PeerIngressLimiter {
    inner: std::sync::Arc<Mutex<HashMap<SocketAddr, PeerIngressState>>>,
}

struct PeerIngressState {
    limiter: RateLimiter,
    last_seen: Instant,
}

impl PeerIngressLimiter {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(HashMap::with_capacity(capacity))),
        }
    }

    pub fn allow(&self, addr: SocketAddr) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.lock();
        guard.retain(|_, state| now.duration_since(state.last_seen) <= ENTRY_IDLE_TTL);
        let state = guard.entry(addr).or_insert_with(|| PeerIngressState {
            limiter: RateLimiter::new(INGRESS_BURST, INGRESS_REFILL_PER_SEC),
            last_seen: now,
        });
        state.last_seen = now;
        state.limiter.try_acquire()
    }
}

#[cfg(test)]
mod tests {
    use super::PeerIngressLimiter;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn allows_initial_burst() {
        let limiter = PeerIngressLimiter::new(1);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4000));

        for _ in 0..512 {
            assert!(limiter.allow(addr));
        }
        assert!(!limiter.allow(addr));
    }

    #[test]
    fn tracks_addresses_independently() {
        let limiter = PeerIngressLimiter::new(2);
        let addr1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4000));
        let addr2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4001));

        for _ in 0..512 {
            assert!(limiter.allow(addr1));
        }
        assert!(!limiter.allow(addr1));
        assert!(limiter.allow(addr2));
    }
}
