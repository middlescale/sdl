use crate::util::limit::{
    ConcurrentTrafficMeter, TrafficMeterMultiAddress, TrafficMeterMultiChannel,
    TrafficMeterMultiIpAddr,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Total bytes and per-channel byte totals with their history samples.
pub type ChannelTrafficHistory = (u64, HashMap<usize, (u64, Vec<usize>)>);

/// Shared node statistics; cloning only retains the single inner allocation.
#[derive(Clone)]
pub struct DataPlaneStats {
    inner: Arc<DataPlaneStatsInner>,
}

struct DataPlaneStatsInner {
    up_traffic_meter: Option<TrafficMeterMultiChannel>,
    down_traffic_meter: Option<TrafficMeterMultiChannel>,
    up_peer_traffic_meter: Option<TrafficMeterMultiAddress>,
    down_peer_traffic_meter: Option<TrafficMeterMultiAddress>,
    up_transport_traffic_meter: Option<TrafficMeterMultiIpAddr>,
    down_transport_traffic_meter: Option<TrafficMeterMultiIpAddr>,
    logical_up_total: Option<AtomicU64>,
    logical_down_total: Option<AtomicU64>,
    gateway_up_total: Option<AtomicU64>,
    gateway_down_total: Option<AtomicU64>,
    gateway_send_failures_total: AtomicU64,
    gateway_up_meter: Option<ConcurrentTrafficMeter>,
    gateway_down_meter: Option<ConcurrentTrafficMeter>,
}

impl DataPlaneStats {
    pub fn new(enable_traffic: bool) -> Self {
        Self {
            inner: Arc::new(DataPlaneStatsInner {
                up_traffic_meter: enable_traffic.then(TrafficMeterMultiChannel::default),
                down_traffic_meter: enable_traffic.then(TrafficMeterMultiChannel::default),
                up_peer_traffic_meter: enable_traffic.then(TrafficMeterMultiAddress::default),
                down_peer_traffic_meter: enable_traffic.then(TrafficMeterMultiAddress::default),
                up_transport_traffic_meter: enable_traffic.then(TrafficMeterMultiIpAddr::default),
                down_transport_traffic_meter: enable_traffic.then(TrafficMeterMultiIpAddr::default),
                logical_up_total: enable_traffic.then(|| AtomicU64::new(0)),
                logical_down_total: enable_traffic.then(|| AtomicU64::new(0)),
                gateway_up_total: enable_traffic.then(|| AtomicU64::new(0)),
                gateway_down_total: enable_traffic.then(|| AtomicU64::new(0)),
                gateway_send_failures_total: AtomicU64::new(0),
                gateway_up_meter: enable_traffic.then(|| ConcurrentTrafficMeter::new(100)),
                gateway_down_meter: enable_traffic.then(|| ConcurrentTrafficMeter::new(100)),
            }),
        }
    }

    pub fn record_up(&self, channel: usize, len: usize) {
        if let Some(up_traffic_meter) = &self.inner.up_traffic_meter {
            up_traffic_meter.add_traffic(channel, len);
        }
    }

    pub fn record_down(&self, channel: usize, len: usize) {
        if let Some(down_traffic_meter) = &self.inner.down_traffic_meter {
            down_traffic_meter.add_traffic(channel, len);
        }
    }

    pub fn record_peer_up(&self, vip: Ipv4Addr, len: usize) {
        if let Some(up_peer_traffic_meter) = &self.inner.up_peer_traffic_meter {
            up_peer_traffic_meter.add_traffic(vip, len);
        }
    }

    pub fn record_peer_down(&self, vip: Ipv4Addr, len: usize) {
        if let Some(down_peer_traffic_meter) = &self.inner.down_peer_traffic_meter {
            down_peer_traffic_meter.add_traffic(vip, len);
        }
    }

    pub fn record_logical_up(&self, len: usize) {
        if let Some(logical_up_total) = &self.inner.logical_up_total {
            logical_up_total.fetch_add(len as u64, Ordering::Relaxed);
        }
    }

    pub fn record_logical_down(&self, len: usize) {
        if let Some(logical_down_total) = &self.inner.logical_down_total {
            logical_down_total.fetch_add(len as u64, Ordering::Relaxed);
        }
    }

    pub fn record_transport_up(&self, ip: IpAddr, len: usize) {
        if let Some(up_transport_traffic_meter) = &self.inner.up_transport_traffic_meter {
            up_transport_traffic_meter.add_traffic(ip, len);
        }
    }

    pub fn record_transport_down(&self, ip: IpAddr, len: usize) {
        if let Some(down_transport_traffic_meter) = &self.inner.down_transport_traffic_meter {
            down_transport_traffic_meter.add_traffic(ip, len);
        }
    }

    pub fn record_gateway_up(&self, len: usize) {
        if let Some(gateway_up_total) = &self.inner.gateway_up_total {
            gateway_up_total.fetch_add(len as u64, Ordering::Relaxed);
        }
        if let Some(gateway_up_meter) = &self.inner.gateway_up_meter {
            gateway_up_meter.add_traffic(len);
        }
    }

    pub fn record_gateway_down(&self, len: usize) {
        if let Some(gateway_down_total) = &self.inner.gateway_down_total {
            gateway_down_total.fetch_add(len as u64, Ordering::Relaxed);
        }
        if let Some(gateway_down_meter) = &self.inner.gateway_down_meter {
            gateway_down_meter.add_traffic(len);
        }
    }

    /// Socket-level relay failures, separate from end-to-end probe health.
    pub fn record_gateway_send_failure(&self) {
        self.inner
            .gateway_send_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn gateway_send_failures_total(&self) -> u64 {
        self.inner
            .gateway_send_failures_total
            .load(Ordering::Relaxed)
    }

    pub fn up_traffic_total(&self) -> u64 {
        self.inner
            .up_traffic_meter
            .as_ref()
            .map_or(0, |v| v.total())
    }

    pub fn up_traffic_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.inner.up_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn up_traffic_history(&self) -> Option<ChannelTrafficHistory> {
        self.inner
            .up_traffic_meter
            .as_ref()
            .map(|v| v.get_all_history())
    }

    pub fn down_traffic_total(&self) -> u64 {
        self.inner
            .down_traffic_meter
            .as_ref()
            .map_or(0, |v| v.total())
    }

    pub fn down_traffic_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.inner.down_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn down_traffic_history(&self) -> Option<ChannelTrafficHistory> {
        self.inner
            .down_traffic_meter
            .as_ref()
            .map(|v| v.get_all_history())
    }

    pub fn up_peer_traffic_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.inner
            .up_peer_traffic_meter
            .as_ref()
            .map(|v| v.get_all())
    }

    pub fn down_peer_traffic_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.inner
            .down_peer_traffic_meter
            .as_ref()
            .map(|v| v.get_all())
    }

    pub fn up_peer_traffic_rates(&self, window_secs: usize) -> Option<HashMap<Ipv4Addr, u64>> {
        self.inner
            .up_peer_traffic_meter
            .as_ref()
            .map(|v| v.get_all_rates(window_secs))
    }

    pub fn down_peer_traffic_rates(&self, window_secs: usize) -> Option<HashMap<Ipv4Addr, u64>> {
        self.inner
            .down_peer_traffic_meter
            .as_ref()
            .map(|v| v.get_all_rates(window_secs))
    }

    pub fn up_peer_active_speeds(&self) -> Option<HashMap<Ipv4Addr, u64>> {
        self.inner
            .up_peer_traffic_meter
            .as_ref()
            .map(|v| v.get_all_active_speeds())
    }

    pub fn down_peer_active_speeds(&self) -> Option<HashMap<Ipv4Addr, u64>> {
        self.inner
            .down_peer_traffic_meter
            .as_ref()
            .map(|v| v.get_all_active_speeds())
    }

    pub fn up_transport_traffic_all(&self) -> Option<(u64, HashMap<IpAddr, u64>)> {
        self.inner
            .up_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all())
    }

    pub fn down_transport_traffic_all(&self) -> Option<(u64, HashMap<IpAddr, u64>)> {
        self.inner
            .down_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all())
    }

    pub fn up_transport_traffic_rates(&self, window_secs: usize) -> Option<HashMap<IpAddr, u64>> {
        self.inner
            .up_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all_rates(window_secs))
    }

    pub fn down_transport_traffic_rates(&self, window_secs: usize) -> Option<HashMap<IpAddr, u64>> {
        self.inner
            .down_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all_rates(window_secs))
    }

    pub fn up_transport_active_speeds(&self) -> Option<HashMap<IpAddr, u64>> {
        self.inner
            .up_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all_active_speeds())
    }

    pub fn down_transport_active_speeds(&self) -> Option<HashMap<IpAddr, u64>> {
        self.inner
            .down_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all_active_speeds())
    }

    pub fn logical_up_total(&self) -> u64 {
        self.inner
            .logical_up_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn logical_down_total(&self) -> u64 {
        self.inner
            .logical_down_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn gateway_up_total(&self) -> u64 {
        self.inner
            .gateway_up_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn gateway_down_total(&self) -> u64 {
        self.inner
            .gateway_down_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn gateway_up_rate(&self, window_secs: usize) -> u64 {
        self.inner
            .gateway_up_meter
            .as_ref()
            .map(|v| v.rate_per_sec(window_secs))
            .unwrap_or(0)
    }

    pub fn gateway_down_rate(&self, window_secs: usize) -> u64 {
        self.inner
            .gateway_down_meter
            .as_ref()
            .map(|v| v.rate_per_sec(window_secs))
            .unwrap_or(0)
    }

    pub fn gateway_up_active_speed(&self) -> u64 {
        self.inner
            .gateway_up_meter
            .as_ref()
            .map(|v| v.active_speed_per_sec())
            .unwrap_or(0)
    }

    pub fn gateway_down_active_speed(&self) -> u64 {
        self.inner
            .gateway_down_meter
            .as_ref()
            .map(|v| v.active_speed_per_sec())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_counters_and_traffic_meters() {
        let stats = DataPlaneStats::new(true);
        let clone = stats.clone();
        assert!(Arc::ptr_eq(&stats.inner, &clone.inner));
        let vip = Ipv4Addr::new(10, 26, 0, 2);
        let ip = IpAddr::V4(vip);

        clone.record_up(1, 11);
        clone.record_down(1, 13);
        clone.record_peer_up(vip, 17);
        clone.record_peer_down(vip, 19);
        clone.record_transport_up(ip, 23);
        clone.record_transport_down(ip, 29);
        clone.record_logical_up(31);
        clone.record_logical_down(37);
        clone.record_gateway_up(41);
        clone.record_gateway_down(43);
        clone.record_gateway_send_failure();

        assert_eq!(stats.up_traffic_total(), 11);
        assert_eq!(stats.down_traffic_total(), 13);
        assert_eq!(stats.up_peer_traffic_all().unwrap().1[&vip], 17);
        assert_eq!(stats.down_peer_traffic_all().unwrap().1[&vip], 19);
        assert_eq!(stats.up_transport_traffic_all().unwrap().1[&ip], 23);
        assert_eq!(stats.down_transport_traffic_all().unwrap().1[&ip], 29);
        assert_eq!(stats.logical_up_total(), 31);
        assert_eq!(stats.logical_down_total(), 37);
        assert_eq!(stats.gateway_up_total(), 41);
        assert_eq!(stats.gateway_down_total(), 43);
        assert_eq!(
            stats.inner.gateway_up_meter.as_ref().unwrap().get_history(),
            clone.inner.gateway_up_meter.as_ref().unwrap().get_history()
        );
        assert_eq!(stats.gateway_send_failures_total(), 1);

        stats.record_gateway_send_failure();
        assert_eq!(clone.gateway_send_failures_total(), 2);
    }

    #[test]
    fn disabled_traffic_still_shares_gateway_failure_accounting() {
        let stats = DataPlaneStats::new(false);
        let clone = stats.clone();
        clone.record_up(1, 11);
        clone.record_down(1, 13);
        clone.record_peer_up(Ipv4Addr::LOCALHOST, 17);
        clone.record_transport_down(IpAddr::V4(Ipv4Addr::LOCALHOST), 19);
        clone.record_logical_up(23);
        clone.record_logical_down(29);
        clone.record_gateway_up(31);
        clone.record_gateway_down(37);
        clone.record_gateway_send_failure();
        assert_eq!(stats.up_traffic_total(), 0);
        assert_eq!(stats.down_traffic_total(), 0);
        assert!(stats.up_peer_traffic_all().is_none());
        assert!(stats.down_transport_traffic_all().is_none());
        assert_eq!(stats.logical_up_total(), 0);
        assert_eq!(stats.logical_down_total(), 0);
        assert_eq!(stats.gateway_up_total(), 0);
        assert_eq!(stats.gateway_down_total(), 0);
        assert_eq!(stats.gateway_up_rate(1), 0);
        assert_eq!(stats.gateway_down_rate(1), 0);
        assert_eq!(stats.gateway_send_failures_total(), 1);
    }

    #[test]
    fn concurrent_clones_accumulate_in_the_same_atomic_counters() {
        let stats = DataPlaneStats::new(true);
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let clone = stats.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        clone.record_logical_up(1);
                        clone.record_logical_down(2);
                        clone.record_gateway_send_failure();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(stats.logical_up_total(), 4000);
        assert_eq!(stats.logical_down_total(), 8000);
        assert_eq!(stats.gateway_send_failures_total(), 4000);
    }
}
