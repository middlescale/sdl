use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct TrafficMeterMultiAddress {
    history_capacity: usize,
    inner: Arc<Mutex<(u64, HashMap<Ipv4Addr, TrafficMeter>)>>,
}

#[derive(Clone)]
pub struct TrafficMeterMultiIpAddr {
    history_capacity: usize,
    inner: Arc<Mutex<(u64, HashMap<IpAddr, TrafficMeter>)>>,
}

impl Default for TrafficMeterMultiIpAddr {
    fn default() -> Self {
        TrafficMeterMultiIpAddr::new(100)
    }
}

impl TrafficMeterMultiIpAddr {
    pub fn new(history_capacity: usize) -> Self {
        let inner = Arc::new(Mutex::new((0, HashMap::new())));
        Self {
            inner,
            history_capacity,
        }
    }
    pub fn add_traffic(&self, ip: IpAddr, amount: usize) {
        let mut guard = self.inner.lock();
        guard.0 += amount as u64;
        guard
            .1
            .entry(ip)
            .or_insert(TrafficMeter::new(self.history_capacity))
            .add_traffic(amount)
    }
    pub fn total(&self) -> u64 {
        self.inner.lock().0
    }
    pub fn get_all(&self) -> (u64, HashMap<IpAddr, u64>) {
        let guard = self.inner.lock();
        (
            guard.0,
            guard.1.iter().map(|(ip, t)| (*ip, t.total())).collect(),
        )
    }
    pub fn get_all_rates(&self, window_secs: usize) -> HashMap<IpAddr, u64> {
        let mut guard = self.inner.lock();
        guard
            .1
            .iter_mut()
            .map(|(ip, t)| (*ip, t.rate_per_sec(window_secs)))
            .collect()
    }
}

impl Default for TrafficMeterMultiAddress {
    fn default() -> Self {
        TrafficMeterMultiAddress::new(100)
    }
}

impl TrafficMeterMultiAddress {
    pub fn new(history_capacity: usize) -> Self {
        let inner = Arc::new(Mutex::new((0, HashMap::new())));
        Self {
            inner,
            history_capacity,
        }
    }
    pub fn add_traffic(&self, ip: Ipv4Addr, amount: usize) {
        let mut guard = self.inner.lock();
        guard.0 += amount as u64;
        guard
            .1
            .entry(ip)
            .or_insert(TrafficMeter::new(self.history_capacity))
            .add_traffic(amount)
    }
    pub fn total(&self) -> u64 {
        self.inner.lock().0
    }
    pub fn get_all(&self) -> (u64, HashMap<Ipv4Addr, u64>) {
        let guard = self.inner.lock();
        (
            guard.0,
            guard.1.iter().map(|(ip, t)| (*ip, t.total())).collect(),
        )
    }
    pub fn get_all_history(&self) -> (u64, HashMap<Ipv4Addr, (u64, Vec<usize>)>) {
        let guard = self.inner.lock();
        (
            guard.0,
            guard
                .1
                .iter()
                .map(|(ip, t)| (*ip, (t.total(), t.get_history())))
                .collect(),
        )
    }
    pub fn get_history(&self, ip: &Ipv4Addr) -> Option<(u64, Vec<usize>)> {
        self.inner
            .lock()
            .1
            .get(ip)
            .map(|t| (t.total(), t.get_history()))
    }
    pub fn get_all_rates(&self, window_secs: usize) -> HashMap<Ipv4Addr, u64> {
        let mut guard = self.inner.lock();
        guard
            .1
            .iter_mut()
            .map(|(ip, t)| (*ip, t.rate_per_sec(window_secs)))
            .collect()
    }
}

#[derive(Clone)]
pub struct TrafficMeterMultiChannel {
    history_capacity: usize,
    inner: Arc<Mutex<(u64, HashMap<usize, TrafficMeter>)>>,
}

impl Default for TrafficMeterMultiChannel {
    fn default() -> Self {
        TrafficMeterMultiChannel::new(100)
    }
}

impl TrafficMeterMultiChannel {
    pub fn new(history_capacity: usize) -> Self {
        let inner = Arc::new(Mutex::new((0, HashMap::new())));
        Self {
            inner,
            history_capacity,
        }
    }
    pub fn add_traffic(&self, channel: usize, amount: usize) {
        let mut guard = self.inner.lock();
        guard.0 += amount as u64;
        guard
            .1
            .entry(channel)
            .or_insert(TrafficMeter::new(self.history_capacity))
            .add_traffic(amount)
    }
    pub fn total(&self) -> u64 {
        self.inner.lock().0
    }
    pub fn get_all(&self) -> (u64, HashMap<usize, u64>) {
        let guard = self.inner.lock();
        (
            guard.0,
            guard
                .1
                .iter()
                .map(|(channel, t)| (*channel, t.total()))
                .collect(),
        )
    }
    pub fn get_all_history(&self) -> (u64, HashMap<usize, (u64, Vec<usize>)>) {
        let guard = self.inner.lock();
        (
            guard.0,
            guard
                .1
                .iter()
                .map(|(channel, t)| (*channel, (t.total(), t.get_history())))
                .collect(),
        )
    }
}

#[derive(Clone)]
pub struct ConcurrentTrafficMeter {
    inner: Arc<Mutex<TrafficMeter>>,
}

impl ConcurrentTrafficMeter {
    pub fn new(history_capacity: usize) -> Self {
        let inner = Arc::new(Mutex::new(TrafficMeter::new(history_capacity)));
        Self { inner }
    }
    pub fn add_traffic(&self, amount: usize) {
        self.inner.lock().add_traffic(amount)
    }
    pub fn get_history(&self) -> Vec<usize> {
        self.inner.lock().get_history()
    }
    pub fn rate_per_sec(&self, window_secs: usize) -> u64 {
        self.inner.lock().rate_per_sec(window_secs)
    }
}

pub struct TrafficMeter {
    start_time: Instant,
    total: u64,
    count: usize,
    history_capacity: usize,
    history: VecDeque<usize>,
}

impl TrafficMeter {
    // 初始化一个新的 TrafficMeter
    pub fn new(history_capacity: usize) -> Self {
        Self {
            start_time: Instant::now(),
            total: 0,
            count: 0,
            history: VecDeque::with_capacity(history_capacity),
            history_capacity,
        }
    }

    // 增加流量计数
    pub fn add_traffic(&mut self, amount: usize) {
        self.check_time();
        self.total += amount as u64;
        self.count += amount;
    }

    fn check_time(&mut self) {
        self.roll_to_now();
    }

    fn push_sample(&mut self, count: usize) {
        if self.history.len() >= self.history_capacity {
            self.history.pop_front();
        }
        self.history.push_back(count);
    }

    fn roll_to_now(&mut self) {
        let elapsed_secs = self.start_time.elapsed().as_secs() as usize;
        if elapsed_secs == 0 {
            return;
        }
        self.push_sample(self.count);
        let zero_samples = elapsed_secs.saturating_sub(1).min(self.history_capacity);
        for _ in 0..zero_samples {
            self.push_sample(0);
        }
        self.count = 0;
        self.start_time = Instant::now();
    }
    pub fn total(&self) -> u64 {
        self.total
    }
    // 获取流量记录
    pub fn get_history(&self) -> Vec<usize> {
        self.history.iter().cloned().collect()
    }
    pub fn rate_per_sec(&mut self, window_secs: usize) -> u64 {
        self.roll_to_now();
        let window_secs = window_secs.max(1);
        let mut samples: Vec<usize> = self
            .history
            .iter()
            .rev()
            .take(window_secs)
            .copied()
            .collect();
        samples.push(self.count);
        let bytes: usize = samples.iter().sum();
        (bytes / window_secs) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::{ConcurrentTrafficMeter, TrafficMeterMultiChannel};
    use std::time::{Duration, Instant};

    #[test]
    fn multi_channel_meter_tracks_total_and_per_channel_usage() {
        let meter = TrafficMeterMultiChannel::new(4);
        meter.add_traffic(0, 10);
        meter.add_traffic(1, 20);
        meter.add_traffic(0, 5);

        let (total, by_channel) = meter.get_all();
        assert_eq!(total, 35);
        assert_eq!(by_channel.get(&0), Some(&15));
        assert_eq!(by_channel.get(&1), Some(&20));
    }

    #[test]
    fn multi_channel_meter_exposes_history_per_channel() {
        let meter = TrafficMeterMultiChannel::new(4);
        meter.add_traffic(2, 7);
        {
            let mut guard = meter.inner.lock();
            let channel_meter = guard.1.get_mut(&2).expect("channel meter");
            channel_meter.start_time = Instant::now() - Duration::from_secs(2);
        }
        meter.add_traffic(2, 3);

        let (total, history) = meter.get_all_history();
        assert_eq!(total, 10);
        let (channel_total, samples) = history.get(&2).expect("channel history");
        assert_eq!(*channel_total, 10);
        assert_eq!(samples, &vec![7, 0]);
    }

    #[test]
    fn concurrent_meter_rate_drops_to_zero_after_idle_window() {
        let meter = ConcurrentTrafficMeter::new(8);
        meter.add_traffic(500);
        {
            let mut guard = meter.inner.lock();
            guard.start_time = Instant::now() - Duration::from_secs(10);
        }

        assert_eq!(meter.rate_per_sec(5), 0);
    }

    #[test]
    fn concurrent_meter_rate_uses_recent_window() {
        let meter = ConcurrentTrafficMeter::new(8);
        meter.add_traffic(500);

        assert_eq!(meter.rate_per_sec(5), 100);
    }

    #[test]
    fn concurrent_meter_counts_first_packet_after_idle_in_current_window() {
        let meter = ConcurrentTrafficMeter::new(8);
        meter.add_traffic(100);
        {
            let mut guard = meter.inner.lock();
            guard.start_time = Instant::now() - Duration::from_secs(10);
        }
        meter.add_traffic(500);

        assert_eq!(meter.rate_per_sec(5), 100);
    }
}
