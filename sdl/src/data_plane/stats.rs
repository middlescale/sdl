use crate::util::limit::{
    TrafficMeterMultiAddress, TrafficMeterMultiChannel, TrafficMeterMultiIpAddr,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct DataPlaneStats {
    up_traffic_meter: Option<TrafficMeterMultiChannel>,
    down_traffic_meter: Option<TrafficMeterMultiChannel>,
    up_peer_traffic_meter: Option<TrafficMeterMultiAddress>,
    down_peer_traffic_meter: Option<TrafficMeterMultiAddress>,
    up_transport_traffic_meter: Option<TrafficMeterMultiIpAddr>,
    down_transport_traffic_meter: Option<TrafficMeterMultiIpAddr>,
    logical_up_total: Option<Arc<AtomicU64>>,
    logical_down_total: Option<Arc<AtomicU64>>,
    gateway_up_total: Option<Arc<AtomicU64>>,
    gateway_down_total: Option<Arc<AtomicU64>>,
}

impl DataPlaneStats {
    pub fn new(enable_traffic: bool) -> Self {
        Self {
            up_traffic_meter: enable_traffic.then(TrafficMeterMultiChannel::default),
            down_traffic_meter: enable_traffic.then(TrafficMeterMultiChannel::default),
            up_peer_traffic_meter: enable_traffic.then(TrafficMeterMultiAddress::default),
            down_peer_traffic_meter: enable_traffic.then(TrafficMeterMultiAddress::default),
            up_transport_traffic_meter: enable_traffic.then(TrafficMeterMultiIpAddr::default),
            down_transport_traffic_meter: enable_traffic.then(TrafficMeterMultiIpAddr::default),
            logical_up_total: enable_traffic.then(|| Arc::new(AtomicU64::new(0))),
            logical_down_total: enable_traffic.then(|| Arc::new(AtomicU64::new(0))),
            gateway_up_total: enable_traffic.then(|| Arc::new(AtomicU64::new(0))),
            gateway_down_total: enable_traffic.then(|| Arc::new(AtomicU64::new(0))),
        }
    }

    pub fn record_up(&self, channel: usize, len: usize) {
        if let Some(up_traffic_meter) = &self.up_traffic_meter {
            up_traffic_meter.add_traffic(channel, len);
        }
    }

    pub fn record_down(&self, channel: usize, len: usize) {
        if let Some(down_traffic_meter) = &self.down_traffic_meter {
            down_traffic_meter.add_traffic(channel, len);
        }
    }

    pub fn record_peer_up(&self, vip: Ipv4Addr, len: usize) {
        if let Some(up_peer_traffic_meter) = &self.up_peer_traffic_meter {
            up_peer_traffic_meter.add_traffic(vip, len);
        }
    }

    pub fn record_peer_down(&self, vip: Ipv4Addr, len: usize) {
        if let Some(down_peer_traffic_meter) = &self.down_peer_traffic_meter {
            down_peer_traffic_meter.add_traffic(vip, len);
        }
    }

    pub fn record_logical_up(&self, len: usize) {
        if let Some(logical_up_total) = &self.logical_up_total {
            logical_up_total.fetch_add(len as u64, Ordering::Relaxed);
        }
    }

    pub fn record_logical_down(&self, len: usize) {
        if let Some(logical_down_total) = &self.logical_down_total {
            logical_down_total.fetch_add(len as u64, Ordering::Relaxed);
        }
    }

    pub fn record_transport_up(&self, ip: IpAddr, len: usize) {
        if let Some(up_transport_traffic_meter) = &self.up_transport_traffic_meter {
            up_transport_traffic_meter.add_traffic(ip, len);
        }
    }

    pub fn record_transport_down(&self, ip: IpAddr, len: usize) {
        if let Some(down_transport_traffic_meter) = &self.down_transport_traffic_meter {
            down_transport_traffic_meter.add_traffic(ip, len);
        }
    }

    pub fn record_gateway_up(&self, len: usize) {
        if let Some(gateway_up_total) = &self.gateway_up_total {
            gateway_up_total.fetch_add(len as u64, Ordering::Relaxed);
        }
    }

    pub fn record_gateway_down(&self, len: usize) {
        if let Some(gateway_down_total) = &self.gateway_down_total {
            gateway_down_total.fetch_add(len as u64, Ordering::Relaxed);
        }
    }

    pub fn up_traffic_total(&self) -> u64 {
        self.up_traffic_meter.as_ref().map_or(0, |v| v.total())
    }

    pub fn up_traffic_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn up_traffic_history(&self) -> Option<(u64, HashMap<usize, (u64, Vec<usize>)>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all_history())
    }

    pub fn down_traffic_total(&self) -> u64 {
        self.down_traffic_meter.as_ref().map_or(0, |v| v.total())
    }

    pub fn down_traffic_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.down_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn down_traffic_history(&self) -> Option<(u64, HashMap<usize, (u64, Vec<usize>)>)> {
        self.down_traffic_meter
            .as_ref()
            .map(|v| v.get_all_history())
    }

    pub fn up_peer_traffic_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.up_peer_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn down_peer_traffic_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.down_peer_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn up_transport_traffic_all(&self) -> Option<(u64, HashMap<IpAddr, u64>)> {
        self.up_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all())
    }

    pub fn down_transport_traffic_all(&self) -> Option<(u64, HashMap<IpAddr, u64>)> {
        self.down_transport_traffic_meter
            .as_ref()
            .map(|v| v.get_all())
    }

    pub fn logical_up_total(&self) -> u64 {
        self.logical_up_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn logical_down_total(&self) -> u64 {
        self.logical_down_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn gateway_up_total(&self) -> u64 {
        self.gateway_up_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn gateway_down_total(&self) -> u64 {
        self.gateway_down_total
            .as_ref()
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}
