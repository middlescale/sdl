use crate::util::limit::TrafficMeterMultiChannel;
use std::collections::HashMap;

#[derive(Clone)]
pub struct DataPlaneStats {
    up_traffic_meter: Option<TrafficMeterMultiChannel>,
    down_traffic_meter: Option<TrafficMeterMultiChannel>,
}

impl DataPlaneStats {
    pub fn new(enable_traffic: bool) -> Self {
        Self {
            up_traffic_meter: enable_traffic.then(TrafficMeterMultiChannel::default),
            down_traffic_meter: enable_traffic.then(TrafficMeterMultiChannel::default),
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
}
