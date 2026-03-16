use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;

use crate::channel::context::ChannelContext;
use crate::channel::idle::{Idle, IdleType};
use crate::handle::callback::{ErrorType, VntCallback};
use crate::handle::{change_status, ConnectStatus, CurrentDeviceInfo};
use crate::ErrorInfo;

pub fn next_cleanup_delay<Call: VntCallback>(
    idle: &Idle,
    context: &ChannelContext,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    call: &Call,
) -> Duration {
    let cur = current_device.load();
    match idle.next_idle() {
        IdleType::Timeout(ip, route) => {
            log::info!("route Timeout {:?},{:?}", ip, route);
            context.remove_route(&ip, route.route_key());
            if cur.is_gateway_vip(&ip) {
                change_status(current_device, ConnectStatus::Connecting);
                call.error(ErrorInfo::new(ErrorType::Disconnect));
            }
            Duration::from_millis(100)
        }
        IdleType::Sleep(duration) => duration,
        IdleType::None => Duration::from_millis(3000),
    }
}
