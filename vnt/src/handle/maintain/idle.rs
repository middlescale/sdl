use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;

use crate::channel::context::ChannelContext;
use crate::channel::idle::Idle;
use crate::handle::maintain::route_maintenance;
use crate::handle::CurrentDeviceInfo;
use crate::util::Scheduler;
use crate::VntCallback;

pub fn idle_route<Call: VntCallback>(
    scheduler: &Scheduler,
    idle: Idle,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    call: Call,
) {
    let delay = idle_route0(&idle, &context, &current_device_info, &call);
    let rs = scheduler.timeout(delay, move |s| {
        idle_route(s, idle, context, current_device_info, call)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn idle_route0<Call: VntCallback>(
    idle: &Idle,
    context: &ChannelContext,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    call: &Call,
) -> Duration {
    route_maintenance::next_cleanup_delay(idle, context, current_device, call)
}
