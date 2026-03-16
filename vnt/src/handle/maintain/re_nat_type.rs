use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::core::VntRuntime;
use crate::nat;
use crate::util::Scheduler;

/// 10分钟探测一次nat
pub fn retrieve_nat_type(scheduler: &Scheduler, runtime: Arc<VntRuntime>) {
    retrieve_nat_type0(runtime.clone());
    scheduler.timeout(Duration::from_secs(60 * 10), move |s| {
        retrieve_nat_type(s, runtime)
    });
}

fn retrieve_nat_type0(runtime: Arc<VntRuntime>) {
    thread::Builder::new()
        .name("natTest".into())
        .spawn(move || {
            if runtime.nat_test.can_update() {
                let local_ipv4 = if runtime.nat_test.update_local_ipv4 {
                    nat::local_ipv4()
                } else {
                    None
                };
                let local_ipv6 = nat::local_ipv6();
                match runtime.nat_test.re_test(
                    local_ipv4,
                    local_ipv6,
                    &runtime.config.default_interface,
                ) {
                    Ok(nat_info) => {
                        log::info!("当前nat信息:{:?}", nat_info);
                    }
                    Err(e) => {
                        log::warn!("nat re_test {:?}", e);
                    }
                };
                #[cfg(feature = "upnp")]
                runtime.nat_test.reset_upnp();
                log::info!("刷新nat结束")
            }
        })
        .expect("natTest");
}
