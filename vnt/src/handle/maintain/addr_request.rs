use std::sync::Arc;
use std::time::Duration;

use crate::channel::punch::NatType;
use crate::core::VntRuntime;
use crate::util::Scheduler;

pub fn addr_request(scheduler: &Scheduler, runtime: Arc<VntRuntime>) {
    pub_address_request(scheduler, runtime, 0);
}

fn pub_address_request(scheduler: &Scheduler, runtime: Arc<VntRuntime>, count: usize) {
    let channel_num = runtime.channel_num();
    let index = count % channel_num;
    if let Err(e) = addr_request0(runtime.as_ref(), index) {
        log::warn!("{:?}", e);
    }
    let nat_info = runtime.nat_test.nat_info();
    let time = if !nat_info.public_ports.contains(&0) && !nat_info.public_ips.is_empty() {
        //对称网络探测端口没啥作用，把频率放低，（锥形网络也只在打洞前需要探测端口，后续可以改改）
        if nat_info.nat_type == NatType::Symmetric {
            600
        } else {
            if index == channel_num - 1 {
                19
            } else {
                9
            }
        }
    } else {
        3
    };

    let rs = scheduler.timeout(Duration::from_secs(time), move |s| {
        pub_address_request(s, runtime, index + 1)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn addr_request0(runtime: &VntRuntime, index: usize) -> anyhow::Result<()> {
    let current_dev = runtime.current_device.load();
    if current_dev.status.offline() {
        return Ok(());
    }
    let (data, addr) = runtime.nat_test.send_data()?;
    runtime.udp_channel.send_main(index, &data, addr)?;
    Ok(())
}
