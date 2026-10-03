use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tun_rs::SyncDevice;

use crate::net::system_route::add_route;
use crate::{DeviceConfig, ErrorInfo, ErrorType};

#[cfg(any(target_os = "windows", target_os = "linux"))]
const DEFAULT_TUN_NAME: &str = "sdl-tun";

pub fn create_device(config: DeviceConfig) -> Result<Arc<SyncDevice>, ErrorInfo> {
    let device = match create_sync_device(&config) {
        Ok(device) => device,
        Err(e) => {
            return Err(ErrorInfo::new_msg(
                ErrorType::FailedToCreateDevice,
                format!("create device {:?}", e),
            ));
        }
    };
    #[cfg(windows)]
    let index = device.if_index().unwrap();
    #[cfg(unix)]
    let index = &device.name().unwrap();
    if let Err(e) = add_route(index, Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST) {
        log::warn!("添加广播路由失败 ={:?}", e);
    }

    if let Err(e) = add_route(
        index,
        Ipv4Addr::from([224, 0, 0, 0]),
        Ipv4Addr::from([240, 0, 0, 0]),
    ) {
        log::warn!("添加组播路由失败 ={:?}", e);
    }

    Ok(device)
}

fn create_sync_device(config: &DeviceConfig) -> io::Result<Arc<SyncDevice>> {
    let mut tun_builder = tun_rs::DeviceBuilder::new();
    tun_builder = tun_builder.ipv4(config.virtual_ip, config.virtual_netmask, None);

    match &config.device_name {
        None => {
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            {
                tun_builder = tun_builder.name(DEFAULT_TUN_NAME);
            }
        }
        Some(name) => {
            tun_builder = tun_builder.name(name);
        }
    }

    #[cfg(target_os = "windows")]
    {
        tun_builder = tun_builder.metric(0).ring_capacity(4 * 1024 * 1024);
    }

    #[cfg(target_os = "linux")]
    {
        let device_name = config
            .device_name
            .clone()
            .unwrap_or(DEFAULT_TUN_NAME.to_string());
        delete_device(&device_name);
        let device = tun_builder.mtu(config.mtu as u16).build_sync()?;
        device.set_nonblocking(true)?;
        set_device_up(&device_name)?;
        Ok(Arc::new(device))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let device = tun_builder.mtu(config.mtu as u16).build_sync()?;
        Ok(Arc::new(device))
    }
}

#[cfg(target_os = "linux")]
fn delete_device(name: &str) {
    // 删除默认网卡，此操作有风险，后续可能去除
    use std::process::Command;
    let cmd = format!("ip link delete {}", name);
    let delete_tun = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("sh exec error!");
    if !delete_tun.status.success() {
        log::warn!("删除网卡失败:{:?}", delete_tun);
    }
}

#[cfg(target_os = "linux")]
fn set_device_up(name: &str) -> io::Result<()> {
    use std::process::Command;

    let cmd = format!("ip link set dev {} up", name);
    let out = Command::new("sh").arg("-c").arg(&cmd).output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={},out={:?}", cmd, out),
        ));
    }
    Ok(())
}
