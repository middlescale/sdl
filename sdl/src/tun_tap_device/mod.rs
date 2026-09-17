#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) use create_device::create_device;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) mod create_device;
pub(crate) mod tun_create_helper;

pub mod vnt_device;
