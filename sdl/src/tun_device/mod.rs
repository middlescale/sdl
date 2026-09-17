#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) use create::create_device;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) mod create;
pub(crate) mod io;
pub(crate) mod lifecycle;
