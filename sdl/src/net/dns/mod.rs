pub(crate) mod forward;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
pub(crate) mod local;
#[cfg(any(test, target_os = "macos"))]
pub(crate) mod macos;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) mod platform;
pub(crate) mod query;
pub(crate) mod tunnel;
#[cfg(target_os = "windows")]
pub(crate) mod windows;
