pub(crate) mod forward;
#[cfg(all(feature = "integrated_tun", target_os = "linux"))]
pub(crate) mod linux;
pub(crate) mod local;
#[cfg(any(test, all(feature = "integrated_tun", target_os = "macos")))]
pub(crate) mod macos;
#[cfg(all(
    feature = "integrated_tun",
    any(target_os = "windows", target_os = "linux", target_os = "macos")
))]
pub(crate) mod platform;
pub(crate) mod query;
pub(crate) mod tunnel;
#[cfg(all(feature = "integrated_tun", target_os = "windows"))]
pub(crate) mod windows;
