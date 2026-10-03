#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) use create::create_device;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) mod create;
pub(crate) mod io;
mod subsystem;
mod writer;

pub(crate) use subsystem::{TunSubsystem, TunTransition};
pub(crate) use writer::TunDeviceWriter;
