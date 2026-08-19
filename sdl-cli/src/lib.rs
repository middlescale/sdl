pub mod app;
pub mod callback;
pub mod cli;
#[cfg(feature = "command")]
pub mod command;
pub mod config;
#[cfg(feature = "command")]
pub mod console_out;
pub mod frontend;
pub mod fs_access;
pub mod root_check;
mod service_lock;
#[cfg(target_os = "windows")]
mod windows_service;

pub(crate) fn build_version_string() -> String {
    sdl::build_version_string()
}
