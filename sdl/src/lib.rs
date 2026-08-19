#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    pub package_name: &'static str,
    pub package_version: &'static str,
    pub git_tag: &'static str,
    pub git_commit: &'static str,
    pub serial: &'static str,
}

pub const BUILD_INFO: BuildInfo = BuildInfo {
    package_name: env!("CARGO_PKG_NAME"),
    package_version: env!("CARGO_PKG_VERSION"),
    git_tag: env!("SDL_BUILD_GIT_TAG"),
    git_commit: env!("SDL_BUILD_GIT_COMMIT"),
    serial: env!("SDL_BUILD_SERIAL"),
};

pub fn build_version_string() -> String {
    let version = if BUILD_INFO.git_tag.is_empty() {
        "main"
    } else {
        BUILD_INFO.git_tag
    };
    if BUILD_INFO.git_commit.is_empty() {
        format!("{version} (serial {})", BUILD_INFO.serial)
    } else {
        format!(
            "{version} (commit {}, serial {})",
            BUILD_INFO.git_commit, BUILD_INFO.serial
        )
    }
}

pub const SDL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cipher;
pub mod control;
pub mod core;
pub mod data_plane;
pub mod handle;
pub mod nat;
pub mod net;
#[cfg(feature = "port_mapping")]
mod port_mapping;
mod proto;
pub mod protocol;
pub mod transport;
mod tun_tap_device;
pub use tun_tap_device::*;
pub mod util;

pub use handle::callback::*;

pub mod compression;
pub use sdl_packet;

pub(crate) fn ensure_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

pub(crate) fn ignore_io_interrupted(e: std::io::Error) -> std::io::Result<()> {
    if e.kind() == std::io::ErrorKind::Interrupted {
        log::warn!("ignore_io_interrupted");
        Ok(())
    } else {
        Err(e)
    }
}
