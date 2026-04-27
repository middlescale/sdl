pub const SDL_VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub mod cipher;
pub mod control;
pub mod core;
pub mod data_plane;
mod external_route;
pub mod handle;
pub mod nat;
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

#[cfg(feature = "quic")]
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
