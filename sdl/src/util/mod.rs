mod notify;
pub use notify::{StopManager, Worker};

// mod counter;
// pub use counter::*;

mod dns_query;
pub(crate) mod dns_tunnel;
pub use dns_query::*;
mod device_identity;
pub use device_identity::*;
#[cfg(all(feature = "integrated_tun", target_os = "linux"))]
pub(crate) mod linux_dns;
#[cfg(any(test, all(feature = "integrated_tun", target_os = "macos")))]
pub(crate) mod macos_dns;
mod peer_crypto_manager;
#[cfg(any(test, all(feature = "integrated_tun", target_os = "windows")))]
pub(crate) mod windows_dns;
pub use peer_crypto_manager::*;

#[cfg(feature = "upnp")]
mod upnp;
#[cfg(feature = "upnp")]
pub use upnp::*;

pub mod limit;
