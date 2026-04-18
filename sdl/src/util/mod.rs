mod notify;
pub use notify::{StopManager, Worker};

// mod counter;
// pub use counter::*;

mod dns_query;
pub(crate) mod dns_tunnel;
pub use dns_query::*;
mod device_identity;
pub use device_identity::*;
mod debug_watch;
pub use debug_watch::*;
#[cfg(all(feature = "integrated_tun", target_os = "linux"))]
pub(crate) mod linux_dns;
#[cfg(any(test, all(feature = "integrated_tun", target_os = "macos")))]
pub(crate) mod macos_dns;
mod peer_discovery_noise;
mod peer_ingress_limiter;
mod peer_replay_guard;
mod peer_session_manager;
mod peer_setup_limiter;
#[cfg(any(test, all(feature = "integrated_tun", target_os = "windows")))]
pub(crate) mod windows_dns;
pub use peer_discovery_noise::*;
pub use peer_ingress_limiter::*;
pub use peer_replay_guard::*;
pub use peer_session_manager::*;
pub use peer_setup_limiter::*;

#[cfg(feature = "upnp")]
mod upnp;
#[cfg(feature = "upnp")]
pub use upnp::*;

pub mod limit;
