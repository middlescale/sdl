//! Saved DNS restoration state and platform-specific DNS operations.
use super::validate_iface_name;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::client_exit_dns_active;
#[cfg(target_os = "linux")]
use linux::{setup_client_dns_platform, teardown_client_dns_platform};
#[cfg(target_os = "macos")]
use macos::{setup_client_dns_platform, teardown_client_dns_platform};
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use unsupported::{setup_client_dns_platform, teardown_client_dns_platform};
#[cfg(target_os = "windows")]
use windows::{setup_client_dns_platform, teardown_client_dns_platform};

pub type ClientDnsState = Vec<ClientDnsServiceState>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientDnsServiceState {
    pub service: String,
    pub restore_servers: Vec<String>,
    pub restore_metric: Option<u32>,
    pub restore_automatic_metric: Option<bool>,
}

pub fn setup_client_dns(
    tun_name: &str,
    dns_service_ip: Ipv4Addr,
    previous_state: Option<&ClientDnsState>,
) -> anyhow::Result<(Option<ClientDnsState>, String)> {
    validate_iface_name(tun_name, "tun name")?;
    setup_client_dns_platform(tun_name, dns_service_ip, previous_state)
}

pub fn teardown_client_dns(state: Option<&ClientDnsState>) -> anyhow::Result<String> {
    teardown_client_dns_platform(state)
}
