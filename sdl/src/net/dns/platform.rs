use std::io;

use crate::DnsProfile;

pub(crate) fn apply_split_dns(
    interface_name: &str,
    previous_profile: Option<&DnsProfile>,
    profile: &DnsProfile,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return crate::net::dns::linux::apply_split_dns(interface_name, previous_profile, profile);
    }
    #[cfg(target_os = "macos")]
    {
        crate::net::dns::macos::apply_split_dns(interface_name, previous_profile, profile)
            .map(|_| ())
    }
    #[cfg(target_os = "windows")]
    {
        crate::net::dns::windows::apply_split_dns(interface_name, previous_profile, profile)
            .map(|_| ())
    }
}

pub(crate) fn revert_split_dns(
    interface_name: Option<&str>,
    previous_profile: Option<&DnsProfile>,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if let Some(interface_name) = interface_name {
            return crate::net::dns::linux::revert_split_dns(interface_name, previous_profile);
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let _ = interface_name;
        crate::net::dns::macos::revert_split_dns(previous_profile)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = interface_name;
        crate::net::dns::windows::revert_split_dns(previous_profile)
    }
}
