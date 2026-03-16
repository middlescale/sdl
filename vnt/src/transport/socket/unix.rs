use crate::transport::socket::{LocalInterface, VntSocketTrait};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;

#[cfg(target_os = "linux")]
impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> anyhow::Result<()> {
        if let Some(name) = &interface.name {
            self.bind_device(Some(name.as_bytes()))
                .context("bind_device")?;
        }
        Ok(())
    }
}
#[cfg(target_os = "macos")]
impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> anyhow::Result<()> {
        if interface.index != 0 {
            self.bind_device_by_index_v4(std::num::NonZeroU32::new(interface.index))
                .with_context(|| format!("bind_device_by_index_v4 {:?}", interface))?;
        }
        Ok(())
    }
}
#[cfg(target_os = "android")]
impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, _interface: &LocalInterface) -> anyhow::Result<()> {
        Ok(())
    }
}
