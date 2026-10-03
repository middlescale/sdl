use std::io;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use tun_rs::SyncDevice;

/// Stable write capability shared by packet handlers across TUN replacements.
/// Only the owning TUN subsystem can publish or remove the current device.
#[derive(Clone, Default)]
pub(crate) struct TunDeviceWriter {
    tun: Arc<ArcSwapOption<SyncDevice>>,
}

impl TunDeviceWriter {
    pub(super) fn insert(&self, device: Arc<SyncDevice>) {
        let previous = self
            .tun
            .compare_and_swap(&None::<Arc<SyncDevice>>, Some(device));
        assert!(previous.is_none(), "inserting over an existing TUN device");
    }

    pub(super) fn remove(&self) {
        // Unpublish the device without draining in-flight writes. A writer that
        // already loaded it may still send after this returns; its guard keeps
        // the old device alive. This overlap during TUN transitions is accepted
        // so the packet write path does not need a lifecycle lock.
        self.tun.store(None);
    }

    pub(super) fn name(&self) -> Option<String> {
        self.tun.load().as_ref().and_then(|tun| tun.name().ok())
    }

    #[inline]
    pub(crate) fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // SyncDevice supports concurrent writes. This guard keeps the loaded
        // device alive during I/O without serialising writers or TUN removal.
        let device = self.tun.load();
        if let Some(tun) = device.as_ref() {
            #[cfg(target_os = "windows")]
            {
                tun.try_send(buf)
            }
            #[cfg(not(target_os = "windows"))]
            {
                tun.send(buf)
            }
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "not tun device"))
        }
    }
}
