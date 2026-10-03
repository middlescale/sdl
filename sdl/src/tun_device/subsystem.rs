use std::io;
use std::sync::{Arc, Weak};
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, MutexGuard};
use tun_rs::SyncDevice;

use super::TunDeviceWriter;
use crate::compression::Compressor;
use crate::core::SdlRuntime;
use crate::handle::tun_tap::DeviceStop;
use crate::util::StopManager;

/// Owns the current TUN device and reader lifetime. Clones share one owner.
#[derive(Clone)]
pub(crate) struct TunSubsystem {
    inner: Arc<TunInner>,
}

struct TunInner {
    suspended: AtomicCell<bool>,
    transition_lock: Mutex<Option<DeviceStop>>,
    writer: TunDeviceWriter,
    stop_manager: StopManager,
    runtime: Weak<SdlRuntime>,
    compressor: Compressor,
}

/// Holds the transition lock across both TUN operations and the runtime's DNS
/// updates. Device start/stop is available only through this locked handle.
pub(crate) struct TunTransition<'a> {
    tun: &'a TunInner,
    reader_stop: MutexGuard<'a, Option<DeviceStop>>,
}

impl TunSubsystem {
    pub(crate) fn new(
        stop_manager: StopManager,
        runtime: Weak<SdlRuntime>,
        compressor: Compressor,
    ) -> Self {
        Self {
            inner: Arc::new(TunInner {
                suspended: AtomicCell::new(false),
                transition_lock: Mutex::new(None),
                writer: TunDeviceWriter::default(),
                stop_manager,
                runtime,
                compressor,
            }),
        }
    }

    pub(crate) fn writer(&self) -> TunDeviceWriter {
        self.inner.writer.clone()
    }

    pub(crate) fn device_name(&self) -> Option<String> {
        self.inner.writer.name()
    }

    pub(crate) fn is_suspended(&self) -> bool {
        self.inner.suspended.load()
    }

    pub(crate) fn transition(&self) -> TunTransition<'_> {
        TunTransition {
            tun: &self.inner,
            reader_stop: self.inner.transition_lock.lock(),
        }
    }
}

impl TunTransition<'_> {
    pub(crate) fn set_suspended(&self, suspended: bool) {
        self.tun.suspended.store(suspended);
    }

    pub(crate) fn is_suspended(&self) -> bool {
        self.tun.suspended.load()
    }

    pub(crate) fn stop_device(&mut self) {
        if let Some(device_stop) = self.reader_stop.take() {
            self.tun.writer.remove();
            loop {
                device_stop.stop();
                std::thread::sleep(Duration::from_millis(300));
                if device_stop.is_stopped() {
                    break;
                }
            }
        }
    }

    pub(crate) fn start_device(&mut self, device: Arc<SyncDevice>) -> io::Result<()> {
        self.tun.writer.insert(device.clone());
        let device_stop = DeviceStop::default();
        let previous = self.reader_stop.replace(device_stop.clone());
        assert!(previous.is_none());
        crate::handle::tun_tap::tun_handler::start(
            self.tun.stop_manager.clone(),
            self.tun.runtime.clone(),
            device,
            self.tun.compressor,
            device_stop,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tun() -> TunSubsystem {
        TunSubsystem::new(StopManager::new(|| {}), Weak::new(), Compressor::None)
    }

    #[test]
    fn clones_share_pause_state_and_transition_lock() {
        let tun = test_tun();
        let clone = tun.clone();
        assert!(!clone.is_suspended());
        let transition = tun.transition();
        transition.set_suspended(true);
        assert!(clone.is_suspended());
        assert!(clone.inner.transition_lock.try_lock().is_none());
        drop(transition);
        assert!(clone.inner.transition_lock.try_lock().is_some());
        clone.transition().set_suspended(false);
        assert!(!tun.is_suspended());
    }

    #[test]
    fn stopping_without_a_device_keeps_shared_writers_unavailable() {
        let tun = test_tun();
        let writer = tun.writer();
        let clone_writer = tun.clone().writer();
        assert_eq!(
            writer.write(&[]).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        tun.transition().stop_device();
        assert!(tun.device_name().is_none());
        assert_eq!(
            clone_writer.write(&[]).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
