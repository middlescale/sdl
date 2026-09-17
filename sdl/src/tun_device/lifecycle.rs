use std::io;
use std::sync::Arc;

use crate::compression::Compressor;
use crate::core::ExitNodeRoute;
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::CurrentDeviceInfo;
use crate::util::StopManager;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};
use tun_rs::SyncDevice;

#[repr(transparent)]
#[derive(Clone, Default)]
pub(crate) struct TunDeviceWriter {
    tun: Arc<Mutex<Option<Arc<SyncDevice>>>>,
}

impl TunDeviceWriter {
    pub(crate) fn insert(&self, device: Arc<SyncDevice>) {
        let r = self.tun.lock().replace(device);
        assert!(r.is_none());
    }
    pub(crate) fn remove(&self) {
        drop(self.tun.lock().take());
    }
    pub(crate) fn name(&self) -> Option<String> {
        self.tun.lock().as_ref().and_then(|tun| tun.name().ok())
    }
}

impl TunDeviceWriter {
    #[inline]
    pub(crate) fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(tun) = self.tun.lock().as_ref() {
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

#[derive(Clone)]
pub(crate) struct TunDeviceLifecycle {
    inner: Arc<Mutex<TunDeviceLifecycleInner>>,
    device_writer: TunDeviceWriter,
    device_stop: Arc<Mutex<Option<DeviceStop>>>,
}

#[derive(Clone)]
struct TunDeviceLifecycleInner {
    stop_manager: StopManager,
    data_channel: DataChannel,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    gateway_sessions: GatewaySessions,
    exit_node_route: ExitNodeRoute,
    peer_table: Arc<RwLock<crate::core::PeerTable>>,
    peer_crypto: Arc<PeerCryptoManager>,
    compressor: Compressor,
}

impl TunDeviceLifecycle {
    pub fn new(
        stop_manager: StopManager,
        data_channel: DataChannel,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        gateway_sessions: GatewaySessions,
        exit_node_route: ExitNodeRoute,
        peer_table: Arc<RwLock<crate::core::PeerTable>>,
        peer_crypto: Arc<PeerCryptoManager>,
        compressor: Compressor,
        device_writer: TunDeviceWriter,
    ) -> Self {
        let inner = TunDeviceLifecycleInner {
            stop_manager,
            data_channel,
            current_device,
            gateway_sessions,
            exit_node_route,
            peer_table,
            peer_crypto,
            compressor,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
            device_writer,
            device_stop: Default::default(),
        }
    }
    pub fn stop(&self) {
        if let Some(device_stop) = self.device_stop.lock().take() {
            self.device_writer.remove();
            loop {
                device_stop.stop();
                std::thread::sleep(std::time::Duration::from_millis(300));
                if device_stop.is_stopped() {
                    break;
                }
            }
        }
    }
    pub fn start(&self, device: Arc<SyncDevice>) -> io::Result<()> {
        self.device_writer.insert(device.clone());
        let device_stop = DeviceStop::default();
        let s = self.device_stop.lock().replace(device_stop.clone());
        assert!(s.is_none());
        let inner = self.inner.lock().clone();
        crate::handle::tun_tap::tun_handler::start(
            inner.stop_manager,
            inner.data_channel,
            device,
            inner.current_device,
            inner.gateway_sessions,
            inner.exit_node_route,
            inner.peer_table,
            inner.peer_crypto,
            inner.compressor,
            device_stop,
        )
    }
    pub fn device_name(&self) -> Option<String> {
        self.device_writer.name()
    }
}
