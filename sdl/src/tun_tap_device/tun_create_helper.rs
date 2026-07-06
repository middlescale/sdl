use std::io;
use std::sync::Arc;

use crate::compression::Compressor;
use crate::core::ExitNodeRoute;
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::CurrentDeviceInfo;
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::{PeerCryptoManager, StopManager};
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tun_rs::SyncDevice;

#[repr(transparent)]
#[derive(Clone, Default)]
pub struct DeviceAdapter {
    tun: Arc<Mutex<Option<Arc<SyncDevice>>>>,
}

impl DeviceAdapter {
    pub fn insert(&self, device: Arc<SyncDevice>) {
        let r = self.tun.lock().replace(device);
        assert!(r.is_none());
    }
    pub fn remove(&self) {
        drop(self.tun.lock().take());
    }
    pub fn name(&self) -> Option<String> {
        self.tun.lock().as_ref().and_then(|tun| tun.name().ok())
    }
}

impl DeviceWrite for DeviceAdapter {
    #[inline]
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
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

    fn into_device_adapter(self) -> DeviceAdapter {
        self
    }
}

#[derive(Clone)]
pub struct TunDeviceHelper {
    inner: Arc<Mutex<TunDeviceHelperInner>>,
    device_adapter: DeviceAdapter,
    device_stop: Arc<Mutex<Option<DeviceStop>>>,
}

#[derive(Clone)]
struct TunDeviceHelperInner {
    stop_manager: StopManager,
    data_channel: DataChannel,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    gateway_sessions: GatewaySessions,
    exit_node_route: ExitNodeRoute,
    peer_state: Arc<Mutex<crate::handle::PeerState>>,
    peer_crypto: Arc<PeerCryptoManager>,
    compressor: Compressor,
}

impl TunDeviceHelper {
    pub fn new(
        stop_manager: StopManager,
        data_channel: DataChannel,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        gateway_sessions: GatewaySessions,
        exit_node_route: ExitNodeRoute,
        peer_state: Arc<Mutex<crate::handle::PeerState>>,
        peer_crypto: Arc<PeerCryptoManager>,
        compressor: Compressor,
        device_adapter: DeviceAdapter,
    ) -> Self {
        let inner = TunDeviceHelperInner {
            stop_manager,
            data_channel,
            current_device,
            gateway_sessions,
            exit_node_route,
            peer_state,
            peer_crypto,
            compressor,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
            device_adapter,
            device_stop: Default::default(),
        }
    }
    pub fn stop(&self) {
        if let Some(device_stop) = self.device_stop.lock().take() {
            self.device_adapter.remove();
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
        self.device_adapter.insert(device.clone());
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
            inner.peer_state,
            inner.peer_crypto,
            inner.compressor,
            device_stop,
        )
    }
    pub fn device_name(&self) -> Option<String> {
        self.device_adapter.name()
    }
}
