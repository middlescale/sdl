use crate::compression::Compressor;
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::BUFFER_SIZE;
use crate::util::{PeerCryptoManager, StopManager};
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::sync::Arc;
use tun_rs::InterruptEvent;
use tun_rs::SyncDevice;

pub(crate) fn start_simple(
    stop_manager: StopManager,
    data_channel: &DataChannel,
    device: Arc<SyncDevice>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    gateway_sessions: GatewaySessions,
    ip_route: ExternalRoute,
    peer_state: Arc<Mutex<crate::handle::PeerState>>,
    peer_crypto: Arc<PeerCryptoManager>,
    compressor: Compressor,
    device_stop: DeviceStop,
) -> anyhow::Result<()> {
    let event = Arc::new(InterruptEvent::new()?);

    let worker = {
        let event = event.clone();
        stop_manager.add_listener("tun_device".into(), move || {
            if let Err(e) = event.trigger() {
                log::warn!("interrupt tun device failed: {:?}", e);
            }
        })?
    };
    let worker_cell = Arc::new(AtomicCell::new(Some(worker)));

    {
        let worker_cell = worker_cell.clone();
        device_stop.set_stop_fn(move || {
            if let Some(worker) = worker_cell.take() {
                worker.stop_self()
            }
        });
    }

    if let Err(e) = start_simple0(
        data_channel,
        device,
        &event,
        current_device,
        gateway_sessions,
        ip_route,
        peer_state,
        peer_crypto,
        compressor,
    ) {
        log::error!("{:?}", e);
    }
    device_stop.stopped();
    if let Some(worker) = worker_cell.take() {
        worker.stop_all();
    }
    Ok(())
}

fn start_simple0(
    data_channel: &DataChannel,
    device: Arc<SyncDevice>,
    event: &InterruptEvent,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    gateway_sessions: GatewaySessions,
    ip_route: ExternalRoute,
    peer_state: Arc<Mutex<crate::handle::PeerState>>,
    peer_crypto: Arc<PeerCryptoManager>,
    compressor: Compressor,
) -> anyhow::Result<()> {
    let mut buf = [0; BUFFER_SIZE];
    let mut extend = [0; BUFFER_SIZE];
    loop {
        let len = match device.recv_intr(&mut buf[12..], event) {
            Ok(len) => len + 12,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted && event.is_trigger() {
                    log::info!("tun device interrupted");
                    break;
                }
                return Err(e.into());
            }
        };
        buf[..12].fill(0);
        match crate::handle::tun_tap::tun_handler::handle(
            data_channel,
            &mut buf,
            len,
            &mut extend,
            &device,
            current_device.load(),
            &gateway_sessions,
            &ip_route,
            &peer_state,
            &peer_crypto,
            &compressor,
        ) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("tun/tap {:?}", e)
            }
        }
    }
    Ok(())
}
