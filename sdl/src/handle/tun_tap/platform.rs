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
use std::io;
use std::sync::Arc;
use std::time::Duration;
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
    let mut disabled_retry_count = 0u32;
    loop {
        let len = match recv_tun_packet(&device, &mut buf[12..], event) {
            Ok(len) => {
                disabled_retry_count = 0;
                len + 12
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted && event.is_trigger() {
                    log::info!("tun device interrupted");
                    break;
                }
                if is_retryable_interface_disabled_error(&e) {
                    disabled_retry_count = disabled_retry_count.saturating_add(1);
                    if disabled_retry_count == 1 || disabled_retry_count % 10 == 0 {
                        log::warn!(
                            "tun interface temporarily disabled, retrying (attempt {}): {:?}",
                            disabled_retry_count,
                            e
                        );
                    }
                    if event.is_trigger() {
                        log::info!("tun device interrupted while waiting for interface recovery");
                        break;
                    }
                    std::thread::sleep(interface_disabled_retry_delay(disabled_retry_count));
                    continue;
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

#[cfg(target_os = "windows")]
fn recv_tun_packet(
    device: &SyncDevice,
    buf: &mut [u8],
    event: &InterruptEvent,
) -> io::Result<usize> {
    loop {
        if event.is_trigger() {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        match device.try_recv(buf) {
            Ok(len) => return Ok(len),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn recv_tun_packet(
    device: &SyncDevice,
    buf: &mut [u8],
    event: &InterruptEvent,
) -> io::Result<usize> {
    device.recv_intr(buf, event)
}

#[cfg(target_os = "windows")]
fn is_retryable_interface_disabled_error(err: &io::Error) -> bool {
    err.to_string()
        .to_ascii_lowercase()
        .contains("interface has been disabled")
}

#[cfg(not(target_os = "windows"))]
fn is_retryable_interface_disabled_error(_err: &io::Error) -> bool {
    false
}

fn interface_disabled_retry_delay(retry_count: u32) -> Duration {
    let millis = 100u64.saturating_mul(2u64.saturating_pow(retry_count.saturating_sub(1).min(3)));
    Duration::from_millis(millis.min(1_000))
}

#[cfg(test)]
mod tests {
    use super::interface_disabled_retry_delay;

    #[test]
    fn interface_disabled_retry_delay_is_capped() {
        assert_eq!(interface_disabled_retry_delay(1).as_millis(), 100);
        assert_eq!(interface_disabled_retry_delay(2).as_millis(), 200);
        assert_eq!(interface_disabled_retry_delay(3).as_millis(), 400);
        assert_eq!(interface_disabled_retry_delay(4).as_millis(), 800);
        assert_eq!(interface_disabled_retry_delay(5).as_millis(), 800);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_interface_disabled_errors_are_retryable() {
        let err = std::io::Error::other("The interface has been disabled");
        assert!(super::is_retryable_interface_disabled_error(&err));
    }
}
