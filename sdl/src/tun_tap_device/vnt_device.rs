use std::io;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "integrated_tun")]
use tun_rs::SyncDevice;

pub trait DeviceWrite: Clone + Send + Sync + 'static {
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    #[cfg(feature = "integrated_tun")]
    fn into_device_adapter(self) -> crate::tun_tap_device::tun_create_helper::DeviceAdapter;
}

pub(crate) fn write_full_device<Device: DeviceWrite>(
    device: &Device,
    buf: &[u8],
    context: &str,
) -> io::Result<usize> {
    write_full_impl(|| device.write(buf), buf.len(), context)
}

#[cfg(feature = "integrated_tun")]
pub(crate) fn write_full_sync_device(
    device: &SyncDevice,
    buf: &[u8],
    context: &str,
) -> io::Result<usize> {
    write_full_impl(|| send_sync_device(device, buf), buf.len(), context)
}

fn write_full_impl<F>(mut writer: F, expected_len: usize, context: &str) -> io::Result<usize>
where
    F: FnMut() -> io::Result<usize>,
{
    let mut retry_count = 0u32;
    let start = Instant::now();
    loop {
        match writer() {
            Ok(written) => {
                if written != expected_len {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("{context} short write: wrote {written} of {expected_len}"),
                    ));
                }
                return Ok(written);
            }
            Err(err) if is_retryable_write_error(&err) => {
                retry_count = retry_count.saturating_add(1);
                let elapsed = start.elapsed();
                if retry_count > max_write_retry_attempts() || elapsed >= max_write_retry_duration()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "{context} TUN write retry budget exhausted after {} attempts over {:?}: {}",
                            retry_count, elapsed, err
                        ),
                    ));
                }
                if retry_count == 1 || retry_count % 10 == 0 {
                    log::warn!(
                        "{context} temporary TUN write error, retrying (attempt {}): {:?}",
                        retry_count,
                        err
                    );
                }
                thread::sleep(write_retry_delay(retry_count));
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(feature = "integrated_tun")]
#[cfg(target_os = "windows")]
fn send_sync_device(device: &SyncDevice, buf: &[u8]) -> io::Result<usize> {
    device.try_send(buf)
}

#[cfg(feature = "integrated_tun")]
#[cfg(not(target_os = "windows"))]
fn send_sync_device(device: &SyncDevice, buf: &[u8]) -> io::Result<usize> {
    device.send(buf)
}

#[cfg(target_os = "windows")]
fn is_retryable_write_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
        || err
            .to_string()
            .to_ascii_lowercase()
            .contains("interface has been disabled")
}

#[cfg(not(target_os = "windows"))]
fn is_retryable_write_error(_err: &io::Error) -> bool {
    false
}

fn write_retry_delay(retry_count: u32) -> Duration {
    let millis = 10u64.saturating_mul(2u64.saturating_pow(retry_count.saturating_sub(1).min(4)));
    Duration::from_millis(millis.min(200))
}

fn max_write_retry_attempts() -> u32 {
    20
}

fn max_write_retry_duration() -> Duration {
    Duration::from_secs(2)
}

#[cfg(test)]
mod tests {
    use super::{max_write_retry_attempts, max_write_retry_duration, write_retry_delay};
    use std::time::Duration;

    #[test]
    fn write_retry_delay_is_capped() {
        assert_eq!(write_retry_delay(1).as_millis(), 10);
        assert_eq!(write_retry_delay(2).as_millis(), 20);
        assert_eq!(write_retry_delay(3).as_millis(), 40);
        assert_eq!(write_retry_delay(4).as_millis(), 80);
        assert_eq!(write_retry_delay(5).as_millis(), 160);
        assert_eq!(write_retry_delay(6).as_millis(), 160);
    }

    #[test]
    fn write_retry_budget_is_bounded() {
        assert_eq!(max_write_retry_attempts(), 20);
        assert_eq!(max_write_retry_duration(), Duration::from_secs(2));
    }
}
