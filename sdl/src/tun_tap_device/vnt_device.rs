use std::io;

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
    let written = device.write(buf)?;
    if written != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("{context} short write: wrote {written} of {}", buf.len()),
        ));
    }
    Ok(written)
}
