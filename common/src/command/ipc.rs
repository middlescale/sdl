use interprocess::local_socket::{prelude::*, ConnectOptions, ListenerOptions, Name};
use std::io::{self, Read, Write};

#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;

pub const COMMAND_MAX_MESSAGE_SIZE: usize = 65536 * 8;

#[cfg(windows)]
fn command_name() -> io::Result<Name<'static>> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let app_home = crate::cli::app_home()?;
    let mut hasher = DefaultHasher::new();
    app_home.hash(&mut hasher);
    let name = format!("vnt-command-{:016x}", hasher.finish());
    name.to_ns_name::<GenericNamespaced>().map(Name::into_owned)
}

#[cfg(not(windows))]
fn command_name() -> io::Result<Name<'static>> {
    let path = crate::cli::app_home()?.join("command.sock");
    path.to_fs_name::<GenericFilePath>().map(Name::into_owned)
}

pub fn bind_listener() -> io::Result<LocalSocketListener> {
    ListenerOptions::new()
        .name(command_name()?)
        .try_overwrite(true)
        .create_sync()
}

pub fn connect_stream() -> io::Result<LocalSocketStream> {
    ConnectOptions::new().name(command_name()?).connect_sync()
}

pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = payload.len();
    if len > COMMAND_MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("ipc payload too large: {len}"),
        ));
    }
    writer.write_all(&(len as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > COMMAND_MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ipc payload too large: {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}
