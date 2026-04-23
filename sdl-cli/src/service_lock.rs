use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub struct ServiceInstanceGuard {
    _file: File,
    path: PathBuf,
}

impl ServiceInstanceGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn acquire_service_lock() -> io::Result<ServiceInstanceGuard> {
    let path = crate::cli::app_home()?.join("service.lock");
    acquire_service_lock_at(&path)
}

fn acquire_service_lock_at(path: &Path) -> io::Result<ServiceInstanceGuard> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    crate::fs_access::ensure_user_access(path, 0o600)?;

    file.try_lock_exclusive().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "another sdl-service instance is already running (lock: {})",
                path.display()
            ),
        )
    })?;

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(file, "pid={}", std::process::id())?;
    let exe = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    writeln!(file, "exe={exe}")?;
    file.sync_data()?;

    Ok(ServiceInstanceGuard {
        _file: file,
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::acquire_service_lock_at;

    #[test]
    fn service_lock_blocks_second_holder_until_drop() {
        let dir = std::env::temp_dir().join(format!(
            "sdl-service-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("service.lock");

        let first = acquire_service_lock_at(&path).unwrap();
        let second = acquire_service_lock_at(&path);
        assert!(second.is_err());
        drop(first);

        let third = acquire_service_lock_at(&path);
        assert!(third.is_ok());
        drop(third);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
    }
}
