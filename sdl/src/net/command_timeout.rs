//! Bounded execution of network configuration commands.
use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(crate) const NETWORK_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn output(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    #[cfg(windows)]
    let job = match WindowsJob::attach(&child) {
        Ok(job) => job,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };
    let (sender, receiver) = mpsc::channel();
    read_pipe(
        0,
        child.stdout.take().expect("stdout piped"),
        sender.clone(),
    );
    read_pipe(
        1,
        child.stderr.take().expect("stderr piped"),
        sender.clone(),
    );
    drop(sender);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                terminate(
                    &mut child,
                    #[cfg(windows)]
                    &job,
                );
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            terminate(
                &mut child,
                #[cfg(windows)]
                &job,
            );
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "network command timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut buffers = [Vec::new(), Vec::new()];
    for _ in 0..2 {
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok((index, result)) => buffers[index] = result?,
            Err(_) => {
                terminate(
                    &mut child,
                    #[cfg(windows)]
                    &job,
                );
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "network command output timed out",
                ));
            }
        }
    }
    let [stdout, stderr] = buffers;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_pipe(
    index: usize,
    mut pipe: impl Read + Send + 'static,
    sender: mpsc::Sender<(usize, io::Result<Vec<u8>>)>,
) {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = pipe.read_to_end(&mut bytes).map(|_| bytes);
        let _ = sender.send((index, result));
    });
}

fn terminate(child: &mut std::process::Child, #[cfg(windows)] job: &WindowsJob) {
    #[cfg(unix)]
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::JobObjects::TerminateJobObject(job.0, 1);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(windows)]
struct WindowsJob(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl WindowsJob {
    fn attach(child: &std::process::Child) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        if unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as _) } == 0 {
            let error = io::Error::last_os_error();
            unsafe {
                CloseHandle(job);
            }
            return Err(error);
        }
        Ok(Self(job))
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn captures_output_and_bounds_command_and_descendant() {
        let captured = output(
            Command::new("sh").args(["-c", "printf ok; printf err >&2"]),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(captured.stdout, b"ok");
        assert_eq!(captured.stderr, b"err");
        let start = Instant::now();
        let error = output(
            Command::new("sh").args(["-c", "sleep 10 & wait"]),
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
