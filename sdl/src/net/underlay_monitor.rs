use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use crate::util::StopManager;

#[cfg(target_os = "linux")]
fn physical_default_routes() -> std::io::Result<Vec<String>> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};
    let routes = std::fs::read_to_string("/proc/net/route")?;
    let interfaces = NetworkInterface::show().map_err(std::io::Error::other)?;
    let mut result = Vec::new();
    for line in routes.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        let addresses = interfaces
            .iter()
            .find(|iface| iface.name == fields[0])
            .map(|iface| format!("{:?}", iface.addr))
            .unwrap_or_default();
        result.push(format!(
            "{}:{}:{}:{}:{}",
            fields[0], fields[2], fields[3], fields[6], addresses
        ));
    }
    result.sort();
    Ok(result)
}

#[cfg(target_os = "macos")]
fn physical_default_routes() -> std::io::Result<Vec<String>> {
    use network_interface::{NetworkInterface, NetworkInterfaceConfig};
    let output = super::command_timeout::output(
        std::process::Command::new("route").args(["-n", "get", "default"]),
        super::command_timeout::NETWORK_COMMAND_TIMEOUT,
    )?;
    let output = macos_route_output(output)?;
    let field = |key: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
            .unwrap_or("")
    };
    let interface = field("interface:");
    if interface.is_empty() {
        return Err(std::io::Error::other("default route has no interface"));
    }
    let addresses = NetworkInterface::show()
        .map_err(std::io::Error::other)?
        .into_iter()
        .find(|item| item.name == interface)
        .map(|item| format!("{:?}", item.addr))
        .unwrap_or_default();
    Ok(vec![format!(
        "{}:{}:{}",
        interface,
        field("gateway:"),
        addresses
    )])
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn macos_route_output(output: std::process::Output) -> std::io::Result<String> {
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "cannot inspect macOS default route: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "windows")]
fn physical_default_routes() -> std::io::Result<Vec<String>> {
    let output = super::command_timeout::output(
        std::process::Command::new("route.exe").args(["print", "-4"]),
        super::command_timeout::NETWORK_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(std::io::Error::other("cannot inspect IPv4 route table"));
    }
    let mut defaults = windows_default_route_rows(&String::from_utf8_lossy(&output.stdout));
    defaults.sort();
    Ok(defaults)
}

#[cfg(any(test, target_os = "windows"))]
fn windows_default_route_rows(routes: &str) -> Vec<String> {
    routes
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 5 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
                return None;
            }
            fields[3].parse::<std::net::Ipv4Addr>().ok()?;
            fields[4].parse::<u32>().ok()?;
            Some(format!("{}:{}:{}", fields[2], fields[3], fields[4]))
        })
        .collect()
}

const POLL_INTERVAL: Duration = Duration::from_secs(15);
const TIME_JUMP_TOLERANCE: Duration = Duration::from_secs(5);

#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
fn update_route_snapshot(
    last: &mut Option<Vec<String>>,
    sample: std::io::Result<Vec<String>>,
) -> bool {
    match sample {
        Ok(routes) => {
            let changed = last.as_ref().is_some_and(|previous| previous != &routes);
            *last = Some(routes);
            changed
        }
        Err(err) => {
            log::debug!("cannot inspect underlay routes: {err}");
            false
        }
    }
}

struct TimeJumpDetector {
    last_wall: SystemTime,
    last_monotonic: Instant,
}

impl TimeJumpDetector {
    fn new() -> Self {
        Self {
            last_wall: SystemTime::now(),
            last_monotonic: Instant::now(),
        }
    }

    fn poll(&mut self) -> bool {
        let wall = SystemTime::now();
        let monotonic = Instant::now();
        let jumped = time_jump_detected(
            wall.duration_since(self.last_wall),
            monotonic.duration_since(self.last_monotonic),
        );
        self.last_wall = wall;
        self.last_monotonic = monotonic;
        jumped
    }
}

fn time_jump_detected(
    wall_elapsed: Result<Duration, std::time::SystemTimeError>,
    monotonic_elapsed: Duration,
) -> bool {
    let Ok(wall_elapsed) = wall_elapsed else {
        return true;
    };
    wall_elapsed.abs_diff(monotonic_elapsed) > TIME_JUMP_TOLERANCE
}

/// Watches for suspend/resume and Linux physical default route changes.
///
/// Linux `Instant` normally excludes time spent suspended while wall time
/// advances, so this reliably detects a suspend gap there. Other platforms may
/// use a monotonic clock that advances during sleep; on those platforms this is
/// best-effort and can miss a resume without producing a false recovery.
/// Comparing deltas avoids treating ordinary scheduler delays as
/// a network recovery event.
pub(crate) fn start_underlay_monitor<F>(
    stop_manager: StopManager,
    on_underlay_change: F,
) -> anyhow::Result<()>
where
    F: Fn() + Send + 'static,
{
    let (stop_sender, stop_receiver) = mpsc::channel::<()>();
    let worker = stop_manager.add_listener("underlayMonitor".into(), move || {
        let _ = stop_sender.send(());
    })?;
    std::thread::Builder::new()
        .name("underlayMonitor".into())
        .spawn(move || {
            let mut detector = TimeJumpDetector::new();
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            let mut last_routes = physical_default_routes().ok();
            loop {
                if stop_receiver.recv_timeout(POLL_INTERVAL).is_ok() {
                    break;
                }
                let jumped = detector.poll();
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                let routes_changed = update_route_snapshot(&mut last_routes, physical_default_routes());
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                let routes_changed = false;
                if jumped || routes_changed {
                    log::info!("underlay changed (time_jump={jumped}, routes_changed={routes_changed}); recovering network paths");
                    on_underlay_change();
                }
            }
            drop(worker);
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        time_jump_detected, update_route_snapshot, windows_default_route_rows, TIME_JUMP_TOLERANCE,
    };
    use std::time::{Duration, SystemTime};

    #[cfg(unix)]
    #[test]
    fn macos_route_command_failure_is_not_an_empty_snapshot() {
        use std::os::unix::process::ExitStatusExt;
        let failed = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"route query failed".to_vec(),
        };
        assert!(super::macos_route_output(failed).is_err());
        let success = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"interface: en0".to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(
            super::macos_route_output(success).unwrap(),
            "interface: en0"
        );
    }

    #[test]
    fn failed_route_sample_preserves_previous_snapshot() {
        let mut snapshot = Some(vec!["en0:gateway".to_string()]);
        assert!(!update_route_snapshot(
            &mut snapshot,
            Err(std::io::Error::other("route failed"))
        ));
        assert_eq!(
            snapshot.as_deref(),
            Some(["en0:gateway".to_string()].as_slice())
        );
        assert!(!update_route_snapshot(
            &mut snapshot,
            Ok(vec!["en0:gateway".into()])
        ));
        assert!(update_route_snapshot(&mut snapshot, Ok(Vec::new())));
        assert!(update_route_snapshot(
            &mut snapshot,
            Ok(vec!["en1:new-gateway".into()])
        ));
    }

    #[test]
    fn windows_route_parser_tracks_default_gateway_and_metric() {
        let rows = windows_default_route_rows("Network Destination Netmask Gateway Interface Metric\n 0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.3 25\n 10.0.0.0 255.0.0.0 On-link 10.0.0.2 1\n");
        assert_eq!(rows, ["192.168.1.1:192.168.1.3:25"]);
    }

    #[test]
    fn normal_scheduler_delay_is_not_a_time_jump() {
        assert!(!time_jump_detected(
            Ok(Duration::from_secs(16)),
            Duration::from_secs(16),
        ));
    }

    #[test]
    fn suspend_gap_is_a_time_jump() {
        assert!(time_jump_detected(
            Ok(Duration::from_secs(60)),
            Duration::from_secs(15),
        ));
    }

    #[test]
    fn wall_clock_rollback_is_a_time_jump() {
        let later = SystemTime::now();
        let earlier = later - Duration::from_secs(1);
        assert!(time_jump_detected(
            earlier.duration_since(later),
            Duration::from_secs(1),
        ));
    }

    #[test]
    fn tolerance_boundary_is_not_a_time_jump() {
        assert!(!time_jump_detected(
            Ok(Duration::from_secs(15) + TIME_JUMP_TOLERANCE),
            Duration::from_secs(15),
        ));
    }
}
