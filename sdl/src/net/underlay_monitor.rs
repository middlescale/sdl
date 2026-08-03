use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use crate::util::StopManager;

const POLL_INTERVAL: Duration = Duration::from_secs(15);
const TIME_JUMP_TOLERANCE: Duration = Duration::from_secs(5);

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

/// Watches for a wall-clock jump that indicates a suspend/resume cycle.
///
/// Linux `Instant` normally excludes time spent suspended while wall time
/// advances, so this reliably detects a suspend gap there. Other platforms may
/// use a monotonic clock that advances during sleep; on those platforms this is
/// best-effort and can miss a resume without producing a false recovery.
/// Platform network-interface change notifications can supplement this signal
/// in the future. Comparing deltas avoids treating ordinary scheduler delays as
/// a network recovery event.
pub(crate) fn start_underlay_monitor<F>(
    stop_manager: StopManager,
    on_time_jump: F,
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
            loop {
                if stop_receiver.recv_timeout(POLL_INTERVAL).is_ok() {
                    break;
                }
                if detector.poll() {
                    log::info!("underlay time jump detected; recovering network paths");
                    on_time_jump();
                }
            }
            drop(worker);
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{time_jump_detected, TIME_JUMP_TOLERANCE};
    use std::time::{Duration, SystemTime};

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
