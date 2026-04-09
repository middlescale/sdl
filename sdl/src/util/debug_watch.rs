use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct DebugWatchEventRecord {
    pub watch_id: u64,
    pub section: String,
    pub event_type: String,
    pub event_unix_ms: i64,
    pub payload_json: String,
}

#[derive(Clone)]
struct ActiveDebugWatch {
    watch_id: u64,
    sections: HashSet<String>,
    expire_at_unix_ms: i64,
}

type DebugWatchSender = Arc<dyn Fn(DebugWatchEventRecord) + Send + Sync>;

#[derive(Clone, Default)]
pub struct DebugWatch {
    enabled: Arc<AtomicBool>,
    active: Arc<Mutex<Option<ActiveDebugWatch>>>,
    sender: Arc<Mutex<Option<DebugWatchSender>>>,
}

impl DebugWatch {
    pub fn set_sender<F>(&self, sender: F)
    where
        F: Fn(DebugWatchEventRecord) + Send + Sync + 'static,
    {
        *self.sender.lock() = Some(Arc::new(sender));
    }

    pub fn start(&self, watch_id: u64, sections: &[String], duration_sec: u32) -> (i64, i64) {
        let started_at_unix_ms = crate::handle::now_time() as i64;
        let expire_at_unix_ms =
            started_at_unix_ms + i64::from(duration_sec.max(1).min(3600)) * 1_000;
        let normalized = normalize_sections(sections);
        *self.active.lock() = Some(ActiveDebugWatch {
            watch_id,
            sections: normalized,
            expire_at_unix_ms,
        });
        self.enabled.store(true, Ordering::Release);
        (started_at_unix_ms, expire_at_unix_ms)
    }

    pub fn stop(&self, expected_watch_id: Option<u64>) -> Option<u64> {
        let mut guard = self.active.lock();
        let current = guard.as_ref()?;
        if let Some(expected) = expected_watch_id {
            if expected != 0 && current.watch_id != expected {
                return None;
            }
        }
        let watch_id = current.watch_id;
        *guard = None;
        self.enabled.store(false, Ordering::Release);
        Some(watch_id)
    }

    pub fn current_watch_id(&self) -> Option<u64> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }
        self.active.lock().as_ref().map(|active| active.watch_id)
    }

    pub fn emit(&self, section: &str, event_type: &str, payload: Value) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let now_ms = crate::handle::now_time() as i64;
        let active = {
            let mut guard = self.active.lock();
            let Some(active) = guard.as_ref() else {
                self.enabled.store(false, Ordering::Release);
                return;
            };
            if now_ms > active.expire_at_unix_ms {
                *guard = None;
                self.enabled.store(false, Ordering::Release);
                return;
            }
            if !active.sections.contains("all") && !active.sections.contains(section) {
                return;
            }
            active.clone()
        };
        let Some(sender) = self.sender.lock().clone() else {
            return;
        };
        let payload_json = match serde_json::to_string(&payload) {
            Ok(value) => value,
            Err(_) => return,
        };
        sender(DebugWatchEventRecord {
            watch_id: active.watch_id,
            section: section.to_string(),
            event_type: event_type.to_string(),
            event_unix_ms: now_ms,
            payload_json,
        });
    }
}

fn normalize_sections(sections: &[String]) -> HashSet<String> {
    let mut normalized = HashSet::new();
    for section in sections {
        let section = section.trim().to_ascii_lowercase();
        if !section.is_empty() {
            normalized.insert(section);
        }
    }
    if normalized.is_empty() {
        normalized.insert("all".to_string());
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn emit_returns_immediately_when_disabled() {
        let watch = DebugWatch::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        watch.set_sender(move |_| {
            calls_clone.fetch_add(1, Ordering::Relaxed);
        });

        watch.emit("icmp", "tun_outbound", serde_json::json!({"ok": true}));

        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(watch.current_watch_id(), None);
    }

    #[test]
    fn start_enables_and_stop_disables_watch() {
        let watch = DebugWatch::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        watch.set_sender(move |_| {
            calls_clone.fetch_add(1, Ordering::Relaxed);
        });

        let _ = watch.start(42, &[], 60);
        assert_eq!(watch.current_watch_id(), Some(42));
        watch.emit("icmp", "tun_outbound", serde_json::json!({"ok": true}));
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        assert_eq!(watch.stop(Some(42)), Some(42));
        assert_eq!(watch.current_watch_id(), None);
        watch.emit("icmp", "tun_outbound", serde_json::json!({"ok": true}));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
