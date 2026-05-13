//! Activity monitoring abstractions.
//!
//! [`ActivityEvent`] is the universal event type produced by every platform
//! adapter.  The threat scorer and the UI layer consume it without needing to
//! know which platform produced it.

/// High-level category of a monitored activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// A process was created or forked.
    ProcessCreated,
    /// A process exited.
    ProcessExited,
    /// A file was opened for reading.
    FileRead,
    /// A file was created or written.
    FileWrite,
    /// A file was deleted.
    FileDelete,
    /// An outbound network connection was attempted.
    NetworkConnect,
    /// An inbound network connection was accepted.
    NetworkAccept,
    /// An application permission was requested (Android / Windows UAC).
    PermissionRequest,
    /// A suspicious pattern matched a threat signature.
    ThreatSignature,
}

/// A single activity event emitted by the platform monitor.
#[derive(Debug, Clone)]
pub struct ActivityEvent {
    /// Monotonic timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Event category.
    pub kind: EventKind,
    /// The primary subject (file path, remote address, process name…).
    pub subject: String,
    /// PID of the process that triggered the event, if known.
    pub pid: Option<u32>,
    /// Extra detail (e.g. target path for rename, destination for network).
    pub detail: Option<String>,
}

impl ActivityEvent {
    pub fn new(kind: EventKind, subject: impl Into<String>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            timestamp_ms: ts,
            kind,
            subject: subject.into(),
            pid: None,
            detail: None,
        }
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_event_construction() {
        let ev = ActivityEvent::new(EventKind::FileWrite, "/tmp/test.db")
            .with_pid(1234)
            .with_detail("truncated");
        assert_eq!(ev.kind, EventKind::FileWrite);
        assert_eq!(ev.subject, "/tmp/test.db");
        assert_eq!(ev.pid, Some(1234));
        assert_eq!(ev.detail.as_deref(), Some("truncated"));
        assert!(ev.timestamp_ms > 0);
    }
}
