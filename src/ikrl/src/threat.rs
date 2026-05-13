//! Threat detection — pattern-based scoring of [`ActivityEvent`]s.
//!
//! Each event receives a threat score 0–100.  Scores ≥ [`BLOCK_THRESHOLD`]
//! are hard-blocked; scores above 0 are logged as warnings.
//!
//! Patterns are intentionally kept simple so they can be audited in full.
//! More sophisticated ML-based scoring is a roadmap item (v1.4).

use crate::monitor::{ActivityEvent, EventKind};
use intentkernel_sdk::config::KernelConfig;

/// Events scoring at or above this value are blocked (not just warned).
pub const BLOCK_THRESHOLD: u32 = 70;

/// Compute a threat score (0–100) for a single activity event.
///
/// Returns 0 if the event is considered benign under the current config.
pub fn score(event: &ActivityEvent, config: &KernelConfig) -> u32 {
    let mut s: u32 = 0;

    match &event.kind {
        // ── File operations ───────────────────────────────────────────────────
        EventKind::FileWrite => {
            // Writing to sensitive paths is elevated risk.
            if is_sensitive_path(&event.subject) {
                s += 40;
            }
            // Writing inside another user's home directory is suspicious.
            if event.subject.starts_with("/home/") && !event.subject.contains("/.cache/") {
                s += 20;
            }
            // Rapid repeated writes to the same path → ransomware pattern.
            if event.detail.as_deref() == Some("rapid-repeat") {
                s += 50;
            }
        }
        EventKind::FileDelete => {
            if is_sensitive_path(&event.subject) {
                s += 60;
            }
        }
        // ── Network operations ────────────────────────────────────────────────
        EventKind::NetworkConnect => {
            // Network is blocked by default in the config.
            if !config.execution.network_enabled {
                s += 80;
            }
            // Known bad ports.
            if let Some(d) = &event.detail {
                if d.contains(":4444") || d.contains(":1337") || d.contains(":31337") {
                    s += 90; // Common reverse-shell ports.
                }
            }
        }
        // ── Process creation ──────────────────────────────────────────────────
        EventKind::ProcessCreated => {
            if event.subject.contains("cryptominer")
                || event.subject.contains("xmrig")
                || event.subject.contains("mimikatz")
            {
                s += 100;
            }
        }
        // ── Permission requests ───────────────────────────────────────────────
        EventKind::PermissionRequest => {
            // Unexpected permission requests while evidence_only_mode is on.
            if config.persona.evidence_only_mode {
                s += 30;
            }
        }
        // ── Pre-scored threat signature ───────────────────────────────────────
        EventKind::ThreatSignature => {
            s += 95;
        }
        _ => {}
    }

    s.min(100)
}

/// Returns `true` if the path is considered security-sensitive.
fn is_sensitive_path(path: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/boot/",
        "/sys/",
        "/proc/sysrq",
        "\\Windows\\System32\\",
        "\\Windows\\SysWOW64\\",
        "C:\\Users\\",
    ];
    SENSITIVE.iter().any(|p| path.starts_with(p) || path.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::ActivityEvent;
    use intentkernel_sdk::config::KernelConfig;

    fn cfg() -> KernelConfig {
        KernelConfig::default()
    }

    #[test]
    fn benign_file_read_scores_zero() {
        let ev = ActivityEvent::new(EventKind::FileRead, "/home/user/documents/report.pdf");
        assert_eq!(score(&ev, &cfg()), 0);
    }

    #[test]
    fn sensitive_write_scores_high() {
        let ev = ActivityEvent::new(EventKind::FileWrite, "/etc/passwd");
        let s = score(&ev, &cfg());
        assert!(s >= BLOCK_THRESHOLD, "got {s}");
    }

    #[test]
    fn network_blocked_by_default_config() {
        let ev = ActivityEvent::new(EventKind::NetworkConnect, "198.51.100.1")
            .with_detail("198.51.100.1:443");
        // Default config has network_enabled=false.
        assert!(score(&ev, &cfg()) >= BLOCK_THRESHOLD);
    }

    #[test]
    fn network_allowed_when_enabled() {
        let ev = ActivityEvent::new(EventKind::NetworkConnect, "198.51.100.1")
            .with_detail("198.51.100.1:443");
        let mut c = cfg();
        c.execution.network_enabled = true;
        assert_eq!(score(&ev, &c), 0);
    }

    #[test]
    fn ransomware_rapid_repeat_score_above_threshold() {
        let ev = ActivityEvent::new(EventKind::FileWrite, "/home/user/important.docx")
            .with_detail("rapid-repeat");
        assert!(score(&ev, &cfg()) >= BLOCK_THRESHOLD);
    }

    #[test]
    fn threat_signature_always_blocks() {
        let ev = ActivityEvent::new(EventKind::ThreatSignature, "xmrig");
        assert!(score(&ev, &cfg()) >= BLOCK_THRESHOLD);
    }
}
