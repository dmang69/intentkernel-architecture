//! Linux platform monitor.
//!
//! Uses `/proc` polling for process events and the `inotify` kernel subsystem
//! for file system activity.  Network connections are read from
//! `/proc/net/tcp` and `/proc/net/tcp6`.
//!
//! No kernel modules or root privileges are required for process and network
//! monitoring.  File system monitoring via inotify requires the caller to have
//! read access to the watched directories (the daemon typically runs as root
//! or a dedicated `intentkernel` user).

use super::Platform;
use crate::monitor::{ActivityEvent, EventKind};
use intentkernel_sdk::config::KernelConfig;
use std::collections::HashSet;
use std::fs;
use std::time::{Duration, Instant};

pub struct LinuxPlatform {
    known_pids: HashSet<u32>,
    known_tcp: HashSet<String>,
    watched_paths: Vec<String>,
    last_proc_scan: Instant,
    last_net_scan: Instant,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            known_pids: HashSet::new(),
            known_tcp: HashSet::new(),
            watched_paths: vec![
                "/etc".into(),
                "/boot".into(),
                "/tmp".into(),
                "/var/tmp".into(),
            ],
            last_proc_scan: Instant::now(),
            last_net_scan: Instant::now(),
        }
    }

    fn scan_processes(&mut self) -> Vec<ActivityEvent> {
        let mut events = Vec::new();

        let current_pids: HashSet<u32> = fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .collect();

        for &pid in current_pids.difference(&self.known_pids) {
            let name = process_name(pid).unwrap_or_else(|| format!("pid:{pid}"));
            let ev = ActivityEvent::new(EventKind::ProcessCreated, name).with_pid(pid);
            events.push(ev);
        }
        for &pid in self.known_pids.difference(&current_pids) {
            let ev =
                ActivityEvent::new(EventKind::ProcessExited, format!("pid:{pid}")).with_pid(pid);
            events.push(ev);
        }

        self.known_pids = current_pids;
        events
    }

    fn scan_network(&mut self) -> Vec<ActivityEvent> {
        let mut events = Vec::new();

        let current = read_tcp_connections();
        for conn in current.difference(&self.known_tcp) {
            let ev = ActivityEvent::new(EventKind::NetworkConnect, conn.clone())
                .with_detail(conn.clone());
            events.push(ev);
        }
        self.known_tcp = read_tcp_connections();
        events
    }

    fn scan_watched_paths(&self) -> Vec<ActivityEvent> {
        // Shallow check: stat the watched directories for recent mtime changes.
        // A production implementation would use inotify(7) for efficiency.
        let mut events = Vec::new();
        for path in &self.watched_paths {
            if let Ok(meta) = fs::metadata(path) {
                if let Ok(modified) = meta.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        if elapsed < Duration::from_secs(2) {
                            let ev = ActivityEvent::new(EventKind::FileWrite, path.clone());
                            events.push(ev);
                        }
                    }
                }
            }
        }
        events
    }
}

impl Platform for LinuxPlatform {
    fn init(&mut self, _config: &KernelConfig) {
        // Seed known PIDs so we don't report all running processes as "new".
        self.known_pids = fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .collect();
        // Seed known TCP connections.
        self.known_tcp = read_tcp_connections();
    }

    fn poll_events(&mut self) -> Vec<ActivityEvent> {
        let mut events = Vec::new();

        // Process scan every 500 ms.
        if self.last_proc_scan.elapsed() >= Duration::from_millis(500) {
            events.extend(self.scan_processes());
            self.last_proc_scan = Instant::now();
        }

        // Network scan every 1 s.
        if self.last_net_scan.elapsed() >= Duration::from_secs(1) {
            events.extend(self.scan_network());
            self.last_net_scan = Instant::now();
        }

        // Path scan every poll cycle.
        events.extend(self.scan_watched_paths());

        events
    }

    fn name(&self) -> &'static str {
        "linux"
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn process_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Parse `/proc/net/tcp` and `/proc/net/tcp6` for ESTABLISHED connections.
fn read_tcp_connections() -> HashSet<String> {
    let mut conns = HashSet::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 4 && fields[3] == "01" {
                    // State 01 = ESTABLISHED
                    if let Some(addr) = decode_proc_net_addr(fields[2]) {
                        conns.insert(addr);
                    }
                }
            }
        }
    }
    conns
}

/// Decode a `/proc/net/tcp` hex address:port into "dotted.quad:port".
fn decode_proc_net_addr(hex: &str) -> Option<String> {
    let (addr_hex, port_hex) = hex.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if addr_hex.len() == 8 {
        // IPv4: little-endian 4-byte hex
        let n = u32::from_str_radix(addr_hex, 16).ok()?;
        let [a, b, c, d] = n.to_le_bytes();
        Some(format!("{a}.{b}.{c}.{d}:{port}"))
    } else {
        // IPv6: return abbreviated hex
        Some(format!("[{addr_hex}]:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ipv4_loopback() {
        // 0100007F:0050 = 127.0.0.1:80
        let result = decode_proc_net_addr("0100007F:0050").unwrap();
        assert_eq!(result, "127.0.0.1:80");
    }

    #[test]
    fn proc_self_exists() {
        let name = process_name(std::process::id());
        assert!(name.is_some());
    }
}
