//! IKRL — IntentKernel Relief Layer
//!
//! A cross-platform capability upgrade daemon.  When installed on an existing
//! device it adds IntentKernel capability enforcement without replacing the
//! host operating system or touching user data.
//!
//! # Supported platforms
//! | Platform    | Enforcement mechanism               |
//! |-------------|-------------------------------------|
//! | Linux       | inotify + /proc polling + intentd   |
//! | Windows     | ETW provider + SCM service          |
//! | Android     | JNI service + UsageStatsManager     |
//! | Chrome OS   | Linux compatibility layer (above)   |
//!
//! # Zero data-loss guarantee
//! IKRL is a pure add-on layer.  It never modifies, moves, or deletes existing
//! files, applications, or user settings.  Every enforcement action is
//! capability-mediated and logged.

mod comm;
mod monitor;
mod platform;
mod threat;

use comm::BrokerClient;
use intentkernel_sdk::config::KernelConfig;
use monitor::ActivityEvent;
use platform::Platform;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── Runtime state ────────────────────────────────────────────────────────────

pub struct IkrlState {
    pub config: KernelConfig,
    pub events: Vec<ActivityEvent>,
    pub threat_count: u64,
    pub blocked_count: u64,
}

impl IkrlState {
    fn new() -> Self {
        Self {
            config: KernelConfig::default(),
            events: Vec::new(),
            threat_count: 0,
            blocked_count: 0,
        }
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    println!("ikrl v0.1 — IntentKernel Relief Layer");
    println!("platform: {}", platform::current_name());
    println!("intentd socket: {}", comm::SOCKET_PATH);

    let state = Arc::new(Mutex::new(IkrlState::new()));

    // Load config from intentd if reachable; otherwise use safe defaults.
    let broker = BrokerClient::new();
    if let Some(mut b) = broker {
        match b.fetch_config() {
            Ok(cfg) => {
                println!("loaded config from intentd");
                state.lock().unwrap().config = cfg;
            }
            Err(e) => eprintln!("intentd not reachable ({e}), using defaults"),
        }
    }

    // Initialise the platform monitor.
    let mut plat = platform::create();
    plat.init(&state.lock().unwrap().config);
    println!("monitor initialised");

    // Main event loop.
    println!("ikrl: monitoring started (Ctrl-C to stop)");
    loop {
        let raw_events = plat.poll_events();
        let mut st = state.lock().unwrap();

        for ev in raw_events {
            // Threat scoring.
            let score = threat::score(&ev, &st.config);
            if score > 0 {
                st.threat_count += 1;
                let action = if score >= threat::BLOCK_THRESHOLD {
                    st.blocked_count += 1;
                    "BLOCKED"
                } else {
                    "WARN"
                };
                let ts = now_ms();
                println!(
                    "[{ts}] {action} score={score} kind={:?} subject={}",
                    ev.kind, ev.subject
                );
            }

            // Rolling event buffer (last 500 events).
            st.events.push(ev);
            if st.events.len() > 500 {
                st.events.remove(0);
            }
        }

        drop(st);
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
