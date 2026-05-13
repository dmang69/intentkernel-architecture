//! Platform abstraction layer.
//!
//! Each platform implements the [`Platform`] trait, which the IKRL main loop
//! calls uniformly regardless of the host OS.

use crate::monitor::ActivityEvent;
use intentkernel_sdk::config::KernelConfig;

pub trait Platform: Send {
    /// One-time initialisation (open handles, register callbacks, etc.).
    fn init(&mut self, config: &KernelConfig);
    /// Return any new events since the last call.  Non-blocking.
    fn poll_events(&mut self) -> Vec<ActivityEvent>;
    /// Human-readable platform name for logging.
    fn name(&self) -> &'static str;
}

// ── Platform selection ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
mod stub;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub fn create() -> Box<dyn Platform> {
    Box::new(linux::LinuxPlatform::new())
}

#[cfg(target_os = "windows")]
pub fn create() -> Box<dyn Platform> {
    Box::new(windows::WindowsPlatform::new())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
pub fn create() -> Box<dyn Platform> {
    Box::new(stub::StubPlatform)
}

/// Human-readable name of the currently compiled platform.
pub fn current_name() -> &'static str {
    #[cfg(target_os = "linux")]
    return "linux";
    #[cfg(target_os = "windows")]
    return "windows";
    #[cfg(target_os = "android")]
    return "android";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "android"
    )))]
    return "unknown";
}
