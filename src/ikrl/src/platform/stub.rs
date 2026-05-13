//! Stub platform — used on macOS and other unsupported hosts during development.

use super::Platform;
use crate::monitor::ActivityEvent;
use intentkernel_sdk::config::KernelConfig;

pub struct StubPlatform;

impl Platform for StubPlatform {
    fn init(&mut self, _config: &KernelConfig) {}

    fn poll_events(&mut self) -> Vec<ActivityEvent> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "stub"
    }
}
