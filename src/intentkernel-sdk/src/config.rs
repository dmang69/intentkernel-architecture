//! KernelConfig — serialisable control-surface configuration for IntentKernel.
//!
//! Every subsystem toggle is represented here.  The system starts from a safe
//! default (all hard safety rules enforced, developer options locked) and the
//! operator explicitly relaxes constraints through `ikctl` or the `intentd`
//! socket API.
//!
//! # Safety rules
//! [`KernelConfig::validate`] and [`KernelConfig::sanitize`] enforce the hard
//! constraints described in Shennell's Doctrine:
//! - No self-modifying code
//! - No unlogged transformations
//! - No evidence destruction
//! - No persona-boundary deletion
//! - No network access unless explicitly enabled
//! - Developer-only options require `execution.developer_mode = true`

use serde::{Deserialize, Serialize};

/// Top-level configuration bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KernelConfig {
    pub persona: PersonaConfig,
    pub agents: AgentsConfig,
    pub determinism: DeterminismConfig,
    pub evidence: EvidenceConfig,
    pub logging: LoggingConfig,
    pub execution: ExecutionConfig,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            persona: PersonaConfig::default(),
            agents: AgentsConfig::default(),
            determinism: DeterminismConfig::default(),
            evidence: EvidenceConfig::default(),
            logging: LoggingConfig::default(),
            execution: ExecutionConfig::default(),
        }
    }
}

// ─── Persona ──────────────────────────────────────────────────────────────────

/// Persona boundary controls (Section 2.1 of the control-surface spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PersonaConfig {
    /// Master switch: enforce all persona boundaries.
    pub enforcement_enabled: bool,
    /// Block speculative reasoning that lacks evidence backing.
    pub speculation_block: bool,
    /// Restrict output to verified evidence only.
    pub evidence_only_mode: bool,
    /// Block emotionally-charged content generation.
    pub emotional_content_block: bool,
    /// Block open-ended creative output.
    pub creativity_block: bool,
    /// Boundary strictness level 0–100 (100 = maximum enforcement).
    pub boundary_strictness: u8,
    /// Developer-only: allow persona override without confirmation dialog.
    pub developer_override: bool,
}

impl Default for PersonaConfig {
    fn default() -> Self {
        Self {
            enforcement_enabled: true,
            speculation_block: false,
            evidence_only_mode: false,
            emotional_content_block: false,
            creativity_block: false,
            boundary_strictness: 70,
            developer_override: false,
        }
    }
}

// ─── Agents ───────────────────────────────────────────────────────────────────

/// Per-agent enable/disable and scheduling policy (Section 2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentsConfig {
    pub strategist_enabled: bool,
    pub analyst_enabled: bool,
    pub indexer_enabled: bool,
    pub executor_enabled: bool,
    /// Maximum concurrently active agents (clamped to 1–16).
    pub max_concurrency: u8,
    /// Per-agent execution timeout in seconds.
    pub timeout_secs: u32,
    /// Agent scheduling priority 0–100 (higher = runs first).
    pub priority: u8,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            strategist_enabled: true,
            analyst_enabled: true,
            indexer_enabled: true,
            executor_enabled: true,
            max_concurrency: 4,
            timeout_secs: 30,
            priority: 50,
        }
    }
}

// ─── Determinism ──────────────────────────────────────────────────────────────

/// Determinism controls for reproducible execution (Section 2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeterminismConfig {
    /// Strict determinism: same input must always produce same output.
    pub strict_mode: bool,
    /// Log all inputs/outputs to enable replay.
    pub reproducibility_enforcement: bool,
    /// Record execution hashes for integrity verification.
    pub hash_locking: bool,
    /// Developer-only: allow relaxed (non-deterministic) paths.
    pub developer_relaxed: bool,
    /// Non-deterministic sandbox (testing only; requires developer_mode).
    pub sandbox_nondeterministic: bool,
}

impl Default for DeterminismConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            reproducibility_enforcement: true,
            hash_locking: true,
            developer_relaxed: false,
            sandbox_nondeterministic: false,
        }
    }
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

/// Evidence pipeline controls (Section 2.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EvidenceConfig {
    /// Read-only mode: no evidence transformation allowed.
    pub safe_read_only: bool,
    /// Chain-of-custody: all evidence changes are logged with originator.
    pub chain_of_custody: bool,
    /// Extract and index file metadata automatically.
    pub metadata_extraction: bool,
    /// Enable OCR for image-based evidence.
    pub ocr_enabled: bool,
    /// Enable chronology inference from embedded timestamps.
    pub chronology_inference: bool,
    /// Developer-only: allow evidence transformation.
    pub developer_transform: bool,
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self {
            safe_read_only: true,
            chain_of_custody: true,
            metadata_extraction: true,
            ocr_enabled: false,
            chronology_inference: true,
            developer_transform: false,
        }
    }
}

// ─── Logging ──────────────────────────────────────────────────────────────────

/// Logging verbosity level (Section 2.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogMode {
    /// Full judicial trace: every event, every token, every decision.
    Judicial,
    /// Standard operational logging.
    Standard,
    /// Minimal: errors and critical events only.
    Minimal,
    /// No logs — developer sandbox only; requires `developer_mode = true`.
    None,
}

impl LogMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogMode::Judicial => "judicial",
            LogMode::Standard => "standard",
            LogMode::Minimal => "minimal",
            LogMode::None => "none",
        }
    }
}

impl std::fmt::Display for LogMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "judicial" => Ok(LogMode::Judicial),
            "standard" => Ok(LogMode::Standard),
            "minimal" => Ok(LogMode::Minimal),
            "none" => Ok(LogMode::None),
            other => Err(format!("unknown log mode '{other}'; expected judicial|standard|minimal|none")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub mode: LogMode,
    /// Automatically export logs on session end.
    pub auto_export: bool,
    /// Require manual confirmation before any log redaction (hard safety rule).
    pub manual_redaction_only: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            mode: LogMode::Standard,
            auto_export: false,
            manual_redaction_only: true,
        }
    }
}

// ─── Execution ────────────────────────────────────────────────────────────────

/// Execution and developer debug controls (Section 2.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecutionConfig {
    /// Pause before each agent action for inspection.
    pub step_through: bool,
    /// Enable breakpoints in the agent execution loop.
    pub breakpoints_enabled: bool,
    /// Emit per-skill debug output.
    pub skill_debug: bool,
    /// Surface persona conflict events in the execution panel.
    pub persona_inspector: bool,
    /// Flag non-deterministic execution paths in the trace.
    pub determinism_inspector: bool,
    /// Verify evidence integrity on every access.
    pub evidence_inspector: bool,
    /// Allow outbound network access (disabled by default — hard safety rule).
    pub network_enabled: bool,
    /// Developer mode master switch — unlocks dangerous options.
    pub developer_mode: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            step_through: false,
            breakpoints_enabled: false,
            skill_debug: false,
            persona_inspector: false,
            determinism_inspector: false,
            evidence_inspector: false,
            network_enabled: false,
            developer_mode: false,
        }
    }
}

// ─── KernelConfig methods ─────────────────────────────────────────────────────

impl KernelConfig {
    /// Validate config against hard safety rules.
    /// Returns a list of violation descriptions; empty means the config is safe.
    pub fn validate(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        let dev = self.execution.developer_mode;
        if self.logging.mode == LogMode::None && !dev {
            v.push("logging.mode=none requires execution.developer_mode=true");
        }
        if self.determinism.sandbox_nondeterministic && !dev {
            v.push("determinism.sandbox_nondeterministic requires developer_mode");
        }
        if self.evidence.developer_transform && !dev {
            v.push("evidence.developer_transform requires developer_mode");
        }
        if self.persona.developer_override && !dev {
            v.push("persona.developer_override requires developer_mode");
        }
        if self.determinism.developer_relaxed && !dev {
            v.push("determinism.developer_relaxed requires developer_mode");
        }
        v
    }

    /// Enforce hard safety rules, clamping any out-of-range values.
    /// Call after deserialising untrusted config.
    pub fn sanitize(&mut self) {
        if !self.execution.developer_mode {
            if self.logging.mode == LogMode::None {
                self.logging.mode = LogMode::Minimal;
            }
            self.determinism.sandbox_nondeterministic = false;
            self.evidence.developer_transform = false;
            self.persona.developer_override = false;
            self.determinism.developer_relaxed = false;
        }
        // Hard safety rules that NEVER get disabled.
        self.logging.manual_redaction_only = true;
        // Range clamping.
        self.persona.boundary_strictness = self.persona.boundary_strictness.min(100);
        self.agents.max_concurrency = self.agents.max_concurrency.clamp(1, 16);
        self.agents.priority = self.agents.priority.min(100);
    }

    /// Get a config field by dot-notation key.
    /// Returns `None` for unknown keys.
    pub fn get_field(&self, key: &str) -> Option<String> {
        Some(match key {
            "persona.enforcement_enabled" => self.persona.enforcement_enabled.to_string(),
            "persona.speculation_block" => self.persona.speculation_block.to_string(),
            "persona.evidence_only_mode" => self.persona.evidence_only_mode.to_string(),
            "persona.emotional_content_block" => self.persona.emotional_content_block.to_string(),
            "persona.creativity_block" => self.persona.creativity_block.to_string(),
            "persona.boundary_strictness" => self.persona.boundary_strictness.to_string(),
            "persona.developer_override" => self.persona.developer_override.to_string(),
            "agents.strategist_enabled" => self.agents.strategist_enabled.to_string(),
            "agents.analyst_enabled" => self.agents.analyst_enabled.to_string(),
            "agents.indexer_enabled" => self.agents.indexer_enabled.to_string(),
            "agents.executor_enabled" => self.agents.executor_enabled.to_string(),
            "agents.max_concurrency" => self.agents.max_concurrency.to_string(),
            "agents.timeout_secs" => self.agents.timeout_secs.to_string(),
            "agents.priority" => self.agents.priority.to_string(),
            "determinism.strict_mode" => self.determinism.strict_mode.to_string(),
            "determinism.reproducibility_enforcement" => {
                self.determinism.reproducibility_enforcement.to_string()
            }
            "determinism.hash_locking" => self.determinism.hash_locking.to_string(),
            "determinism.developer_relaxed" => self.determinism.developer_relaxed.to_string(),
            "determinism.sandbox_nondeterministic" => {
                self.determinism.sandbox_nondeterministic.to_string()
            }
            "evidence.safe_read_only" => self.evidence.safe_read_only.to_string(),
            "evidence.chain_of_custody" => self.evidence.chain_of_custody.to_string(),
            "evidence.metadata_extraction" => self.evidence.metadata_extraction.to_string(),
            "evidence.ocr_enabled" => self.evidence.ocr_enabled.to_string(),
            "evidence.chronology_inference" => self.evidence.chronology_inference.to_string(),
            "evidence.developer_transform" => self.evidence.developer_transform.to_string(),
            "logging.mode" => self.logging.mode.to_string(),
            "logging.auto_export" => self.logging.auto_export.to_string(),
            "logging.manual_redaction_only" => self.logging.manual_redaction_only.to_string(),
            "execution.step_through" => self.execution.step_through.to_string(),
            "execution.breakpoints_enabled" => self.execution.breakpoints_enabled.to_string(),
            "execution.skill_debug" => self.execution.skill_debug.to_string(),
            "execution.persona_inspector" => self.execution.persona_inspector.to_string(),
            "execution.determinism_inspector" => self.execution.determinism_inspector.to_string(),
            "execution.evidence_inspector" => self.execution.evidence_inspector.to_string(),
            "execution.network_enabled" => self.execution.network_enabled.to_string(),
            "execution.developer_mode" => self.execution.developer_mode.to_string(),
            _ => return None,
        })
    }

    /// Set a config field by dot-notation key.
    /// Returns an error string on unknown key or invalid value.
    pub fn set_field(&mut self, key: &str, value: &str) -> Result<(), String> {
        fn parse_bool(v: &str) -> Result<bool, String> {
            match v {
                "true" | "1" | "yes" => Ok(true),
                "false" | "0" | "no" => Ok(false),
                other => Err(format!("expected true/false, got '{other}'")),
            }
        }
        fn parse_u8(v: &str) -> Result<u8, String> {
            v.parse::<u8>()
                .map_err(|_| format!("expected 0–255, got '{v}'"))
        }
        fn parse_u32(v: &str) -> Result<u32, String> {
            v.parse::<u32>()
                .map_err(|_| format!("expected integer, got '{v}'"))
        }

        match key {
            "persona.enforcement_enabled" => {
                self.persona.enforcement_enabled = parse_bool(value)?
            }
            "persona.speculation_block" => self.persona.speculation_block = parse_bool(value)?,
            "persona.evidence_only_mode" => {
                self.persona.evidence_only_mode = parse_bool(value)?
            }
            "persona.emotional_content_block" => {
                self.persona.emotional_content_block = parse_bool(value)?
            }
            "persona.creativity_block" => self.persona.creativity_block = parse_bool(value)?,
            "persona.boundary_strictness" => {
                self.persona.boundary_strictness = parse_u8(value)?.min(100)
            }
            "persona.developer_override" => {
                self.persona.developer_override = parse_bool(value)?
            }
            "agents.strategist_enabled" => {
                self.agents.strategist_enabled = parse_bool(value)?
            }
            "agents.analyst_enabled" => self.agents.analyst_enabled = parse_bool(value)?,
            "agents.indexer_enabled" => self.agents.indexer_enabled = parse_bool(value)?,
            "agents.executor_enabled" => self.agents.executor_enabled = parse_bool(value)?,
            "agents.max_concurrency" => {
                self.agents.max_concurrency = parse_u8(value)?.clamp(1, 16)
            }
            "agents.timeout_secs" => self.agents.timeout_secs = parse_u32(value)?,
            "agents.priority" => self.agents.priority = parse_u8(value)?.min(100),
            "determinism.strict_mode" => self.determinism.strict_mode = parse_bool(value)?,
            "determinism.reproducibility_enforcement" => {
                self.determinism.reproducibility_enforcement = parse_bool(value)?
            }
            "determinism.hash_locking" => self.determinism.hash_locking = parse_bool(value)?,
            "determinism.developer_relaxed" => {
                self.determinism.developer_relaxed = parse_bool(value)?
            }
            "determinism.sandbox_nondeterministic" => {
                self.determinism.sandbox_nondeterministic = parse_bool(value)?
            }
            "evidence.safe_read_only" => self.evidence.safe_read_only = parse_bool(value)?,
            "evidence.chain_of_custody" => self.evidence.chain_of_custody = parse_bool(value)?,
            "evidence.metadata_extraction" => {
                self.evidence.metadata_extraction = parse_bool(value)?
            }
            "evidence.ocr_enabled" => self.evidence.ocr_enabled = parse_bool(value)?,
            "evidence.chronology_inference" => {
                self.evidence.chronology_inference = parse_bool(value)?
            }
            "evidence.developer_transform" => {
                self.evidence.developer_transform = parse_bool(value)?
            }
            "logging.mode" => self.logging.mode = value.parse::<LogMode>()?,
            "logging.auto_export" => self.logging.auto_export = parse_bool(value)?,
            "logging.manual_redaction_only" => {
                // Hard safety rule: this field cannot be set to false.
                let requested = parse_bool(value)?;
                if !requested {
                    return Err(
                        "logging.manual_redaction_only cannot be disabled (hard safety rule)"
                            .into(),
                    );
                }
                self.logging.manual_redaction_only = true;
            }
            "execution.step_through" => self.execution.step_through = parse_bool(value)?,
            "execution.breakpoints_enabled" => {
                self.execution.breakpoints_enabled = parse_bool(value)?
            }
            "execution.skill_debug" => self.execution.skill_debug = parse_bool(value)?,
            "execution.persona_inspector" => {
                self.execution.persona_inspector = parse_bool(value)?
            }
            "execution.determinism_inspector" => {
                self.execution.determinism_inspector = parse_bool(value)?
            }
            "execution.evidence_inspector" => {
                self.execution.evidence_inspector = parse_bool(value)?
            }
            "execution.network_enabled" => self.execution.network_enabled = parse_bool(value)?,
            "execution.developer_mode" => self.execution.developer_mode = parse_bool(value)?,
            _ => return Err(format!("unknown config key '{key}'")),
        }

        // Re-sanitize after every change.
        self.sanitize();

        // Validate and return the first violation as an error, if any.
        let violations = self.validate();
        if let Some(v) = violations.first() {
            return Err(v.to_string());
        }
        Ok(())
    }

    /// Return a flat list of all (key, value) pairs for display.
    pub fn list_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("persona.enforcement_enabled", self.persona.enforcement_enabled.to_string()),
            ("persona.speculation_block", self.persona.speculation_block.to_string()),
            ("persona.evidence_only_mode", self.persona.evidence_only_mode.to_string()),
            ("persona.emotional_content_block", self.persona.emotional_content_block.to_string()),
            ("persona.creativity_block", self.persona.creativity_block.to_string()),
            ("persona.boundary_strictness", self.persona.boundary_strictness.to_string()),
            ("persona.developer_override", self.persona.developer_override.to_string()),
            ("agents.strategist_enabled", self.agents.strategist_enabled.to_string()),
            ("agents.analyst_enabled", self.agents.analyst_enabled.to_string()),
            ("agents.indexer_enabled", self.agents.indexer_enabled.to_string()),
            ("agents.executor_enabled", self.agents.executor_enabled.to_string()),
            ("agents.max_concurrency", self.agents.max_concurrency.to_string()),
            ("agents.timeout_secs", self.agents.timeout_secs.to_string()),
            ("agents.priority", self.agents.priority.to_string()),
            ("determinism.strict_mode", self.determinism.strict_mode.to_string()),
            (
                "determinism.reproducibility_enforcement",
                self.determinism.reproducibility_enforcement.to_string(),
            ),
            ("determinism.hash_locking", self.determinism.hash_locking.to_string()),
            ("determinism.developer_relaxed", self.determinism.developer_relaxed.to_string()),
            (
                "determinism.sandbox_nondeterministic",
                self.determinism.sandbox_nondeterministic.to_string(),
            ),
            ("evidence.safe_read_only", self.evidence.safe_read_only.to_string()),
            ("evidence.chain_of_custody", self.evidence.chain_of_custody.to_string()),
            ("evidence.metadata_extraction", self.evidence.metadata_extraction.to_string()),
            ("evidence.ocr_enabled", self.evidence.ocr_enabled.to_string()),
            ("evidence.chronology_inference", self.evidence.chronology_inference.to_string()),
            ("evidence.developer_transform", self.evidence.developer_transform.to_string()),
            ("logging.mode", self.logging.mode.to_string()),
            ("logging.auto_export", self.logging.auto_export.to_string()),
            ("logging.manual_redaction_only", self.logging.manual_redaction_only.to_string()),
            ("execution.step_through", self.execution.step_through.to_string()),
            ("execution.breakpoints_enabled", self.execution.breakpoints_enabled.to_string()),
            ("execution.skill_debug", self.execution.skill_debug.to_string()),
            ("execution.persona_inspector", self.execution.persona_inspector.to_string()),
            ("execution.determinism_inspector", self.execution.determinism_inspector.to_string()),
            ("execution.evidence_inspector", self.execution.evidence_inspector.to_string()),
            ("execution.network_enabled", self.execution.network_enabled.to_string()),
            ("execution.developer_mode", self.execution.developer_mode.to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_and_safe() {
        let cfg = KernelConfig::default();
        assert!(cfg.validate().is_empty(), "default config must pass all safety rules");
    }

    #[test]
    fn developer_only_options_blocked_without_developer_mode() {
        let mut cfg = KernelConfig::default();
        cfg.determinism.sandbox_nondeterministic = true;
        let violations = cfg.validate();
        assert!(!violations.is_empty());
    }

    #[test]
    fn developer_only_options_allowed_with_developer_mode() {
        let mut cfg = KernelConfig::default();
        cfg.execution.developer_mode = true;
        cfg.determinism.sandbox_nondeterministic = true;
        cfg.evidence.developer_transform = true;
        cfg.persona.developer_override = true;
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn sanitize_resets_unsafe_developer_options() {
        let mut cfg = KernelConfig::default();
        cfg.determinism.sandbox_nondeterministic = true;
        cfg.evidence.developer_transform = true;
        cfg.logging.mode = LogMode::None;
        cfg.sanitize();
        assert!(!cfg.determinism.sandbox_nondeterministic);
        assert!(!cfg.evidence.developer_transform);
        assert_ne!(cfg.logging.mode, LogMode::None);
    }

    #[test]
    fn set_field_and_get_field_round_trip() {
        let mut cfg = KernelConfig::default();
        cfg.set_field("persona.boundary_strictness", "85").unwrap();
        assert_eq!(cfg.get_field("persona.boundary_strictness").unwrap(), "85");
    }

    #[test]
    fn set_field_rejects_unknown_key() {
        let mut cfg = KernelConfig::default();
        assert!(cfg.set_field("nonexistent.key", "value").is_err());
    }

    #[test]
    fn set_field_clamps_boundary_strictness() {
        let mut cfg = KernelConfig::default();
        cfg.set_field("persona.boundary_strictness", "200").unwrap();
        assert_eq!(cfg.persona.boundary_strictness, 100);
    }

    #[test]
    fn manual_redaction_only_cannot_be_disabled() {
        let mut cfg = KernelConfig::default();
        let result = cfg.set_field("logging.manual_redaction_only", "false");
        assert!(result.is_err());
        assert!(cfg.logging.manual_redaction_only);
    }

    #[test]
    fn log_mode_round_trip() {
        use std::str::FromStr;
        for mode in ["judicial", "standard", "minimal"] {
            let m = LogMode::from_str(mode).unwrap();
            assert_eq!(m.to_string(), mode);
        }
    }
}
