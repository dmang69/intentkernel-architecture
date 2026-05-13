# IntentKernel

**A capability-oriented execution architecture that replaces persistent permissions with event-scoped authority derived from verified user intent.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
**Status:** Architecture specification and prototype development
**Version:** 1.1.0

---

## The Problem

Every major operating system in use today — Windows, Linux, macOS, Android, iOS — relies on a permission model inherited from Multics (1969):

> **All code runs with ambient authority.**

Once a process starts, it inherits a persistent set of permissions for its entire lifetime. Every security mechanism in widespread use — antivirus, EDR, firewalls, sandboxes, SELinux, AppArmor — attempts to limit the damage caused by this design. None of them address the structural root cause.

The consequences are measurable:

- Hundreds of thousands of new malware samples appear daily (AV-TEST Institute, 2024)
- The majority of enterprise breaches involve endpoint compromise (Verizon DBIR, 2024)
- Average cost of a data breach exceeds $4.8M (IBM Cost of a Data Breach Report, 2024)
- Billions of IoT devices operate with minimal access control (Zscaler ThreatLabz, 2024)
- Quantum computing is expected to compromise widely deployed asymmetric cryptographic protocols within the next decade

Ambient authority creates a structural vulnerability that cannot be fully remediated by detection-based security layers alone.

## The Approach

IntentKernel is designed to eliminate ambient authority. It is built on three core principles:

1. **No default authority.** A process starts with zero capabilities. It cannot access any resource until explicitly authorized.
2. **Event-scoped authority.** A capability is granted for exactly one action, at the moment the user intends it. The scope is bound to a specific resource, operation, and context.
3. **Automatic expiry.** Every capability has a hard time-to-live. No capability persists beyond its defined scope or duration.

> **Example:** A user taps "Send" on an email. The application receives a one-time capability to send one message to one address. After sending, the capability is consumed. The application cannot silently send a second email, read contacts, or access the network without a new user-initiated action.

### Security Property

The capability model ensures that even if an attacker achieves arbitrary code execution within a process, the attacker's actions are bounded by the capabilities currently held by that process. Since capabilities are event-scoped and time-limited, the window and scope of any exploitation are structurally constrained compared to ambient authority models.

## Architecture Stack

IntentKernel is not a single component. It is a four-layer ecosystem:

| Layer | Role | Specification |
|-------|------|---------------|
| **IntentKernel** | Core execution model — zero ambient authority, event-scoped capabilities | [`docs/intentkernel_thesis.md`](docs/intentkernel_thesis.md) |
| **UCCS** | Universal Capability Computing Substrate — hardware-independent abstraction across all device classes | [`docs/uccs_spec.md`](docs/uccs_spec.md) |
| **IKRL** | IntentKernel Relief Layer — compatibility shim for Windows/Linux/Android/macOS/IoT | [`docs/ikrl_spec.md`](docs/ikrl_spec.md) |
| **IBPS** | Intent Broker Protocol — wire format, state machines, token lifecycle | [`docs/ibp_spec.md`](docs/ibp_spec.md) + [`docs/token_rfc.md`](docs/token_rfc.md) |

```
┌─────────────────────────────────────────────────┐
│              USER INTERACTION                    │
│       (Click, Voice, Sensor, GPIO)               │
└──────────────────┬──────────────────────────────┘
                   │ Verified Intent
                   ▼
┌─────────────────────────────────────────────────┐
│             INTENT BROKER                        │
│    intentd / capd / leasebroker / eventscope     │
│    • Classifies action                           │
│    • Issues PQC-signed capability token          │
│    • Enforces expiry                             │
└──────────────────┬──────────────────────────────┘
                   │ Capability Token (ML-DSA-87)
                   ▼
┌─────────────────────────────────────────────────┐
│           EXECUTION CONTEXT                      │
│     (Process / Container / Firmware Task)        │
│    • Zero authority without token                │
│    • Token auto-expires after TTL                │
└──────────────────┬──────────────────────────────┘
                   │ Syscall + Token
                   ▼
┌─────────────────────────────────────────────────┐
│          HOST OPERATING SYSTEM                   │
│   (Windows / Linux / Android / Embedded)         │
│    • Treated as untrusted resource provider      │
│    • Interceptor validates token before access   │
└─────────────────────────────────────────────────┘
```

## Deployment Strategy

IntentKernel does not require replacing existing operating systems. It enters as a compatibility layer and can evolve toward deeper integration over time.

| Stage | Target | Mechanism | Value Proposition |
| :--- | :--- | :--- | :--- |
| **1** | Windows Enterprise | VBS Service + Micro-VM | Capability-scoped file access for ransomware mitigation |
| **2** | Linux / Cloud | LSM Module + eBPF | Intent-mediated container and process isolation |
| **3** | Android / Mobile | Privileged System Service | Event-scoped sensor and data access control |
| **4** | Embedded / IoT / Vehicles | Firmware Supervisor | Capability-constrained device operation |
| **5** | Native Hardware | Capability-secure kernel | Native enforcement without host OS dependency (long-term target) |

Stages 1–4 operate on unmodified host operating systems. Stage 5 is a long-term research direction requiring dedicated kernel development.

## Security Design Goals

The following table describes the intended security posture of a fully realized IntentKernel deployment. These are **design goals** of the architecture. The current prototype has been evaluated under controlled experimental conditions. Production-grade validation requires further testing and, for Stage 5, formal verification.

| Threat | IntentKernel Design Goal | Current OS Status |
| :--- | :--- | :--- |
| Zero-day malware | Structurally constrained — no ambient authority to exploit | Dependent on signature-based detection |
| Ransomware | Mitigated — write capabilities require explicit user intent per file | Relies on behavioral heuristics |
| Commercial spyware | Mitigated — sensor and input capabilities expire after capture | Persistent permissions once granted |
| Data exfiltration | Constrained — network capabilities scoped per destination and session | Broad network access after initial grant |
| Privilege escalation | Addressed — no process can grant itself capabilities; only the broker issues tokens | Escalation paths exist via kernel vulnerabilities |
| Quantum cryptographic attack | Resistant — all tokens signed with ML-DSA-87 (NIST FIPS 204) | Dependent on classical asymmetric cryptography |
| Botnet enrollment | Structurally resistant — no persistent background network authority | Common on unmanaged endpoints |

## Post-Quantum Cryptography

All cryptographic operations use NIST-standardized post-quantum algorithms — the same suite mandated by NSA CNSA 2.0 for Top Secret communications:

| Function | Algorithm | Standard |
|----------|-----------|----------|
| Token signatures | ML-DSA-87 (Dilithium 5) | NIST FIPS 204 |
| Key exchange | ML-KEM-1024 (Kyber) | NIST FIPS 203 |
| Hashing | SHA3-384 / SHA3-512 | NIST FIPS 202 |
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 |

No fallback to classical cryptography. No experimental algorithms.

## Developer Interface

The capability-mediated interface defines 9 primitive operations through which all privileged resource access is requested:

| API | Description |
| :--- | :--- |
| `draw()` | Submit a framebuffer to the display |
| `wait_event()` | Block until a capability is received |
| `get_resource()` | Request access to one resource |
| `put_resource()` | Release access to one resource |
| `network_request()` | Make one scoped network request |
| `schedule_notification()` | Schedule one notification |
| `create_capability()` | Create a new capability token |
| `invoke_capability()` | Execute an action using a token |
| `exit()` | Terminate the current execution context |

Applications use standard programming facilities for computation, memory management, and local data processing. These 9 primitives govern interaction with protected resources mediated by the capability system.

## Trusted Computing Base

The IntentKernel capability enforcement logic targets a minimal trusted computing base. The reference implementation of core token handling, intent validation, and lease management is designed to remain small enough for systematic audit.

| Component | Description |
| :--- | :--- |
| Capability token logic | Reference C implementation of token creation, validation, and expiry (`src/reference/capability_core.c`) |
| Intent broker core | Intent classification, routing, and correlation |
| Lease scheduler | TTL enforcement and automatic revocation |

For context, the formally verified seL4 microkernel consists of approximately 8,700 LOC of C. The IntentKernel prototype has not undergone formal verification. Formal verification is identified as a future research direction.

## Repository Structure

```
intentkernel/
├── README.md                          # This file
├── LICENSE                            # Apache License 2.0
├── AUTHORS.md                         # Authorship and attribution
├── docs/
│   ├── architecture_overview.md       # Executive summary and stack overview
│   ├── intentkernel_thesis.md         # Core thesis — capability execution model
│   ├── uccs_spec.md                   # Universal Capability Computing Substrate
│   ├── ikrl_spec.md                   # IntentKernel Relief Layer (compatibility)
│   ├── ibp_spec.md                    # Intent Broker Protocol specification
│   └── token_rfc.md                   # RFC-INTENT-001: Capability Token Wire Format
├── src/
│   └── reference/
│       └── capability_core.c          # Reference microkernel capability logic
├── roadmap/
│   └── implementation_plan.md         # Phased development timeline
└── governance/
    └── principles.md                  # Architectural compliance requirements
```

## Roadmap

| Phase | Status | Deliverable |
| :--- | :--- | :--- |
| **v1.0** | Published | Architecture specification and protocol definitions |
| **v1.1** | Current | Consolidated repository with full specification suite |
| **v1.2** | In progress | Reference implementation (Rust) and controlled security evaluation |
| **v1.3** | Planned | Platform-specific enforcement drivers (Windows VBS + Linux LSM) |
| **v1.4** | Planned | SDK release and developer documentation |
| **v2.0** | Long-term | Native hardware specification and SoC integration |

## v1.2 Reference Prototype (Implementation Scaffold)

The repository now includes a Rust workspace under [`src/`](src/) that implements a reference v1.2 prototype:

- [`src/intentkernel-sdk`](src/intentkernel-sdk): capability lifecycle + 9 primitive SDK APIs
- [`src/intentd`](src/intentd): Intent Broker daemon prototype for intent classification and token issuance
- [`src/ransomware-demo`](src/ransomware-demo): end-to-end one-shot capability demo showing repeat-write blocking
- [`src/lsm/intentkernel_lsm.c`](src/lsm/intentkernel_lsm.c): Linux LSM interceptor reference hooks for token-gated file/network/exec operations

### Build and run (Rust workspace)

```bash
cd src
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p ransomware-demo
```

## License

This architecture is released under the [Apache License 2.0](LICENSE).

## Citation

> Daniel Kirk Owings, "IntentKernel: A Capability-Secure Execution Model for Event-Scoped Computing," 2025. Available at [Repository URL].

---

## Project Status

This repository contains architectural specifications, protocol definitions, a reference implementation of core capability logic, and supporting research materials.

**Current maturity:** Specification, prototype, and controlled evaluation.

**Not yet provided:** Production-hardened deployment, formal verification, or native kernel implementation.

The architecture describes a long-term system design. The current work validates the core concepts through user-space prototypes on existing operating systems.
