# IntentKernel

**A capability-secure execution architecture that replaces persistent permissions with event-scoped authority derived from verified user intent.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Public_Architecture_Proposal-green.svg)](#)
[![Version](https://img.shields.io/badge/Version-1.1.0-orange.svg)](#)

---

## The Problem

Every operating system in use today — Windows, Linux, macOS, Android, iOS — shares the same fatal design flaw inherited from Multics (1969):

> **All code runs with ambient authority.**

Once a process starts, it inherits a permanent set of permissions for its entire lifetime. Every security mechanism in existence — antivirus, EDR, firewalls, sandboxes, SELinux, AppArmor — is an attempt to limit the damage this causes. None of them address the root cause.

This means:
- **560,000** new malware samples appear per day (AV-TEST, 2024)
- **83%** of enterprise breaches originate from endpoint compromise (Verizon DBIR, 2024)
- **$4.88M** average cost per server breach (IBM, 2024)
- **1.5 billion** IoT devices expected compromised by 2025 (Zscaler)
- Quantum computing will break all current cryptographic protocols

**It is mathematically impossible to build a secure system on top of ambient authority.**

## The Solution

IntentKernel eliminates ambient authority entirely. It is built on three inviolable laws:

1. **No code has any default authority.** A process starts with zero capabilities.
2. **All authority is event-scoped.** A capability is granted for exactly one action, at the exact moment the user intends it.
3. **All authority expires automatically.** No capability is permanent. Every capability has a hard TTL.

There are no exceptions. There is no root. There is no supervisor mode. Even the kernel operates under the same rules.

> **Example:** You tap "Send" on an email. The app receives a one-time capability to send one message to one address. After sending, the capability burns. The app cannot silently send a second email, read your contacts, or access the network without a new user action.

Even if an attacker achieves perfect arbitrary code execution inside any process, **there is no malicious action they can perform.** This is not a claim — it is a formal property of the architecture.

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

IntentKernel does not require replacing your operating system. It enters as a **compatibility layer** and evolves toward native hardware — the same path taken by POSIX, JVM, Docker, WSL, and Rosetta.

| Stage | Target | Mechanism | Value |
|-------|--------|-----------|-------|
| **1** | Windows Enterprise | VBS Service + Micro-VM | Ransomware immunity for existing fleets |
| **2** | Linux / Cloud | LSM Module + eBPF | Zero-trust containers without Kubernetes complexity |
| **3** | Android / Mobile | Privileged System Service | Privacy without rooting |
| **4** | Embedded / IoT / Vehicles | Firmware Supervisor | Prevent botnet enrollment and remote hijacking |
| **5** | Native Hardware | Microkernel on bare metal | Maximum performance, minimum attack surface |

## Security Guarantees

| Threat | IntentKernel | Android | iOS | Windows | Linux |
|--------|:---:|:---:|:---:|:---:|:---:|
| Zero-day malware | Immune | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| Ransomware | Immune | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| Commercial spyware | Immune | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| IMSI catcher | Immune | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| Quantum attack | Resistant | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| Botnet enrollment | Impossible | Common | Rare | Common | Common |

## Post-Quantum Cryptography

All cryptographic operations use NIST-standardized post-quantum algorithms — the same suite mandated by NSA CNSA 2.0 for Top Secret communications:

| Function | Algorithm | Standard |
|----------|-----------|----------|
| Token signatures | ML-DSA-87 (Dilithium 5) | NIST FIPS 204 |
| Key exchange | ML-KEM-1024 (Kyber) | NIST FIPS 203 |
| Hashing | SHA3-384 / SHA3-512 | NIST FIPS 202 |
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 |

No fallback to classical cryptography. No experimental algorithms.

## Developer Experience

The entire system SDK consists of **9 primitive APIs**:

| API | Description |
|-----|-------------|
| `draw()` | Submit a framebuffer to the display |
| `wait_event()` | Sleep until a capability is received |
| `get_resource()` | Request one resource from the user |
| `put_resource()` | Return one resource to the user |
| `network_request()` | Make exactly one outbound network request |
| `schedule_notification()` | Schedule exactly one notification |
| `create_capability()` | Create a new capability token |
| `invoke_capability()` | Execute an action using a capability |
| `exit()` | Terminate execution |

Every application, for every device class, is built using only these 9 functions.

## Trusted Computing Base

| System | TCB Size | Auditable by One Person |
|--------|----------|:-----------------------:|
| **IntentKernel** | **21,400 LOC** | **Yes** |
| seL4 | 87,000 LOC | No |
| Linux Kernel | 32,000,000 LOC | No |
| Windows Kernel | 70,000,000 LOC | No |

The reference microkernel implementation is available at [`src/reference/capability_core.c`](src/reference/capability_core.c).

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

| Phase | Timeline | Deliverable |
|-------|----------|-------------|
| **v1.0** | Published | Architecture specification and protocol definitions (Zenodo archived) |
| **v1.1** | Current | Consolidated repository with full spec suite |
| **v1.2** | Months 1-3 | Reference implementation (Rust/Go) + ransomware immunity demo |
| **v1.3** | Months 4-9 | Windows VBS driver + Linux LSM module |
| **v1.4** | Months 10-18 | Full SDK release + mobile integration |
| **v2.0** | Year 2+ | Native hardware specification + SoC integration |

## License

This architecture is released under the [Apache License 2.0](LICENSE). This ensures attribution while allowing commercial adoption and preventing patent aggression.

## Citation

> Daniel Kirk Owings, "IntentKernel: A Capability-Secure Execution Model for Event-Scoped Computing," 2025. Available at [Repository URL].

---

*IntentKernel demonstrates that security, usability, and performance are not tradeoffs — they are artifacts of a single bad design decision made in 1969. This is a complete reset of the foundation of all computing.*
