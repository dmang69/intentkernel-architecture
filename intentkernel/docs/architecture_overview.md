# IntentKernel Architecture v1.1
## A Capability-Secure Execution Model for Event-Scoped Computing

**Status:** Public Architecture Proposal
**Version:** 1.1.0
**Date:** 2025
**License:** Apache 2.0

---

## 1. Abstract

The IntentKernel Architecture is a universal computing security substrate designed to eliminate ambient authority across all device classes — desktops, mobile devices, servers, IoT systems, vehicles, industrial controllers, and cloud infrastructure.

Traditional computing models rely on persistent permissions granted at install time or login. This creates structural vulnerabilities where compromised applications retain unlimited access indefinitely. IntentKernel replaces this with Event-Scoped Authority: power is granted only at the moment of verified user intent and expires automatically when the task completes.

This specification defines a universal stack consisting of four layers: IntentKernel, UCCS, IKRL, and IBPS. Together, they provide a migration path from legacy operating systems toward a structurally secure future.

---

## 2. Problem Statement

Modern computing security is fundamentally broken due to three legacy design flaws:

**Persistent Privilege.** Applications granted permissions once retain permanent access to sensitive resources (files, network, sensors), enabling ransomware, spyware, and data exfiltration.

**Identity-Based Trust.** Access control relies on who you are (user ID), not what you intend to do. This allows lateral movement within compromised sessions.

**Migration Friction.** Existing ecosystems cannot be replaced overnight. New secure architectures require OS replacement, which stalls adoption for decades (BeOS, Haiku, Qubes desktop adoption all failed this way).

IntentKernel resolves these by treating all authority as temporary. No process runs with ambient power. Every action requires a cryptographic proof of intent, issued by a trusted broker, and bound to a strict time-to-live.

---

## 3. Architecture Stack

The system is divided into four interoperable components:

**IntentKernel (Execution Model)** defines the rules of event-scoped execution and capability lifecycle. No code has authority by default. All access to resources requires a cryptographically signed capability token issued at the moment of verified user intent. See `intentkernel_thesis.md`.

**UCCS (Universal Capability Computing Substrate)** is the hardware-independent abstraction layer. UCCS defines the standard interfaces for capability enforcement across ARM, x86, and RISC-V architectures, ensuring portability from microcontrollers to datacenters. See `uccs_spec.md`.

**IKRL (IntentKernel Relief Layer)** is the compatibility and migration engine. IKRL runs as a virtualization substrate on top of existing operating systems. It intercepts syscalls, enforces capability checks, and manages intent brokering without requiring kernel replacement. See `ikrl_spec.md`.

**IBPS (Intent Broker Protocol Specification)** is the communication standard. IBPS defines how user intent is captured, validated, and translated into capability tokens. It ensures secure federation between devices and cloud services. See `ibp_spec.md` and `token_rfc.md`.

---

## 4. Core Security Model

**Zero Ambient Authority.** Every process starts with zero capabilities. It cannot allocate memory, access files, or send network packets until explicitly granted authority by the Intent Broker. There is no root. There is no admin concept that persists.

**Event-Scoped Privileges.** Capabilities are not permanent. They are scoped to a specific resource (e.g., one file, not a directory), a specific action (READ, not WRITE), a specific time window (TTL = 10 seconds), and a specific use count (Uses = 1).

**Intent Trust Hierarchy.** Authority is weighted based on the source of intent: Hardware (physical buttons, GPIO — highest trust), Biometric (local secure enclave match), UI Event (secure overlay confirmation), and Software (automated signals — lowest trust, restricted scope).

**Post-Quantum Cryptography.** All capability tokens are signed using ML-DSA-87 (Dilithium 5). All network communications use Kyber-1024 key exchange. This ensures security against both classical and quantum adversaries.

---

## 5. Deployment Strategy

IntentKernel follows a Compatibility First doctrine. It enters as a security runtime on existing operating systems and evolves toward native hardware — mirroring the success of TCP/IP, TLS, Docker, and POSIX.

Stage 1 deploys IKRL as a Windows Service using VBS, providing ransomware immunity for existing enterprise fleets. Stage 2 targets Linux and cloud infrastructure via LSM modules and eBPF. Stage 3 covers mobile devices via privileged system services. Stage 4 addresses embedded systems and IoT via firmware supervisors. Stage 5 delivers native hardware enforcement with the IntentKernel microkernel on bare metal.

We are not distributing a new operating system. We are distributing a Runtime Environment compatible with existing OSes. This eliminates the friction that killed every previous secure OS attempt.

---

## 6. Capability Token Specification

Tokens follow RFC-INTENT-001 (see `token_rfc.md`). Key characteristics: CBOR binary encoding for efficiency across IoT and high-performance contexts, ML-DSA-87 post-quantum signatures, Kernel Handle optimization (64-bit handles for syscalls to avoid verifying the full ~4.6KB signature on every call), and global revocation list propagation with sub-100ms latency for critical revocation.

---

## 7. Security Guarantees

Ransomware is eliminated because no file write capability exists unless explicitly triggered by user action. Spyware is eliminated because input and sensor capabilities expire instantly after capture. Backdoors are eliminated because background services require heartbeat lease renewal or are killed. Data exfiltration is eliminated because network capabilities are scoped per destination and revoked after transfer. Privilege escalation is eliminated because no process can grant itself permissions — only the Broker can issue tokens. Quantum attacks are mitigated because all tokens use NIST-standardized post-quantum algorithms.

---

## 8. Governance

To maintain architectural integrity, all implementations claiming IntentKernel compatibility must adhere to the principles defined in `governance/principles.md`. The core requirements are: structural immunity through enforcement (not detection), user sovereignty (no backdoors), transparency (all capabilities visible), portability (protocol works across all stages), and open core (specifications remain publicly available).

---

## 9. References

Detailed specifications are maintained in adjacent documents:

- [`ibp_spec.md`](ibp_spec.md) — Intent Broker Protocol v1.0
- [`token_rfc.md`](token_rfc.md) — RFC-INTENT-001: Capability Token Wire Format
- [`uccs_spec.md`](uccs_spec.md) — Universal Capability Computing Substrate
- [`ikrl_spec.md`](ikrl_spec.md) — IntentKernel Relief Layer Architecture
- [`intentkernel_thesis.md`](intentkernel_thesis.md) — Core Thesis

---

*End of Architecture Overview v1.1*
