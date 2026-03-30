# IntentKernel Governance Principles

## Architectural Compliance Requirements

Any implementation claiming "IntentKernel Compatible" must adhere to all of the following principles. These are non-negotiable and cannot be waived by configuration, policy, or administrative override.

## 1. Structural Immunity

Malware mitigation must be achieved through enforcement (capabilities), not detection (signatures). An IntentKernel-compatible system does not scan for malware. It makes malware structurally impossible by denying all ambient authority.

## 2. Zero Ambient Authority

No process, service, daemon, or kernel module may hold persistent authority. All capabilities must be event-scoped, time-bounded, and use-limited. There is no root. There is no superuser. There is no exception.

## 3. User Sovereignty

The user is the sole authority. No application, service, corporation, or government entity may override the user's intent decisions. The architecture does not support backdoors. If the key is lost, the data is lost.

## 4. Transparency

Users must always know what capabilities are active. All security decisions are auditable and logged to an immutable ledger. There are no silent permissions.

## 5. Portability

The Intent Broker Protocol (IBPS) must work identically across all deployment stages — from IKRL compatibility mode on legacy operating systems through native hardware enforcement. A capability token issued on Stage 1 must be validatable on Stage 5.

## 6. Post-Quantum Mandate

All cryptographic operations must use NIST-standardized post-quantum algorithms. No fallback to classical cryptography (RSA, ECC) is permitted in production deployments. Hybrid modes (PQC + classical) are acceptable only during documented transition periods.

## 7. Open Core

Core specifications (IntentKernel execution model, IBPS protocol, UCCS substrate, token wire format) must remain publicly available. Custom extensions are permitted if they maintain backward compatibility with the core protocol.

## 8. Minimal TCB

The trusted computing base for any device class must never exceed 25,000 lines of code. Any TCB larger than this is by definition unauditable and therefore untrusted.

## 9. Security is Default

Security cannot be disabled by users, administrators, or enterprise policy. There is no "developer mode" that bypasses capability enforcement. Debug and audit tools operate within the capability model, not outside it.
