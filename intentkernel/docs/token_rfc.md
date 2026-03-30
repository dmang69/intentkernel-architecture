# RFC-INTENT-001: Capability Token Wire Format v1.0
## IntentKernel Runtime Environment (IKRE)
### Classification: Proposed Standard
### Date: October 2025
### Status: **Canonical Specification**

---

## 1.0 Executive Summary

This document defines the canonical binary wire format for IntentKernel Capability Tokens. It resolves previous ambiguities regarding token structure, size, and cryptographic suites.

**Key Decisions:**
1.  **Encoding:** **CBOR (RFC 8949)**. Chosen for binary efficiency, extensibility, and native support in embedded/cloud environments.
2.  **Cryptographic Suite:** **ML-DSA-87 (Dilithium 5)** for signatures (Post-Quantum). **SHA-384** for hashing.
3.  **Two-Tier Structure:**
    *   **Full Token:** Used for issuance and federation (includes signature).
    *   **Kernel Handle:** Used for syscalls (indexed reference for performance).
4.  **Intent Anchoring:** Includes a `trust_anchor` field to encode the Intent Trust Hierarchy.
5.  **Lease State:** Includes explicit state machine encoding for background execution.

This format is mandatory for all IntentKernel Relief Layer (IKRL) implementations and Native IntentKernel deployments.

---

## 2.0 Token Structure Overview

A Capability Token consists of three logical sections: **Header**, **Payload**, and **Signature**.

```text
+------------------+------------------+------------------+
|      Header      |      Payload     |     Signature    |
| (5-10 bytes)     | (50-200 bytes)   | (4,595 bytes)    |
+------------------+------------------+------------------+
| CBOR Map         | CBOR Map         | Raw Bytes        |
| Version, Type    | Scope, Context   | ML-DSA-87        |
| Algo, Anchor     | TTL, Lease State |                  |
+------------------+------------------+------------------+
```

> **Note on Size:** The signature dominates the size (~4.6KB for Dilithium 5). To optimize syscall performance, the **Kernel Handle** mechanism (Section 6.0) is used for local enforcement. The Full Token is used for issuance, storage, and cross-device federation.

---

## 3.0 CBOR Data Definition

The token is encoded as a single CBOR Map. Tags are used for semantic typing.

### 3.1 Header Fields (Critical)

| Label | Key | Type | Description |
| :--- | :--- | :--- | :--- |
| `1` | `ver` | `uint` | Protocol Version (Current: `1`) |
| `2` | `typ` | `uint` | Token Type (See 3.3) |
| `3` | `alg` | `uint` | Crypto Algorithm (See 3.4) |
| `4` | `anchor` | `uint` | Intent Trust Anchor (See 4.0) |

### 3.2 Payload Fields (Critical)

| Label | Key | Type | Description |
| :--- | :--- | :--- | :--- |
| `10` | `iss` | `bstr` | Issuer ID (Broker Public Key Hash) |
| `11` | `sub` | `bstr` | Subject ID (App Binary Hash) |
| `12` | `ctx` | `bstr` | Context Hash (SHA-384 of Action) |
| `13` | `scope` | `map` | Resource Scope (See 3.5) |
| `14` | `exp` | `uint` | Expiration (Unix Epoch ms) |
| `15` | `nbf` | `uint` | Not Before (Unix Epoch ms) |
| `16` | `uses` | `uint` | Max Uses (0 = Unlimited within TTL) |
| `17` | `state` | `uint` | Lease State (See 5.0) |
| `18` | `jti` | `bstr` | Unique Token ID (UUID v4) |

### 3.3 Token Types (`typ`)

| Value | Name | Description |
| :--- | :--- | :--- |
| `1` | `CAPABILITY` | Single-use or limited-use access token. |
| `2` | `LEASE` | Renewable background execution lease. |
| `3` | `DELEGATION` | Token derived from a parent token. |
| `4` | `REVOCATION` | Revocation list entry (CRL). |

### 3.4 Cryptographic Algorithms (`alg`)

| Value | Name | Description |
| :--- | :--- | :--- |
| `1` | `ML-DSA-87` | Dilithium 5 (Post-Quantum Signature). |
| `2` | `Ed25519` | Classical (Legacy/Debug only). |
| `3` | `ML-DSA-65` | Dilithium 3 (Constrained IoT). |

### 3.5 Scope Map (`scope`)

Dynamic structure based on resource type.

**Example: Network Scope**
```cbor
{
  "proto": 1,            // 1=TCP, 2=UDP
  "dst_ip": h'0A000001', // 10.0.0.1
  "dst_port": 443,
  "bytes": 1048576       // Max bytes
}
```

**Example: File Scope**
```cbor
{
  "path": "/data/secret.txt",
  "access": 1,           // 1=Read, 2=Write, 3=RW
  "inode": 123456
}
```

---

## 4.0 Intent Trust Hierarchy (`anchor`)

This field encodes the root-of-authority for the token. It prevents software signals from being treated equal to hardware signals.

| Value | Level | Source | Security Property |
| :--- | :--- | :--- | :--- |
| `0` | `NONE` | Software Signal | **Never grants sensitive access.** |
| `1` | `UI_EVENT` | OS Compositor Click | Validated via Secure UI Path. |
| `2` | `BIOMETRIC` | Local Biometric Match | Bound to local user presence. |
| `3` | `HARDWARE` | Physical Button/GPIO | Highest trust (e.g., Emergency Stop). |
| `4` | `FEDERATED` | Remote Broker Trust | Validated via Cross-Device Protocol. |

**Enforcement Rule:**
*   `anchor < 1`: Token invalid for File/Network/Camera.
*   `anchor >= 3`: Required for Vehicle/Industrial Actuator control.

---

## 5.0 Lease State Machine (`state`)

For `typ = LEASE`, this field tracks the lifecycle.

| Value | State | Description | Transition Condition |
| :--- | :--- | :--- | :--- |
| `0` | `REQUESTED` | Pending Broker Approval | Initial state. |
| `1` | `GRANTED` | Active Execution | Broker signature received. |
| `2` | `RENEWING` | Heartbeat Pending | 80% of TTL elapsed. |
| `3` | `EXPIRED` | Execution Halted | TTL reached 0. |
| `4` | `REVOKED` | Forcefully Terminated | Broker revocation received. |
| `5` | `SUSPENDED` | Paused (Resource Save) | System low power. |

**Enforcement Rule:**
*   Kernel scheduler checks `state` on every context switch for leased processes.
*   If `state != GRANTED`, process is suspended.

---

## 6.0 Optimization: The Kernel Handle

Transmitting 4.6KB signatures on every syscall is inefficient. The IntentKernel Relief Layer uses a **Handle Optimization**.

1.  **Issuance:** App receives **Full Token** (CBOR + Signature).
2.  **Registration:** App presents Full Token to Kernel/LSM once.
3.  **Validation:** Kernel verifies signature, stores token in internal table.
4.  **Invocation:** Kernel returns a **64-bit Handle ID**.
5.  **Syscall:** App uses Handle ID for subsequent operations.
6.  **Expiry:** Kernel invalidates Handle ID when Full Token expires.

**Handle Structure (64-bit):**
```c
struct KernelHandle {
    uint32_t table_index;   // Index in kernel capability table
    uint16_t generation;    // Prevents reuse of freed indices
    uint16_t checksum;      // Quick integrity check
};
```

---

## 7.0 C Implementation Reference

### 7.1 Token Structure (Wire Format)

```c
#include <stdint.h>
#include <stdbool.h>

#define ML_DSA_87_SIG_LEN 4595
#define CBOR_HEADER_MAX 16

typedef struct {
    uint8_t cbor_header[CBOR_HEADER_MAX];
    uint8_t payload_buffer[512];
    uint8_t signature[ML_DSA_87_SIG_LEN];
    uint16_t payload_len;
} IntentTokenWire;
```

### 7.2 Kernel Handle (Syscall Argument)

```c
typedef struct {
    uint64_t handle_id;
    uint64_t sequence_num; // Prevents replay within session
} KernelCapHandle;
```

### 7.3 Validation Function Prototype

```c
// Returns 0 on success, -1 on failure
int intent_validate_token(
    const IntentTokenWire *token, 
    const uint8_t *broker_pub_key,
    uint64_t *out_handle_id
);
```

---

## 8.0 Example Flows

### 8.1 File Open (Local)
1.  **App:** Requests `open_file`.
2.  **Broker:** Issues Full Token (`anchor=UI_EVENT`, `scope={path:/doc.txt}`).
3.  **App:** Sends Full Token to IKRL Kernel Driver.
4.  **Kernel:** Verifies ML-DSA signature. Stores in table. Returns `HandleID: 0x5A2`.
5.  **App:** Calls `read(0x5A2)`.
6.  **Kernel:** Checks `HandleID` validity. Allows read.

### 8.2 Cloud Invocation (Federated)
1.  **Local App:** Requests cloud function.
2.  **Local Broker:** Issues Full Token (`anchor=FEDERATED`).
3.  **Network:** Token sent via HTTPS to Cloud Endpoint.
4.  **Cloud Broker:** Verifies signature against Local Broker's public key (pre-shared).
5.  **Cloud Function:** Executes if valid.

### 8.3 Vehicle Actuator (High Trust)
1.  **Controller:** Requests `brake_adjust`.
2.  **Broker:** Checks `anchor`. Requires `HARDWARE` (Level 3).
3.  **Driver:** Presses physical confirmation button on steering wheel.
4.  **Broker:** Issues Token (`anchor=HARDWARE`, `TTL=100ms`).
5.  **ECU:** Executes command. Token expires immediately after.

---

## 9.0 Security Considerations

1.  **Signature Malleability:** CBOR must be strictly canonicalized (deterministic encoding) before signing. Use RFC 8949 Section 4.2 rules.
2.  **Clock Skew:** `exp` and `nbf` rely on synchronized time. IKRL must enforce NTP/PTP sync with a max skew of 5 seconds.
3.  **Key Storage:** Broker private keys **must** reside in hardware enclave (TPM/SGX/Secure Enclave). Never in userspace memory.
4.  **Handle Leakage:** Kernel Handles are volatile. They are invalid after reboot. Full Tokens must be re-presented after reboot.

---

## 10.0 Migration and Versioning

*   **Version Field:** The `ver` field allows future evolution.
*   **Backwards Compatibility:** IKRL v1.0 brokers will reject tokens with `ver > 1`.
*   **Algorithm Agility:** The `alg` field allows migration to new PQ algorithms (e.g., Dilithium 6) without changing the wire format structure.

---

## 11.0 Implementation Roadmap (Immediate)

To validate this RFC, the following steps are required for the **Phase 1 PoC**:

1.  **Week 1:** Implement CBOR encoding/decoding library for C (use TinyCBOR).
2.  **Week 2:** Integrate PQ Crypto Library (liboqs) for ML-DSA-87 signing/verification.
3.  **Week 3:** Build `capd.exe` (Windows) to issue tokens using this format.
4.  **Week 4:** Build `eventscope.dll` to present tokens to the kernel driver.
5.  **Week 5:** Demonstrate **Ransomware Immunity**:
    *   Run ransomware binary inside IKRL.
    *   Attempt `CreateFileW` on target directory.
    *   **Result:** Kernel denies request (Error 5: Access Denied) because no valid Token Handle was presented.
    *   **Metric:** 0 bytes encrypted.

---

## 12.0 Conclusion

RFC-INTENT-001 establishes the single source of truth for authority in the IntentKernel ecosystem. By standardizing on CBOR and Post-Quantum cryptography, while optimizing for syscall performance via Kernel Handles, this format enables both high-security enforcement and high-performance execution.

This specification, combined with the **Intent Broker Protocol** and **Lease Scheduling Model**, completes the triad of engineering artifacts required to begin prototype development.

**End of RFC-INTENT-001**