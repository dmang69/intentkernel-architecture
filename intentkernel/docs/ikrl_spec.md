# INTENTKERNEL RELIEF LAYER (IKRL)
## Evolutionary Security Substrate Specification v2.0

### Document Classification: Public Architecture Guide
### Version: 2.0 (Evolutionary Path Updated)
### Status: Deployable Compatibility Layer

---

## EXECUTIVE SUMMARY: THE EVOLUTIONARY PARADIGM

This specification refines the IntentKernel architecture based on historical deployment analysis of major computing transitions. History proves that new computing paradigms do not replace operating systems directly; they enter as **compatibility layers** and evolve into **native environments**.

*   **POSIX** did not kill proprietary UNIX; it wrapped it until UNIX became POSIX-compliant.
*   **JVM** allowed Java to run on any OS before native bytecode existed.
*   **Docker** normalized containerization before Kubernetes native runtimes were standard.
*   **WSL/Hyper-V** allowed Linux binaries to run on Windows before Windows adopted Linux kernel features natively.
*   **Rosetta** translated x86 to ARM before M-series chips could run legacy code.

**The IntentKernel Relief Layer (IKRL)** follows this exact path. It is not a new OS. It is a **security translation layer** that forces legacy operating systems to behave according to IntentKernel principles: **Event-Scoped Execution** and **Zero Ambient Authority**.

It transforms "Containment" (Sandboxing) into "Authority Scoping" (Capability Leases).

---

## SECTION 1: ARCHITECTURAL CORE — THE FOUR DAEMONS

To function across heterogeneous environments, IKRL decomposes into four universal services. These map to specific platform primitives depending on the host OS, but the logical function remains constant.

```
┌─────────────────────────────────────────────────────────────┐
│                  USER SPACE APPLICATION                      │
└───────────────────────┬─────────────────────────────────────┘
                        │ Syscall / API Intercept
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                   IKRL RELIEF LAYER                          │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │   intentd    │  │     capd     │  │   leasebroker   │   │
│  │ (Intent      │  │ (Capability  │  │ (Time & Lifecycle)│   │
│  │  Broker)     │  │  Engine)     │  │                 │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘   │
│         │                 │                   │             │
│         └─────────────────┴───────────────────┘             │
│                           │                                 │
│                     ┌─────▼─────┐                          │
│                     │  eventscope │                         │
│                     │  Runtime   │                          │
│                     │  (Wrapper) │                          │
│                     └─────┬─────┘                          │
└───────────────────────────┼─────────────────────────────────┘
                            │ Verified Capability Token
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    HOST OPERATING SYSTEM                     │
│                (Windows / Linux / Android / IoT)             │
│            (Treated as Untrusted Resource Provider)          │
└─────────────────────────────────────────────────────────────┘
```

### 1.1 intentd (The Intent Broker)
*   **Function:** Correlates user actions (UI clicks, voice commands, sensor triggers) with application requests.
*   **Platform Mapping:**
    *   **Desktop:** Hooks Input Manager APIs (Win32 UI Thread / X11/Wayland Event Loop).
    *   **Mobile:** Hooks Touch Controller Interrupts / Android WindowManager.
    *   **IoT:** Hooks GPIO Interrupt Handlers / UART Triggers.
*   **Logic:** If `App.Request == Network` AND `User.Intent == False`, THEN `Block`.

### 1.2 capd (The Capability Engine)
*   **Function:** Issues, signs, validates, and revokes capability tokens (PQC-signed data structures).
*   **Platform Mapping:**
    *   **High Security:** Runs inside TPM/TEE/SGX enclave.
    *   **Low Security:** Runs as privileged system service with memory integrity enabled.
*   **Logic:** `Cap_Sign(Intent_Token, Expiry_Time, Scope_Restrictions)`.

### 1.3 leasebroker (The Watchdog)
*   **Function:** Monitors time-to-live (TTL) for every active capability and process lease.
*   **Platform Mapping:**
    *   **General:** Timer Queue / Kernel Cron.
    *   **Critical:** Hardware Watchdog Timers (WDT).
*   **Logic:** On `Ticker_Expire`: `Terminate_Process()`, `Revoke_Capabilities()`, `Zero_Memory()`.

### 1.4 eventscope (The Runtime Wrapper)
*   **Function:** Injects the capability token into the executing process's context (handle table, environment variables, or virtual memory page) only during the execution window.
*   **Platform Mapping:**
    *   **Linux:** ptrace/eBPF injection.
    *   **Windows:** DLL Injection / Job Objects.
    *   **Browser:** Extension Service Worker.
*   **Logic:** `Inject_Capability(Process_ID) → Execute → Purge_Capability`.

---

## SECTION 2: INTERCEPTION VS. CONTAINMENT

The critical differentiation between IKRL and existing security tools (SELinux, AppArmor, Sandboxie) is the **direction of trust**.

| Feature | Traditional Sandbox (Docker/Chrome/Sandwichie) | IKRL Relief Layer |
| :--- | :--- | :--- |
| **Trust Model** | "I trust you, but keep you in a box." | "I do not trust you until I see your intent." |
| **Permission** | Granted at start. Persisted throughout session. | Granted on demand. Expires after use. |
| **Failure Mode** | Jailbreak (Escape the box). | Revocation (Cut the power). |
| **Background** | Allowed to run indefinitely. | Killed if no lease renewal (heartbeat). |
| **Hardware** | Software-enforced isolation. | Logical enforcement (Software) → Physical (Future). |
| **Analogy** | A prison cell. | A turnstile that opens for one person once. |

**Structural Interception:**
IKRL does not just watch syscalls (like AppArmor); it intercepts the **authorization flow**. It ensures that the Host OS cannot grant a handle (file/socket) unless the process presents a valid `capd` token. Even if the Host OS has a bug allowing unauthorized access, IKRL rejects the operation at the application boundary.

---

## SECTION 3: EVOLUTIONARY DEPLOYMENT STAGES

This section defines the technical implementation for each stage of adoption. This allows enterprises to begin deployment immediately without waiting for hardware changes.

### STAGE 1: WINDOWS SERVICE + MICRO-VM WRAPPER
*   **Target:** Enterprise Desktops, Servers, Kiosks.
*   **Implementation:**
    *   `intentd/capd` run as a protected **Hyper-V Guarded Host** agent.
    *   Applications launch inside **Micro-VMs** (Firecracker/QEMU-lite) spawned per task.
    *   `eventscope` uses **Job Objects** to limit memory/CPU quotas.
    *   `leasebroker` monitors VM state via **VMBus**.
*   **Overhead:** 5-15% latency.
*   **Protection Level:** High (Process Isolation). Vulnerable to Hypervisor Escape (Mitigated by HVCI/VBS).

### STAGE 2: LINUX LSM MODULE + NAMESPACE BROKER
*   **Target:** Cloud Instances, Linux Workstations, Edge Gateways.
*   **Implementation:**
    *   `intentd/capd` run as a privileged Daemon using **cgroups v2**.
    *   `eventscope` uses **eBPF programs** to hook syscall entry points (`SEC("syscall")`).
    *   Filesystem access mediated via **OverlayFS** mounts specific to each token.
    *   `leasebroker` uses **Kernel Alarm Timers**.
*   **Overhead:** 2-5% latency.
*   **Protection Level:** Medium-High (Namespace Isolation). Vulnerable to Kernel Exploit.

### STAGE 3: ANDROID PRIVILEGED SYSTEM SERVICE
*   **Target:** Mobile Devices, Tablets.
*   **Implementation:**
    *   `intentd/capd` deployed as a **System Service** signed with Platform Keys.
    *   Integrated into **Activity Manager Service (AMS)**.
    *   `eventscope` wraps **Binder Transactions**.
    *   `leasebroker` integrated with **AlarmManager** (wake locks restricted).
*   **Overhead:** Negligible (<1%).
*   **Protection Level:** Medium (Managed within App Sandbox). Vulnerable to System Compromise.

### STAGE 4: EMBEDDED FIRMWARE SUPERVISOR
*   **Target:** IoT Sensors, Vehicle ECUs, Industrial PLCs.
*   **Implementation:**
    *   `intentd/capd` compiled into **Monolithic Supervisor Loop**.
    *   Uses **Memory Protection Unit (MPU)** to separate Stack/Data/Code.
    *   `leasebroker` is the main timer interrupt handler.
    *   No OS dependency; runs bare-metal alongside firmware.
*   **Overhead:** Minimal (Cycle budget reduction).
*   **Protection Level:** Low-Medium (Hardware dependent). Vulnerable to Flash Read.

### STAGE 5: NATIVE INTENTKERNEL BOOT ENVIRONMENT
*   **Target:** Future Silicon (CHERI-enabled CPUs).
*   **Implementation:**
    *   `capd` logic moves to **Secure Enclave Hardware**.
    *   `intentd` becomes part of **Input Controller Firmware**.
    *   `eventscope` becomes **CPU Capability Register** handling.
    *   Legacy apps run in **Translation Mode** (Stage 1-2 logic).
*   **Overhead:** Near Zero (Hardware Offload).
*   **Protection Level:** Maximum (Physical Impossibility of Violation).

---

## SECTION 4: LEGACY COMPATIBILITY MECHANISMS

How do we make old apps work without recompiling everything?

### 4.1 Shadow Handle Mapping
Legacy apps hold file descriptors (FD) indefinitely.
*   **IKRL Action:** When `open()` is called, IKRL creates a mapping in a local database.
*   **Mapping:** `FD_123` ↔ `CapabilityToken_XYZ`.
*   **Effect:** App thinks it has FD_123 open forever. IKRL sees it as Cap_XYZ which expires in 5 seconds.
*   **Expiration:** When expiry hits, IKRL closes the underlying OS FD silently. App crashes on next read/write, forcing restart (fresh start = fresh capabilities).

### 4.2 Background Process Heartbeat
Legacy daemons run forever.
*   **IKRL Action:** Assigns a "Lease ID" to the process PID.
*   **Check:** Every minute, `leasebroker` checks if PID exists AND if a valid intent event occurred recently.
*   **Action:** If no intent, send `SIGTERM`. If ignored, `SIGKILL`. Memory is scrubbed.

### 4.3 Network Proxy Tunneling
Legacy apps use raw sockets.
*   **IKRL Action:** Force-bind apps to a loopback proxy port managed by `capd`.
*   **Flow:** App connects to localhost:port → `capd` validates token → `capd` forwards real traffic to external endpoint encrypted (PQC-TLS).
*   **Result:** App never touches a network stack directly. All traffic is logged and scoped.

---

## SECTION 5: DEVELOPER WORKFLOW (SDK INTEGRATION)

Developers should not need to rewrite apps, but optional SDK integration enables better compliance.

### 5.1 Annotation System
```python
# Python Example
from ikrl_sdk import intent_scope

@intent_scope(resource="camera", duration_ms=5000)
def capture_image():
    # Camera access automatically revoked after 5 seconds
    return camera.read()

@intent_scope(resource="network_endpoint", target="api.example.com")
def send_data(payload):
    # Network access limited to specific host
    return http.post(payload)
```

### 5.2 Manifest Declaration
No complex permissions XML. Just intent definitions.
```yaml
# ikrl_manifest.yaml
app_id: com.secure.bank
version: 1.0
intents:
  - resource: pinpad_input
    type: ephemeral
    max_tries: 3
  - resource: transaction_sign
    type: biometric_triggered
    requires_pqc_token: true
```

### 5.3 Simulation Tool
Before release, developers run the app through `ikrl_simulate`.
```bash
$ ikrl_simulate --strict ./my_app
[INFO] Launching simulated environment...
[WARN] Detected attempt to access disk without intent scope. BLOCKED.
[WARN] Detected background wake lock without heartbeat. TERMINATED.
[SUCCESS] Compliance Score: 98%
```

---

## SECTION 6: SECURITY GUARANTEES AT EACH STAGE

Even in Stage 1, what guarantees hold?

| Guarantee | Stage 1 (Win) | Stage 2 (Linux) | Stage 3 (Mobile) | Stage 4 (Embedded) | Stage 5 (Native) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **No Persistent Privilege** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Lease Expiry** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Intent Verification** | ⚠️ (Software) | ⚠️ (Software) | ✅ (Hardware UI) | ⚠️ (Timer) | ✅ (Hardware Input) |
| **Anti-Replay** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Memory Integrity** | ⚠️ (HVCI) | ⚠️ (KASLR) | ✅ (SE) | ⚠️ (MPU) | ✅ (CHERI) |
| **Malware Immunity** | Partial | Partial | Partial | Partial | Complete |

**Note on "Partial":** In software stages, malware *can* theoretically exploit bugs in IKRL itself. However, since IKRL is much smaller (~20k LOC) than the OS kernel (~20M LOC), and focused purely on capability validation, the attack surface is drastically reduced.

---

## SECTION 7: IMPLEMENTATION ROADMAP FOR ENTERPRISES

### Q1-Q2: Pilot Deployment (Stage 1)
*   **Scope:** High-value laptops and servers.
*   **Install:** IKRL Agent Installer (.msi/.deb).
*   **Config:** Policy set to "Log Only".
*   **Outcome:** Baseline data on false positives. Identify apps requiring special exemptions.

### Q3-Q4: Strict Enforcement (Stage 1-2)
*   **Scope:** Finance, Legal, Engineering departments.
*   **Config:** Policy set to "Strict". Non-compliant apps block.
*   **Support:** Helpdesk trained on "Intent Denied" error messages.
*   **Outcome:** Reduction in lateral movement incidents. Elimination of persistent backdoors.

### Year 2: Integration (Stage 3)
*   **Scope:** Corporate Mobile Device Management (MDM).
*   **Config:** Push IKRL profile to all managed iOS/Android devices.
*   **Outcome:** Unified security posture across desktop and mobile.

### Year 3+: Hardware Transition (Stage 4-5)
*   **Scope:** New procurement standards.
*   **Config:** Require hardware vendors to support IKRL interfaces (TPM extensions, CHERI pointers).
*   **Outcome:** Phase out IKRL software layers as hardware takes over enforcement.

---

## CONCLUSION: THE PATH TO STRUCTURAL IMMUNITY

The IntentKernel Relief Layer represents the most pragmatic path to a secure computing future. By acknowledging that operating systems cannot be replaced overnight, IKRL acts as the "immune system" overlay for existing hosts.

It enforces three non-negotiable rules:
1.  **Authority is Temporary.** (Leases)
2.  **Power Requires Intent.** (Broker)
3.  **Access Must Be Proven.** (Capabilities)

This does not require users to learn new workflows. They click buttons and open files as usual. Behind the scenes, `intentd` and `capd` ensure that every click generates a single-use ticket and every ticket burns after use.

This is how structural security wins: not by shouting "Stop!", but by quietly ensuring there is no fuel for the fire to burn in the first place.

**END OF SPECIFICATION**