//! intentd — IntentKernel Intent Broker Daemon
//!
//! Accepts connections on both stdin and a Unix domain socket.  Each session
//! receives a line-oriented text protocol:
//!
//! ```text
//! issue <source:A|B|C> <resource_id> <action:wait|get|put|net|notify|invoke|draw|exit> <target> <uses>
//! revoke <token_id>
//! bind <pid>
//! list
//! config get [<key>]
//! config set <key> <value>
//! quit
//! ```
//!
//! All capability events and config changes are written to the audit log at
//! `AUDIT_LOG`.  The Unix socket path is `SOCKET_PATH`.

use intentkernel_sdk::{
    config::KernelConfig, CapabilityScope, IntentKernelSdk, IntentRequest, IntentSource,
    RiskLevel,
};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SOCKET_PATH: &str = "/tmp/intentkernel-intentd.sock";
pub const AUDIT_LOG: &str = "/tmp/intentkernel-audit.log";
const MAX_RESOURCE_BYTES: usize = 1_048_576;

// ─── Shared broker state ──────────────────────────────────────────────────────

struct TokenMeta {
    pid: Option<u32>,
    scope_tag: String,
    resource: String,
    exp_ms: u64,
    uses: u32,
}

struct BrokerState {
    sdk: IntentKernelSdk,
    meta: HashMap<u64, TokenMeta>,
    config: KernelConfig,
}

impl BrokerState {
    fn new() -> Self {
        Self {
            sdk: IntentKernelSdk::new("intentd.mldsa87.v1"),
            meta: HashMap::new(),
            config: KernelConfig::default(),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn audit(line: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG)
    {
        let ts = now_ms();
        let _ = writeln!(f, "[{ts}] {line}");
    }
}

// ─── Command processing ───────────────────────────────────────────────────────

/// Process one line from a session.  Returns `true` if the session should end.
fn handle_line(
    line: &str,
    state: &Arc<Mutex<BrokerState>>,
    session_pid: &mut Option<u32>,
    out: &mut dyn Write,
) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return false;
    }

    match parts[0] {
        // ── issue ────────────────────────────────────────────────────────────
        "issue" if parts.len() >= 6 => {
            let source = match parts[1] {
                "A" => IntentSource::SecureInputPath,
                "B" => IntentSource::DerivedSystemEvent,
                "C" => IntentSource::Scheduler,
                _ => {
                    let _ = writeln!(out, "error: invalid source (expect A|B|C)");
                    return false;
                }
            };
            let resource_id = parts[2].to_string();
            let action = parts[3];
            let target = parts[4].to_string();
            let uses: u32 = match parts[5].parse() {
                Ok(v) if v > 0 => v,
                _ => {
                    let _ = writeln!(out, "error: uses must be a positive integer");
                    return false;
                }
            };

            let scope = match action {
                "draw" => CapabilityScope::Draw,
                "wait" => CapabilityScope::WaitEvent,
                "get" => CapabilityScope::GetResource {
                    resource_id: target.clone(),
                },
                "put" => CapabilityScope::PutResource {
                    resource_id: target.clone(),
                    max_bytes: MAX_RESOURCE_BYTES,
                },
                "net" => CapabilityScope::NetworkRequest {
                    destination: target.clone(),
                    max_bytes: MAX_RESOURCE_BYTES,
                },
                "notify" => CapabilityScope::ScheduleNotification {
                    channel: target.clone(),
                },
                "invoke" => CapabilityScope::InvokeCapability {
                    operation: target.clone(),
                },
                "exit" => CapabilityScope::Exit,
                _ => {
                    let _ = writeln!(out, "error: unknown action '{action}'");
                    return false;
                }
            };

            let risk = match source {
                IntentSource::SecureInputPath => RiskLevel::High,
                IntentSource::DerivedSystemEvent => RiskLevel::Medium,
                IntentSource::Scheduler => RiskLevel::Low,
            };

            let req = IntentRequest {
                source,
                app_id: "intentd.cli".into(),
                user_id: "operator".into(),
                device_id: "linux-host".into(),
                resource_id: resource_id.clone(),
                timestamp_ms: now_ms(),
            };

            let token = {
                let mut s = state.lock().unwrap();

                // Check network guard from config.
                if matches!(scope, CapabilityScope::NetworkRequest { .. })
                    && !s.config.execution.network_enabled
                {
                    let _ = writeln!(
                        out,
                        "denied: network_request requires execution.network_enabled=true"
                    );
                    audit(&format!(
                        "DENIED  pid={:?} scope=NetworkRequest (network_enabled=false)",
                        session_pid
                    ));
                    return false;
                }

                let t = s.sdk.create_capability(&req, scope.clone(), risk, uses);

                // Store metadata for the `list` command.
                s.meta.insert(
                    t.id,
                    TokenMeta {
                        pid: *session_pid,
                        scope_tag: action.to_string(),
                        resource: resource_id.clone(),
                        exp_ms: t.exp_ms,
                        uses,
                    },
                );
                t
            };

            let msg = format!(
                "issued id={} class={:?} exp_ms={} uses={} alg={} kid={}",
                token.id, token.class, token.exp_ms, token.uses, token.alg, token.kid
            );
            let _ = writeln!(out, "{msg}");
            audit(&format!(
                "ISSUED  pid={:?} id={} scope={action} resource={resource_id} uses={uses}",
                session_pid, token.id
            ));
        }

        // ── revoke ───────────────────────────────────────────────────────────
        "revoke" if parts.len() >= 2 => {
            if let Ok(id) = parts[1].parse::<u64>() {
                state.lock().unwrap().sdk.broker_mut().revoke(id);
                let _ = writeln!(out, "revoked id={id}");
                audit(&format!("REVOKED pid={:?} id={id}", session_pid));
            } else {
                let _ = writeln!(out, "error: invalid token id");
            }
        }

        // ── bind ─────────────────────────────────────────────────────────────
        "bind" if parts.len() >= 2 => {
            if let Ok(pid) = parts[1].parse::<u32>() {
                *session_pid = Some(pid);
                let _ = writeln!(out, "bound pid={pid}");
                audit(&format!("BIND    pid={pid}"));
            } else {
                let _ = writeln!(out, "error: invalid pid");
            }
        }

        // ── list ─────────────────────────────────────────────────────────────
        "list" => {
            let s = state.lock().unwrap();
            let now = now_ms();
            let active: Vec<_> = s.meta.iter().filter(|(_, m)| m.exp_ms > now).collect();
            let _ = writeln!(out, "active tokens: {}", active.len());
            for (id, m) in &active {
                let ttl_s = (m.exp_ms.saturating_sub(now)) / 1000;
                let _ = writeln!(
                    out,
                    "  id={id} scope={} resource={} pid={} ttl={}s uses={}",
                    m.scope_tag,
                    m.resource,
                    m.pid.map_or("none".to_string(), |p| p.to_string()),
                    ttl_s,
                    m.uses,
                );
            }
        }

        // ── config get ───────────────────────────────────────────────────────
        "config" if parts.len() >= 2 && parts[1] == "get" => {
            let s = state.lock().unwrap();
            if parts.len() >= 3 {
                match s.config.get_field(parts[2]) {
                    Some(v) => {
                        let _ = writeln!(out, "{}={}", parts[2], v);
                    }
                    None => {
                        let _ = writeln!(out, "error: unknown key '{}'", parts[2]);
                    }
                }
            } else {
                for (k, v) in s.config.list_fields() {
                    let _ = writeln!(out, "{k}={v}");
                }
            }
        }

        // ── config set ───────────────────────────────────────────────────────
        "config" if parts.len() >= 4 && parts[1] == "set" => {
            let key = parts[2];
            let value = parts[3];
            let mut s = state.lock().unwrap();
            match s.config.set_field(key, value) {
                Ok(()) => {
                    let _ = writeln!(out, "ok {key}={value}");
                    audit(&format!("CONFIG  pid={:?} set {key}={value}", session_pid));
                }
                Err(e) => {
                    let _ = writeln!(out, "error: {e}");
                }
            }
        }

        "config" => {
            let _ =
                writeln!(out, "usage: config get [<key>] | config set <key> <value>");
        }

        // ── quit ─────────────────────────────────────────────────────────────
        "quit" => return true,

        _ => {
            let _ = writeln!(out, "unknown command '{}'", parts[0]);
        }
    }

    false
}

// ─── Session runners ──────────────────────────────────────────────────────────

fn run_session<R: BufRead, W: Write>(
    reader: R,
    mut writer: W,
    state: Arc<Mutex<BrokerState>>,
    label: &str,
) {
    let mut session_pid: Option<u32> = None;
    audit(&format!("SESSION_START {label}"));
    for line in reader.lines() {
        match line {
            Ok(l) => {
                if handle_line(&l, &state, &mut session_pid, &mut writer) {
                    break;
                }
                let _ = writer.flush();
            }
            Err(e) => {
                eprintln!("[{label}] read error: {e}");
                break;
            }
        }
    }
    audit(&format!("SESSION_END {label} pid={session_pid:?}"));
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let state = Arc::new(Mutex::new(BrokerState::new()));

    println!("intentd v0.1 — IntentKernel Intent Broker");
    println!("socket: {SOCKET_PATH}");
    println!("audit:  {AUDIT_LOG}");
    println!("stdin:  ready");
    println!(
        "commands: issue | revoke | bind | list | config get [key] | config set key val | quit"
    );
    audit("DAEMON_START");

    // ── Unix socket listener ──────────────────────────────────────────────────
    let socket_state = Arc::clone(&state);
    thread::spawn(move || {
        let _ = std::fs::remove_file(SOCKET_PATH);
        let listener = match UnixListener::bind(SOCKET_PATH) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("intentd: cannot bind socket {SOCKET_PATH}: {e}");
                return;
            }
        };

        let mut conn_id: u64 = 0;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    conn_id += 1;
                    let id = conn_id;
                    let st = Arc::clone(&socket_state);
                    thread::spawn(move || {
                        let label = format!("socket-conn-{id}");
                        let reader =
                            BufReader::new(stream.try_clone().expect("clone socket stream"));
                        let mut writer = stream;
                        run_session(reader, &mut writer, st, &label);
                    });
                }
                Err(e) => eprintln!("intentd: socket accept error: {e}"),
            }
        }
    });

    // ── stdin session (foreground) ────────────────────────────────────────────
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_session(stdin.lock(), stdout.lock(), Arc::clone(&state), "stdin");

    let _ = std::fs::remove_file(SOCKET_PATH);
    audit("DAEMON_STOP");
}
