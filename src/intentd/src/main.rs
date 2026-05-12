use intentkernel_sdk::{
    CapabilityScope, IntentKernelSdk, IntentRequest, IntentSource, RiskLevel,
};
use std::io::{self, BufRead};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut sdk = IntentKernelSdk::new("intentd.mldsa87.v1");
    println!("intentd ready");
    println!("commands:");
    println!("  issue <source:A|B|C> <resource_id> <action:wait|get|put|net|notify|invoke|draw|exit> <target> <uses>");
    println!("  revoke <token_id>");
    println!("  quit");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(v) => v,
            Err(e) => {
                eprintln!("read error: {e}");
                continue;
            }
        };

        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "issue" if parts.len() >= 6 => {
                let source = match parts[1] {
                    "A" => IntentSource::SecureInputPath,
                    "B" => IntentSource::DerivedSystemEvent,
                    "C" => IntentSource::Scheduler,
                    _ => {
                        eprintln!("invalid source");
                        continue;
                    }
                };
                let resource_id = parts[2].to_string();
                let action = parts[3];
                let target = parts[4].to_string();
                let uses: u32 = parts[5].parse().unwrap_or(1);

                let scope = match action {
                    "draw" => CapabilityScope::Draw,
                    "wait" => CapabilityScope::WaitEvent,
                    "get" => CapabilityScope::GetResource {
                        resource_id: target.clone(),
                    },
                    "put" => CapabilityScope::PutResource {
                        resource_id: target.clone(),
                        max_bytes: 1_048_576,
                    },
                    "net" => CapabilityScope::NetworkRequest {
                        destination: target.clone(),
                        max_bytes: 1_048_576,
                    },
                    "notify" => CapabilityScope::ScheduleNotification {
                        channel: target.clone(),
                    },
                    "invoke" => CapabilityScope::InvokeCapability {
                        operation: target.clone(),
                    },
                    "exit" => CapabilityScope::Exit,
                    _ => {
                        eprintln!("unknown action");
                        continue;
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
                    resource_id,
                    timestamp_ms: now_ms(),
                };
                let token = sdk.create_capability(&req, scope, risk, uses);
                println!(
                    "issued id={} class={:?} exp_ms={} uses={} alg={} kid={}",
                    token.id, token.class, token.exp_ms, token.uses, token.alg, token.kid
                );
            }
            "revoke" if parts.len() >= 2 => {
                if let Ok(id) = parts[1].parse::<u64>() {
                    sdk.broker_mut().revoke(id);
                    println!("revoked id={id}");
                } else {
                    eprintln!("invalid token id");
                }
            }
            "quit" => break,
            _ => eprintln!("unknown command"),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

