use intentkernel_sdk::{
    CapabilityScope, IntentKernelSdk, IntentRequest, IntentSource, RiskLevel, SdkError,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut sdk = IntentKernelSdk::new("demo-broker-key");
    let protected = "/vault/customer_records.db";
    sdk.seed_resource(protected, b"customer-data".to_vec());

    let req = IntentRequest {
        source: IntentSource::SecureInputPath,
        app_id: "backup-agent".into(),
        user_id: "alice".into(),
        device_id: "laptop-1".into(),
        resource_id: protected.into(),
        timestamp_ms: now_ms(),
    };

    let mut one_time_write = sdk.create_capability(
        &req,
        CapabilityScope::PutResource {
            resource_id: protected.into(),
            max_bytes: 64,
        },
        RiskLevel::High,
        1,
    );

    let first = sdk.put_resource(protected, b"backup-rotated", &mut one_time_write);
    println!("authorized write result: {first:?}");

    let ransomware_attempt = sdk.put_resource(protected, b"ENCRYPTED_BY_EVIL", &mut one_time_write);
    println!("ransomware write result: {ransomware_attempt:?}");

    match ransomware_attempt {
        Err(SdkError::TokenExhausted) => {
            println!("RANSOMWARE IMMUNITY DEMO: PASS (repeat write blocked)")
        }
        _ => println!("RANSOMWARE IMMUNITY DEMO: FAIL"),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

