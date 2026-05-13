pub mod config;

use core::fmt;
use ml_dsa::{
    Generate, Keypair, MlDsa87, Signature, SignatureEncoding, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentClass {
    ADirectUser,
    BDerivedSystem,
    CBackgroundLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentSource {
    SecureInputPath,
    DerivedSystemEvent,
    Scheduler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityScope {
    Draw,
    WaitEvent,
    GetResource {
        resource_id: String,
    },
    PutResource {
        resource_id: String,
        max_bytes: usize,
    },
    NetworkRequest {
        destination: String,
        max_bytes: usize,
    },
    ScheduleNotification {
        channel: String,
    },
    CreateCapability,
    InvokeCapability {
        operation: String,
    },
    Exit,
}

#[derive(Debug, Clone)]
pub struct IntentRequest {
    pub source: IntentSource,
    pub app_id: String,
    pub user_id: String,
    pub device_id: String,
    pub resource_id: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub ver: u8,
    pub typ: &'static str,
    pub alg: &'static str,
    pub kid: String,
    pub id: u64,
    pub class: IntentClass,
    pub ctx: [u8; 32],
    pub scope: CapabilityScope,
    pub exp_ms: u64,
    pub uses: u32,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    TokenExpired,
    TokenExhausted,
    TokenRevoked,
    ScopeMismatch,
    SignatureInvalid,
    PayloadInvalid,
    ResourceNotFound,
    LimitExceeded,
    AccessDenied,
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SdkError {}

pub struct IntentBroker {
    signing_key: Box<SigningKey<MlDsa87>>,
    verifying_key: Box<VerifyingKey<MlDsa87>>,
    key_id: String,
    revoked: HashSet<u64>,
    consumed_uses: HashMap<u64, u32>,
    next_id: u64,
}

impl IntentBroker {
    pub fn new(key_id: impl Into<String>) -> Self {
        let signing_key = SigningKey::<MlDsa87>::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key: Box::new(signing_key),
            verifying_key: Box::new(verifying_key),
            key_id: key_id.into(),
            revoked: HashSet::new(),
            consumed_uses: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn classify_intent(&self, source: IntentSource) -> IntentClass {
        match source {
            IntentSource::SecureInputPath => IntentClass::ADirectUser,
            IntentSource::DerivedSystemEvent => IntentClass::BDerivedSystem,
            IntentSource::Scheduler => IntentClass::CBackgroundLease,
        }
    }

    pub fn issue_capability(
        &mut self,
        request: &IntentRequest,
        scope: CapabilityScope,
        risk: RiskLevel,
        uses: u32,
    ) -> CapabilityToken {
        let id = self.next_id;
        self.next_id += 1;

        let ttl = ttl_for_risk(risk);
        let now = now_ms();
        let exp_ms = now.saturating_add(ttl.as_millis() as u64);
        let class = self.classify_intent(request.source);
        let ctx = context_hash(
            &request.app_id,
            &request.user_id,
            &request.device_id,
            request.timestamp_ms,
            &request.resource_id,
        );

        let mut token = CapabilityToken {
            ver: 1,
            typ: "capability",
            alg: "ML-DSA-87",
            kid: self.key_id.clone(),
            id,
            class,
            ctx,
            scope,
            exp_ms,
            uses,
            sig: Vec::new(),
        };

        let payload = token_payload_bytes(&token);
        let signature = self.signing_key.sign(&payload);
        token.sig = signature.to_vec();
        token
    }

    pub fn revoke(&mut self, token_id: u64) {
        self.revoked.insert(token_id);
    }

    pub fn verify_and_consume(
        &mut self,
        token: &CapabilityToken,
        requested_scope: &CapabilityScope,
    ) -> Result<(), SdkError> {
        if self.revoked.contains(&token.id) {
            return Err(SdkError::TokenRevoked);
        }
        if token.exp_ms <= now_ms() {
            return Err(SdkError::TokenExpired);
        }
        if token.uses == 0 {
            return Err(SdkError::TokenExhausted);
        }
        let consumed = self.consumed_uses.get(&token.id).copied().unwrap_or(0);
        if consumed >= token.uses {
            return Err(SdkError::TokenExhausted);
        }
        if !scope_allows(&token.scope, requested_scope) {
            return Err(SdkError::ScopeMismatch);
        }

        let payload = token_payload_bytes(token);
        let sig = Signature::<MlDsa87>::try_from(token.sig.as_slice())
            .map_err(|_| SdkError::PayloadInvalid)?;
        self.verifying_key
            .verify(&payload, &sig)
            .map_err(|_| SdkError::SignatureInvalid)?;

        self.consumed_uses.insert(token.id, consumed + 1);
        Ok(())
    }
}

fn scope_allows(token_scope: &CapabilityScope, requested_scope: &CapabilityScope) -> bool {
    match (token_scope, requested_scope) {
        (CapabilityScope::Draw, CapabilityScope::Draw) => true,
        (CapabilityScope::WaitEvent, CapabilityScope::WaitEvent) => true,
        (
            CapabilityScope::GetResource {
                resource_id: token_id,
            },
            CapabilityScope::GetResource {
                resource_id: requested_id,
            },
        ) => token_id == requested_id,
        (
            CapabilityScope::PutResource {
                resource_id: token_id,
                max_bytes: token_max,
            },
            CapabilityScope::PutResource {
                resource_id: requested_id,
                max_bytes: requested_max,
            },
        ) => token_id == requested_id && requested_max <= token_max,
        (
            CapabilityScope::NetworkRequest {
                destination: token_dst,
                max_bytes: token_max,
            },
            CapabilityScope::NetworkRequest {
                destination: requested_dst,
                max_bytes: requested_max,
            },
        ) => token_dst == requested_dst && requested_max <= token_max,
        (
            CapabilityScope::ScheduleNotification {
                channel: token_channel,
            },
            CapabilityScope::ScheduleNotification {
                channel: requested_channel,
            },
        ) => token_channel == requested_channel,
        (CapabilityScope::CreateCapability, CapabilityScope::CreateCapability) => true,
        (
            CapabilityScope::InvokeCapability {
                operation: token_op,
            },
            CapabilityScope::InvokeCapability {
                operation: requested_op,
            },
        ) => token_op == requested_op,
        (CapabilityScope::Exit, CapabilityScope::Exit) => true,
        _ => false,
    }
}

pub struct IntentKernelSdk {
    broker: IntentBroker,
    resources: HashMap<String, Vec<u8>>,
    pub notifications: Vec<String>,
    pub network_log: Vec<String>,
    pub framebuffer: Vec<u8>,
    pub exited: bool,
}

impl IntentKernelSdk {
    pub fn new(broker_key_id: impl Into<String>) -> Self {
        Self {
            broker: IntentBroker::new(broker_key_id),
            resources: HashMap::new(),
            notifications: Vec::new(),
            network_log: Vec::new(),
            framebuffer: Vec::new(),
            exited: false,
        }
    }

    pub fn broker_mut(&mut self) -> &mut IntentBroker {
        &mut self.broker
    }

    pub fn seed_resource(&mut self, resource_id: impl Into<String>, data: Vec<u8>) {
        self.resources.insert(resource_id.into(), data);
    }

    pub fn draw(&mut self, frame: &[u8], token: &mut CapabilityToken) -> Result<(), SdkError> {
        self.broker
            .verify_and_consume(token, &CapabilityScope::Draw)?;
        self.framebuffer.clear();
        self.framebuffer.extend_from_slice(frame);
        Ok(())
    }

    pub fn wait_event(&mut self, token: &mut CapabilityToken) -> Result<&'static str, SdkError> {
        self.broker
            .verify_and_consume(token, &CapabilityScope::WaitEvent)?;
        Ok("event.received")
    }

    pub fn get_resource(
        &mut self,
        resource_id: &str,
        token: &mut CapabilityToken,
    ) -> Result<Vec<u8>, SdkError> {
        self.broker.verify_and_consume(
            token,
            &CapabilityScope::GetResource {
                resource_id: resource_id.to_owned(),
            },
        )?;
        self.resources
            .get(resource_id)
            .cloned()
            .ok_or(SdkError::ResourceNotFound)
    }

    pub fn put_resource(
        &mut self,
        resource_id: &str,
        data: &[u8],
        token: &mut CapabilityToken,
    ) -> Result<(), SdkError> {
        self.broker.verify_and_consume(
            token,
            &CapabilityScope::PutResource {
                resource_id: resource_id.to_owned(),
                max_bytes: data.len(),
            },
        )?;
        self.resources.insert(resource_id.to_owned(), data.to_vec());
        Ok(())
    }

    pub fn network_request(
        &mut self,
        destination: &str,
        bytes: &[u8],
        token: &mut CapabilityToken,
    ) -> Result<(), SdkError> {
        self.broker.verify_and_consume(
            token,
            &CapabilityScope::NetworkRequest {
                destination: destination.to_owned(),
                max_bytes: bytes.len(),
            },
        )?;
        self.network_log
            .push(format!("{destination}:{}B", bytes.len()));
        Ok(())
    }

    pub fn schedule_notification(
        &mut self,
        channel: &str,
        message: &str,
        token: &mut CapabilityToken,
    ) -> Result<(), SdkError> {
        self.broker.verify_and_consume(
            token,
            &CapabilityScope::ScheduleNotification {
                channel: channel.to_owned(),
            },
        )?;
        self.notifications.push(format!("{channel}:{message}"));
        Ok(())
    }

    pub fn create_capability(
        &mut self,
        request: &IntentRequest,
        scope: CapabilityScope,
        risk: RiskLevel,
        uses: u32,
    ) -> CapabilityToken {
        self.broker.issue_capability(request, scope, risk, uses)
    }

    pub fn invoke_capability(
        &mut self,
        operation: &str,
        token: &mut CapabilityToken,
    ) -> Result<(), SdkError> {
        self.broker.verify_and_consume(
            token,
            &CapabilityScope::InvokeCapability {
                operation: operation.to_owned(),
            },
        )
    }

    pub fn exit(&mut self, token: &mut CapabilityToken) -> Result<(), SdkError> {
        self.broker
            .verify_and_consume(token, &CapabilityScope::Exit)?;
        self.exited = true;
        Ok(())
    }
}

pub fn ttl_for_risk(risk: RiskLevel) -> Duration {
    match risk {
        RiskLevel::Low => Duration::from_secs(5),
        // Matches IBP-1.0 Section 6.2 table where medium TTL is longer than high.
        RiskLevel::Medium => Duration::from_secs(30),
        RiskLevel::High => Duration::from_secs(10),
        RiskLevel::Critical => Duration::from_millis(100),
    }
}

pub fn context_hash(
    app_id: &str,
    user_id: &str,
    device_id: &str,
    timestamp_ms: u64,
    resource_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(app_id.as_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(device_id.as_bytes());
    hasher.update(timestamp_ms.to_be_bytes());
    hasher.update(resource_id.as_bytes());
    hasher.finalize().into()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

fn token_payload_bytes(token: &CapabilityToken) -> Vec<u8> {
    let class = match token.class {
        IntentClass::ADirectUser => "A",
        IntentClass::BDerivedSystem => "B",
        IntentClass::CBackgroundLease => "C",
    };

    let scope = match &token.scope {
        CapabilityScope::Draw => "draw".to_string(),
        CapabilityScope::WaitEvent => "wait_event".to_string(),
        CapabilityScope::GetResource { resource_id } => format!("get_resource:{resource_id}"),
        CapabilityScope::PutResource {
            resource_id,
            max_bytes,
        } => format!("put_resource:{resource_id}:{max_bytes}"),
        CapabilityScope::NetworkRequest {
            destination,
            max_bytes,
        } => format!("network_request:{destination}:{max_bytes}"),
        CapabilityScope::ScheduleNotification { channel } => {
            format!("schedule_notification:{channel}")
        }
        CapabilityScope::CreateCapability => "create_capability".to_string(),
        CapabilityScope::InvokeCapability { operation } => format!("invoke_capability:{operation}"),
        CapabilityScope::Exit => "exit".to_string(),
    };

    let mut out = Vec::new();
    out.extend_from_slice(&[token.ver]);
    push_len_prefixed(&mut out, token.typ.as_bytes());
    push_len_prefixed(&mut out, token.alg.as_bytes());
    push_len_prefixed(&mut out, token.kid.as_bytes());
    out.extend_from_slice(&token.id.to_be_bytes());
    push_len_prefixed(&mut out, class.as_bytes());
    out.extend_from_slice(&token.ctx);
    push_len_prefixed(&mut out, scope.as_bytes());
    out.extend_from_slice(&token.exp_ms.to_be_bytes());
    out.extend_from_slice(&token.uses.to_be_bytes());
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("token payload segment exceeds u32::MAX");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn request(resource_id: &str, source: IntentSource) -> IntentRequest {
        IntentRequest {
            source,
            app_id: "app.digest".into(),
            user_id: "user.hash".into(),
            device_id: "device.id".into(),
            resource_id: resource_id.into(),
            timestamp_ms: now_ms(),
        }
    }

    fn run_with_large_stack<F>(f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(f)
            .expect("failed to spawn test thread")
            .join()
            .expect("test thread panicked");
    }

    #[test]
    fn mldsa87_token_lifecycle_issue_verify_expire_revoke() {
        run_with_large_stack(|| {
            let mut sdk = IntentKernelSdk::new("broker-key-v1");
            let req = request("network.tcp:10.0.0.1:443", IntentSource::SecureInputPath);

            let mut token = sdk.create_capability(
                &req,
                CapabilityScope::NetworkRequest {
                    destination: "10.0.0.1:443".into(),
                    max_bytes: 4,
                },
                RiskLevel::Medium,
                1,
            );

            assert!(sdk
                .network_request("10.0.0.1:443", b"ping", &mut token)
                .is_ok());
            assert_eq!(
                sdk.network_request("10.0.0.1:443", b"ping", &mut token),
                Err(SdkError::TokenExhausted)
            );

            let mut token2 =
                sdk.create_capability(&req, CapabilityScope::WaitEvent, RiskLevel::Low, 1);
            sdk.broker_mut().revoke(token2.id);
            assert_eq!(sdk.wait_event(&mut token2), Err(SdkError::TokenRevoked));
        });
    }

    #[test]
    fn ransomware_style_repeat_write_is_blocked() {
        run_with_large_stack(|| {
            let mut sdk = IntentKernelSdk::new("broker-key-v1");
            sdk.seed_resource("/vault/customer.db", b"ORIGINAL".to_vec());
            let req = request("/vault/customer.db", IntentSource::SecureInputPath);

            let mut one_shot = sdk.create_capability(
                &req,
                CapabilityScope::PutResource {
                    resource_id: "/vault/customer.db".into(),
                    max_bytes: 10,
                },
                RiskLevel::High,
                1,
            );

            assert!(sdk
                .put_resource("/vault/customer.db", b"PATCH_ONCE", &mut one_shot)
                .is_ok());
            assert_eq!(
                sdk.put_resource("/vault/customer.db", b"RANSOMED!!", &mut one_shot),
                Err(SdkError::TokenExhausted)
            );
        });
    }
}
