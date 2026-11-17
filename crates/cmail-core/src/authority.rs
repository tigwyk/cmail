//! Human authority core: canonical signed records, verification, and the
//! effective-policy fold. Platform credential-store backends implement
//! [`Authority`] in later tickets; this module ships the record format, the
//! fold rules, and an in-memory backend for tests.

use crate::canonical::canonical_json;
use crate::error::{CoreError, Result};
use crate::identity::fingerprint_of;
#[cfg(any(test, feature = "test-authority"))]
use crate::identity::now_rfc3339;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(any(test, feature = "test-authority"))]
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[cfg(any(test, feature = "test-authority"))]
use std::sync::{Mutex, MutexGuard};

#[cfg(target_os = "macos")]
mod macos;

/// Canonical authority-record format version. Records with any other version
/// are ignored by [`fold_records`].
pub const RECORD_VERSION: u32 = 1;

/// One human decision kind. `Unknown` is deserialized from future/unknown
/// action names and is ignored during the fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAction {
    KeyAdd,
    KeyRemove,
    AllowAdd,
    AllowRemove,
    RelaySet,
    RelayClear,
    Approve,
    Reject,
    QuarantineRelease,
    OutboundMode,
    InboundMode,
    #[serde(other)]
    Unknown,
}

/// One canonically encoded, signed, append-only authority decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRecord {
    pub version: u32,
    pub sequence: u64,
    pub timestamp: String,
    pub action: AuthorityAction,
    pub subject: String,
    pub payload_digest: String,
    pub signer_fingerprint: String,
    pub signature: String,
}

impl AuthorityRecord {
    /// Build and sign a record. `payload` is hashed, never stored: consumers
    /// act on `action` + `subject`, so a message id cannot be replayed for
    /// another message.
    pub fn sign(
        sequence: u64,
        timestamp: String,
        action: AuthorityAction,
        subject: impl Into<String>,
        payload: &Value,
        signing_key: &SigningKey,
    ) -> Self {
        let subject = subject.into();
        let signer_fingerprint =
            fingerprint_of(&B64.encode(signing_key.verifying_key().as_bytes()));
        let payload_digest = payload_digest(payload);
        let mut record = Self {
            version: RECORD_VERSION,
            sequence,
            timestamp,
            action,
            subject,
            payload_digest,
            signer_fingerprint,
            signature: String::new(),
        };
        let bytes = record.signing_bytes();
        record.signature = B64.encode(signing_key.sign(bytes.as_bytes()).to_bytes());
        record
    }

    /// Canonical bytes covered by the signature: every field except
    /// `signature`, serialized with the shared envelope canonicalizer.
    fn signing_bytes(&self) -> String {
        canonical_json(&json!({
            "version": self.version,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action": self.action,
            "subject": self.subject,
            "payload_digest": self.payload_digest,
            "signer_fingerprint": self.signer_fingerprint,
        }))
    }
}

/// SHA-256 of the canonical payload JSON, lowercase hex.
pub fn payload_digest(payload: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json(payload).as_bytes()))
}

/// True when `record` is a supported version, names the authority key's
/// fingerprint, and carries a valid Ed25519 signature over its canonical
/// bytes. Any malformed input is simply false.
pub fn verify_record(record: &AuthorityRecord, authority_key: &VerifyingKey) -> bool {
    if record.version != RECORD_VERSION || record.action == AuthorityAction::Unknown {
        return false;
    }
    let expected = fingerprint_of(&B64.encode(authority_key.as_bytes()));
    if record.signer_fingerprint != expected {
        return false;
    }
    let Ok(sig_bytes) = B64.decode(&record.signature) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let mut raw = [0u8; 64];
    raw.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&raw);
    authority_key
        .verify(record.signing_bytes().as_bytes(), &signature)
        .is_ok()
}

/// The latest valid decision for one subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub action: AuthorityAction,
    pub sequence: u64,
    pub timestamp: String,
}

/// Policy derived only from valid records. A subject's latest valid record
/// wins, so revocation (`*_remove`, `relay_clear`, `reject`) is just another
/// record rather than a deletion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub decisions: BTreeMap<String, PolicyDecision>,
}

/// Fold records in append order. The chain must start at sequence 1 and be
/// contiguous: gaps, duplicates, reordered records, wrong-key records,
/// tampered records, unknown versions, and unknown actions are ignored
/// deterministically. An ignored record does not advance the chain, so a
/// tampered record at the expected position blocks everything after it
/// (fail closed).
pub fn fold_records(records: &[AuthorityRecord], authority_key: &VerifyingKey) -> EffectivePolicy {
    let mut policy = EffectivePolicy::default();
    let mut expected = 1u64;
    for record in records {
        if record.sequence != expected {
            continue;
        }
        if !verify_record(record, authority_key) {
            continue;
        }
        expected += 1;
        policy.decisions.insert(
            record.subject.clone(),
            PolicyDecision {
                action: record.action,
                sequence: record.sequence,
                timestamp: record.timestamp.clone(),
            },
        );
    }
    policy
}

/// Honest platform assurance, as reported by `authority status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Assurance {
    None,
    Advisory,
    Moderate,
    Strong,
}

/// Observable authority state: fingerprint, backend, assurance, and last
/// signing grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityStatus {
    pub available: bool,
    pub fingerprint: Option<String>,
    pub backend: String,
    pub assurance: Assurance,
    pub last_grant: Option<String>,
    /// Honest limitation of the backend, present whenever assurance is
    /// weaker than a real boundary (or the backend is unavailable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// The single authority seam. Platform credential-store backends implement
/// this in later tickets; the CLI is a thin caller.
pub trait Authority {
    /// Report availability and assurance without changing state.
    fn status(&self) -> Result<AuthorityStatus>;
    /// Provision the authority key if absent. Idempotent.
    fn init(&self) -> Result<AuthorityStatus>;
    /// Sign one decision, advancing the append-only sequence.
    fn sign_action(
        &self,
        action: AuthorityAction,
        subject: &str,
        payload: &Value,
    ) -> Result<AuthorityRecord>;
    /// Verify the retained records and fold them into effective policy.
    fn load_effective_policy(&self) -> Result<EffectivePolicy>;
}

#[cfg(any(test, feature = "test-authority"))]
struct MemoryState {
    signing: Option<SigningKey>,
    records: Vec<AuthorityRecord>,
    last_grant: Option<String>,
}

/// Test-only backend: an in-memory key and record log with no presence check
/// (advisory assurance). Never selected by the CLI.
#[cfg(any(test, feature = "test-authority"))]
pub struct InMemoryAuthority {
    state: Mutex<MemoryState>,
}

#[cfg(any(test, feature = "test-authority"))]
impl InMemoryAuthority {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemoryState {
                signing: None,
                records: Vec::new(),
                last_grant: None,
            }),
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, MemoryState>> {
        self.state.lock().map_err(|_| {
            CoreError::AuthorityUnavailable("in-memory authority lock poisoned".into())
        })
    }
}

#[cfg(any(test, feature = "test-authority"))]
impl Default for InMemoryAuthority {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-authority"))]
impl Authority for InMemoryAuthority {
    fn status(&self) -> Result<AuthorityStatus> {
        let state = self.state()?;
        Ok(match &state.signing {
            Some(key) => AuthorityStatus {
                available: true,
                fingerprint: Some(fingerprint_of(&B64.encode(key.verifying_key().as_bytes()))),
                backend: "memory".into(),
                assurance: Assurance::Advisory,
                last_grant: state.last_grant.clone(),
                explanation: None,
            },
            None => AuthorityStatus {
                available: false,
                fingerprint: None,
                backend: "memory".into(),
                assurance: Assurance::None,
                last_grant: None,
                explanation: None,
            },
        })
    }

    fn init(&self) -> Result<AuthorityStatus> {
        {
            let mut state = self.state()?;
            if state.signing.is_none() {
                state.signing = Some(SigningKey::generate(&mut OsRng));
            }
        }
        self.status()
    }

    fn sign_action(
        &self,
        action: AuthorityAction,
        subject: &str,
        payload: &Value,
    ) -> Result<AuthorityRecord> {
        if subject.is_empty() {
            return Err(CoreError::AuthorityInvalid(
                "authority record subject is empty".into(),
            ));
        }
        if action == AuthorityAction::Unknown {
            return Err(CoreError::AuthorityInvalid(
                "unknown authority action".into(),
            ));
        }
        let mut state = self.state()?;
        let key = state
            .signing
            .as_ref()
            .ok_or_else(|| CoreError::AuthorityUnavailable("authority is not initialized".into()))?
            .clone();
        let sequence = state.records.last().map_or(1, |r| r.sequence + 1);
        let record = AuthorityRecord::sign(sequence, now_rfc3339(), action, subject, payload, &key);
        state.last_grant = Some(record.timestamp.clone());
        state.records.push(record.clone());
        Ok(record)
    }

    fn load_effective_policy(&self) -> Result<EffectivePolicy> {
        let state = self.state()?;
        let key = state.signing.as_ref().ok_or_else(|| {
            CoreError::AuthorityUnavailable("authority is not initialized".into())
        })?;
        Ok(fold_records(&state.records, &key.verifying_key()))
    }
}

/// Fail-closed placeholder used until a platform backend lands: status is
/// reportable, every state-producing operation is a typed unavailable error.
pub struct UnavailableAuthority;

impl Authority for UnavailableAuthority {
    fn status(&self) -> Result<AuthorityStatus> {
        Ok(AuthorityStatus {
            available: false,
            fingerprint: None,
            backend: "none".into(),
            assurance: Assurance::None,
            last_grant: None,
            explanation: None,
        })
    }

    fn init(&self) -> Result<AuthorityStatus> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available on this platform yet".into(),
        ))
    }

    fn sign_action(
        &self,
        _action: AuthorityAction,
        _subject: &str,
        _payload: &Value,
    ) -> Result<AuthorityRecord> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available; ask your human to configure authority".into(),
        ))
    }

    fn load_effective_policy(&self) -> Result<EffectivePolicy> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available".into(),
        ))
    }
}

/// The process-wide authority backend. Resolved here so the CLI cannot choose
/// one from the environment; platform backends replace this in later tickets.
#[cfg(target_os = "macos")]
pub fn system_authority() -> &'static dyn Authority {
    macos::authority()
}

#[cfg(target_os = "linux")]
pub fn system_authority() -> &'static dyn Authority {
    static LINUX: crate::authority_linux::LinuxAuthority =
        crate::authority_linux::LinuxAuthority::new();
    &LINUX
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn system_authority() -> &'static dyn Authority {
    static UNAVAILABLE: UnavailableAuthority = UnavailableAuthority;
    &UNAVAILABLE
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn rec(seq: u64, action: AuthorityAction, subject: &str, key: &SigningKey) -> AuthorityRecord {
        AuthorityRecord::sign(
            seq,
            format!("2026-11-16T00:00:{seq:02}Z"),
            action,
            subject,
            &json!({ "seq": seq }),
            key,
        )
    }

    #[test]
    fn signed_record_verifies_and_tamper_fails() {
        let k = key();
        let r = rec(1, AuthorityAction::AllowAdd, "alice", &k);
        assert!(verify_record(&r, &k.verifying_key()));
        let mut tampered = r.clone();
        tampered.subject = "mallory".into();
        assert!(!verify_record(&tampered, &k.verifying_key()));
        let other = key();
        assert!(!verify_record(&r, &other.verifying_key()));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let k = key();
        let mut r = rec(1, AuthorityAction::AllowAdd, "alice", &k);
        r.version = RECORD_VERSION + 1;
        assert!(!verify_record(&r, &k.verifying_key()));
    }

    #[test]
    fn fold_ignores_gaps_duplicates_and_reordering() {
        let k = key();
        let r1 = rec(1, AuthorityAction::AllowAdd, "alice", &k);
        let r2 = rec(2, AuthorityAction::AllowRemove, "bob", &k);
        let r3 = rec(3, AuthorityAction::AllowAdd, "carol", &k);

        // Gap: sequence 3 without 2; records after the gap cannot apply.
        let policy = fold_records(&[r1.clone(), r3.clone()], &k.verifying_key());
        assert_eq!(policy.decisions.len(), 1);
        assert_eq!(policy.decisions["alice"].action, AuthorityAction::AllowAdd);

        // Duplicate sequence is applied at most once.
        let policy = fold_records(&[r1.clone(), r1.clone(), r2.clone()], &k.verifying_key());
        assert_eq!(policy.decisions.len(), 2);
        assert_eq!(policy.decisions["bob"].sequence, 2);

        // Reordered records: 2 arrives before 1, so only 1 applies.
        let policy = fold_records(&[r2.clone(), r1.clone()], &k.verifying_key());
        assert_eq!(policy.decisions.len(), 1);
        assert_eq!(policy.decisions["alice"].sequence, 1);
        assert!(!policy.decisions.contains_key("bob"));
    }

    #[test]
    fn fold_keeps_latest_valid_record_per_subject() {
        let k = key();
        let add = rec(1, AuthorityAction::KeyAdd, "alice", &k);
        let remove = rec(2, AuthorityAction::KeyRemove, "alice", &k);
        let policy = fold_records(&[add, remove], &k.verifying_key());
        let decision = &policy.decisions["alice"];
        assert_eq!(decision.action, AuthorityAction::KeyRemove);
        assert_eq!(decision.sequence, 2);
    }

    #[test]
    fn fold_fails_closed_on_wrong_key_and_tampering() {
        let k = key();
        let attacker = key();
        let forged = rec(1, AuthorityAction::AllowAdd, "mallory", &attacker);
        // Signature does not verify with the authority key.
        let policy = fold_records(&[forged], &k.verifying_key());
        assert!(policy.decisions.is_empty());

        // A tampered record at the expected position blocks the chain.
        let mut r1 = rec(1, AuthorityAction::AllowAdd, "alice", &k);
        r1.subject = "mallory".into();
        let r2 = rec(2, AuthorityAction::AllowAdd, "bob", &k);
        let policy = fold_records(&[r1, r2], &k.verifying_key());
        assert!(policy.decisions.is_empty());
    }

    #[test]
    fn in_memory_backend_creates_signs_and_reports_status() {
        let authority = InMemoryAuthority::new();
        let before = authority.status().unwrap();
        assert!(!before.available);
        assert!(before.fingerprint.is_none());

        let created = authority.init().unwrap();
        assert!(created.available);
        assert!(created.fingerprint.is_some());
        assert_eq!(created.backend, "memory");
        assert_eq!(created.assurance, Assurance::Advisory);

        let record = authority
            .sign_action(
                AuthorityAction::AllowAdd,
                "alice",
                &json!({"name": "alice"}),
            )
            .unwrap();
        assert_eq!(record.sequence, 1);
        assert_eq!(
            record.signer_fingerprint,
            created.fingerprint.clone().unwrap()
        );

        let policy = authority.load_effective_policy().unwrap();
        assert_eq!(policy.decisions["alice"].action, AuthorityAction::AllowAdd);

        assert!(authority.status().unwrap().last_grant.is_some());
    }

    #[test]
    fn in_memory_backend_rejects_empty_subject() {
        let authority = InMemoryAuthority::new();
        authority.init().unwrap();
        let err = authority
            .sign_action(AuthorityAction::AllowAdd, "", &json!(null))
            .unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)));
    }

    #[test]
    fn unavailable_backend_reports_none_and_fails_closed() {
        let authority = UnavailableAuthority;
        let status = authority.status().unwrap();
        assert!(!status.available);
        assert_eq!(status.backend, "none");
        assert_eq!(status.assurance, Assurance::None);
        assert!(status.fingerprint.is_none());

        assert!(matches!(
            authority.init(),
            Err(CoreError::AuthorityUnavailable(_))
        ));
        assert!(matches!(
            authority.sign_action(AuthorityAction::AllowAdd, "alice", &json!(null)),
            Err(CoreError::AuthorityUnavailable(_))
        ));
        assert!(matches!(
            authority.load_effective_policy(),
            Err(CoreError::AuthorityUnavailable(_))
        ));
    }
}
