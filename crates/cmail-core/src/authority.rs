//! Human authority core: canonical signed records, verification, and the
//! effective-policy fold. Platform credential-store backends implement
//! [`Authority`]; this module ships the record format, the fold rules, the
//! in-memory test backend, and the process-wide backend selection.

mod log;

#[cfg(target_os = "windows")]
mod windows;

use crate::canonical::canonical_json;
use crate::error::{CoreError, Result};
use crate::identity::fingerprint_of;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(any(test, feature = "test-authority", debug_assertions))]
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
#[cfg(any(test, feature = "test-authority", debug_assertions))]
use std::sync::{Mutex, MutexGuard};

#[cfg(target_os = "macos")]
mod macos;

/// Canonical authority-record format version. Records with any other version
/// are ignored by [`fold_records`].
///
/// Subject namespaces, not this number, are the compatibility marker for the
/// namespacing change: version-1 records written before [subject] existed are
/// still signature-verified and advance the chain, but their unnamespaced
/// subjects never enter [`EffectivePolicy`]. Adoption must be re-run so the
/// same decisions exist under their documented names.
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

impl AuthorityAction {
    /// True when `subject` names this action's documented namespace. A record
    /// carrying a mismatch is refused at append and ignored by the fold, so a
    /// decision can never be reinterpreted as another family.
    pub fn accepts_subject(self, subject: &str) -> bool {
        use AuthorityAction::*;
        match self {
            KeyAdd | KeyRemove => subject::split_key(subject).is_some(),
            AllowAdd | AllowRemove => subject::name_in(subject, subject::ALLOW).is_some(),
            Approve | Reject => subject::name_in(subject, subject::APPROVAL).is_some(),
            QuarantineRelease => subject::name_in(subject, subject::QUARANTINE).is_some(),
            RelaySet | RelayClear => subject == subject::RELAY,
            OutboundMode => subject == subject::OUTBOUND_MODE,
            InboundMode => subject == subject::INBOUND_MODE,
            Unknown => false,
        }
    }
}

/// The one documented authority-subject scheme. Prefixes keep families apart:
/// an allow entry cannot supersede an approval id even when the suffix text is
/// identical, and singleton settings (`relay`, modes) share a subject so the
/// latest record wins instead of leaving an older one live.
///
/// Version-1 records written before this scheme existed carry unnamespaced
/// subjects; they stay in the record chain but are inert. Adoption must be
/// re-run to write the namespaced forms.
pub mod subject {
    pub const KEY: &str = "key:";
    pub const ALLOW: &str = "allow:";
    pub const APPROVAL: &str = "approval:";
    pub const RELAY: &str = "relay";
    pub const OUTBOUND_MODE: &str = "mode:outbound";
    pub const INBOUND_MODE: &str = "mode:inbound";
    pub const QUARANTINE: &str = "quarantine:";

    /// `key:<name>:<public-key>` for a keyring grant or revocation.
    pub fn key(name: &str, public_key: &str) -> String {
        format!("{KEY}{name}:{public_key}")
    }

    /// `allow:<name>` for an outbound allowlist entry.
    pub fn allow(name: &str) -> String {
        format!("{ALLOW}{name}")
    }

    /// `approval:<message-id>` for an approve or reject decision.
    pub fn approval(message_id: &str) -> String {
        format!("{APPROVAL}{message_id}")
    }

    /// `quarantine:<message-id>` for a quarantine release.
    pub fn quarantine(message_id: &str) -> String {
        format!("{QUARANTINE}{message_id}")
    }

    /// Split a `key:<name>:<public-key>` subject. Names and keys are non-empty;
    /// the public key is standard base64, so it never contains a colon.
    pub fn split_key(subject: &str) -> Option<(&str, &str)> {
        let (name, public_key) = subject.strip_prefix(KEY)?.split_once(':')?;
        (!name.is_empty() && !public_key.is_empty()).then_some((name, public_key))
    }

    /// The non-empty suffix of a prefixed family, if `subject` is in it.
    pub fn name_in<'a>(subject: &'a str, prefix: &str) -> Option<&'a str> {
        subject.strip_prefix(prefix).filter(|rest| !rest.is_empty())
    }
}

/// One canonically encoded, signed, append-only authority decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRecord {
    pub version: u32,
    pub sequence: u64,
    pub timestamp: String,
    pub action: AuthorityAction,
    pub subject: String,
    /// The decision value, retained so non-boolean settings resolve
    /// latest-wins (`relay`, modes). Absent in version-1 records written
    /// before payload retention; such records remain chain-valid but inert
    /// because they also carry unnamespaced subjects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    pub payload_digest: String,
    pub signer_fingerprint: String,
    /// Hash of the previous record (genesis hash for sequence 1). Signed, so
    /// dropping or replacing an earlier record breaks the chain.
    pub prev: String,
    pub signature: String,
}

impl AuthorityRecord {
    /// Build and sign a record with a local signing key. Production paths sign
    /// through [`Authority::sign_bytes`] so the key never leaves the backend;
    /// this constructor exists for tests and for backends that hold the key
    /// in process.
    pub fn sign(
        sequence: u64,
        prev: impl Into<String>,
        timestamp: String,
        action: AuthorityAction,
        subject: impl Into<String>,
        payload: &Value,
        signing_key: &SigningKey,
    ) -> Self {
        let mut record = Self::unsigned(
            sequence,
            prev,
            timestamp,
            action,
            subject,
            payload,
            fingerprint_of(&B64.encode(signing_key.verifying_key().as_bytes())),
        );
        record.signature = B64.encode(
            signing_key
                .sign(record.signing_bytes().as_bytes())
                .to_bytes(),
        );
        record
    }

    /// An unsigned record: every field the signature will cover is final.
    pub fn unsigned(
        sequence: u64,
        prev: impl Into<String>,
        timestamp: String,
        action: AuthorityAction,
        subject: impl Into<String>,
        payload: &Value,
        signer_fingerprint: String,
    ) -> Self {
        Self {
            version: RECORD_VERSION,
            sequence,
            timestamp,
            action,
            subject: subject.into(),
            payload: Some(payload.clone()),
            payload_digest: payload_digest(payload),
            signer_fingerprint,
            prev: prev.into(),
            signature: String::new(),
        }
    }

    /// Canonical bytes covered by the signature: every field except
    /// `signature`, serialized with the shared envelope canonicalizer.
    fn signing_bytes(&self) -> String {
        let mut fields = json!({
            "version": self.version,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action": self.action,
            "subject": self.subject,
            "payload_digest": self.payload_digest,
            "signer_fingerprint": self.signer_fingerprint,
            "prev": self.prev,
        });
        // Omitted, not null, when absent: signatures made before payload
        // retention cover exactly the same bytes and still verify.
        if let Some(payload) = &self.payload {
            if let Value::Object(map) = &mut fields {
                map.insert("payload".into(), payload.clone());
            }
        }
        canonical_json(&fields)
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
    /// The signed decision value, when the record retained one. Singleton
    /// settings (`relay`, modes) resolve latest-wins through this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
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
///
/// Every verified record advances the chain, but only a subject in the
/// action's documented namespace enters effective policy. Version-1 records
/// with unnamespaced (pre-scheme) subjects therefore stay chain-valid and
/// inert: re-adoption can append namespaced records after them, and no old
/// subject is silently trusted under a new meaning.
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
        if !record.action.accepts_subject(&record.subject) {
            continue;
        }
        policy.decisions.insert(
            record.subject.clone(),
            PolicyDecision {
                action: record.action,
                sequence: record.sequence,
                timestamp: record.timestamp.clone(),
                payload: record.payload.clone(),
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

/// Latest verified position of the authority-record chain, pinned beside the
/// key in the credential store (never under the mailbox root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogHead {
    pub sequence: u64,
    pub hash: String,
}

/// The single authority seam. Platform credential-store backends own key
/// material, presence, and the pinned chain head; the root-scoped record log
/// and its fold are shared by every backend in [`log`]. The CLI is a thin
/// caller.
pub trait Authority: Send + Sync {
    /// Report availability and assurance without changing state.
    fn status(&self) -> Result<AuthorityStatus>;
    /// Provision the authority key if absent. Idempotent.
    fn init(&self) -> Result<AuthorityStatus>;
    /// Public half of the authority key. Readable without a presence prompt
    /// so status and record verification never interrupt the human.
    fn verifying_key(&self) -> Result<VerifyingKey>;
    /// Presence-gated Ed25519 signature over canonical record bytes, base64.
    /// This is the only place the private key is used.
    fn sign_bytes(&self, action: AuthorityAction, subject: &str, bytes: &str) -> Result<String>;
    /// The chain head pinned beside the key, if one exists.
    fn pinned_head(&self) -> Result<Option<LogHead>>;
    /// Pin a newer chain head. Called only after a signed record is durable,
    /// so it never needs a second presence prompt.
    fn pin_head(&self, head: &LogHead) -> Result<()>;
    /// Presence-gated credential reset: delete the pinned head and the
    /// authority key, then provision a fresh key. Nothing is deleted unless
    /// presence succeeds, so a denial writes nothing. Recovery only; signed
    /// decisions are discarded, never migrated.
    fn reset_credentials(&self) -> Result<()>;
    /// Timestamp of the last signature, for `authority status`.
    fn last_grant(&self) -> Option<String> {
        None
    }
    /// Note a successful grant for `authority status`.
    fn record_grant(&self, _timestamp: &str) {}

    /// Sign one decision and append it to the root-scoped log.
    fn sign_action(
        &self,
        root: &Path,
        action: AuthorityAction,
        subject: &str,
        payload: &Value,
    ) -> Result<AuthorityRecord> {
        log::sign_and_append(self, root, action, subject, payload)
    }

    /// Verify the root-scoped records and fold them into effective policy.
    fn load_effective_policy(&self, root: &Path) -> Result<EffectivePolicy> {
        log::load_policy(self, root)
    }

    /// Recovery from lost or replaced key material: clear the pinned head and
    /// the stale root-scoped log, then provision a fresh key. Presence is
    /// required before anything is deleted; denial writes nothing.
    fn reset(&self, root: &Path) -> Result<AuthorityStatus> {
        log::reset(self, root)?;
        self.status()
    }
}

#[cfg(any(test, feature = "test-authority", debug_assertions))]
struct MemoryState {
    signing: Option<SigningKey>,
    /// Stands in for the credential-store slot a platform backend uses.
    pinned: Option<LogHead>,
    last_grant: Option<String>,
    /// Test-only stand-in for a denied or absent human-presence prompt.
    presence_denied: bool,
}

/// Test-only backend: an in-memory key and pinned head with no presence check
/// (advisory assurance). Records go to the shared root-scoped log, so tests
/// exercise the same persistence path as a platform backend. Debug builds can
/// select it from an explicit signing key; release builds compile it out.
#[cfg(any(test, feature = "test-authority", debug_assertions))]
pub struct InMemoryAuthority {
    state: Mutex<MemoryState>,
}

#[cfg(any(test, feature = "test-authority", debug_assertions))]
impl InMemoryAuthority {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemoryState {
                signing: None,
                pinned: None,
                last_grant: None,
                presence_denied: false,
            }),
        }
    }

    /// An instance sharing an existing key, so a second "process" verifies
    /// records written by the first.
    pub fn with_signing_key(signing: SigningKey) -> Self {
        Self {
            state: Mutex::new(MemoryState {
                signing: Some(signing),
                pinned: None,
                last_grant: None,
                presence_denied: false,
            }),
        }
    }

    /// Build from a base64 Ed25519 signing key. Debug-only CLI test hook: each
    /// process starts with no pinned head, so the persisted log alone chains
    /// the decisions.
    pub fn from_signing_key_b64(encoded: &str) -> Result<Self> {
        let bytes = B64
            .decode(encoded.trim())
            .map_err(|_| CoreError::Config("test authority key is not base64".into()))?;
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CoreError::Config("test authority key must be 32 bytes".into()))?;
        Ok(Self::with_signing_key(SigningKey::from_bytes(&raw)))
    }

    /// The in-memory key, for restart tests that hand it to a new instance.
    pub fn signing_key(&self) -> Option<SigningKey> {
        self.state.lock().ok()?.signing.clone()
    }

    /// Test-only stand-in for a denied presence prompt. Key use fails with a
    /// typed refusal from then on, and nothing is written.
    pub fn deny_presence(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.presence_denied = true;
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, MemoryState>> {
        self.state.lock().map_err(|_| {
            CoreError::AuthorityUnavailable("in-memory authority lock poisoned".into())
        })
    }
}

#[cfg(any(test, feature = "test-authority", debug_assertions))]
impl Default for InMemoryAuthority {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-authority", debug_assertions))]
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

    fn verifying_key(&self) -> Result<VerifyingKey> {
        let state = self.state()?;
        Ok(state
            .signing
            .as_ref()
            .ok_or_else(|| CoreError::AuthorityUnavailable("authority is not initialized".into()))?
            .verifying_key())
    }

    fn sign_bytes(&self, _action: AuthorityAction, _subject: &str, bytes: &str) -> Result<String> {
        let state = self.state()?;
        if state.presence_denied {
            return Err(CoreError::AuthorityRequired(
                "in-memory authority denied presence".into(),
            ));
        }
        let key = state.signing.as_ref().ok_or_else(|| {
            CoreError::AuthorityUnavailable("authority is not initialized".into())
        })?;
        Ok(B64.encode(key.sign(bytes.as_bytes()).to_bytes()))
    }

    fn pinned_head(&self) -> Result<Option<LogHead>> {
        Ok(self.state()?.pinned.clone())
    }

    fn pin_head(&self, head: &LogHead) -> Result<()> {
        self.state()?.pinned = Some(head.clone());
        Ok(())
    }

    fn reset_credentials(&self) -> Result<()> {
        let mut state = self.state()?;
        if state.presence_denied {
            return Err(CoreError::AuthorityRequired(
                "in-memory authority denied presence".into(),
            ));
        }
        state.signing = Some(SigningKey::generate(&mut OsRng));
        state.pinned = None;
        state.last_grant = None;
        Ok(())
    }

    fn last_grant(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.last_grant.clone())
    }

    fn record_grant(&self, timestamp: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.last_grant = Some(timestamp.to_string());
        }
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

    fn verifying_key(&self) -> Result<VerifyingKey> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available; ask your human to configure authority".into(),
        ))
    }

    fn sign_bytes(&self, _action: AuthorityAction, _subject: &str, _bytes: &str) -> Result<String> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available; ask your human to configure authority".into(),
        ))
    }

    fn pinned_head(&self) -> Result<Option<LogHead>> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available".into(),
        ))
    }

    fn pin_head(&self, _head: &LogHead) -> Result<()> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available".into(),
        ))
    }

    fn reset_credentials(&self) -> Result<()> {
        Err(CoreError::AuthorityUnavailable(
            "no authority backend is available; ask your human to configure authority".into(),
        ))
    }
}

/// The process-wide authority backend. Resolved here so the CLI cannot choose
/// one from the environment; release builds have no injectable backend.
#[cfg(target_os = "macos")]
pub fn system_authority() -> Arc<dyn Authority> {
    macos::authority()
}

#[cfg(target_os = "linux")]
pub fn system_authority() -> Arc<dyn Authority> {
    static LINUX: std::sync::LazyLock<Arc<dyn Authority>> =
        std::sync::LazyLock::new(|| Arc::new(crate::authority_linux::LinuxAuthority::new()));
    LINUX.clone()
}

#[cfg(target_os = "windows")]
pub fn system_authority() -> Arc<dyn Authority> {
    static WINDOWS: std::sync::LazyLock<Arc<dyn Authority>> =
        std::sync::LazyLock::new(|| Arc::new(windows::WindowsAuthority::new()));
    WINDOWS.clone()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn system_authority() -> Arc<dyn Authority> {
    static UNAVAILABLE: std::sync::LazyLock<Arc<dyn Authority>> =
        std::sync::LazyLock::new(|| Arc::new(UnavailableAuthority));
    UNAVAILABLE.clone()
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
            if seq == 1 { "genesis" } else { "previous" },
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
        let r = rec(1, AuthorityAction::AllowAdd, &subject::allow("alice"), &k);
        assert!(verify_record(&r, &k.verifying_key()));
        let mut tampered = r.clone();
        tampered.subject = subject::allow("mallory");
        assert!(!verify_record(&tampered, &k.verifying_key()));
        let other = key();
        assert!(!verify_record(&r, &other.verifying_key()));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let k = key();
        let mut r = rec(1, AuthorityAction::AllowAdd, &subject::allow("alice"), &k);
        r.version = RECORD_VERSION + 1;
        assert!(!verify_record(&r, &k.verifying_key()));
    }

    #[test]
    fn fold_ignores_gaps_duplicates_and_reordering() {
        let k = key();
        let r1 = rec(1, AuthorityAction::AllowAdd, &subject::allow("alice"), &k);
        let r2 = rec(2, AuthorityAction::AllowRemove, &subject::allow("bob"), &k);
        let r3 = rec(3, AuthorityAction::AllowAdd, &subject::allow("carol"), &k);

        // Gap: sequence 3 without 2; records after the gap cannot apply.
        let policy = fold_records(&[r1.clone(), r3.clone()], &k.verifying_key());
        assert_eq!(policy.decisions.len(), 1);
        assert_eq!(
            policy.decisions[&subject::allow("alice")].action,
            AuthorityAction::AllowAdd
        );

        // Duplicate sequence is applied at most once.
        let policy = fold_records(&[r1.clone(), r1.clone(), r2.clone()], &k.verifying_key());
        assert_eq!(policy.decisions.len(), 2);
        assert_eq!(policy.decisions[&subject::allow("bob")].sequence, 2);

        // Reordered records: 2 arrives before 1, so only 1 applies.
        let policy = fold_records(&[r2.clone(), r1.clone()], &k.verifying_key());
        assert_eq!(policy.decisions.len(), 1);
        assert_eq!(policy.decisions[&subject::allow("alice")].sequence, 1);
        assert!(!policy.decisions.contains_key(&subject::allow("bob")));
    }

    #[test]
    fn fold_keeps_latest_valid_record_per_subject() {
        let k = key();
        let grant = subject::key("alice", "a2V5");
        let add = rec(1, AuthorityAction::KeyAdd, &grant, &k);
        let remove = rec(2, AuthorityAction::KeyRemove, &grant, &k);
        let policy = fold_records(&[add, remove], &k.verifying_key());
        let decision = &policy.decisions[&grant];
        assert_eq!(decision.action, AuthorityAction::KeyRemove);
        assert_eq!(decision.sequence, 2);
    }

    #[test]
    fn fold_fails_closed_on_wrong_key_and_tampering() {
        let k = key();
        let attacker = key();
        let forged = rec(
            1,
            AuthorityAction::AllowAdd,
            &subject::allow("mallory"),
            &attacker,
        );
        // Signature does not verify with the authority key.
        let policy = fold_records(&[forged], &k.verifying_key());
        assert!(policy.decisions.is_empty());

        // A tampered record at the expected position blocks the chain.
        let mut r1 = rec(1, AuthorityAction::AllowAdd, &subject::allow("alice"), &k);
        r1.subject = subject::allow("mallory");
        let r2 = rec(2, AuthorityAction::AllowAdd, &subject::allow("bob"), &k);
        let policy = fold_records(&[r1, r2], &k.verifying_key());
        assert!(policy.decisions.is_empty());
    }

    #[test]
    fn in_memory_backend_creates_signs_and_reports_status() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = InMemoryAuthority::new();
        let before = authority.status().unwrap();
        assert!(!before.available);
        assert!(before.fingerprint.is_none());

        let created = authority.init().unwrap();
        assert!(created.available);
        assert!(created.fingerprint.is_some());
        assert_eq!(created.backend, "memory");
        assert_eq!(created.assurance, Assurance::Advisory);

        let allow_alice = subject::allow("alice");
        let record = authority
            .sign_action(
                root.path(),
                AuthorityAction::AllowAdd,
                &allow_alice,
                &json!({"name": "alice"}),
            )
            .unwrap();
        assert_eq!(record.sequence, 1);
        assert_eq!(
            record.signer_fingerprint,
            created.fingerprint.clone().unwrap()
        );

        let policy = authority.load_effective_policy(root.path()).unwrap();
        assert_eq!(
            policy.decisions[&allow_alice].action,
            AuthorityAction::AllowAdd
        );
        assert_eq!(
            policy.decisions[&allow_alice].payload,
            Some(json!({"name": "alice"}))
        );

        assert!(authority.status().unwrap().last_grant.is_some());
    }

    #[test]
    fn in_memory_backend_rejects_empty_subject() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = InMemoryAuthority::new();
        authority.init().unwrap();
        let err = authority
            .sign_action(root.path(), AuthorityAction::AllowAdd, "", &json!(null))
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
        let root = tempfile::TempDir::new().unwrap();
        assert!(matches!(
            authority.sign_action(
                root.path(),
                AuthorityAction::AllowAdd,
                &subject::allow("alice"),
                &json!(null)
            ),
            Err(CoreError::AuthorityUnavailable(_))
        ));
        assert!(matches!(
            authority.load_effective_policy(root.path()),
            Err(CoreError::AuthorityUnavailable(_))
        ));
    }

    fn value_record(
        seq: u64,
        action: AuthorityAction,
        subject: &str,
        payload: Value,
        key: &SigningKey,
    ) -> AuthorityRecord {
        AuthorityRecord::sign(
            seq,
            if seq == 1 { "genesis" } else { "previous" },
            format!("2026-11-16T00:00:{seq:02}Z"),
            action,
            subject,
            &payload,
            key,
        )
    }

    #[test]
    fn allow_and_approval_subjects_never_supersede_each_other() {
        let k = key();
        let allow = value_record(
            1,
            AuthorityAction::AllowAdd,
            &subject::allow("shared-name"),
            json!({ "name": "shared-name" }),
            &k,
        );
        let approve = value_record(
            2,
            AuthorityAction::Approve,
            &subject::approval("shared-name"),
            json!({ "id": "shared-name" }),
            &k,
        );
        let policy = fold_records(&[allow, approve], &k.verifying_key());

        assert_eq!(policy.decisions.len(), 2);
        assert_eq!(
            policy.decisions[&subject::allow("shared-name")].action,
            AuthorityAction::AllowAdd
        );
        assert_eq!(
            policy.decisions[&subject::approval("shared-name")].action,
            AuthorityAction::Approve
        );
    }

    #[test]
    fn relay_setting_supersedes_the_previous_value() {
        let k = key();
        let first = value_record(
            1,
            AuthorityAction::RelaySet,
            subject::RELAY,
            json!({ "url": "https://url1.example.com" }),
            &k,
        );
        let second = value_record(
            2,
            AuthorityAction::RelaySet,
            subject::RELAY,
            json!({ "url": "https://url2.example.com" }),
            &k,
        );
        let policy = fold_records(&[first, second], &k.verifying_key());

        assert_eq!(policy.decisions.len(), 1);
        let decision = &policy.decisions[subject::RELAY];
        assert_eq!(decision.sequence, 2);
        assert_eq!(
            decision.payload.as_ref().unwrap()["url"],
            "https://url2.example.com"
        );
    }

    #[test]
    fn mode_setting_resolves_to_the_latest_value() {
        let k = key();
        let first = value_record(
            1,
            AuthorityAction::OutboundMode,
            subject::OUTBOUND_MODE,
            json!({ "mode": "gated" }),
            &k,
        );
        let second = value_record(
            2,
            AuthorityAction::OutboundMode,
            subject::OUTBOUND_MODE,
            json!({ "mode": "open" }),
            &k,
        );
        let policy = fold_records(&[first, second], &k.verifying_key());

        assert_eq!(policy.decisions.len(), 1);
        let decision = &policy.decisions[subject::OUTBOUND_MODE];
        assert_eq!(decision.sequence, 2);
        assert_eq!(decision.payload.as_ref().unwrap()["mode"], "open");
    }

    #[test]
    fn legacy_unnamespaced_record_is_inert_but_advances_the_chain() {
        let k = key();
        let legacy = rec(1, AuthorityAction::AllowAdd, "alice", &k);
        let namespaced = rec(2, AuthorityAction::AllowAdd, &subject::allow("alice"), &k);
        let policy = fold_records(&[legacy, namespaced], &k.verifying_key());

        assert!(!policy.decisions.contains_key("alice"));
        assert_eq!(policy.decisions.len(), 1);
        let decision = &policy.decisions[&subject::allow("alice")];
        assert_eq!(decision.action, AuthorityAction::AllowAdd);
        assert_eq!(decision.sequence, 2);
    }

    #[test]
    fn tampered_legacy_record_blocks_later_namespaced_records() {
        let k = key();
        let mut legacy = rec(1, AuthorityAction::AllowAdd, "alice", &k);
        legacy.subject = "mallory".into();
        let namespaced = rec(2, AuthorityAction::AllowAdd, &subject::allow("alice"), &k);
        let policy = fold_records(&[legacy, namespaced], &k.verifying_key());

        assert!(policy.decisions.is_empty());
    }

    #[test]
    fn append_refuses_a_subject_outside_the_action_namespace() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = InMemoryAuthority::new();
        authority.init().unwrap();
        let err = authority
            .sign_action(
                root.path(),
                AuthorityAction::AllowAdd,
                &subject::approval("42"),
                &json!(null),
            )
            .unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)));
        assert!(authority
            .load_effective_policy(root.path())
            .unwrap()
            .decisions
            .is_empty());
    }
}
