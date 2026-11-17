//! macOS authority backend.
//!
//! The Ed25519 signing seed lives in the login Keychain as a generic password.
//! Every signing operation first evaluates LocalAuthentication's
//! `deviceOwnerAuthentication` policy, which prompts for Touch ID or the login
//! passcode; the seed is read from the Keychain only after that prompt
//! succeeds. There is no file-based key fallback.
//!
//! Apple's per-item `kSecAttrAccessControl` user-presence ACL only works with
//! the data protection keychain, which requires an app-bundle entitlement that
//! a plain command-line tool does not have (`errSecMissingEntitlement`). This
//! backend therefore reports [`Assurance::Moderate`]: presence is checked on
//! every use, but the key material is not cryptographically bound to the
//! presence check. A same-user process that obtains Keychain access to the item
//! can bypass cmail. Reporting Strong here would be dishonest.

use super::{
    fold_records, Assurance, Authority, AuthorityAction, AuthorityRecord, AuthorityStatus,
    EffectivePolicy,
};
use crate::error::{CoreError, Result};
use crate::identity::fingerprint_of;
use crate::identity::now_rfc3339;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use rand::rngs::OsRng;
use security_framework::base::Error as KeychainError;
use security_framework::item::{ItemClass, ItemSearchOptions};
use security_framework::passwords::{
    delete_generic_password, generic_password, set_generic_password,
};
use serde_json::Value;
use std::borrow::Cow;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Keychain service shared by the authority items.
const SERVICE: &str = "cmail.authority";
/// Account holding the 32-byte Ed25519 seed.
const SEED_ACCOUNT: &str = "ed25519-signing-key-v1";
/// Account holding the public half, readable without a presence prompt so
/// status and policy verification do not interrupt the human.
const PUBLIC_ACCOUNT: &str = "ed25519-public-key-v1";

/// How long a human has to answer the presence prompt before the request fails
/// closed. The evaluation is cancelled when the context is dropped.
const PRESENCE_TIMEOUT: Duration = Duration::from_secs(120);

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

#[derive(Clone)]
struct KeychainIds {
    service: Cow<'static, str>,
    seed_account: Cow<'static, str>,
    public_account: Cow<'static, str>,
}

const SYSTEM_IDS: KeychainIds = KeychainIds {
    service: Cow::Borrowed(SERVICE),
    seed_account: Cow::Borrowed(SEED_ACCOUNT),
    public_account: Cow::Borrowed(PUBLIC_ACCOUNT),
};

pub(super) struct MacAuthority {
    ids: KeychainIds,
    /// Test-only mailbox root. Production resolves `$CMAIL_HOME` or `~/.cmail`.
    root: Option<PathBuf>,
}

/// The process-wide macOS backend.
pub(super) fn authority() -> &'static dyn Authority {
    static MAC: MacAuthority = MacAuthority {
        ids: SYSTEM_IDS,
        root: None,
    };
    &MAC
}

impl MacAuthority {
    #[cfg(test)]
    fn with_ids(ids: KeychainIds, root: &Path) -> Self {
        Self {
            ids,
            root: Some(root.to_path_buf()),
        }
    }

    fn records_path(&self) -> Result<PathBuf> {
        let root = match &self.root {
            Some(root) => root.clone(),
            None => default_root()?,
        };
        Ok(root.join("authority").join("records.jsonl"))
    }

    fn item_exists(&self, account: &str) -> Result<bool> {
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .service(self.ids.service.as_ref())
            .account(account)
            .load_attributes(true)
            .load_data(false);
        match options.search() {
            Ok(items) => Ok(!items.is_empty()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(self.keychain_error("inspect", error)),
        }
    }

    fn get(&self, account: &str) -> Result<Vec<u8>> {
        generic_password_for(self.ids.service.as_ref(), account)
            .map_err(|error| self.keychain_error("read", error))
    }

    fn set(&self, account: &str, bytes: &[u8]) -> Result<()> {
        set_generic_password(self.ids.service.as_ref(), account, bytes)
            .map_err(|error| self.keychain_error("write", error))
    }

    fn delete(&self, account: &str) -> Result<()> {
        match delete_generic_password(self.ids.service.as_ref(), account) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(self.keychain_error("delete", error)),
        }
    }

    fn keychain_error(&self, operation: &str, error: KeychainError) -> CoreError {
        match error.code() {
            ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => {
                CoreError::AuthorityRequired(format!(
                    "macOS Keychain denied {operation} of the authority key: {error}; ask your human to unlock it"
                ))
            }
            ERR_SEC_ITEM_NOT_FOUND => CoreError::AuthorityUnavailable(
                "macOS authority key is not initialized (run: cmail authority init)".into(),
            ),
            _ => CoreError::AuthorityUnavailable(format!(
                "macOS Keychain could not {operation} the authority key: {error}"
            )),
        }
    }

    fn read_public_key(&self) -> Result<VerifyingKey> {
        let bytes = self.get(self.ids.public_account.as_ref())?;
        let raw: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            CoreError::AuthorityInvalid("macOS authority public key is malformed".into())
        })?;
        VerifyingKey::from_bytes(&raw).map_err(|_| {
            CoreError::AuthorityInvalid("macOS authority public key is malformed".into())
        })
    }

    fn read_seed(&self) -> Result<SigningKey> {
        let mut bytes = self.get(self.ids.seed_account.as_ref())?;
        let raw: [u8; 32] = match bytes.as_slice().try_into() {
            Ok(raw) => raw,
            Err(_) => {
                bytes.fill(0);
                return Err(CoreError::AuthorityInvalid(
                    "macOS authority signing key is malformed".into(),
                ));
            }
        };
        bytes.fill(0);
        Ok(SigningKey::from_bytes(&raw))
    }

    fn last_grant(&self) -> Result<Option<String>> {
        let records = read_records(&self.records_path()?)?;
        let key = self.read_public_key()?;
        Ok(fold_records(&records, &key)
            .decisions
            .values()
            .max_by_key(|decision| decision.sequence)
            .map(|decision| decision.timestamp.clone()))
    }
}

fn generic_password_for(
    service: &str,
    account: &str,
) -> std::result::Result<Vec<u8>, KeychainError> {
    generic_password(
        security_framework::passwords::PasswordOptions::new_generic_password(service, account),
    )
}

fn default_root() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("CMAIL_HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    let home = std::env::var("HOME").map_err(|_| {
        CoreError::AuthorityUnavailable(
            "cannot determine the mailbox root (set CMAIL_HOME or HOME)".into(),
        )
    })?;
    Ok(PathBuf::from(home).join(".cmail"))
}

/// Require OS-verified human presence before any key use. LocalAuthentication
/// accepts Touch ID or the login passcode; a process running unattended cannot
/// answer the system prompt.
fn require_presence(reason: &str) -> Result<()> {
    let (sender, receiver) = std::sync::mpsc::channel();
    // Safety: LAContext is a normal Objective-C object; the block only sends a
    // plain message over an mpsc channel and touches no Rust state after the
    // call returns except that message. The context outlives the evaluation.
    unsafe {
        let context = LAContext::new();
        if let Err(error) = context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) {
            return Err(CoreError::AuthorityUnavailable(format!(
                "macOS user presence is unavailable: {}",
                error.localizedDescription()
            )));
        }

        let reply = block2::RcBlock::new(move |success: Bool, error: *mut NSError| {
            let message = if success.as_bool() {
                None
            } else if error.is_null() {
                Some("authentication failed".to_string())
            } else {
                // Safety: LocalAuthentication passes an NSError the block may read.
                Some((*error).localizedDescription().to_string())
            };
            let _ = sender.send(message);
        });

        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &NSString::from_str(reason),
            &reply,
        );

        match receiver.recv_timeout(PRESENCE_TIMEOUT) {
            Ok(None) => Ok(()),
            Ok(Some(message)) => Err(CoreError::AuthorityRequired(format!(
                "macOS user presence was denied: {message}; ask your human to approve the Touch ID or passcode prompt"
            ))),
            Err(_) => Err(CoreError::AuthorityRequired(
                "macOS user presence prompt did not complete; ask your human to approve it".into(),
            )),
        }
    }
}

impl Authority for MacAuthority {
    fn status(&self) -> Result<AuthorityStatus> {
        if !self.item_exists(self.ids.public_account.as_ref())? {
            return Ok(AuthorityStatus {
                available: false,
                fingerprint: None,
                backend: "macos-keychain".into(),
                assurance: Assurance::None,
                last_grant: None,
            });
        }
        let key = self.read_public_key()?;
        Ok(AuthorityStatus {
            available: true,
            fingerprint: Some(fingerprint_of(&B64.encode(key.as_bytes()))),
            backend: "macos-keychain".into(),
            assurance: Assurance::Moderate,
            last_grant: self.last_grant()?,
        })
    }

    fn init(&self) -> Result<AuthorityStatus> {
        if self.item_exists(self.ids.public_account.as_ref())? {
            return self.status();
        }

        if self.item_exists(self.ids.seed_account.as_ref())? {
            require_presence("Repair the cmail human authority key")?;
            let signing = self.read_seed()?;
            self.set(
                self.ids.public_account.as_ref(),
                signing.verifying_key().as_bytes(),
            )?;
            return self.status();
        }

        require_presence("Create the cmail human authority key")?;
        let signing = SigningKey::generate(&mut OsRng);
        self.set(
            self.ids.public_account.as_ref(),
            signing.verifying_key().as_bytes(),
        )?;
        if let Err(error) = self.set(self.ids.seed_account.as_ref(), &signing.to_bytes()) {
            // Do not leave a public key that cannot sign. Delete it only when
            // it is still ours, so a racing init is never damaged.
            if let Ok(current) = self.get(self.ids.public_account.as_ref()) {
                if current == signing.verifying_key().as_bytes() {
                    let _ = self.delete(self.ids.public_account.as_ref());
                }
            }
            return Err(error);
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

        // Fail before prompting if no authority exists.
        let _ = self.read_public_key()?;
        require_presence("Approve a cmail human-authority signing request")?;
        let signing = self.read_seed()?;

        let path = self.records_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        file.lock().map_err(|error| {
            CoreError::AuthorityUnavailable(format!(
                "cannot lock the authority log {}: {error}",
                path.display()
            ))
        })?;

        let result = (|| {
            let mut text = String::new();
            file.seek(SeekFrom::Start(0))?;
            file.read_to_string(&mut text)?;
            let sequence = next_sequence(&text)?;
            let record =
                AuthorityRecord::sign(sequence, now_rfc3339(), action, subject, payload, &signing);
            let line = serde_json::to_string(&record)?;
            writeln!(file, "{line}")?;
            file.sync_data()?;
            Ok(record)
        })();

        let _ = file.unlock();
        result
    }

    fn load_effective_policy(&self) -> Result<EffectivePolicy> {
        let key = self.read_public_key()?;
        let records = read_records(&self.records_path()?)?;
        Ok(fold_records(&records, &key))
    }
}

/// Highest sequence already present, plus one. Malformed lines are ignored by
/// the fold, but they still consume a sequence so a tampered log cannot cause
/// a rewritten sequence to be accepted.
fn next_sequence(text: &str) -> Result<u64> {
    let highest = text
        .lines()
        .filter_map(|line| serde_json::from_str::<AuthorityRecord>(line).ok())
        .map(|record| record.sequence)
        .max()
        .unwrap_or(0);
    highest
        .checked_add(1)
        .ok_or_else(|| CoreError::AuthorityInvalid("authority log sequence is exhausted".into()))
}

fn read_records(path: &Path) -> Result<Vec<AuthorityRecord>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use tempfile::TempDir;

    fn signed(
        sequence: u64,
        action: AuthorityAction,
        subject: &str,
        key: &SigningKey,
    ) -> AuthorityRecord {
        AuthorityRecord::sign(
            sequence,
            format!("2026-11-16T00:00:{sequence:02}Z"),
            action,
            subject,
            &json!({ "seq": sequence }),
            key,
        )
    }

    fn append(path: &Path, record: &AuthorityRecord) {
        let line = serde_json::to_string(record).unwrap();
        crate::fsutil::append_line(path, &format!("{line}\n")).unwrap();
    }

    #[test]
    fn log_round_trips_through_the_fold() {
        let root = TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join("authority")).unwrap();
        let path = root.path().join("authority").join("records.jsonl");
        let key = SigningKey::generate(&mut OsRng);

        append(&path, &signed(1, AuthorityAction::AllowAdd, "alice", &key));
        append(
            &path,
            &signed(2, AuthorityAction::AllowRemove, "alice", &key),
        );
        let records = read_records(&path).unwrap();
        assert_eq!(
            next_sequence(&std::fs::read_to_string(&path).unwrap()).unwrap(),
            3
        );
        let policy = fold_records(&records, &key.verifying_key());
        assert_eq!(policy.decisions["alice"].sequence, 2);
        assert_eq!(
            policy.decisions["alice"].action,
            AuthorityAction::AllowRemove
        );
    }

    #[test]
    fn malformed_lines_are_ignored_without_losing_sequence_progress() {
        let root = TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join("authority")).unwrap();
        let path = root.path().join("authority").join("records.jsonl");
        let key = SigningKey::generate(&mut OsRng);
        append(&path, &signed(1, AuthorityAction::AllowAdd, "alice", &key));
        crate::fsutil::append_line(&path, "not json\n").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(next_sequence(&text).unwrap(), 2);
        assert_eq!(read_records(&path).unwrap().len(), 1);
    }

    #[test]
    fn authority_log_contains_no_private_key_material() {
        let root = TempDir::new().unwrap();
        std::fs::create_dir_all(root.path().join("authority")).unwrap();
        let path = root.path().join("authority").join("records.jsonl");
        let key = SigningKey::generate(&mut OsRng);
        append(&path, &signed(1, AuthorityAction::AllowAdd, "alice", &key));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&B64.encode(key.to_bytes())));
        assert!(!text.contains(&hex::encode(key.to_bytes())));
    }

    /// Manual proof that macOS presence gating and Keychain storage work. Not
    /// run by CI: it prompts for Touch ID/passcode and writes a temporary
    /// Keychain item under a unique service name.
    ///
    ///     cargo test -p cmail-core --lib \
    ///       authority::macos::tests::manual_presence_signing -- --ignored --nocapture
    #[test]
    #[ignore = "requires a human at a Touch ID/passcode prompt"]
    fn manual_presence_signing() {
        let root = TempDir::new().unwrap();
        let ids = KeychainIds {
            service: Cow::Owned(format!(
                "com.tigwyk.cmail.authority.test.{}",
                std::process::id()
            )),
            seed_account: Cow::Borrowed("seed"),
            public_account: Cow::Borrowed("public"),
        };
        let authority = MacAuthority::with_ids(ids, root.path());

        let status = authority.init().expect("authority init");
        assert!(status.available);
        assert_eq!(status.backend, "macos-keychain");

        let record = authority
            .sign_action(
                AuthorityAction::AllowAdd,
                "manual-test",
                &json!({ "probe": true }),
            )
            .expect("presence-gated signature");
        let policy = authority.load_effective_policy().expect("policy");
        assert_eq!(policy.decisions["manual-test"].sequence, record.sequence);

        authority.delete(&authority.ids.seed_account).unwrap();
        authority.delete(&authority.ids.public_account).unwrap();
    }
}
