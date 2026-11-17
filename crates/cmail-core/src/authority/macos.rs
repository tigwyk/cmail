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
//! a plain command-line tool does not have (`errSecMissingEntitlement`). The
//! binary is also not built with the hardened runtime. This backend therefore
//! reports [`Assurance::Advisory`]: presence is an in-process speed bump, the
//! Keychain item is not cryptographically bound to that check, and a same-user
//! process can bypass it, for example by injecting into cmail with
//! `DYLD_INSERT_LIBRARIES`. Reporting Moderate or Strong would be dishonest.

use super::{Assurance, Authority, AuthorityAction, AuthorityStatus, LogHead};
use crate::error::{CoreError, Result};
use crate::identity::fingerprint_of;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use rand::rngs::OsRng;
use security_framework::base::Error as KeychainError;
use security_framework::item::{ItemClass, ItemSearchOptions};
use security_framework::passwords::{
    delete_generic_password, generic_password, set_generic_password,
};
use std::borrow::Cow;
use std::sync::Mutex;
use std::time::Duration;

/// Keychain service shared by the authority items.
const SERVICE: &str = "cmail.authority";
/// Account holding the 32-byte Ed25519 seed.
const SEED_ACCOUNT: &str = "ed25519-signing-key-v1";
/// Account holding the public half, readable without a presence prompt so
/// status and policy verification do not interrupt the human.
const PUBLIC_ACCOUNT: &str = "ed25519-public-key-v1";
/// Account holding the pinned log head. Beside the key, in the credential
/// store, so truncating the mailbox-root log cannot roll policy back.
const HEAD_ACCOUNT: &str = "authority-log-head-v1";

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
    head_account: Cow<'static, str>,
}

const SYSTEM_IDS: KeychainIds = KeychainIds {
    service: Cow::Borrowed(SERVICE),
    seed_account: Cow::Borrowed(SEED_ACCOUNT),
    public_account: Cow::Borrowed(PUBLIC_ACCOUNT),
    head_account: Cow::Borrowed(HEAD_ACCOUNT),
};

#[derive(Default)]
struct MacState {
    last_grant: Option<String>,
}

pub(super) struct MacAuthority {
    ids: KeychainIds,
    /// Key material and the pinned log head live in the Keychain; records
    /// live in the shared root-scoped log.
    state: Mutex<MacState>,
}

/// The process-wide macOS backend.
pub(super) fn authority() -> std::sync::Arc<dyn Authority> {
    static MAC: std::sync::LazyLock<std::sync::Arc<dyn Authority>> =
        std::sync::LazyLock::new(|| {
            std::sync::Arc::new(MacAuthority {
                ids: SYSTEM_IDS,
                state: Mutex::new(MacState { last_grant: None }),
            })
        });
    MAC.clone()
}

impl MacAuthority {
    #[cfg(test)]
    fn with_ids(ids: KeychainIds) -> Self {
        Self {
            ids,
            state: Mutex::new(MacState::default()),
        }
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

    /// Generate and store a fresh key pair. Callers gate this behind presence;
    /// it never prompts itself, so a reset prompts only once.
    fn provision_key(&self) -> Result<()> {
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
        // A newly created key starts a new chain.
        if let Ok(mut state) = self.state.lock() {
            state.last_grant = None;
        }
        Ok(())
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

/// Require OS-verified human presence before any key use. LocalAuthentication
/// accepts Touch ID or the login passcode; a process running unattended cannot
/// answer the system prompt.
fn require_presence(reason: &str) -> Result<()> {
    let (sender, receiver) = std::sync::mpsc::channel();
    // Safety: LAContext is a normal Objective-C object; the block only sends a
    // plain message over an mpsc channel. The context outlives the evaluation.
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
                explanation: Some(
                    "no macOS authority key is initialized; run: cmail authority init".into(),
                ),
            });
        }
        let key = self.read_public_key()?;
        Ok(AuthorityStatus {
            available: true,
            fingerprint: Some(fingerprint_of(&B64.encode(key.as_bytes()))),
            backend: "macos-keychain".into(),
            assurance: Assurance::Advisory,
            last_grant: self.last_grant(),
            explanation: Some(
                "presence is an in-process LocalAuthentication speed bump; the Keychain item is not cryptographically bound to that check, and without the hardened runtime a same-user process can bypass it (for example with DYLD_INSERT_LIBRARIES)"
                    .into(),
            ),
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
        self.provision_key()?;
        self.status()
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        self.read_public_key()
    }

    fn sign_bytes(&self, _action: AuthorityAction, _subject: &str, bytes: &str) -> Result<String> {
        // Fail before prompting if no authority exists.
        let _ = self.read_public_key()?;
        require_presence("Approve a cmail human-authority signing request")?;
        let signing = self.read_seed()?;
        Ok(B64.encode(signing.sign(bytes.as_bytes()).to_bytes()))
    }

    fn pinned_head(&self) -> Result<Option<LogHead>> {
        if !self.item_exists(self.ids.head_account.as_ref())? {
            return Ok(None);
        }
        let bytes = self.get(self.ids.head_account.as_ref())?;
        serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            CoreError::AuthorityInvalid("macOS authority log head is malformed".into())
        })
    }

    fn pin_head(&self, head: &LogHead) -> Result<()> {
        let bytes = serde_json::to_vec(head).map_err(|_| {
            CoreError::AuthorityInvalid("authority log head is not serializable".into())
        })?;
        self.set(self.ids.head_account.as_ref(), &bytes)
    }

    fn reset_credentials(&self) -> Result<()> {
        require_presence("Reset the cmail human authority key and discard its record log")?;
        self.delete(self.ids.head_account.as_ref())?;
        self.delete(self.ids.seed_account.as_ref())?;
        self.delete(self.ids.public_account.as_ref())?;
        self.provision_key()
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Manual proof that macOS presence gating and Keychain storage work. Not
    /// run by CI: it prompts for Touch ID/passcode and writes a temporary
    /// Keychain item under a unique service name.
    ///
    ///     cargo test -p cmail-core --lib \
    ///       authority::macos::tests::manual_presence_signing -- --ignored --nocapture
    #[test]
    #[ignore = "requires a human at a Touch ID/passcode prompt"]
    fn manual_presence_signing() {
        let ids = KeychainIds {
            service: Cow::Owned(format!(
                "com.tigwyk.cmail.authority.test.{}",
                std::process::id()
            )),
            seed_account: Cow::Borrowed("seed"),
            public_account: Cow::Borrowed("public"),
            head_account: Cow::Borrowed("head"),
        };
        let authority = MacAuthority::with_ids(ids);
        let root = tempfile::TempDir::new().unwrap();

        let status = authority.init().expect("authority init");
        assert!(status.available);
        assert_eq!(status.backend, "macos-keychain");

        let subject = crate::authority::subject::allow("manual-test");
        let record = authority
            .sign_action(
                root.path(),
                AuthorityAction::AllowAdd,
                &subject,
                &json!({ "probe": true }),
            )
            .expect("presence-gated signature");
        let policy = authority
            .load_effective_policy(root.path())
            .expect("policy");
        assert_eq!(policy.decisions[&subject].sequence, record.sequence);

        authority
            .delete(authority.ids.seed_account.as_ref())
            .unwrap();
        authority
            .delete(authority.ids.public_account.as_ref())
            .unwrap();
        authority
            .delete(authority.ids.head_account.as_ref())
            .unwrap();
    }
}
