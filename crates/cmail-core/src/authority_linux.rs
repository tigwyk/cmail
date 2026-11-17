//! Linux authority backend: the Ed25519 signing key lives in the Secret
//! Service (GNOME Keyring, KWallet, or any compatible provider) and is read
//! only after the collection has been unlocked.
//!
//! Honest assurance: a login keyring is normally unlocked for the whole
//! session and is readable by any process running as the same user, so the
//! presence check is a speed bump, not a boundary. [`Assurance::Advisory`]
//! and an explanation are reported rather than claiming otherwise.

use crate::authority::{Assurance, Authority, AuthorityAction, AuthorityStatus, LogHead};
use crate::error::{CoreError, Result};
use crate::identity::fingerprint_of;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error as SecretServiceError};
use std::collections::HashMap;
use std::sync::Mutex;

const BACKEND: &str = "secret-service";
const ITEM_LABEL: &str = "cmail human authority";
/// The pinned log head lives in the keyring beside the key, never under the
/// mailbox root, so truncating the log cannot roll policy back.
const HEAD_LABEL: &str = "cmail authority log head";
const CONTENT_TYPE: &str = "application/octet-stream";
const ASSURANCE_EXPLANATION: &str = "Secret Service has no per-use presence guarantee: the login keyring is normally unlocked for the whole session, so any process running as this user can read the key. Presence is a speed bump, not a boundary.";
const NOT_INITIALIZED: &str = "authority is not initialized; run: cmail authority init";
const LOCKED: &str = "the login keyring is locked; run a human-only command to unlock it";

fn attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([("application", "cmail"), ("purpose", "authority")])
}

fn head_attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([("application", "cmail"), ("purpose", "authority-head")])
}

fn connect() -> Result<SecretService<'static>> {
    SecretService::connect(EncryptionType::Dh).map_err(map_error)
}

fn map_error(err: SecretServiceError) -> CoreError {
    match err {
        SecretServiceError::Prompt => CoreError::AuthorityRequired(
            "Secret Service presence check was dismissed; ask your human to unlock the login keyring"
                .into(),
        ),
        SecretServiceError::Locked => CoreError::AuthorityRequired(LOCKED.into()),
        SecretServiceError::Unavailable => CoreError::AuthorityUnavailable(
            "no Secret Service provider is available on this system".into(),
        ),
        SecretServiceError::NoResult => CoreError::AuthorityUnavailable(NOT_INITIALIZED.into()),
        other => CoreError::AuthorityUnavailable(format!("Secret Service: {other}")),
    }
}

fn unavailable(explanation: impl Into<String>) -> AuthorityStatus {
    AuthorityStatus {
        available: false,
        fingerprint: None,
        backend: BACKEND.into(),
        assurance: Assurance::None,
        last_grant: None,
        explanation: Some(explanation.into()),
    }
}

/// Decode the stored secret into a signing key. A wrong length is corrupt
/// credential-store state, never a reason to fall back to a file.
fn signing_key_from_secret(bytes: &[u8]) -> Result<SigningKey> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        CoreError::AuthorityInvalid(
            "stored authority key is not a 32-byte Ed25519 secret key".into(),
        )
    })?;
    Ok(SigningKey::from_bytes(&raw))
}

fn verifying_key_from_secret(bytes: &[u8]) -> Result<VerifyingKey> {
    Ok(signing_key_from_secret(bytes)?.verifying_key())
}

/// Find the authority item without prompting. Returns the item and whether
/// the provider reported it as locked.
fn find_item<'a>(
    ss: &'a SecretService<'_>,
    attributes: HashMap<&'static str, &'static str>,
) -> Result<(Option<Item<'a>>, bool)> {
    let items = ss.search_items(attributes).map_err(map_error)?;
    if let Some(item) = items.unlocked.into_iter().next() {
        return Ok((Some(item), false));
    }
    if let Some(item) = items.locked.into_iter().next() {
        return Ok((Some(item), true));
    }
    Ok((None, false))
}

fn unlock(collection: &Collection<'_>) -> Result<()> {
    collection.unlock().map_err(map_error)
}

/// Read the signing key after unlocking the default collection. The unlock
/// is the presence gate; a dismissed prompt is a typed refusal.
fn signing_key_with_presence(ss: &SecretService<'_>) -> Result<SigningKey> {
    let (item, _) = find_item(ss, attributes())?;
    if item.is_none() {
        return Err(CoreError::AuthorityUnavailable(NOT_INITIALIZED.into()));
    }
    let collection = ss.get_default_collection().map_err(map_error)?;
    unlock(&collection)?;
    let (item, _) = find_item(ss, attributes())?;
    let item = item.ok_or_else(|| CoreError::AuthorityUnavailable(NOT_INITIALIZED.into()))?;
    let secret = item.get_secret().map_err(map_error)?;
    signing_key_from_secret(&secret)
}

/// Linux presence-gated backend. Key material and the pinned log head live
/// only in the Secret Service; records live in the shared root-scoped log.
pub struct LinuxAuthority {
    last_grant: Mutex<Option<String>>,
}

impl LinuxAuthority {
    pub const fn new() -> Self {
        Self {
            last_grant: Mutex::new(None),
        }
    }
}

impl Default for LinuxAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl Authority for LinuxAuthority {
    fn status(&self) -> Result<AuthorityStatus> {
        let ss = match connect() {
            Ok(ss) => ss,
            Err(err) => return Ok(unavailable(err.to_string())),
        };
        let (item, item_locked) = match find_item(&ss, attributes()) {
            Ok(found) => found,
            Err(err) => return Ok(unavailable(err.to_string())),
        };
        let Some(item) = item else {
            return Ok(unavailable(
                "no authority key is stored in the Secret Service; run: cmail authority init",
            ));
        };

        // Never prompt from status: a locked keyring simply hides the
        // fingerprint until a human-present operation unlocks it.
        let fingerprint = if item_locked {
            None
        } else {
            item.get_secret()
                .ok()
                .and_then(|secret| verifying_key_from_secret(&secret).ok())
                .map(|key| fingerprint_of(&B64.encode(key.as_bytes())))
        };
        let explanation = if item_locked {
            format!("{ASSURANCE_EXPLANATION} The login keyring is currently locked.")
        } else {
            ASSURANCE_EXPLANATION.to_string()
        };
        Ok(AuthorityStatus {
            available: true,
            fingerprint,
            backend: BACKEND.into(),
            assurance: Assurance::Advisory,
            last_grant: self.last_grant(),
            explanation: Some(explanation),
        })
    }

    fn init(&self) -> Result<AuthorityStatus> {
        let ss = connect()?;
        let (item, _) = find_item(&ss, attributes())?;
        if item.is_some() {
            return self.status();
        }
        let collection = match ss.get_default_collection() {
            Ok(collection) => collection,
            Err(SecretServiceError::NoResult) => ss
                .create_collection("cmail authority", "default")
                .map_err(map_error)?,
            Err(err) => return Err(map_error(err)),
        };
        unlock(&collection)?;
        let signing = SigningKey::generate(&mut OsRng);
        collection
            .create_item(
                ITEM_LABEL,
                attributes(),
                &signing.to_bytes(),
                false,
                CONTENT_TYPE,
            )
            .map_err(map_error)?;
        self.status()
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        let ss = connect()?;
        let (item, item_locked) = find_item(&ss, attributes())?;
        let item = item.ok_or_else(|| CoreError::AuthorityUnavailable(NOT_INITIALIZED.into()))?;
        if item_locked {
            // Read paths never prompt; a locked keyring fails closed.
            return Err(CoreError::AuthorityUnavailable(LOCKED.into()));
        }
        let secret = item.get_secret().map_err(map_error)?;
        verifying_key_from_secret(&secret)
    }

    fn sign_bytes(&self, _action: AuthorityAction, _subject: &str, bytes: &str) -> Result<String> {
        let ss = connect()?;
        // Presence first: no signature exists unless the key was readable.
        let signing = signing_key_with_presence(&ss)?;
        Ok(B64.encode(signing.sign(bytes.as_bytes()).to_bytes()))
    }

    fn pinned_head(&self) -> Result<Option<LogHead>> {
        let ss = connect()?;
        let (item, item_locked) = find_item(&ss, head_attributes())?;
        let Some(item) = item else {
            return Ok(None);
        };
        if item_locked {
            return Err(CoreError::AuthorityUnavailable(LOCKED.into()));
        }
        let secret = item.get_secret().map_err(map_error)?;
        serde_json::from_slice(&secret).map(Some).map_err(|_| {
            CoreError::AuthorityInvalid("Secret Service authority log head is malformed".into())
        })
    }

    fn pin_head(&self, head: &LogHead) -> Result<()> {
        let ss = connect()?;
        let collection = ss.get_default_collection().map_err(map_error)?;
        unlock(&collection)?;
        let secret = serde_json::to_vec(head).map_err(|_| {
            CoreError::AuthorityInvalid("authority log head is not serializable".into())
        })?;
        collection
            .create_item(HEAD_LABEL, head_attributes(), &secret, true, CONTENT_TYPE)
            .map_err(map_error)?;
        Ok(())
    }

    fn last_grant(&self) -> Option<String> {
        self.last_grant.lock().ok().and_then(|grant| grant.clone())
    }

    fn record_grant(&self, timestamp: &str) {
        if let Ok(mut grant) = self.last_grant.lock() {
            *grant = Some(timestamp.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_secret_round_trips_to_the_same_signing_key() {
        let key = SigningKey::generate(&mut OsRng);
        let restored = signing_key_from_secret(&key.to_bytes()).unwrap();
        assert_eq!(restored.verifying_key(), key.verifying_key());
    }

    #[test]
    fn wrong_secret_length_is_a_typed_error() {
        assert!(matches!(
            signing_key_from_secret(&[0u8; 31]),
            Err(CoreError::AuthorityInvalid(_))
        ));
    }

    #[test]
    fn unavailable_status_names_the_backend_and_explains_itself() {
        let status = unavailable("no provider");
        assert_eq!(status.backend, BACKEND);
        assert_eq!(status.assurance, Assurance::None);
        assert!(status.explanation.is_some());
        assert!(!status.available);
    }
}
