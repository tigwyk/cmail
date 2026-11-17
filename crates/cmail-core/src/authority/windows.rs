//! Windows authority backend: the Ed25519 seed lives in Windows Credential
//! Manager (DPAPI-protected) and every signature is gated by a Windows Hello
//! user-presence prompt.
//!
//! The backend owns the key, presence, and the pinned log head. Signed
//! records go to the shared root-scoped log in [`super::log`], so adopted
//! state survives a new process on every platform.
//!
//! There is no file or environment fallback: when the credential is missing,
//! Windows Hello is unavailable, or presence is denied, signing fails closed
//! with a typed error.

use super::{Assurance, Authority, AuthorityAction, AuthorityStatus, LogHead};
use crate::error::{CoreError, Result};
use crate::identity::fingerprint_of;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::future::IntoFuture;
use std::sync::Mutex;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};
use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

/// Credential Manager target name for the authority seed.
const CREDENTIAL_TARGET: &str = "cmail.authority.v1";
/// Credential Manager target name for the pinned log head. Beside the key,
/// never under the mailbox root.
const CHAIN_HEAD_TARGET: &str = "cmail.authority.log-head.v1";
const SEED_LEN: usize = 32;
const ASSURANCE_EXPLANATION: &str = "Windows Hello proves human presence, but the DPAPI-protected credential blob is not cryptographically bound to that check: a same-user process that locates the blob can decrypt it after login.";

/// Windows backend: Credential Manager key plus Windows Hello presence.
pub struct WindowsAuthority {
    last_grant: Mutex<Option<String>>,
}

impl WindowsAuthority {
    pub(crate) const fn new() -> Self {
        Self {
            last_grant: Mutex::new(None),
        }
    }
}

impl Authority for WindowsAuthority {
    fn status(&self) -> Result<AuthorityStatus> {
        let signing = signing_key()?;
        Ok(match signing {
            Some(key) => AuthorityStatus {
                available: true,
                fingerprint: Some(fingerprint_of(&B64.encode(key.verifying_key().as_bytes()))),
                backend: "windows-credential-manager".into(),
                assurance: Assurance::Moderate,
                last_grant: self.last_grant(),
                explanation: Some(ASSURANCE_EXPLANATION.into()),
            },
            None => AuthorityStatus {
                available: false,
                fingerprint: None,
                backend: "windows-credential-manager".into(),
                assurance: Assurance::None,
                last_grant: None,
                explanation: Some(ASSURANCE_EXPLANATION.into()),
            },
        })
    }

    fn init(&self) -> Result<AuthorityStatus> {
        if signing_key()?.is_some() {
            return self.status();
        }
        require_hello_available()?;
        let key = SigningKey::generate(&mut OsRng);
        write_seed(&key.to_bytes())?;
        self.status()
    }

    fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        Ok(signing_key()?
            .ok_or_else(|| {
                CoreError::AuthorityUnavailable(
                    "authority is not initialized; ask your human to run: cmail authority init"
                        .into(),
                )
            })?
            .verifying_key())
    }

    fn sign_bytes(&self, action: AuthorityAction, subject: &str, bytes: &str) -> Result<String> {
        // Presence is required before any signature exists.
        let key = signing_key()?.ok_or_else(|| {
            CoreError::AuthorityUnavailable(
                "authority is not initialized; ask your human to run: cmail authority init".into(),
            )
        })?;
        require_presence(&format!("action {} for {subject}", action_name(action)))?;
        Ok(B64.encode(key.sign(bytes.as_bytes()).to_bytes()))
    }

    fn pinned_head(&self) -> Result<Option<LogHead>> {
        let Some(blob) = read_credential(CHAIN_HEAD_TARGET)? else {
            return Ok(None);
        };
        serde_json::from_slice(&blob).map(Some).map_err(|_| {
            CoreError::AuthorityInvalid("Credential Manager authority log head is malformed".into())
        })
    }

    fn pin_head(&self, head: &LogHead) -> Result<()> {
        let blob = serde_json::to_vec(head).map_err(|_| {
            CoreError::AuthorityInvalid("authority log head is not serializable".into())
        })?;
        write_credential(CHAIN_HEAD_TARGET, &blob)
    }

    fn reset_credentials(&self) -> Result<()> {
        // Presence gates every deletion; a denied or absent Windows Hello
        // writes nothing.
        require_presence("reset (delete the old key and every signed authority record)")?;
        delete_credential(CHAIN_HEAD_TARGET)?;
        delete_credential(CREDENTIAL_TARGET)?;
        let key = SigningKey::generate(&mut OsRng);
        write_seed(&key.to_bytes())?;
        if let Ok(mut grant) = self.last_grant.lock() {
            *grant = None;
        }
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

fn signing_key() -> Result<Option<SigningKey>> {
    read_seed().map(|seed| seed.map(|seed| SigningKey::from_bytes(&seed)))
}

fn read_seed() -> Result<Option<[u8; SEED_LEN]>> {
    let Some(blob) = read_credential(CREDENTIAL_TARGET)? else {
        return Ok(None);
    };
    let seed: [u8; SEED_LEN] = blob.as_slice().try_into().map_err(|_| {
        CoreError::AuthorityInvalid(
            "Windows Credential Manager authority credential is malformed".into(),
        )
    })?;
    Ok(Some(seed))
}

fn write_seed(seed: &[u8; SEED_LEN]) -> Result<()> {
    write_credential(CREDENTIAL_TARGET, seed)
}

/// Read one generic credential. Absent or unreadable credentials are `None`:
/// there is never a file fallback.
fn read_credential(target: &str) -> Result<Option<Vec<u8>>> {
    let target = wide(target);
    let mut raw: *mut CREDENTIALW = std::ptr::null_mut();
    if unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None, &mut raw) }.is_err() {
        return Ok(None);
    }
    if raw.is_null() {
        return Ok(None);
    }
    let credential = unsafe { &*raw };
    let size = credential.CredentialBlobSize as usize;
    let blob = credential.CredentialBlob;
    let result = if blob.is_null() {
        Err(CoreError::AuthorityInvalid(
            "Windows Credential Manager credential is malformed".into(),
        ))
    } else {
        Ok(Some(
            unsafe { std::slice::from_raw_parts(blob, size) }.to_vec(),
        ))
    };
    unsafe { CredFree(raw.cast()) };
    result
}

fn write_credential(target: &str, secret: &[u8]) -> Result<()> {
    let mut target = wide(target);
    let mut user = wide("cmail authority");
    let mut blob = secret.to_vec();
    let credential = CREDENTIALW {
        Flags: CRED_FLAGS(0),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_mut_ptr()),
        Comment: PWSTR(std::ptr::null_mut()),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: PWSTR(user.as_mut_ptr()),
        ..Default::default()
    };
    let result =
        unsafe { CredWriteW(&credential, 0) }.map_err(|error| credential_error("write", &error));
    blob.fill(0);
    result
}

/// Delete one generic credential. An already-absent target is success, so a
/// retried reset is idempotent.
fn delete_credential(target: &str) -> Result<()> {
    const ERROR_NOT_FOUND: i32 = 0x8007_0490u32 as i32;
    let target = wide(target);
    match unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) } {
        Ok(()) => Ok(()),
        Err(error) if error.code().0 == ERROR_NOT_FOUND => Ok(()),
        Err(error) => Err(credential_error("delete", &error)),
    }
}

fn credential_error(operation: &str, error: &windows::core::Error) -> CoreError {
    CoreError::AuthorityUnavailable(format!(
        "Windows Credential Manager {operation} failed: {error}"
    ))
}

fn require_hello_available() -> Result<()> {
    init_winrt();
    let operation =
        UserConsentVerifier::CheckAvailabilityAsync().map_err(|error| presence_error(&error))?;
    let availability =
        pollster::block_on(operation.into_future()).map_err(|error| presence_error(&error))?;
    if availability != UserConsentVerifierAvailability::Available {
        return Err(CoreError::AuthorityUnavailable(format!(
            "Windows Hello is not available: {}",
            availability_label(availability)
        )));
    }
    Ok(())
}

fn require_presence(request: &str) -> Result<()> {
    init_winrt();
    let operation =
        UserConsentVerifier::CheckAvailabilityAsync().map_err(|error| presence_error(&error))?;
    let availability =
        pollster::block_on(operation.into_future()).map_err(|error| presence_error(&error))?;
    if availability != UserConsentVerifierAvailability::Available {
        return Err(CoreError::AuthorityUnavailable(format!(
            "Windows Hello is not available: {}",
            availability_label(availability)
        )));
    }

    let prompt = HSTRING::from(format!("Approve cmail authority {request}"));
    let operation = UserConsentVerifier::RequestVerificationAsync(&prompt)
        .map_err(|error| presence_error(&error))?;
    let result =
        pollster::block_on(operation.into_future()).map_err(|error| presence_error(&error))?;
    if result == UserConsentVerificationResult::Verified {
        Ok(())
    } else {
        Err(CoreError::AuthorityRequired(format!(
            "{}; ask your human to confirm the Windows Hello prompt for {request}",
            verification_label(result)
        )))
    }
}

fn init_winrt() {
    // WinRT activation needs an initialized apartment. `RoInitialize` is
    // idempotent per thread; an already-initialized apartment is fine.
    unsafe {
        let _ = RoInitialize(RO_INIT_MULTITHREADED);
    }
}

fn presence_error(error: &windows::core::Error) -> CoreError {
    CoreError::AuthorityUnavailable(format!("Windows Hello failed: {error}"))
}

fn availability_label(availability: UserConsentVerifierAvailability) -> &'static str {
    match availability {
        UserConsentVerifierAvailability::Available => "available",
        UserConsentVerifierAvailability::DeviceNotPresent => "no Windows Hello device",
        UserConsentVerifierAvailability::NotConfiguredForUser => {
            "Windows Hello is not configured for this user"
        }
        UserConsentVerifierAvailability::DisabledByPolicy => "disabled by policy",
        UserConsentVerifierAvailability::DeviceBusy => "device busy",
        _ => "unknown availability",
    }
}

fn verification_label(result: UserConsentVerificationResult) -> &'static str {
    match result {
        UserConsentVerificationResult::Verified => "presence verified",
        UserConsentVerificationResult::DeviceNotPresent => "Windows Hello device not present",
        UserConsentVerificationResult::NotConfiguredForUser => {
            "Windows Hello is not configured for this user"
        }
        UserConsentVerificationResult::DisabledByPolicy => "Windows Hello is disabled by policy",
        UserConsentVerificationResult::DeviceBusy => "Windows Hello device is busy",
        UserConsentVerificationResult::RetriesExhausted => {
            "presence verification retries exhausted"
        }
        UserConsentVerificationResult::Canceled => "presence verification was canceled",
        _ => "presence was not verified",
    }
}

fn action_name(action: AuthorityAction) -> &'static str {
    match action {
        AuthorityAction::KeyAdd => "key_add",
        AuthorityAction::KeyRemove => "key_remove",
        AuthorityAction::AllowAdd => "allow_add",
        AuthorityAction::AllowRemove => "allow_remove",
        AuthorityAction::RelaySet => "relay_set",
        AuthorityAction::RelayClear => "relay_clear",
        AuthorityAction::Approve => "approve",
        AuthorityAction::Reject => "reject",
        AuthorityAction::QuarantineRelease => "quarantine_release",
        AuthorityAction::OutboundMode => "outbound_mode",
        AuthorityAction::InboundMode => "inbound_mode",
        AuthorityAction::Unknown => "unknown",
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
