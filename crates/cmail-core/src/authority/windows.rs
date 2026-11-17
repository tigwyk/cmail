//! Windows authority backend: the Ed25519 seed lives in Windows Credential
//! Manager (DPAPI-protected) and every signature is gated by a Windows Hello
//! user-presence prompt.
//!
//! The backend only creates and uses the key and returns signed records. The
//! durable append-only authority log is deliberately not implemented here;
//! ticket #19 moves it under the mailbox root behind a shared store.
//!
//! There is no file or environment fallback: when the credential is missing,
//! Windows Hello is unavailable, or presence is denied, signing fails closed
//! with a typed error.

use super::{
    Assurance, Authority, AuthorityAction, AuthorityRecord, AuthorityStatus, EffectivePolicy,
};
use crate::error::{CoreError, Result};
use crate::identity::{fingerprint_of, now_rfc3339};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::Value;
use std::future::IntoFuture;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Security::Credentials::{
    CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

/// Credential Manager target name for the authority seed.
const CREDENTIAL_TARGET: &str = "cmail.authority.v1";
const SEED_LEN: usize = 32;
const ASSURANCE_EXPLANATION: &str = "Windows Hello proves human presence, but the DPAPI-protected credential blob is not cryptographically bound to that check: a same-user process that locates the blob can decrypt it after login.";

/// Windows backend: Credential Manager key plus Windows Hello presence.
pub struct WindowsAuthority {
    /// Per-process record sequence. Durable sequence ownership arrives with
    /// the shared store in ticket #19.
    sequence: AtomicU64,
    last_grant: Mutex<Option<String>>,
}

impl WindowsAuthority {
    pub(crate) const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
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
                last_grant: self
                    .last_grant
                    .lock()
                    .map_err(|_| {
                        CoreError::AuthorityUnavailable("authority status lock poisoned".into())
                    })?
                    .clone(),
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

        let key = signing_key()?.ok_or_else(|| {
            CoreError::AuthorityUnavailable(
                "authority is not initialized; ask your human to run: cmail authority init".into(),
            )
        })?;

        // Presence is required before any signature exists.
        require_presence(action, subject)?;

        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let record = AuthorityRecord::sign(sequence, now_rfc3339(), action, subject, payload, &key);
        if let Ok(mut last_grant) = self.last_grant.lock() {
            *last_grant = Some(record.timestamp.clone());
        }
        Ok(record)
    }

    fn load_effective_policy(&self) -> Result<EffectivePolicy> {
        Err(CoreError::AuthorityUnavailable(
            "authority record storage is not implemented until ticket #19".into(),
        ))
    }
}

fn signing_key() -> Result<Option<SigningKey>> {
    read_seed().map(|seed| seed.map(|seed| SigningKey::from_bytes(&seed)))
}

fn read_seed() -> Result<Option<[u8; SEED_LEN]>> {
    let target = wide(CREDENTIAL_TARGET);
    let mut raw: *mut CREDENTIALW = std::ptr::null_mut();
    if unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None, &mut raw) }.is_err() {
        // Absent or unreadable credential: report it as unavailable, never
        // fall back to a file.
        return Ok(None);
    }
    if raw.is_null() {
        return Ok(None);
    }
    let credential = unsafe { &*raw };
    let size = credential.CredentialBlobSize as usize;
    let blob = credential.CredentialBlob;
    let result = if size != SEED_LEN || blob.is_null() {
        Err(CoreError::AuthorityInvalid(
            "Windows Credential Manager authority credential is malformed".into(),
        ))
    } else {
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(unsafe { std::slice::from_raw_parts(blob, SEED_LEN) });
        Ok(Some(seed))
    };
    unsafe { CredFree(raw.cast()) };
    result
}

fn write_seed(seed: &[u8; SEED_LEN]) -> Result<()> {
    let mut target = wide(CREDENTIAL_TARGET);
    let mut user = wide("cmail authority");
    let mut blob = seed.to_vec();
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

fn require_presence(action: AuthorityAction, subject: &str) -> Result<()> {
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

    let prompt = HSTRING::from(format!(
        "Approve cmail authority action {} for {subject}",
        action_name(action)
    ));
    let operation = UserConsentVerifier::RequestVerificationAsync(&prompt)
        .map_err(|error| presence_error(&error))?;
    let result =
        pollster::block_on(operation.into_future()).map_err(|error| presence_error(&error))?;
    if result == UserConsentVerificationResult::Verified {
        Ok(())
    } else {
        Err(CoreError::AuthorityRequired(format!(
            "{}; ask your human to confirm the Windows Hello prompt for {}",
            verification_label(result),
            action_name(action)
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
