//! Windows authority backend: the Ed25519 seed lives in Windows Credential
//! Manager (DPAPI-protected) and every signature is gated by a Windows Hello
//! user-presence prompt.
//!
//! There is no file or environment fallback: when the credential is missing,
//! Windows Hello is unavailable, or presence is denied, signing fails closed
//! with a typed error.

use super::{
    fold_records, verify_record, Assurance, Authority, AuthorityAction, AuthorityRecord,
    AuthorityStatus, EffectivePolicy,
};
use crate::error::{CoreError, Result};
use crate::identity::{fingerprint_of, now_rfc3339};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::future::IntoFuture;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
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
const RECORD_FILE: &str = "authority.log";

/// One signing operation and its record append are serialized in-process so
/// concurrent callers cannot reuse a sequence number.
static SIGN_LOCK: Mutex<()> = Mutex::new(());

/// Windows backend: Credential Manager key plus Windows Hello presence.
pub struct WindowsAuthority;

impl Authority for WindowsAuthority {
    fn status(&self) -> Result<AuthorityStatus> {
        let signing = signing_key()?;
        Ok(match signing {
            Some(key) => AuthorityStatus {
                available: true,
                fingerprint: Some(fingerprint_of(&B64.encode(key.verifying_key().as_bytes()))),
                backend: "windows-credential-manager".into(),
                assurance: Assurance::Moderate,
                last_grant: last_grant(&key),
            },
            None => AuthorityStatus {
                available: false,
                fingerprint: None,
                backend: "windows-credential-manager".into(),
                assurance: Assurance::None,
                last_grant: None,
            },
        })
    }

    fn init(&self) -> Result<AuthorityStatus> {
        let _guard = lock()?;
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

        let _guard = lock()?;
        let key = signing_key()?.ok_or_else(|| {
            CoreError::AuthorityUnavailable(
                "authority is not initialized; ask your human to run: cmail authority init".into(),
            )
        })?;
        let records = read_records()?;
        let sequence = records.last().map_or(1, |record| record.sequence + 1);

        // Presence is required before any signature exists.
        require_presence(action, subject)?;

        let record = AuthorityRecord::sign(sequence, now_rfc3339(), action, subject, payload, &key);
        append_record(&record)?;
        Ok(record)
    }

    fn load_effective_policy(&self) -> Result<EffectivePolicy> {
        let key = signing_key()?.ok_or_else(|| {
            CoreError::AuthorityUnavailable("authority is not initialized".into())
        })?;
        Ok(fold_records(&read_records()?, &key.verifying_key()))
    }
}

fn lock() -> Result<std::sync::MutexGuard<'static, ()>> {
    SIGN_LOCK
        .lock()
        .map_err(|_| CoreError::AuthorityUnavailable("authority lock poisoned".into()))
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

/// Record log lives in per-user application data, never under the mailbox
/// root and never beside the key material.
fn record_path() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        CoreError::AuthorityUnavailable(
            "LOCALAPPDATA is not set; cannot locate the authority log".into(),
        )
    })?;
    Ok(PathBuf::from(base).join("cmail").join(RECORD_FILE))
}

fn read_records() -> Result<Vec<AuthorityRecord>> {
    let path = record_path()?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(CoreError::AuthorityUnavailable(format!(
                "cannot read the authority log: {error}"
            )))
        }
    };
    // Malformed lines are ignored; their sequence gap blocks later records
    // during the fold, so corruption fails closed instead of granting policy.
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

fn append_record(record: &AuthorityRecord) -> Result<()> {
    let path = record_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            CoreError::AuthorityUnavailable(format!("cannot create the authority log: {error}"))
        })?;
    }
    let mut line = serde_json::to_string(record)?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| {
            CoreError::AuthorityUnavailable(format!("cannot open the authority log: {error}"))
        })?;
    file.write_all(line.as_bytes()).map_err(|error| {
        CoreError::AuthorityUnavailable(format!("cannot append to the authority log: {error}"))
    })?;
    file.sync_all().map_err(|error| {
        CoreError::AuthorityUnavailable(format!("cannot sync the authority log: {error}"))
    })
}

fn last_grant(key: &SigningKey) -> Option<String> {
    read_records()
        .ok()?
        .into_iter()
        .rfind(|record| verify_record(record, &key.verifying_key()))
        .map(|record| record.timestamp)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
