//! File-backed relay storage (spec §2.2).
//!
//! Layout under the relay root:
//! - `mailboxes/{fp}/meta.json`           — pubkey pinned at first deposit, created ts
//! - `mailboxes/{fp}/{id}.parcel`         — raw parcel JSON bytes, stored opaquely
//! - `mailboxes/{fp}/{id}.meta.json`      — sidecar recording `received_unix` for retention GC
//! - `nonces/{fp}/{sha256(nonce)[0..16]}.json` — `{"nonce", "expires_unix"}`, single-use
//!
//! The relay NEVER parses inside envelope interiors: parcels are validated
//! upstream ([`cmail_core::relay::Parcel::validate`] + fingerprint check in the
//! server) and stored/fetched as raw bytes. Caps (spec §2.2): raw parcel body
//! <= [`MAX_BODY_BYTES`] (a max-decoded 36 MiB parcel encodes to ~48 MiB of
//! base64 + JSON, so the body cap has encoding headroom), per-mailbox
//! <= [`MAX_MAILBOX_BYTES`] and <= [`MAX_MAILBOX_ENTRIES`].
//!
//! Per-mailbox cap accounting is an in-memory cache seeded by one directory
//! scan on first touch and maintained across store-mediated writes; files
//! planted directly on disk after first touch are seen by retention GC and
//! listings (which always scan) but may lag the cap counters until restart.
//! Exact-enough for a reference server; disclosed in the task report.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cmail_core::identity::fingerprint_of;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;
use time::OffsetDateTime;

/// Cap on a deposited parcel's raw encoded body (36 MiB decoded attachments
/// become ~48 MiB of base64 + JSON overhead; 64 MiB mirrors the reference
/// client's own response-read cap). Checked via Content-Length BEFORE the
/// body is read, and again on the stored bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Per-mailbox total parcel bytes cap (spec §2.2: 256 MiB).
pub const MAX_MAILBOX_BYTES: u64 = 256 * 1024 * 1024;
/// Per-mailbox entry count cap (spec §2.2: 1000).
pub const MAX_MAILBOX_ENTRIES: usize = 1000;
/// Max outstanding (unconsumed, unexpired) nonces per fingerprint (spec §2.2).
pub const MAX_OUTSTANDING_NONCES: usize = 8;
/// Nonce time-to-live (spec §2: 5 minutes).
pub const NONCE_TTL_SECS: i64 = 5 * 60;

const DAY_SECS: i64 = 86400;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("bad request: {0}")]
    Bad(String),
    #[error("over size cap: {0}")]
    Full(String),
    #[error("too many entries: {0}")]
    TooMany(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("storage error: {0}")]
    Io(#[from] std::io::Error),
}

impl StoreError {
    /// HTTP status the server answers this store error with.
    pub fn http_status(&self) -> u16 {
        match self {
            StoreError::Bad(_) => 400,
            StoreError::Full(_) => 413,
            StoreError::TooMany(_) => 429,
            StoreError::Conflict(_) => 409,
            StoreError::Io(_) => 500,
        }
    }
}

/// Fingerprints are 16 hex chars (path-safe by construction; the same idiom
/// as core's store id validation).
pub(crate) fn valid_fp(fp: &str) -> bool {
    fp.len() == 16 && fp.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parcel ids are 32 hex chars assigned by the relay.
fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) fn rfc3339(ts: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::from_unix_timestamp(ts)
        .map(|t| t.format(&Rfc3339).unwrap_or_default())
        .unwrap_or_default()
}

pub struct RelayStore {
    root: PathBuf,
    retention_days: u64,
    /// Per-fp `(entry count, total parcel bytes)` cap cache, lazily seeded.
    caps: Mutex<HashMap<String, (usize, u64)>>,
}

impl RelayStore {
    pub fn new(root: PathBuf, retention_days: u64) -> Self {
        Self {
            root,
            retention_days,
            caps: Mutex::new(HashMap::new()),
        }
    }

    fn mailbox_dir(&self, fp: &str) -> PathBuf {
        self.root.join("mailboxes").join(fp)
    }

    fn nonce_dir(&self, fp: &str) -> PathBuf {
        self.root.join("nonces").join(fp)
    }

    fn meta_path(&self, fp: &str) -> PathBuf {
        self.mailbox_dir(fp).join("meta.json")
    }

    fn parcel_path(&self, fp: &str, id: &str) -> PathBuf {
        self.mailbox_dir(fp).join(format!("{id}.parcel"))
    }

    fn sidecar_path(&self, fp: &str, id: &str) -> PathBuf {
        self.mailbox_dir(fp).join(format!("{id}.meta.json"))
    }

    /// `nonces/{fp}/{sha256(nonce)[0..16]}.json` — hash-addressed so the
    /// nonce value never appears in a filename.
    fn nonce_path(&self, fp: &str, nonce: &str) -> PathBuf {
        let hash = hex::encode(Sha256::digest(nonce.as_bytes()));
        self.nonce_dir(fp).join(format!("{}.json", &hash[..16]))
    }

    /// Deposit a parcel: pin the pubkey at first deposit, enforce caps,
    /// assign a fresh 32-hex id, store the raw bytes plus a sidecar with the
    /// received timestamp for retention GC. The parcel itself is opaque.
    pub fn deposit(
        &self,
        fp: &str,
        pubkey_b64: &str,
        parcel_bytes: &[u8],
    ) -> Result<(), StoreError> {
        if !valid_fp(fp) {
            return Err(StoreError::Bad(format!(
                "malformed mailbox fingerprint '{fp}'"
            )));
        }
        if fingerprint_of(pubkey_b64) != fp {
            return Err(StoreError::Bad(
                "parcel pubkey does not fingerprint to this mailbox".into(),
            ));
        }
        if parcel_bytes.len() > MAX_BODY_BYTES {
            return Err(StoreError::Full("parcel body exceeds the size cap".into()));
        }
        let (entries, bytes) = self.caps_of(fp);
        if let Some(err) = cap_status(entries, bytes, parcel_bytes.len() as u64) {
            return Err(err);
        }
        fs::create_dir_all(self.mailbox_dir(fp))?;
        let meta = self.meta_path(fp);
        if !meta.exists() {
            fs::write(
                &meta,
                json!({"pubkey": pubkey_b64, "created": rfc3339(now_unix())}).to_string(),
            )?;
        }
        let id = self.fresh_id(fp);
        fs::write(self.parcel_path(fp, &id), parcel_bytes)?;
        fs::write(
            self.sidecar_path(fp, &id),
            json!({"received_unix": now_unix()}).to_string(),
        )?;
        self.bump_caps(fp, 1, parcel_bytes.len() as i64);
        Ok(())
    }

    /// Pending parcel ids (sorted). Always scans the directory so entries
    /// planted directly on disk are visible.
    pub fn list(&self, fp: &str) -> Vec<String> {
        if !valid_fp(fp) {
            return Vec::new();
        }
        let mut ids = Vec::new();
        if let Ok(rd) = fs::read_dir(self.mailbox_dir(fp)) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("parcel") {
                    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                        ids.push(stem.to_string());
                    }
                }
            }
        }
        ids.sort();
        ids
    }

    /// Raw stored parcel bytes for `(fp, id)`; `None` if unknown.
    pub fn get(&self, fp: &str, id: &str) -> Option<Vec<u8>> {
        if !(valid_fp(fp) && valid_id(id)) {
            return None;
        }
        fs::read(self.parcel_path(fp, id)).ok()
    }

    /// Delete a parcel (and its sidecar); `true` if it existed.
    pub fn delete(&self, fp: &str, id: &str) -> bool {
        if !(valid_fp(fp) && valid_id(id)) {
            return false;
        }
        let parcel = self.parcel_path(fp, id);
        let size = fs::metadata(&parcel).map(|m| m.len()).unwrap_or(0);
        if fs::remove_file(&parcel).is_err() {
            return false;
        }
        let _ = fs::remove_file(self.sidecar_path(fp, id));
        self.bump_caps(fp, -1, -(size as i64));
        true
    }

    /// The mailbox owner's pubkey, pinned at first deposit; `None` when the
    /// mailbox is unknown (or its meta is unreadable — treated as unknown).
    pub fn mailbox_pubkey(&self, fp: &str) -> Option<String> {
        if !valid_fp(fp) {
            return None;
        }
        let raw = fs::read_to_string(self.meta_path(fp)).ok()?;
        let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
        v.get("pubkey")?.as_str().map(str::to_string)
    }

    /// Issue a nonce: 32 random bytes, b64, persisted with a 5-minute TTL.
    /// Single-use is enforced by [`Self::consume_nonce`] deleting on success.
    pub fn nonce(&self, fp: &str) -> String {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let nonce = B64.encode(raw);
        let _ = fs::create_dir_all(self.nonce_dir(fp));
        let _ = fs::write(
            self.nonce_path(fp, &nonce),
            json!({"nonce": nonce, "expires_unix": now_unix() + NONCE_TTL_SECS}).to_string(),
        );
        nonce
    }

    /// Outstanding (unconsumed) nonce count for `fp`. Sweep expired ones
    /// first ([`Self::gc_nonces`]) for an honest count.
    pub fn nonce_count(&self, fp: &str) -> usize {
        if !valid_fp(fp) {
            return 0;
        }
        fs::read_dir(self.nonce_dir(fp))
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Verify and consume one specific nonce: Ed25519-verify the signature
    /// over the nonce's ASCII bytes with the mailbox pubkey; on success the
    /// nonce file is deleted (single-use). Expired or unknown nonces fail
    /// (expired files are swept). Never deletes on verification failure.
    pub fn consume_nonce(
        &self,
        fp: &str,
        nonce_b64: &str,
        sig_b64: &str,
        mailbox_pubkey_b64: &str,
    ) -> bool {
        if !valid_fp(fp) {
            return false;
        }
        let path = self.nonce_path(fp, nonce_b64);
        let Ok(raw) = fs::read_to_string(&path) else {
            return false;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
            let _ = fs::remove_file(&path); // corrupt nonce file is garbage
            return false;
        };
        let stored = v.get("nonce").and_then(|n| n.as_str()).unwrap_or("");
        let expires = v.get("expires_unix").and_then(|t| t.as_i64()).unwrap_or(0);
        if stored != nonce_b64 {
            return false;
        }
        if expires <= now_unix() {
            let _ = fs::remove_file(&path);
            return false;
        }
        if !verify_challenge_sig(nonce_b64, sig_b64, mailbox_pubkey_b64) {
            return false;
        }
        fs::remove_file(&path).is_ok()
    }

    /// Server-side auth entry: the wire protocol sends only the signature
    /// (no nonce echo), so verify the signature against each outstanding
    /// nonce for `fp` (bounded by [`MAX_OUTSTANDING_NONCES`]) and consume
    /// the matching one.
    pub fn consume_nonce_by_signature(
        &self,
        fp: &str,
        sig_b64: &str,
        mailbox_pubkey_b64: &str,
    ) -> bool {
        if !valid_fp(fp) {
            return false;
        }
        let Ok(rd) = fs::read_dir(self.nonce_dir(fp)) else {
            return false;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = fs::read_to_string(&p) else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
                continue;
            };
            let Some(nonce) = v.get("nonce").and_then(|n| n.as_str()) else {
                continue;
            };
            if verify_challenge_sig(nonce, sig_b64, mailbox_pubkey_b64) {
                return self.consume_nonce(fp, nonce, sig_b64, mailbox_pubkey_b64);
            }
        }
        false
    }

    /// Lazy GC on mailbox access and deposit (spec §2.2): retention sweep of
    /// old entries (pruning mailboxes left empty by the sweep) + expired
    /// nonce sweep.
    pub fn gc(&self, fp: &str) {
        self.gc_mailbox(fp);
        self.gc_nonces(fp);
    }

    /// Expired-nonce sweep — run on every request touching `fp`, including
    /// `/challenge/{fp}`, which must NOT trigger the mailbox retention sweep
    /// (a challenge is not mailbox access).
    pub fn gc_nonces(&self, fp: &str) {
        if !valid_fp(fp) {
            return;
        }
        let Ok(rd) = fs::read_dir(self.nonce_dir(fp)) else {
            return;
        };
        let now = now_unix();
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let expired = match read_json_field(&p, "expires_unix") {
                Some(exp) => exp <= now,
                None => true, // unreadable nonce files are garbage
            };
            if expired {
                let _ = fs::remove_file(&p);
            }
        }
    }

    /// Retention sweep: delete `.parcel` files whose sidecar `received_unix`
    /// is older than the retention window (missing/unreadable sidecar →
    /// treated as fresh, conservatively). A mailbox left empty BY THIS SWEEP
    /// is pruned entirely (meta included), making it unknown again — a
    /// mailbox emptied by acks keeps its meta so the owner can keep listing.
    fn gc_mailbox(&self, fp: &str) {
        if !valid_fp(fp) {
            return;
        }
        let dir = self.mailbox_dir(fp);
        let Ok(rd) = fs::read_dir(&dir) else {
            return;
        };
        let cutoff = now_unix() - (self.retention_days as i64) * DAY_SECS;
        let mut removed = 0usize;
        let mut remaining = 0usize;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("parcel") {
                continue;
            }
            let Some(id) = p.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let received =
                read_json_field(&self.sidecar_path(fp, id), "received_unix").unwrap_or(i64::MAX);
            if received <= cutoff {
                let _ = fs::remove_file(&p);
                let _ = fs::remove_file(self.sidecar_path(fp, id));
                removed += 1;
            } else {
                remaining += 1;
            }
        }
        if removed > 0 {
            let mut caps = self.caps.lock().unwrap();
            if let Some(slot) = caps.get_mut(fp) {
                *slot = scan_mailbox(&dir);
            }
            if remaining == 0 {
                caps.remove(fp);
                let _ = fs::remove_dir_all(&dir);
            }
        }
    }

    fn fresh_id(&self, fp: &str) -> String {
        loop {
            let mut raw = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let id = hex::encode(raw);
            if !self.parcel_path(fp, &id).exists() {
                return id;
            }
        }
    }

    fn caps_of(&self, fp: &str) -> (usize, u64) {
        let mut caps = self.caps.lock().unwrap();
        *caps
            .entry(fp.to_string())
            .or_insert_with(|| scan_mailbox(&self.mailbox_dir(fp)))
    }

    fn bump_caps(&self, fp: &str, d_entries: i64, d_bytes: i64) {
        let mut caps = self.caps.lock().unwrap();
        if let Some((entries, bytes)) = caps.get_mut(fp) {
            *entries = (*entries as i64 + d_entries).max(0) as usize;
            *bytes = (*bytes as i64 + d_bytes).max(0) as u64;
        }
    }
}

/// Pure cap decision (unit-tested): entries over cap → TooMany (429), then
/// bytes over cap → Full (413).
fn cap_status(entries: usize, bytes: u64, new_bytes: u64) -> Option<StoreError> {
    if entries + 1 > MAX_MAILBOX_ENTRIES {
        return Some(StoreError::TooMany(format!(
            "mailbox is full ({MAX_MAILBOX_ENTRIES} entries)"
        )));
    }
    if bytes + new_bytes > MAX_MAILBOX_BYTES {
        return Some(StoreError::Full(
            "mailbox exceeds the 256 MiB size cap".into(),
        ));
    }
    None
}

/// Ed25519-verify `sig_b64` over the nonce's ASCII bytes with the b64 pubkey.
fn verify_challenge_sig(nonce: &str, sig_b64: &str, pubkey_b64: &str) -> bool {
    let pubkey = match B64.decode(pubkey_b64) {
        Ok(p) if p.len() == 32 => p,
        _ => return false,
    };
    let sig = match B64.decode(sig_b64) {
        Ok(s) if s.len() == 64 => s,
        _ => return false,
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pubkey[..32].try_into().unwrap()) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig) else {
        return false;
    };
    verifying.verify(nonce.as_bytes(), &sig).is_ok()
}

/// Read one integer field out of a small JSON file (`None` if unreadable).
fn read_json_field(path: &Path, field: &str) -> Option<i64> {
    let raw = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get(field).and_then(|f| f.as_i64())
}

/// Count `.parcel` entries and total bytes in a mailbox directory.
fn scan_mailbox(dir: &Path) -> (usize, u64) {
    let mut entries = 0usize;
    let mut bytes = 0u64;
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("parcel") {
                entries += 1;
                bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    (entries, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn key_and_fp() -> (SigningKey, String, String) {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = B64.encode(key.verifying_key().as_bytes());
        let fp = fingerprint_of(&pubkey);
        (key, pubkey, fp)
    }

    #[test]
    fn cap_status_decisions() {
        assert!(cap_status(0, 0, 1).is_none());
        assert!(cap_status(MAX_MAILBOX_ENTRIES - 1, 0, 1).is_none());
        let err = cap_status(MAX_MAILBOX_ENTRIES, 0, 1).expect("entry cap");
        assert!(matches!(err, StoreError::TooMany(_)));
        assert_eq!(err.http_status(), 429);
        let err = cap_status(0, MAX_MAILBOX_BYTES, 1).expect("size cap");
        assert!(matches!(err, StoreError::Full(_)));
        assert_eq!(err.http_status(), 413);
        // exactly at the byte cap is allowed, one over is not
        assert!(cap_status(0, MAX_MAILBOX_BYTES - 1, 1).is_none());
        assert!(cap_status(0, 0, MAX_BODY_BYTES as u64).is_none());
    }

    #[test]
    fn nonce_lifecycle_single_use() {
        let root = tempfile::tempdir().unwrap();
        let store = RelayStore::new(root.path().to_path_buf(), 7);
        let (key, pubkey, fp) = key_and_fp();
        let nonce = store.nonce(&fp);
        assert_eq!(store.nonce_count(&fp), 1);
        let sig = cmail_core::relay::sign_challenge(&key, &nonce);
        // wrong signature does not consume and does not grant
        let wrong_key = SigningKey::generate(&mut OsRng);
        let bad = cmail_core::relay::sign_challenge(&wrong_key, &nonce);
        assert!(!store.consume_nonce(&fp, &nonce, &bad, &pubkey));
        assert_eq!(store.nonce_count(&fp), 1, "failed auth does not consume");
        // good signature consumes (single-use)
        assert!(store.consume_nonce(&fp, &nonce, &sig, &pubkey));
        assert_eq!(store.nonce_count(&fp), 0);
        assert!(!store.consume_nonce(&fp, &nonce, &sig, &pubkey));
    }

    #[test]
    fn nonce_files_are_hash_addressed_with_short_names() {
        let root = tempfile::tempdir().unwrap();
        let store = RelayStore::new(root.path().to_path_buf(), 7);
        let (_, _, fp) = key_and_fp();
        let nonce = store.nonce(&fp);
        let dir = store.nonce_dir(&fp);
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1);
        let expected = &hex::encode(Sha256::digest(nonce.as_bytes()))[..16];
        assert_eq!(names[0], format!("{expected}.json"));
        // the nonce value itself never appears in the filename
        assert!(!names[0].contains(&nonce));
    }
}
