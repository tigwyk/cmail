//! Parcel wire format + fingerprint, deliberately duplicated from
//! `cmail-core::relay` (the v0.3.1 spec §1 forbids modifying existing
//! crates, so the worker carries its own copy). Parity with core is
//! enforced host-side by the dev-dep tests in `tests/parcel_unit.rs`;
//! production wasm code never links core.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Parcel protocol version (spec §2.1 pins v1 for interop).
pub const PARCEL_VERSION: u8 = 1;
/// Maximum attachment frames per parcel (spec §2.1).
pub const MAX_PARCEL_ATTACHMENTS: usize = 8;
/// Maximum total decoded attachment bytes per parcel (spec §2.1: 36 MiB).
pub const MAX_PARCEL_BYTES: usize = 36 * 1024 * 1024;

/// The unit of transfer: a sealed envelope plus its encrypted attachment
/// frames in one body (spec §2.1). `pubkey` is the RECIPIENT's Ed25519
/// public key (b64); the relay checks `fingerprint(pubkey) == {fp}`.
/// Unlike core, `envelope` is an opaque [`serde_json::Value`] — the relay
/// is zero-trust and never parses inside it, so this crate refuses to even
/// hold a typed view of envelope contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Parcel {
    pub v: u8,
    pub pubkey: String,
    pub envelope: serde_json::Value,
    pub attachments: Vec<ParcelAttachment>,
}

/// One encrypted attachment frame: index `i` (matching the envelope's
/// attachment order) and the b64 of the raw `att-<i>.bin` frame bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParcelAttachment {
    pub i: usize,
    pub data: String,
}

impl Parcel {
    /// Structural validation per spec §2.1: v == 1, pubkey is b64 for 32
    /// bytes (so its fingerprint is meaningful), count <= 8, every `data`
    /// decodes as standard base64, total decoded <= 36 MiB — and, stricter
    /// than core, the `i` values must be exactly the canonical set
    /// `0..len` (no duplicates, no gaps, no out-of-range indices).
    pub fn validate(&self) -> Result<(), String> {
        if self.v != PARCEL_VERSION {
            return Err(format!("parcel v must be 1, got {}", self.v));
        }
        match B64.decode(&self.pubkey).map(|raw| raw.len()) {
            Ok(32) => {}
            _ => return Err("parcel pubkey must be base64 for 32 bytes".into()),
        }
        if self.attachments.len() > MAX_PARCEL_ATTACHMENTS {
            return Err("parcel carries more than 8 attachments".into());
        }
        let mut seen = [false; MAX_PARCEL_ATTACHMENTS];
        let mut total = 0usize;
        for att in &self.attachments {
            if att.i >= self.attachments.len() || seen[att.i] {
                return Err(format!(
                    "parcel attachment indices must be exactly 0..{}",
                    self.attachments.len()
                ));
            }
            seen[att.i] = true;
            let decoded = B64
                .decode(&att.data)
                .map_err(|_| format!("parcel attachment {} data is not valid base64", att.i))?;
            total += decoded.len();
        }
        if total > MAX_PARCEL_BYTES {
            return Err("parcel attachments exceed 36 MiB total".into());
        }
        Ok(())
    }
}

/// 16-hex-char sha256 fingerprint of a recipient pubkey — identical to
/// `cmail_core::identity::fingerprint_of` for every decodable key. `None`
/// on bad base64 (stricter than core, which fingerprints the empty
/// decode).
pub fn fingerprint_of(pubkey_b64: &str) -> Option<String> {
    let raw = B64.decode(pubkey_b64).ok()?;
    let hash = Sha256::digest(&raw);
    Some(hex::encode(&hash[..8]))
}
