//! Path-segment validation and on-platform key derivation.
//!
//! Mirrors relayd's `valid_fp`/`valid_id` byte-for-byte (both length-exact
//! hex) so the two relays are indistinguishable at the routing layer.

use sha2::{Digest, Sha256};

/// Fingerprints are 16 hex chars (path-safe by construction; the same idiom
/// as relayd's store validation).
pub fn valid_fp(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parcel ids are 32 hex chars assigned by the relay.
pub fn valid_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Durable Object name for a mailbox: hex sha256 of the fingerprint, so the
/// DO name never carries the raw fp (spec §2).
pub fn do_name(fp: &str) -> String {
    hex::encode(Sha256::digest(fp.as_bytes()))
}

/// R2 object key for a parcel blob: `{fp}/{id}` (never parsed, just stored).
pub fn blob_key(fp: &str, id: &str) -> String {
    format!("{fp}/{id}")
}
