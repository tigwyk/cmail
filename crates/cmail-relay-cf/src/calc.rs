//! Pure mailbox arithmetic (spec §3/§4), cfg-free so the host test cycle
//! exercises exactly what the wasm Durable Object executes: cap ordering,
//! retention expiry math, and nonce-slot counting. The DO calls these on the
//! mailbox's POST-deposit state and mirrors `cmail-relayd`'s decisions.

/// Per-mailbox entry count cap (spec §2.2: 1000; over → 429).
pub const MAX_MAILBOX_ENTRIES: usize = 1000;
/// Per-mailbox total parcel bytes cap (spec §2.2: 256 MiB; over → 413).
pub const MAX_MAILBOX_BYTES: u64 = 256 * 1024 * 1024;
/// Max outstanding (unconsumed, unexpired) nonces per fingerprint (spec §2.2).
pub const MAX_OUTSTANDING_NONCES: usize = 8;
/// Nonce time-to-live (spec §2: 5 minutes).
pub const NONCE_TTL_SECS: i64 = 5 * 60;
/// Retention used when a mailbox never recorded one (spec §4 default: 7 days).
pub const DEFAULT_RETENTION_DAYS: u64 = 7;

/// Cap decision for a mailbox's POST-deposit state (`count` already includes
/// the new entry, `total_bytes` its encoded size). Count is checked FIRST:
/// over-count → 429 even when the size cap is blown too; then over-size →
/// 413. Exactly-at-cap on either axis is allowed — relayd `cap_status` parity.
pub fn cap_status(count: usize, total_bytes: u64) -> Option<u16> {
    if count > MAX_MAILBOX_ENTRIES {
        return Some(429);
    }
    if total_bytes > MAX_MAILBOX_BYTES {
        return Some(413);
    }
    None
}

/// Retention expiry (spec §4): an entry received at `received_unix` expires
/// the instant `received_unix + retention_days * 86400 <= now_unix` (relayd's
/// `received <= now - retention` cutoff, boundary-inclusive).
pub fn is_expired(received_unix: i64, retention_days: u64, now_unix: i64) -> bool {
    let retention_secs = (retention_days as i64).saturating_mul(86400);
    received_unix.saturating_add(retention_secs) <= now_unix
}

/// Whether one more challenge nonce may be issued given `outstanding`
/// unexpired ones (spec §2.2: ≤ 8 outstanding; the 9th request → 429).
pub fn nonce_slot_available(outstanding: usize) -> bool {
    outstanding < MAX_OUTSTANDING_NONCES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_boundary_exact_is_allowed_on_both_axes() {
        assert_eq!(cap_status(0, 0), None);
        assert_eq!(cap_status(MAX_MAILBOX_ENTRIES, MAX_MAILBOX_BYTES), None);
        assert_eq!(
            cap_status(MAX_MAILBOX_ENTRIES - 1, MAX_MAILBOX_BYTES - 1),
            None
        );
    }

    #[test]
    fn cap_count_over_is_429_even_tiny() {
        assert_eq!(cap_status(MAX_MAILBOX_ENTRIES + 1, 1), Some(429));
        // 1001 entries at well-under the byte cap is still the count cap
        assert_eq!(cap_status(MAX_MAILBOX_ENTRIES + 1, 1024), Some(429));
    }

    #[test]
    fn cap_size_over_is_413_when_count_within() {
        assert_eq!(
            cap_status(MAX_MAILBOX_ENTRIES, MAX_MAILBOX_BYTES + 1),
            Some(413)
        );
        assert_eq!(cap_status(1, MAX_MAILBOX_BYTES + 1), Some(413));
        // one byte over the cap, everything else minimal
        assert_eq!(cap_status(1, MAX_MAILBOX_BYTES + 1), Some(413));
    }

    #[test]
    fn cap_count_wins_when_both_over() {
        assert_eq!(
            cap_status(MAX_MAILBOX_ENTRIES + 1, MAX_MAILBOX_BYTES + 1),
            Some(429)
        );
        assert_eq!(
            cap_status(usize::MAX, u64::MAX),
            Some(429),
            "count is checked first no matter how large the total"
        );
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let received = 1_700_000_000i64;
        let expires_at = received + 7 * 86400;
        assert!(is_expired(received, 7, expires_at));
        assert!(!is_expired(received, 7, expires_at - 1));
    }

    #[test]
    fn expiry_zero_retention_expires_immediately() {
        let received = 42i64;
        assert!(is_expired(received, 0, received));
        assert!(!is_expired(received, 0, received - 1));
    }

    #[test]
    fn expiry_uses_days_not_seconds() {
        let received = 1_700_000_000i64;
        // 7 days minus one second is not yet expired
        assert!(!is_expired(received, 7, received + 7 * 86400 - 1));
        // ...but 7 days + 1 second past receipt is
        assert!(is_expired(received, 7, received + 7 * 86400 + 1));
    }

    #[test]
    fn nonce_slots_below_cap_only() {
        assert!(nonce_slot_available(0));
        assert!(nonce_slot_available(MAX_OUTSTANDING_NONCES - 1));
        assert!(!nonce_slot_available(MAX_OUTSTANDING_NONCES));
        assert!(!nonce_slot_available(MAX_OUTSTANDING_NONCES + 5));
    }
}
