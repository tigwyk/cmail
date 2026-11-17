//! Root-scoped append-only authority-record log, shared by every backend.
//!
//! Signing is the backend's job: it owns the credential-store key and the
//! presence check. Storage and the fold live here, so a record signed on one
//! run is verified and honored by the next process on any platform.
//!
//! Rollback protection: every record names the hash of its predecessor, and
//! the latest `(sequence, hash)` is pinned beside the key in the credential
//! store — outside the mailbox root. Truncating the log, deleting it, or
//! swapping in a log signed by another key therefore fails closed instead of
//! silently restoring an earlier grant.

use super::{
    fold_records, verify_record, Authority, AuthorityAction, AuthorityRecord, EffectivePolicy,
    LogHead,
};
use crate::canonical::canonical_json;
use crate::error::{CoreError, Result};
use crate::fsutil;
use crate::identity::{fingerprint_of, now_rfc3339};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// `prev` of the first record: no predecessor.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The log file under the mailbox root.
pub(super) fn log_path(root: &Path) -> PathBuf {
    root.join("authority.log")
}

fn lock_path(root: &Path) -> PathBuf {
    root.join("authority.log.lock")
}

/// SHA-256 over the complete canonical record, signature included. Changing
/// any byte of any earlier record breaks every later link.
fn record_hash(record: &AuthorityRecord) -> String {
    let value = serde_json::to_value(record).expect("authority record is serializable");
    hex::encode(Sha256::digest(canonical_json(&value).as_bytes()))
}

fn head_of(record: &AuthorityRecord) -> LogHead {
    LogHead {
        sequence: record.sequence,
        hash: record_hash(record),
    }
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::AuthorityInvalid(message.into())
}

/// Read the retained records. A single incomplete final line is the tail of
/// an interrupted append and is ignored; everything before it must parse.
fn read_records(path: &Path) -> Result<Vec<AuthorityRecord>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    // `append_line` writes one complete line plus its newline, so a file that
    // stops mid-line is a torn tail and nothing else.
    let complete = match bytes.last() {
        Some(b'\n') => &bytes[..],
        Some(_) => match bytes.iter().rposition(|byte| *byte == b'\n') {
            Some(index) => &bytes[..=index],
            None => &[],
        },
        None => &[],
    };
    let text =
        std::str::from_utf8(complete).map_err(|_| invalid("authority log is not valid UTF-8"))?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let record: AuthorityRecord = serde_json::from_str(line)
            .map_err(|_| invalid(format!("authority log line {} is corrupt", index + 1)))?;
        records.push(record);
    }
    Ok(records)
}

/// Strict chain verification: contiguity from sequence 1, a signature under
/// the current authority key, and a `prev` hash matching the record before.
/// Any failure fails the whole load closed; a tampered interior record is
/// never skipped, because skipping it would silently drop later revocations.
fn verify_chain(records: &[AuthorityRecord], authority_key: &VerifyingKey) -> Result<()> {
    let mut prev = GENESIS.to_string();
    for (index, record) in records.iter().enumerate() {
        let expected = index as u64 + 1;
        if record.sequence != expected {
            return Err(invalid(format!(
                "authority log line {} has sequence {}, expected {expected}",
                index + 1,
                record.sequence
            )));
        }
        if !verify_record(record, authority_key) {
            return Err(invalid(format!(
                "authority log line {} does not verify against the authority key",
                index + 1
            )));
        }
        if record.prev != prev {
            return Err(invalid(format!(
                "authority log line {} does not chain to its predecessor",
                index + 1
            )));
        }
        prev = record_hash(record);
    }
    Ok(())
}

/// Compare the log with the head pinned beside the key. A log behind the pin
/// was truncated; a log whose record at the pinned sequence no longer hashes
/// to the pinned hash was replaced or rewritten, even when it has grown past
/// the pin; a missing log with a pinned head was deleted. All fail closed.
fn check_head(pinned: Option<&LogHead>, records: &[AuthorityRecord]) -> Result<()> {
    let Some(pinned) = pinned else {
        return Ok(());
    };
    let Some(head) = records.last().map(head_of) else {
        return Err(invalid(format!(
            "authority log is missing but a head at sequence {} is pinned",
            pinned.sequence
        )));
    };
    if head.sequence < pinned.sequence {
        return Err(invalid(format!(
            "authority log ends at sequence {} but the pinned head is {}: the log was truncated",
            head.sequence, pinned.sequence
        )));
    }
    // The chain is verified contiguous from sequence 1, so a log that reaches
    // the pinned sequence must still carry the pinned record byte for byte.
    let anchored = usize::try_from(pinned.sequence)
        .ok()
        .and_then(|sequence| sequence.checked_sub(1))
        .and_then(|index| records.get(index))
        .is_some_and(|record| record_hash(record) == pinned.hash);
    if !anchored {
        return Err(invalid(
            "authority log head differs from the pinned head: the log was replaced",
        ));
    }
    Ok(())
}

/// Load, verify, and fold the log. Refreshes the pinned head when the log is
/// ahead of it (an append crashed between the durable write and the pin), so
/// the pin only ever moves forward.
pub(super) fn load_policy(
    authority: &(impl Authority + ?Sized),
    root: &Path,
) -> Result<EffectivePolicy> {
    let key = authority.verifying_key()?;
    let records = read_records(&log_path(root))?;
    verify_chain(&records, &key)?;
    let head = records.last().map(head_of);
    let pinned = authority.pinned_head()?;
    check_head(pinned.as_ref(), &records)?;
    if let Some(head) = &head {
        if pinned.as_ref() != Some(head) {
            authority.pin_head(head)?;
        }
    }
    Ok(fold_records(&records, &key))
}

/// Presence-gated recovery: replace the backend's key material and pinned
/// head, then delete the stale root-scoped log. The backend call runs first
/// and owns the presence prompt, so a denial leaves the log untouched. Old
/// records can never be trusted afterwards: the new key does not verify them.
pub(super) fn reset(authority: &(impl Authority + ?Sized), root: &Path) -> Result<()> {
    authority.reset_credentials()?;
    // Serialize with appends so a concurrent sign cannot recreate the chain
    // between the credential reset and this deletion.
    std::fs::create_dir_all(root)?;
    let _lock = LockFile::acquire(root)?;
    match std::fs::remove_file(log_path(root)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Sign one decision and append it durably under the root lock. Presence is
/// the backend's gate inside `sign_bytes`; record bytes only exist once the
/// chain position is known, so the lock is held across the prompt.
pub(super) fn sign_and_append(
    authority: &(impl Authority + ?Sized),
    root: &Path,
    action: AuthorityAction,
    subject: &str,
    payload: &Value,
) -> Result<AuthorityRecord> {
    if subject.is_empty() {
        return Err(invalid("authority record subject is empty"));
    }
    if action == AuthorityAction::Unknown {
        return Err(invalid("unknown authority action"));
    }
    if !action.accepts_subject(subject) {
        return Err(invalid(format!(
            "authority record subject '{subject}' is not in the {action:?} namespace"
        )));
    }
    // Fail before prompting when no authority key exists.
    let key = authority.verifying_key()?;
    std::fs::create_dir_all(root)?;
    let _lock = LockFile::acquire(root)?;

    // Drop a torn line left by an interrupted append, so the record we add
    // starts on a clean line instead of merging into the fragment.
    truncate_torn_tail(&log_path(root))?;
    let records = read_records(&log_path(root))?;
    verify_chain(&records, &key)?;
    let head = records.last().map(head_of);
    check_head(authority.pinned_head()?.as_ref(), &records)?;

    let sequence = head.as_ref().map_or(1, |head| head.sequence + 1);
    let prev = head
        .as_ref()
        .map_or_else(|| GENESIS.to_string(), |head| head.hash.clone());
    let mut record = AuthorityRecord::unsigned(
        sequence,
        prev,
        now_rfc3339(),
        action,
        subject,
        payload,
        fingerprint_of(&B64.encode(key.as_bytes())),
    );
    record.signature = authority.sign_bytes(action, subject, &record.signing_bytes())?;

    // One write of one full line under the lock: no interleaving, no reused
    // sequence, and a torn tail is at worst one ignored final line.
    let line = format!(
        "{}\n",
        canonical_json(&serde_json::to_value(&record).expect("authority record is serializable"),)
    );
    fsutil::append_line(&log_path(root), &line)?;
    let head = head_of(&record);
    authority.pin_head(&head)?;
    authority.record_grant(&record.timestamp);
    Ok(record)
}

/// Cut an interrupted final append back to the last complete line. Only ever
/// called while holding the append lock.
fn truncate_torn_tail(path: &Path) -> Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Ok(());
    }
    let keep = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(keep as u64)?;
    file.sync_data()?;
    Ok(())
}

/// Exclusive cross-process append lock, released on drop.
struct LockFile(File);

impl LockFile {
    fn acquire(root: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path(root))?;
        file.lock()?;
        Ok(Self(file))
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{subject, InMemoryAuthority};
    use serde_json::json;
    use std::io::Write;

    fn authority() -> InMemoryAuthority {
        let authority = InMemoryAuthority::new();
        authority.init().unwrap();
        authority
    }

    fn sign(authority: &InMemoryAuthority, root: &Path, name: &str) -> AuthorityRecord {
        let subject = subject::allow(name);
        authority
            .sign_action(
                root,
                AuthorityAction::AllowAdd,
                &subject,
                &json!({ "subject": subject }),
            )
            .unwrap()
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn rewrite(path: &Path, lines: &[String]) {
        let mut text = String::new();
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn records_survive_a_new_backend_instance() {
        let root = tempfile::TempDir::new().unwrap();
        let first = authority();
        assert_eq!(sign(&first, root.path(), "alice").sequence, 1);

        // A second instance with the same key stands in for a new process.
        let second = InMemoryAuthority::with_signing_key(first.signing_key().unwrap());
        let allow_alice = subject::allow("alice");
        let policy = second.load_effective_policy(root.path()).unwrap();
        assert_eq!(
            policy.decisions[&allow_alice].action,
            AuthorityAction::AllowAdd
        );
        assert_eq!(policy.decisions[&allow_alice].sequence, 1);

        // Loading is stable, and the next record continues the sequence.
        assert_eq!(second.load_effective_policy(root.path()).unwrap(), policy);
        let next = second
            .sign_action(
                root.path(),
                AuthorityAction::AllowRemove,
                &allow_alice,
                &json!({ "name": "alice" }),
            )
            .unwrap();
        assert_eq!(next.sequence, 2);
        assert_eq!(
            second.load_effective_policy(root.path()).unwrap().decisions[&allow_alice].action,
            AuthorityAction::AllowRemove
        );
        assert_eq!(lines(&log_path(root.path())).len(), 2);
    }

    #[test]
    fn a_single_torn_tail_is_ignored_and_repaired_by_the_next_append() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        sign(&authority, root.path(), "bob");
        let path = log_path(root.path());

        // An interrupted append leaves a partial final line with no newline.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"version\":1,\"sequence\":3")
            .unwrap();

        let policy = authority.load_effective_policy(root.path()).unwrap();
        assert_eq!(policy.decisions.len(), 2);

        let third = sign(&authority, root.path(), "carol");
        assert_eq!(third.sequence, 3);
        assert_eq!(lines(&path).len(), 3);
        assert_eq!(
            authority
                .load_effective_policy(root.path())
                .unwrap()
                .decisions
                .len(),
            3
        );
    }

    #[test]
    fn legacy_unnamespaced_record_is_inert_and_re_adoption_applies() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        let key = authority.signing_key().unwrap();
        // A version-1 record from before the subject scheme: valid signature,
        // unnamespaced subject.
        let legacy = AuthorityRecord::sign(
            1,
            GENESIS,
            "2026-11-16T00:00:01Z".to_string(),
            AuthorityAction::AllowAdd,
            "alice",
            &json!({ "name": "alice" }),
            &key,
        );
        let line = canonical_json(&serde_json::to_value(&legacy).unwrap());
        std::fs::write(log_path(root.path()), format!("{line}\n")).unwrap();

        let policy = authority.load_effective_policy(root.path()).unwrap();
        assert!(
            policy.decisions.is_empty(),
            "an unnamespaced subject must be inert"
        );

        // Re-adoption appends the namespaced form after the legacy record; the
        // chain advances because the legacy record verified.
        let record = sign(&authority, root.path(), "alice");
        assert_eq!(record.sequence, 2);
        let allow_alice = subject::allow("alice");
        let policy = authority.load_effective_policy(root.path()).unwrap();
        assert_eq!(policy.decisions.len(), 1);
        assert_eq!(policy.decisions[&allow_alice].sequence, 2);
        assert!(!policy.decisions.contains_key("alice"));
    }

    #[test]
    fn a_corrupt_interior_line_fails_closed() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        sign(&authority, root.path(), "bob");
        let path = log_path(root.path());

        let mut retained = lines(&path);
        retained[0] = "not a record".into();
        rewrite(&path, &retained);

        let err = authority.load_effective_policy(root.path()).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)), "{err}");
        assert!(err.to_string().contains("corrupt"), "{err}");
    }

    #[test]
    fn a_tampered_record_fails_closed_instead_of_dropping_grants() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        sign(&authority, root.path(), "bob");
        let path = log_path(root.path());

        let mut retained = lines(&path);
        let mut value: serde_json::Value = serde_json::from_str(&retained[1]).unwrap();
        value["subject"] = "mallory".into();
        retained[1] = value.to_string();
        rewrite(&path, &retained);

        let err = authority.load_effective_policy(root.path()).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)), "{err}");
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn reordered_or_duplicated_records_fail_closed() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        sign(&authority, root.path(), "bob");
        let path = log_path(root.path());
        let original = lines(&path);

        let mut swapped = original.clone();
        swapped.swap(0, 1);
        rewrite(&path, &swapped);
        let err = authority.load_effective_policy(root.path()).unwrap_err();
        assert!(err.to_string().contains("sequence"), "{err}");

        rewrite(&path, &[original[0].clone(), original[0].clone()]);
        let err = authority.load_effective_policy(root.path()).unwrap_err();
        assert!(err.to_string().contains("sequence"), "{err}");
    }

    #[test]
    fn truncating_a_revocation_fails_closed() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        let revoke = authority
            .sign_action(
                root.path(),
                AuthorityAction::AllowRemove,
                &subject::allow("alice"),
                &json!({ "name": "alice" }),
            )
            .unwrap();
        assert_eq!(revoke.sequence, 2);
        let path = log_path(root.path());

        // Drop the revocation: the pinned head still remembers sequence 2.
        rewrite(&path, &lines(&path)[..1]);
        let err = authority.load_effective_policy(root.path()).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)), "{err}");
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn a_longer_log_with_a_divergent_prefix_fails_closed() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        let pinned = authority.pinned_head().unwrap();

        // A self-consistent replacement chain under the same key that has
        // grown past the pin: comparing heads alone would re-pin it.
        let other_root = tempfile::TempDir::new().unwrap();
        let other = InMemoryAuthority::with_signing_key(authority.signing_key().unwrap());
        sign(&other, other_root.path(), "mallory");
        sign(&other, other_root.path(), "eve");
        let replacement = lines(&log_path(other_root.path()));
        assert_eq!(replacement.len(), 2);
        rewrite(&log_path(root.path()), &replacement);

        let err = authority.load_effective_policy(root.path()).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)), "{err}");
        assert!(err.to_string().contains("replaced"), "{err}");
        assert_eq!(authority.pinned_head().unwrap(), pinned);
    }

    #[test]
    fn a_normal_append_advances_the_pinned_head() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        let first = sign(&authority, root.path(), "alice");
        let first_head = authority.pinned_head().unwrap().unwrap();
        assert_eq!(first_head.sequence, first.sequence);

        authority.load_effective_policy(root.path()).unwrap();
        let second = sign(&authority, root.path(), "bob");
        assert_eq!(second.sequence, first.sequence + 1);
        authority.load_effective_policy(root.path()).unwrap();

        let head = authority.pinned_head().unwrap().unwrap();
        assert_eq!(head.sequence, second.sequence);
        assert_ne!(head.hash, first_head.hash);
    }

    #[test]
    fn deleting_the_log_with_a_pinned_head_fails_closed() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        std::fs::remove_file(log_path(root.path())).unwrap();

        let err = authority.load_effective_policy(root.path()).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)), "{err}");
        assert!(err.to_string().contains("missing"), "{err}");
    }

    #[test]
    fn a_log_signed_by_another_key_fails_closed() {
        let root = tempfile::TempDir::new().unwrap();
        let first = authority();
        sign(&first, root.path(), "alice");

        let other_root = tempfile::TempDir::new().unwrap();
        let other = authority();
        sign(&other, other_root.path(), "mallory");
        std::fs::copy(log_path(other_root.path()), log_path(root.path())).unwrap();

        let err = first.load_effective_policy(root.path()).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)), "{err}");
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn concurrent_appends_get_unique_sequences_without_partial_lines() {
        let root = tempfile::TempDir::new().unwrap();
        let base = authority();
        let key = base.signing_key().unwrap();

        let writers: Vec<_> = (0..8)
            .map(|index| {
                let key = key.clone();
                let path = root.path().to_path_buf();
                std::thread::spawn(move || {
                    // One instance per writer: sequence ownership must come
                    // from the log, not from process memory.
                    let writer = InMemoryAuthority::with_signing_key(key);
                    writer
                        .sign_action(
                            &path,
                            AuthorityAction::AllowAdd,
                            &subject::allow(&format!("subject-{index}")),
                            &json!({ "index": index }),
                        )
                        .unwrap()
                        .sequence
                })
            })
            .collect();

        let mut sequences: Vec<u64> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=8).collect::<Vec<u64>>());

        let text = std::fs::read_to_string(log_path(root.path())).unwrap();
        assert!(text.ends_with('\n'));
        for line in text.lines() {
            serde_json::from_str::<AuthorityRecord>(line).expect("every line is a complete record");
        }
        assert_eq!(
            base.load_effective_policy(root.path())
                .unwrap()
                .decisions
                .len(),
            8
        );
    }

    #[test]
    fn reset_requires_presence_and_denial_writes_nothing() {
        let root = tempfile::TempDir::new().unwrap();
        let authority = authority();
        sign(&authority, root.path(), "alice");
        sign(&authority, root.path(), "bob");
        let log = std::fs::read(log_path(root.path())).unwrap();
        let pinned = authority.pinned_head().unwrap();
        let fingerprint = authority.status().unwrap().fingerprint;

        authority.deny_presence();
        let err = crate::service::Cmail::open(root.path())
            .unwrap()
            .reset_authority(&authority)
            .unwrap_err();
        assert!(matches!(err, CoreError::AuthorityRequired(_)), "{err}");
        assert_eq!(std::fs::read(log_path(root.path())).unwrap(), log);
        assert_eq!(authority.pinned_head().unwrap(), pinned);
        assert_eq!(authority.status().unwrap().fingerprint, fingerprint);
    }

    #[test]
    fn reset_clears_the_chain_and_a_new_process_loads_empty_policy() {
        let root = tempfile::TempDir::new().unwrap();
        let first = authority();
        let previous = first.signing_key().unwrap();
        sign(&first, root.path(), "alice");
        sign(&first, root.path(), "bob");
        let stale = std::fs::read(log_path(root.path())).unwrap();

        let status = crate::service::Cmail::open(root.path())
            .unwrap()
            .reset_authority(&first)
            .unwrap();
        assert!(status.available);
        assert!(first.pinned_head().unwrap().is_none());
        assert!(!log_path(root.path()).exists());
        let fresh = first.signing_key().unwrap();
        assert_ne!(fresh.verifying_key(), previous.verifying_key());

        // A new process holding only the fresh key sees an empty policy.
        let second = InMemoryAuthority::with_signing_key(fresh);
        assert!(second
            .load_effective_policy(root.path())
            .unwrap()
            .decisions
            .is_empty());

        // Records signed by the previous key are never trusted again.
        std::fs::write(log_path(root.path()), &stale).unwrap();
        let err = second.load_effective_policy(root.path()).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityInvalid(_)), "{err}");
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn reset_without_a_backend_writes_nothing() {
        let root = tempfile::TempDir::new().unwrap();
        let err = crate::authority::UnavailableAuthority
            .reset(root.path())
            .unwrap_err();
        assert!(matches!(err, CoreError::AuthorityUnavailable(_)), "{err}");
        assert!(!log_path(root.path()).exists());
    }
}
