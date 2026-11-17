//! One-time adoption of legacy root-local policy into signed authority records.
//!
//! Legacy `keyring.json`, `config.toml`, and held-approval files are read only
//! here. Enforcement tickets consume the resulting signed records; this module
//! does not change live policy reads.

use crate::authority::{subject, Authority, AuthorityAction, AuthorityRecord};
use crate::config::{Config, InboundMode, OutboundMode};
use crate::error::Result;
use crate::identity::fingerprint_of;
use crate::keyring::KeyRing;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

/// Subject for a keyring grant: `key:<name>:<public-key>`. The public key is
/// carried in the subject so consumers recover the effective keyring without
/// trusting an unsigned cache.
pub fn key_subject(name: &str, public_key: &str) -> String {
    subject::key(name, public_key)
}

/// One legacy keyring entry, as shown to the human before signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyKey {
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub route: Option<String>,
}

/// One held outbound message, as shown to the human before signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyApproval {
    pub id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub created: String,
}

/// One legacy quarantine release, shown with the sender and subject so the
/// human signs what was actually quarantined rather than an audit-line id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyQuarantine {
    pub id: String,
    pub from: String,
    pub subject: String,
}

/// Everything adoption will bless, before any signature is requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacySnapshot {
    pub keyring: Vec<LegacyKey>,
    pub allow: Vec<String>,
    pub relay_url: Option<String>,
    pub outbound_mode: OutboundMode,
    pub inbound_mode: InboundMode,
    pub approvals: Vec<LegacyApproval>,
    /// Quarantined messages a pre-enforcement build recorded as released.
    /// The audit log is unsigned and non-authoritative; these ids become
    /// signed decisions only when the human confirms adoption, and only when
    /// a quarantined or archived copy still exists.
    #[serde(default)]
    pub quarantine_releases: Vec<LegacyQuarantine>,
}

impl LegacySnapshot {
    pub fn is_empty(&self) -> bool {
        self.keyring.is_empty()
            && self.allow.is_empty()
            && self.relay_url.is_none()
            && self.approvals.is_empty()
            && self.outbound_mode == OutboundMode::Gated
            && self.inbound_mode == InboundMode::Permissive
            && self.quarantine_releases.is_empty()
    }
}

/// One record that adoption will sign, with the human-readable diff line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdoptionEntry {
    pub action: AuthorityAction,
    pub subject: String,
    pub payload: Value,
    pub summary: String,
}

/// The adoption diff: entries not yet covered by a valid record, and entries
/// already settled by a previous adoption or later revocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdoptionPlan {
    pub legacy: LegacySnapshot,
    pub pending: Vec<AdoptionEntry>,
    pub already_adopted: Vec<AdoptionEntry>,
}

impl AdoptionPlan {
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// True before the first adoption of legacy state: nothing has a record yet.
    pub fn first_adoption(&self) -> bool {
        self.already_adopted.is_empty() && !self.legacy.is_empty()
    }
}

/// Result of a (possibly declined) adoption.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdoptionOutcome {
    pub plan: AdoptionPlan,
    pub signed: Vec<AuthorityRecord>,
}

/// Read legacy state and diff it against the effective signed policy.
///
/// `approvals` comes from the service layer because held files are mailbox
/// state, not policy state.
pub fn plan(
    root: &Path,
    authority: &dyn Authority,
    approvals: Vec<LegacyApproval>,
) -> Result<AdoptionPlan> {
    let config = Config::load_or_init(root)?;
    let keyring = KeyRing::load(root)?;
    let legacy = LegacySnapshot {
        keyring: keyring
            .list()
            .into_iter()
            .map(|(name, entry)| LegacyKey {
                fingerprint: fingerprint_of(&entry.public_key),
                name,
                public_key: entry.public_key,
                route: entry.route,
            })
            .collect(),
        allow: config.allow.send.clone(),
        relay_url: config.relay.url.clone().filter(|url| !url.is_empty()),
        outbound_mode: config.outbound,
        inbound_mode: config.inbound,
        approvals,
        quarantine_releases: legacy_quarantine_releases(root)?,
    };
    let policy = authority.load_effective_policy(root)?;
    let (pending, already_adopted) = proposals(&legacy)
        .into_iter()
        .partition(|entry| !policy.decisions.contains_key(&entry.subject));
    Ok(AdoptionPlan {
        legacy,
        pending,
        already_adopted,
    })
}

/// Sign every pending entry when confirmed. Declining never asks for a
/// signature and never writes a record.
pub fn apply(
    root: &Path,
    authority: &dyn Authority,
    plan: AdoptionPlan,
    confirmed: bool,
) -> Result<AdoptionOutcome> {
    let mut signed = Vec::new();
    if confirmed {
        for entry in &plan.pending {
            signed.push(authority.sign_action(
                root,
                entry.action,
                &entry.subject,
                &entry.payload,
            )?);
        }
    }
    Ok(AdoptionOutcome { plan, signed })
}

fn proposals(legacy: &LegacySnapshot) -> Vec<AdoptionEntry> {
    let mut entries = Vec::new();
    for key in &legacy.keyring {
        entries.push(AdoptionEntry {
            action: AuthorityAction::KeyAdd,
            subject: key_subject(&key.name, &key.public_key),
            payload: json!({ "name": key.name, "public_key": key.public_key }),
            summary: format!("keyring add {} ({})", key.name, key.fingerprint),
        });
    }
    for name in &legacy.allow {
        entries.push(AdoptionEntry {
            action: AuthorityAction::AllowAdd,
            subject: subject::allow(name),
            payload: json!({ "name": name }),
            summary: format!("allow add {name}"),
        });
    }
    if let Some(url) = &legacy.relay_url {
        entries.push(AdoptionEntry {
            action: AuthorityAction::RelaySet,
            subject: subject::RELAY.to_string(),
            payload: json!({ "url": url }),
            summary: format!("relay set {url}"),
        });
    }
    // Modes are signed so an upgrade cannot silently loosen the gate: a
    // pre-enforcement `known-only` config becomes a `mode:inbound` record.
    entries.push(AdoptionEntry {
        action: AuthorityAction::OutboundMode,
        subject: subject::OUTBOUND_MODE.to_string(),
        payload: json!({ "mode": legacy.outbound_mode }),
        summary: format!(
            "outbound mode {}",
            match legacy.outbound_mode {
                OutboundMode::Gated => "gated",
                OutboundMode::Open => "open",
            }
        ),
    });
    entries.push(AdoptionEntry {
        action: AuthorityAction::InboundMode,
        subject: subject::INBOUND_MODE.to_string(),
        payload: json!({ "mode": legacy.inbound_mode }),
        summary: format!(
            "inbound mode {}",
            match legacy.inbound_mode {
                InboundMode::Permissive => "permissive",
                InboundMode::KnownOnly => "known-only",
            }
        ),
    });
    for approval in &legacy.approvals {
        entries.push(AdoptionEntry {
            action: AuthorityAction::Approve,
            subject: subject::approval(&approval.id),
            payload: json!({ "id": approval.id }),
            summary: format!(
                "approve {} ({} -> {}: {})",
                approval.id, approval.from, approval.to, approval.subject
            ),
        });
    }
    for release in &legacy.quarantine_releases {
        entries.push(AdoptionEntry {
            action: AuthorityAction::QuarantineRelease,
            subject: subject::quarantine(&release.id),
            payload: json!({ "message_id": release.id }),
            summary: format!(
                "release quarantine {} (from {}: {})",
                release.id, release.from, release.subject
            ),
        });
    }
    entries
}

/// Quarantined messages with a legacy `quarantine_release` audit event, in
/// log order and deduplicated. Only an id whose quarantined or archived copy
/// still exists is proposed: the audit log alone cannot name mail to release.
/// Lossy: a malformed line is skipped rather than failing adoption, and a
/// skipped release stays locked (fail closed). An unparseable copy is still
/// proposed, with its sender and subject marked unknown.
fn legacy_quarantine_releases(root: &Path) -> Result<Vec<LegacyQuarantine>> {
    let store = crate::store::MailStore::new(root);
    let identities = crate::identity::list_identities(root);
    let mut seen = std::collections::HashSet::new();
    let mut releases = Vec::new();
    for record in crate::audit::tail_lossy(root, usize::MAX)? {
        if record.event != crate::audit::AuditEvent::QuarantineRelease {
            continue;
        }
        let Some(id) = record.msg_id else {
            continue;
        };
        if seen.contains(&id) {
            continue;
        }
        let Some((from, subject)) = quarantined_metadata(&store, &identities, &id) else {
            continue;
        };
        seen.insert(id.clone());
        releases.push(LegacyQuarantine { id, from, subject });
    }
    Ok(releases)
}

/// Sender and display subject of an existing quarantined or archived copy.
fn quarantined_metadata(
    store: &crate::store::MailStore,
    identities: &[String],
    id: &str,
) -> Option<(String, String)> {
    for owner in identities {
        for dir in [store.quarantine_dir(owner), store.archive_dir(owner)] {
            let Ok(raw) = store.read_raw(&dir, id) else {
                continue;
            };
            return Some(match crate::envelope::Envelope::parse(&raw) {
                Ok(env) => (env.from.clone(), env.subject_label().to_string()),
                Err(_) => ("<unparseable>".into(), "<unparseable>".into()),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        AuthorityStatus, InMemoryAuthority, UnavailableAuthority, RECORD_VERSION,
    };
    use crate::error::CoreError;
    use crate::service::{Cmail, InitOutcome, SendOutcome};
    use tempfile::TempDir;

    fn legacy_service() -> (TempDir, Cmail) {
        let root = TempDir::new().unwrap();
        let authority = std::sync::Arc::new(InMemoryAuthority::new());
        authority.init().unwrap();
        let c = Cmail::open_with_authority(root.path(), authority).unwrap();
        assert_eq!(c.init("alice", false).unwrap(), InitOutcome::Created);
        assert_eq!(c.init("zoe", false).unwrap(), InitOutcome::Created);
        // Hold one outbound message before allowlisting the recipient.
        assert!(matches!(
            c.send(Some("alice"), "zoe", "note", "s", "held", &[], None)
                .unwrap(),
            SendOutcome::Held { .. }
        ));
        // Unsigned legacy keyring and config allowlist, as a pre-enforcement
        // install has them. Written directly: allow_add now signs, and this
        // fixture must model the unsigned state adoption migrates.
        let alice = crate::identity::load_identity(root.path(), "alice").unwrap();
        let mut legacy = crate::keyring::KeyRing::load(root.path()).unwrap();
        legacy.add("alice", &alice.public_key_b64()).unwrap();
        legacy.save(root.path()).unwrap();
        let mut cfg = crate::config::Config::load_or_init(root.path()).unwrap();
        cfg.allow.send.push("zoe".into());
        // A pre-enforcement install hand-edited its relay in config; that
        // legacy value is what adoption blesses.
        cfg.relay.url = Some("https://relay.example.com".into());
        cfg.save(root.path()).unwrap();
        (root, c)
    }

    fn authority() -> InMemoryAuthority {
        let authority = InMemoryAuthority::new();
        authority.init().unwrap();
        authority
    }

    fn alice_key(c: &Cmail) -> String {
        crate::identity::load_identity(&c.root, "alice")
            .unwrap()
            .public_key_b64()
    }

    #[test]
    fn plan_shows_every_legacy_entry() {
        let (_root, c) = legacy_service();
        let plan = c.adoption_plan(&authority()).unwrap();

        assert!(plan.first_adoption());
        assert!(plan.already_adopted.is_empty());
        assert_eq!(plan.pending.len(), 6);

        let key = alice_key(&c);
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::KeyAdd
                && e.subject == key_subject("alice", &key)
                && e.payload["public_key"] == key
        }));
        assert!(plan
            .pending
            .iter()
            .any(|e| e.action == AuthorityAction::AllowAdd && e.subject == subject::allow("zoe")));
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::RelaySet
                && e.subject == subject::RELAY
                && e.payload["url"] == "https://relay.example.com"
                && e.summary.contains("https://relay.example.com")
        }));
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::OutboundMode
                && e.subject == subject::OUTBOUND_MODE
                && e.payload["mode"] == "gated"
                && e.summary.contains("outbound mode gated")
        }));
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::InboundMode
                && e.subject == subject::INBOUND_MODE
                && e.payload["mode"] == "permissive"
                && e.summary.contains("inbound mode permissive")
        }));
        let held = c.approvals(None).unwrap();
        assert_eq!(held.len(), 1);
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::Approve && e.subject == subject::approval(&held[0].id)
        }));
    }

    #[test]
    fn declining_writes_nothing() {
        let (root, c) = legacy_service();
        let keyring = std::fs::read(root.path().join("keyring.json")).unwrap();
        let config = std::fs::read(root.path().join("config.toml")).unwrap();
        let authority = authority();
        let outcome = c.adopt_legacy(&authority, false).unwrap();

        assert!(outcome.signed.is_empty());
        assert_eq!(outcome.plan.pending.len(), 6);
        assert!(authority
            .load_effective_policy(root.path())
            .unwrap()
            .decisions
            .is_empty());
        assert!(authority.status().unwrap().last_grant.is_none());
        assert_eq!(
            std::fs::read(root.path().join("keyring.json")).unwrap(),
            keyring
        );
        assert_eq!(
            std::fs::read(root.path().join("config.toml")).unwrap(),
            config
        );
    }

    #[test]
    fn confirming_signs_one_batch_visible_in_status() {
        let (root, c) = legacy_service();
        let authority = authority();
        let key = alice_key(&c);
        let outcome = c.adopt_legacy(&authority, true).unwrap();

        assert_eq!(outcome.signed.len(), 6);
        assert_eq!(outcome.signed[0].version, RECORD_VERSION);
        let policy = authority.load_effective_policy(root.path()).unwrap();
        assert_eq!(policy.decisions.len(), 6);
        assert_eq!(
            policy.decisions[&key_subject("alice", &key)].action,
            AuthorityAction::KeyAdd
        );
        assert_eq!(
            policy.decisions[&subject::allow("zoe")].action,
            AuthorityAction::AllowAdd
        );
        assert_eq!(
            policy.decisions[subject::RELAY].action,
            AuthorityAction::RelaySet
        );
        assert_eq!(
            policy.decisions[subject::RELAY].payload.as_ref().unwrap()["url"],
            "https://relay.example.com"
        );
        let held = c.approvals(None).unwrap();
        assert_eq!(
            policy.decisions[&subject::approval(&held[0].id)].action,
            AuthorityAction::Approve
        );
        assert!(authority.status().unwrap().last_grant.is_some());
    }

    #[test]
    fn adopts_legacy_known_only_inbound_mode_and_restores_it() {
        let (root, c) = legacy_service();
        let mut cfg = Config::load_or_init(root.path()).unwrap();
        cfg.inbound = InboundMode::KnownOnly;
        cfg.save(root.path()).unwrap();

        let authority = authority();
        let plan = c.adoption_plan(&authority).unwrap();
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::InboundMode
                && e.subject == subject::INBOUND_MODE
                && e.payload["mode"] == "known-only"
                && e.summary.contains("inbound mode known-only")
        }));
        let outcome = c.adopt_legacy(&authority, true).unwrap();
        assert_eq!(outcome.signed.len(), 6);

        // A fresh verifier sees the signed known-only record, so the upgrade
        // cannot silently return to permissive.
        let restart = std::sync::Arc::new(InMemoryAuthority::with_signing_key(
            authority.signing_key().unwrap(),
        ));
        let policy = crate::policy::Policy::load(root.path(), restart).unwrap();
        assert_eq!(policy.inbound_mode(), InboundMode::KnownOnly);
        assert_eq!(policy.outbound_mode().unwrap(), Some(OutboundMode::Gated));

        // Re-adoption is idempotent: every mode record is already settled.
        let second = c.adoption_plan(&authority).unwrap();
        assert!(second.pending.is_empty());
    }

    #[test]
    fn second_adoption_is_idempotent() {
        let (root, c) = legacy_service();
        let authority = authority();
        let first = c.adopt_legacy(&authority, true).unwrap();
        let records = first.signed.len();
        let policy = authority.load_effective_policy(root.path()).unwrap();

        let second = c.adopt_legacy(&authority, true).unwrap();
        assert!(second.signed.is_empty());
        assert!(second.plan.pending.is_empty());
        assert_eq!(second.plan.already_adopted.len(), records);
        assert!(!second.plan.first_adoption());
        assert_eq!(
            authority
                .load_effective_policy(root.path())
                .unwrap()
                .decisions
                .len(),
            policy.decisions.len()
        );
    }

    #[test]
    fn adopted_state_survives_a_new_authority_instance() {
        let (root, c) = legacy_service();
        let first = authority();
        let outcome = c.adopt_legacy(&first, true).unwrap();
        assert_eq!(outcome.signed.len(), 6);

        // A new process: same key, fresh in-memory state, records only on disk.
        let second = InMemoryAuthority::with_signing_key(first.signing_key().unwrap());
        let plan = c.adoption_plan(&second).unwrap();
        assert!(plan.pending.is_empty());
        assert_eq!(plan.already_adopted.len(), outcome.signed.len());
        assert!(!plan.first_adoption());

        let policy = second.load_effective_policy(root.path()).unwrap();
        assert_eq!(policy.decisions.len(), outcome.signed.len());
        assert_eq!(
            policy.decisions[&subject::allow("zoe")].action,
            AuthorityAction::AllowAdd
        );
    }

    /// Put a readable alice -> zoe message in zoe's quarantine, so a legacy
    /// release has a real file and visible metadata behind it.
    fn quarantined_message(c: &Cmail) -> String {
        let alice = crate::identity::load_identity(&c.root, "alice").unwrap();
        let id = "cafebabecafebabecafebabecafebabe";
        let env = crate::envelope::build_and_sign(
            id,
            &crate::envelope::NewEnvelope {
                from: "alice".into(),
                from_key: alice.public_key_b64(),
                to: "zoe".into(),
                kind: "note".into(),
                subject: "legacy quarantine".into(),
                body: "b".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            &alice.signing,
        )
        .unwrap();
        c.store
            .write_envelope(&c.store.quarantine_dir("zoe"), &env)
            .unwrap();
        id.to_string()
    }

    fn legacy_release(root: &Path, id: &str) {
        crate::audit::append(
            root,
            &crate::audit::AuditRecord::now(crate::audit::AuditEvent::QuarantineRelease, "human")
                .msg(id),
        )
        .unwrap();
    }

    #[test]
    fn legacy_quarantine_releases_are_adopted_once() {
        let (root, c) = legacy_service();
        let id = quarantined_message(&c);
        // A pre-enforcement build wrote only unsigned audit events (twice).
        legacy_release(root.path(), &id);
        legacy_release(root.path(), &id);
        let authority = authority();
        let plan = c.adoption_plan(&authority).unwrap();
        assert_eq!(
            plan.legacy.quarantine_releases,
            vec![LegacyQuarantine {
                id: id.clone(),
                from: "alice".into(),
                subject: "legacy quarantine".into(),
            }]
        );
        let releases: Vec<_> = plan
            .pending
            .iter()
            .filter(|entry| entry.action == AuthorityAction::QuarantineRelease)
            .collect();
        assert_eq!(releases.len(), 1, "duplicate audit events collapse");
        assert_eq!(releases[0].subject, subject::quarantine(&id));
        assert!(
            releases[0]
                .summary
                .contains("from alice: legacy quarantine"),
            "summary names the quarantined mail: {}",
            releases[0].summary
        );

        // Declining leaves the legacy release unsigned (still locked).
        let declined = c.adopt_legacy(&authority, false).unwrap();
        assert!(declined.signed.is_empty());
        let policy = authority.load_effective_policy(root.path()).unwrap();
        assert!(!policy.decisions.contains_key(&subject::quarantine(&id)));

        // Confirming signs the release in the same batch.
        let adopted = c.adopt_legacy(&authority, true).unwrap();
        assert!(adopted.signed.iter().any(|record| {
            record.action == AuthorityAction::QuarantineRelease
                && record.subject == subject::quarantine(&id)
        }));
        let policy = authority.load_effective_policy(root.path()).unwrap();
        assert_eq!(
            policy.decisions[&subject::quarantine(&id)].action,
            AuthorityAction::QuarantineRelease
        );

        // Re-adoption is idempotent: no duplicate record for the same id.
        let again = c.adopt_legacy(&authority, true).unwrap();
        assert!(again.plan.pending.is_empty());
        assert!(again.signed.is_empty());
        assert_eq!(
            again
                .plan
                .already_adopted
                .iter()
                .filter(|entry| entry.subject == subject::quarantine(&id))
                .count(),
            1
        );
    }

    /// An appended audit line alone must not become a human-signed release:
    /// with no quarantined or archived copy, nothing is proposed.
    #[test]
    fn audit_release_without_a_quarantined_file_is_not_proposed() {
        let (root, c) = legacy_service();
        let bogus = "deadbeefdeadbeefdeadbeefdeadbeef";
        legacy_release(root.path(), bogus);

        let authority = authority();
        let plan = c.adoption_plan(&authority).unwrap();
        assert!(plan.legacy.quarantine_releases.is_empty());
        assert!(!plan
            .pending
            .iter()
            .any(|entry| entry.action == AuthorityAction::QuarantineRelease));

        let adopted = c.adopt_legacy(&authority, true).unwrap();
        assert!(!adopted
            .signed
            .iter()
            .any(|record| { record.action == AuthorityAction::QuarantineRelease }));
    }

    #[test]
    fn unavailable_backend_fails_closed() {
        let (_root, c) = legacy_service();
        let err = c.adoption_plan(&UnavailableAuthority).unwrap_err();
        assert!(matches!(err, CoreError::AuthorityUnavailable(_)));
        let status: AuthorityStatus = UnavailableAuthority.status().unwrap();
        assert!(!status.available);
    }
}
