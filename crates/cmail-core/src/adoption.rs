//! One-time adoption of legacy root-local policy into signed authority records.
//!
//! Legacy `keyring.json`, `config.toml`, and held-approval files are read only
//! here. Enforcement tickets consume the resulting signed records; this module
//! does not change live policy reads.

use crate::authority::{Authority, AuthorityAction, AuthorityRecord};
use crate::config::Config;
use crate::error::Result;
use crate::identity::fingerprint_of;
use crate::keyring::KeyRing;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

/// Subject for a keyring grant. Records store only a payload digest, so the
/// public key is carried in the subject; consumers recover the effective
/// keyring from `name:public_key` pairs.
pub fn key_subject(name: &str, public_key: &str) -> String {
    format!("{name}:{public_key}")
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

/// Everything adoption will bless, before any signature is requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacySnapshot {
    pub keyring: Vec<LegacyKey>,
    pub allow: Vec<String>,
    pub relay_url: Option<String>,
    pub approvals: Vec<LegacyApproval>,
}

impl LegacySnapshot {
    pub fn is_empty(&self) -> bool {
        self.keyring.is_empty()
            && self.allow.is_empty()
            && self.relay_url.is_none()
            && self.approvals.is_empty()
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
        approvals,
    };
    let policy = authority.load_effective_policy()?;
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
    authority: &dyn Authority,
    plan: AdoptionPlan,
    confirmed: bool,
) -> Result<AdoptionOutcome> {
    let mut signed = Vec::new();
    if confirmed {
        for entry in &plan.pending {
            signed.push(authority.sign_action(entry.action, &entry.subject, &entry.payload)?);
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
            subject: name.clone(),
            payload: json!({ "name": name }),
            summary: format!("allow add {name}"),
        });
    }
    if let Some(url) = &legacy.relay_url {
        entries.push(AdoptionEntry {
            action: AuthorityAction::RelaySet,
            subject: url.clone(),
            payload: json!({ "url": url }),
            summary: format!("relay set {url}"),
        });
    }
    for approval in &legacy.approvals {
        entries.push(AdoptionEntry {
            action: AuthorityAction::Approve,
            subject: approval.id.clone(),
            payload: json!({ "id": approval.id }),
            summary: format!(
                "approve {} ({} -> {}: {})",
                approval.id, approval.from, approval.to, approval.subject
            ),
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        AuthorityStatus, InMemoryAuthority, UnavailableAuthority, RECORD_VERSION,
    };
    use crate::error::CoreError;
    use crate::service::KeySource;
    use crate::service::{Cmail, InitOutcome, SendOutcome};
    use tempfile::TempDir;

    fn legacy_service() -> (TempDir, Cmail) {
        let root = TempDir::new().unwrap();
        let c = Cmail::open(root.path()).unwrap();
        assert_eq!(c.init("alice", false).unwrap(), InitOutcome::Created);
        assert_eq!(c.init("zoe", false).unwrap(), InitOutcome::Created);
        // Hold one outbound message before allowlisting the recipient.
        assert!(matches!(
            c.send(Some("alice"), "zoe", "note", "s", "held", &[], None)
                .unwrap(),
            SendOutcome::Held { .. }
        ));
        c.keyring_add("alice", KeySource::LocalIdentity).unwrap();
        c.allow_add("zoe").unwrap();
        c.relay_set(Some("https://relay.example.com")).unwrap();
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
        assert_eq!(plan.pending.len(), 4);

        let key = alice_key(&c);
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::KeyAdd
                && e.subject == key_subject("alice", &key)
                && e.payload["public_key"] == key
        }));
        assert!(plan
            .pending
            .iter()
            .any(|e| e.action == AuthorityAction::AllowAdd && e.subject == "zoe"));
        assert!(plan.pending.iter().any(|e| {
            e.action == AuthorityAction::RelaySet
                && e.subject == "https://relay.example.com"
                && e.summary.contains("https://relay.example.com")
        }));
        let held = c.approvals(None).unwrap();
        assert_eq!(held.len(), 1);
        assert!(plan
            .pending
            .iter()
            .any(|e| { e.action == AuthorityAction::Approve && e.subject == held[0].id }));
    }

    #[test]
    fn declining_writes_nothing() {
        let (root, c) = legacy_service();
        let keyring = std::fs::read(root.path().join("keyring.json")).unwrap();
        let config = std::fs::read(root.path().join("config.toml")).unwrap();
        let authority = authority();
        let outcome = c.adopt_legacy(&authority, false).unwrap();

        assert!(outcome.signed.is_empty());
        assert_eq!(outcome.plan.pending.len(), 4);
        assert!(authority
            .load_effective_policy()
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
        let (_root, c) = legacy_service();
        let authority = authority();
        let key = alice_key(&c);
        let outcome = c.adopt_legacy(&authority, true).unwrap();

        assert_eq!(outcome.signed.len(), 4);
        assert_eq!(outcome.signed[0].version, RECORD_VERSION);
        let policy = authority.load_effective_policy().unwrap();
        assert_eq!(policy.decisions.len(), 4);
        assert_eq!(
            policy.decisions[&key_subject("alice", &key)].action,
            AuthorityAction::KeyAdd
        );
        assert_eq!(policy.decisions["zoe"].action, AuthorityAction::AllowAdd);
        assert_eq!(
            policy.decisions["https://relay.example.com"].action,
            AuthorityAction::RelaySet
        );
        let held = c.approvals(None).unwrap();
        assert_eq!(
            policy.decisions[&held[0].id].action,
            AuthorityAction::Approve
        );
        assert!(authority.status().unwrap().last_grant.is_some());
    }

    #[test]
    fn second_adoption_is_idempotent() {
        let (_root, c) = legacy_service();
        let authority = authority();
        let first = c.adopt_legacy(&authority, true).unwrap();
        let records = first.signed.len();
        let policy = authority.load_effective_policy().unwrap();

        let second = c.adopt_legacy(&authority, true).unwrap();
        assert!(second.signed.is_empty());
        assert!(second.plan.pending.is_empty());
        assert_eq!(second.plan.already_adopted.len(), records);
        assert!(!second.plan.first_adoption());
        assert_eq!(
            authority.load_effective_policy().unwrap().decisions.len(),
            policy.decisions.len()
        );
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
