use crate::authority::{AuthorityAction, EffectivePolicy};
use crate::error::{CoreError, Result};
use crate::identity::{fingerprint_of, now_rfc3339};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyEntry {
    pub public_key: String,
    pub first_seen: String,
    /// Relay base URL routing hint (spec §3.1): where mail for this name is
    /// deposited when no local identity exists. Pure routing — never affects
    /// trust. Absent in v0.2 keyrings; skipped on save when unset so old
    /// files round-trip byte-stably.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KeyRing {
    #[serde(flatten)]
    entries: BTreeMap<String, KeyEntry>,
}

impl KeyRing {
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join("keyring.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let path = root.join("keyring.json");
        crate::fsutil::write_durable(&path, serde_json::to_string_pretty(self)?.as_bytes())
    }

    pub fn get(&self, name: &str) -> Option<&KeyEntry> {
        self.entries.get(name)
    }

    pub fn add(&mut self, name: &str, public_key: &str) -> Result<()> {
        match self.entries.get(name) {
            Some(existing) if existing.public_key == public_key => Ok(()),
            Some(existing) => Err(CoreError::Config(format!(
                "keyring already has a different key for '{name}' ({}); remove it first",
                fingerprint_of(&existing.public_key)
            ))),
            None => {
                self.entries.insert(
                    name.to_string(),
                    KeyEntry {
                        public_key: public_key.to_string(),
                        first_seen: now_rfc3339(),
                        route: None,
                    },
                );
                Ok(())
            }
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    /// Set (`Some`) or clear (`None`) the relay route on an existing entry.
    /// Errors on an unknown name: routes attach to known keys only.
    pub fn set_route(&mut self, name: &str, url: Option<&str>) -> Result<()> {
        match self.entries.get_mut(name) {
            Some(entry) => {
                entry.route = url.map(str::to_string);
                Ok(())
            }
            None => Err(CoreError::Config(format!(
                "keyring has no entry for '{name}'; add it first (cmail keyring add)"
            ))),
        }
    }

    /// The entry's relay route, if any (None for unknown names and unset routes).
    pub fn get_route(&self, name: &str) -> Option<String> {
        self.entries.get(name).and_then(|e| e.route.clone())
    }

    pub fn list(&self) -> Vec<(String, KeyEntry)> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Split a signed key subject (`name:public_key`) into its parts.
    pub fn split_key_subject(subject: &str) -> Option<(&str, &str)> {
        let (name, public_key) = subject.split_once(':')?;
        (!name.is_empty() && !public_key.is_empty()).then_some((name, public_key))
    }

    /// Public keys currently granted to `name` by the latest signed decision
    /// per subject. A later `KeyRemove` at the same subject supersedes the
    /// grant, so revocations are simply absent. Used to revoke every live
    /// subject on rotation or `keyring remove`.
    pub fn granted_keys(policy: &EffectivePolicy, name: &str) -> Vec<String> {
        let mut keys = BTreeSet::new();
        for (subject, decision) in &policy.decisions {
            if decision.action != AuthorityAction::KeyAdd {
                continue;
            }
            if let Some((subject_name, public_key)) = Self::split_key_subject(subject) {
                if subject_name == name {
                    keys.insert(public_key.to_string());
                }
            }
        }
        keys.into_iter().collect()
    }

    /// The effective trust keyring: names granted by a latest signed
    /// `KeyAdd`, and nothing else. Unsigned, wrong-key, and replayed records
    /// never reach the fold. A name with two live keys is dropped (fail
    /// closed) rather than silently trusting either.
    pub fn from_decisions(policy: &EffectivePolicy) -> Self {
        let mut grants: BTreeMap<String, Vec<(&str, &str)>> = BTreeMap::new();
        for (subject, decision) in &policy.decisions {
            if decision.action != AuthorityAction::KeyAdd {
                continue;
            }
            if let Some((name, public_key)) = Self::split_key_subject(subject) {
                grants
                    .entry(name.to_string())
                    .or_default()
                    .push((public_key, decision.timestamp.as_str()));
            }
        }
        let mut keyring = Self::default();
        for (name, keys) in grants {
            if keys.len() != 1 {
                continue;
            }
            let (public_key, first_seen) = keys[0];
            keyring.entries.insert(
                name,
                KeyEntry {
                    public_key: public_key.to_string(),
                    first_seen: first_seen.to_string(),
                    route: None,
                },
            );
        }
        keyring
    }

    /// Copy relay routes from the legacy keyring file. Routes are pure
    /// routing: they never grant trust, so this cannot resurrect an entry.
    pub fn overlay_routes(&mut self, routes: &KeyRing) {
        for (name, entry) in &mut self.entries {
            if let Some(legacy) = routes.get(name) {
                entry.route = legacy.route.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::PolicyDecision;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn decision(action: AuthorityAction, sequence: u64) -> PolicyDecision {
        PolicyDecision {
            action,
            sequence,
            timestamp: format!("2026-11-01T00:00:0{sequence}Z"),
        }
    }

    #[test]
    fn effective_keyring_takes_latest_grant_and_revocation_wins() {
        let mut decisions = BTreeMap::new();
        decisions.insert(
            "alice:a2V5".to_string(),
            decision(AuthorityAction::KeyAdd, 1),
        );
        let policy = EffectivePolicy { decisions };
        let effective = KeyRing::from_decisions(&policy);
        assert_eq!(effective.get("alice").unwrap().public_key, "a2V5");
        assert_eq!(
            KeyRing::granted_keys(&policy, "alice"),
            vec!["a2V5".to_string()]
        );

        // A later KeyRemove at the same subject supersedes the grant.
        let mut decisions = BTreeMap::new();
        decisions.insert(
            "alice:a2V5".to_string(),
            decision(AuthorityAction::KeyRemove, 2),
        );
        let policy = EffectivePolicy { decisions };
        assert!(KeyRing::from_decisions(&policy).get("alice").is_none());
        assert!(KeyRing::granted_keys(&policy, "alice").is_empty());
    }

    #[test]
    fn ambiguous_live_keys_drop_the_name_instead_of_dual_trust() {
        let mut decisions = BTreeMap::new();
        decisions.insert(
            "alice:a2V5".to_string(),
            decision(AuthorityAction::KeyAdd, 1),
        );
        decisions.insert(
            "alice:b2V5".to_string(),
            decision(AuthorityAction::KeyAdd, 2),
        );
        let effective = KeyRing::from_decisions(&EffectivePolicy { decisions });
        assert!(
            effective.get("alice").is_none(),
            "two live keys must never both verify"
        );
    }

    #[test]
    fn add_get_persist_round_trip() {
        let root = TempDir::new().unwrap();
        let mut kr = KeyRing::load(root.path()).unwrap();
        assert!(kr.get("alice").is_none());
        kr.add("alice", "a2V5").unwrap();
        kr.save(root.path()).unwrap();
        let reloaded = KeyRing::load(root.path()).unwrap();
        assert_eq!(reloaded.get("alice").unwrap().public_key, "a2V5");
        assert!(
            reloaded.get("alice").unwrap().first_seen.ends_with('Z')
                || reloaded.get("alice").unwrap().first_seen.contains("+00:00")
        );
    }

    #[test]
    fn conflicting_key_rejected_identical_ok() {
        let mut kr = KeyRing::default();
        kr.add("alice", "a2V5").unwrap();
        assert!(kr.add("alice", "b2V5").is_err());
        assert!(kr.add("alice", "a2V5").is_ok());
    }

    #[test]
    fn conflict_error_names_the_existing_fingerprint() {
        let mut kr = KeyRing::default();
        kr.add("alice", "YWxpY2VrZXk=").unwrap();
        let err = kr.add("alice", "bWFsbG9yeWtleQ==").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("different key"), "{msg}");
        assert!(
            msg.contains(&fingerprint_of("YWxpY2VrZXk=")),
            "must name the EXISTING key: {msg}"
        );
    }

    #[test]
    fn remove_reports_existence() {
        let mut kr = KeyRing::default();
        kr.add("alice", "a2V5").unwrap();
        assert!(kr.remove("alice"));
        assert!(!kr.remove("alice"));
    }

    #[test]
    fn route_set_get_clear() {
        let mut kr = KeyRing::default();
        kr.add("alice", "a2V5").unwrap();
        assert_eq!(kr.get_route("alice"), None);
        kr.set_route("alice", Some("https://relay.example.com"))
            .unwrap();
        assert_eq!(
            kr.get_route("alice").as_deref(),
            Some("https://relay.example.com")
        );
        // None clears
        kr.set_route("alice", None).unwrap();
        assert_eq!(kr.get_route("alice"), None);
    }

    #[test]
    fn route_on_unknown_name_is_config_error() {
        let mut kr = KeyRing::default();
        let err = kr
            .set_route("ghost", Some("https://relay.example.com"))
            .unwrap_err();
        assert!(matches!(err, CoreError::Config(_)), "{err}");
        assert!(
            err.to_string().contains("ghost"),
            "must name the missing entry: {err}"
        );
        assert!(matches!(
            kr.set_route("ghost", None).unwrap_err(),
            CoreError::Config(_)
        ));
    }

    #[test]
    fn route_persists_round_trip() {
        let root = TempDir::new().unwrap();
        let mut kr = KeyRing::default();
        kr.add("alice", "a2V5").unwrap();
        kr.set_route("alice", Some("https://relay.example.com"))
            .unwrap();
        kr.save(root.path()).unwrap();
        let mut reloaded = KeyRing::load(root.path()).unwrap();
        assert_eq!(
            reloaded.get_route("alice").as_deref(),
            Some("https://relay.example.com")
        );
        reloaded.set_route("alice", None).unwrap();
        reloaded.save(root.path()).unwrap();
        assert_eq!(KeyRing::load(root.path()).unwrap().get_route("alice"), None);
    }

    #[test]
    fn old_keyring_without_route_parses_and_reserializes_without_it() {
        let root = TempDir::new().unwrap();
        // hand-written v0.2-format keyring: no `route` key anywhere
        std::fs::write(
            root.path().join("keyring.json"),
            r#"{"alice": {"public_key": "a2V5", "first_seen": "2026-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let kr = KeyRing::load(root.path()).unwrap();
        assert_eq!(kr.get("alice").unwrap().public_key, "a2V5");
        assert_eq!(kr.get_route("alice"), None);
        kr.save(root.path()).unwrap();
        let text = std::fs::read_to_string(root.path().join("keyring.json")).unwrap();
        assert!(
            !text.contains("route"),
            "re-saving an old keyring must not churn bytes with a route key: {text}"
        );
    }
}
