use crate::error::{CoreError, Result};
use crate::identity::{fingerprint_of, now_rfc3339};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
