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
                    },
                );
                Ok(())
            }
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
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
    fn remove_reports_existence() {
        let mut kr = KeyRing::default();
        kr.add("alice", "a2V5").unwrap();
        assert!(kr.remove("alice"));
        assert!(!kr.remove("alice"));
    }
}
