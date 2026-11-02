use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundMode {
    #[default]
    Gated,
    Open,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InboundMode {
    #[default]
    Permissive,
    KnownOnly,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_identity: Option<String>,
    #[serde(default)]
    pub outbound: OutboundMode,
    #[serde(default)]
    pub inbound: InboundMode,
    #[serde(default)]
    pub allow: AllowSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub relay: RelaySection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AllowSection {
    #[serde(default)]
    pub send: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LimitsSection {
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_attachment_bytes: default_max_attachment_bytes(),
        }
    }
}

fn default_max_attachment_bytes() -> u64 {
    10 * 1024 * 1024
}

/// Pickup relay (spec §3.3): where `cmail fetch` polls for mail addressed to
/// my key. One url in v0.3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RelaySection {
    // None (absent) and Some("") both mean "no relay configured"; skipped on
    // save when None so a cleared section round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl Config {
    pub fn path(root: &Path) -> PathBuf {
        root.join("config.toml")
    }

    pub fn load_or_init(root: &Path) -> Result<Self> {
        let path = Self::path(root);
        if !path.exists() {
            fs::create_dir_all(root)?;
            fs::write(&path, default_config_toml())?;
        }
        let cfg: Config = toml::from_str(&fs::read_to_string(&path)?)
            .map_err(|e| CoreError::Config(format!("{}: {e}", path.display())))?;
        Ok(cfg)
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let path = Self::path(root);
        let text = toml::to_string_pretty(self).map_err(|e| CoreError::Config(e.to_string()))?;
        crate::fsutil::write_durable(&path, text.as_bytes())
    }

    pub fn is_send_allowed(&self, name: &str) -> bool {
        self.allow.send.iter().any(|n| n == name)
    }

    /// The configured pickup relay url, if any (empty string counts as unset —
    /// the generated default carries `url = ""` for human editability).
    pub fn relay_url(&self) -> Option<String> {
        self.relay
            .url
            .as_deref()
            .filter(|u| !u.is_empty())
            .map(str::to_string)
    }
}

pub fn default_config_toml() -> String {
    r#"# cmail configuration. Human-edited is fine.
default_identity = ""
outbound = "gated"      # gated (default) | open
inbound = "permissive"  # permissive (default) | known-only

[allow]
send = []               # names pre-authorized for outbound

[limits]
max_attachment_bytes = 10485760

[relay]
url = ""                # pickup relay for `cmail fetch` (https://relay.example.com)
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generates_and_parses_defaults() {
        let root = TempDir::new().unwrap();
        let cfg = Config::load_or_init(root.path()).unwrap();
        assert_eq!(cfg.outbound, OutboundMode::Gated);
        assert_eq!(cfg.inbound, InboundMode::Permissive);
        assert!(!cfg.is_send_allowed("anyone"));
        // the generated file carries a [relay] section with an empty url
        assert_eq!(cfg.relay_url(), None);
        let again = Config::load_or_init(root.path()).unwrap();
        assert_eq!(cfg, again);
        let text = fs::read_to_string(Config::path(root.path())).unwrap();
        assert_eq!(text, default_config_toml());
        assert!(text.contains("[relay]"));
        assert!(text.contains("url = \"\""));
    }

    #[test]
    fn save_preserves_absent_default_identity() {
        let mut cfg = Config::default();
        assert_eq!(cfg.default_identity, None);
        cfg.allow.send = vec!["zoe".into()];
        let root = TempDir::new().unwrap();
        cfg.save(root.path()).unwrap();
        let back = Config::load_or_init(root.path()).unwrap();
        assert_eq!(back.default_identity, None);
        assert!(back.is_send_allowed("zoe"));
    }

    #[test]
    fn allowlist_and_modes_round_trip() {
        let mut cfg = Config::default();
        cfg.allow.send = vec!["zoe".into()];
        cfg.default_identity = Some("alice".into());
        cfg.inbound = InboundMode::KnownOnly;
        let root = TempDir::new().unwrap();
        cfg.save(root.path()).unwrap();
        let back = Config::load_or_init(root.path()).unwrap();
        assert!(back.is_send_allowed("zoe"));
        assert_eq!(back.inbound, InboundMode::KnownOnly);
        assert_eq!(back.default_identity.as_deref(), Some("alice"));
    }

    #[test]
    fn relay_section_round_trip() {
        let mut cfg = Config::default();
        assert_eq!(cfg.relay_url(), None);
        cfg.relay.url = Some("https://relay.example.com".into());
        assert_eq!(
            cfg.relay_url().as_deref(),
            Some("https://relay.example.com")
        );
        let root = TempDir::new().unwrap();
        cfg.save(root.path()).unwrap();
        let back = Config::load_or_init(root.path()).unwrap();
        assert_eq!(
            back.relay_url().as_deref(),
            Some("https://relay.example.com")
        );
    }

    #[test]
    fn relay_url_treats_empty_string_as_unset() {
        // the generated default config carries `url = ""` (human-editable):
        // relay_url must report None, not Some("")
        let mut cfg = Config::default();
        cfg.relay.url = Some(String::new());
        assert_eq!(cfg.relay_url(), None);
    }

    #[test]
    fn relay_clear_round_trips_as_unset() {
        let mut cfg = Config::default();
        cfg.relay.url = Some("https://relay.example.com".into());
        let root = TempDir::new().unwrap();
        cfg.save(root.path()).unwrap();
        let mut back = Config::load_or_init(root.path()).unwrap();
        back.relay.url = None; // what relay_set(None) writes
        back.save(root.path()).unwrap();
        let again = Config::load_or_init(root.path()).unwrap();
        assert_eq!(again.relay_url(), None);
    }
}
