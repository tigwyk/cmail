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
    #[serde(default)]
    pub default_identity: Option<String>,
    #[serde(default)]
    pub outbound: OutboundMode,
    #[serde(default)]
    pub inbound: InboundMode,
    #[serde(default)]
    pub allow: AllowSection,
    #[serde(default)]
    pub limits: LimitsSection,
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
        let tmp = path.with_extension("toml.tmp");
        fs::write(
            &tmp,
            toml::to_string_pretty(self).map_err(|e| CoreError::Config(e.to_string()))?,
        )?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn is_send_allowed(&self, name: &str) -> bool {
        self.allow.send.iter().any(|n| n == name)
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
        let again = Config::load_or_init(root.path()).unwrap();
        assert_eq!(cfg, again);
        let text = fs::read_to_string(Config::path(root.path())).unwrap();
        assert_eq!(text, default_config_toml());
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
}
