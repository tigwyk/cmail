//! Effective-policy seam: every protected policy read goes through [`Policy`].
//!
//! Today the effective policy is the legacy root-local `config.toml` plus
//! `keyring.json`. When signed policy lands, only [`Policy::load`] changes;
//! trust computation, the outbound gate, relay selection, approvals listing
//! and quarantine release keep reading through this type.

use crate::config::{Config, InboundMode, OutboundMode};
use crate::envelope::Envelope;
use crate::error::Result;
use crate::keyring::KeyRing;
use crate::trust::{self, TrustResult};
use std::cell::OnceCell;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Policy {
    root: PathBuf,
    config: Config,
    /// Parsed on first use: relay/config-only reads must not fail on a corrupt
    /// keyring (fetch, relay show, allow list never needed one before).
    keyring: OnceCell<KeyRing>,
}

impl Policy {
    /// Load the effective policy for `root`, fresh from disk so a long-lived
    /// handle observes human edits made since it opened.
    pub fn load(root: &Path) -> Result<Self> {
        Ok(Self {
            root: root.to_path_buf(),
            config: Config::load_or_init(root)?,
            keyring: OnceCell::new(),
        })
    }

    /// The keyring that trust decisions and recipient lookups resolve against,
    /// parsed on demand. A corrupt keyring fails every such read (fail closed).
    pub fn keyring(&self) -> Result<&KeyRing> {
        if self.keyring.get().is_none() {
            // Cache success only: a corrupt file cannot become valid mid-process.
            let _ = self.keyring.set(KeyRing::load(&self.root)?);
        }
        Ok(self.keyring.get().expect("keyring was just set"))
    }

    /// Trust level for `env` under this policy's keyring.
    pub fn trust(&self, env: &Envelope) -> Result<TrustResult> {
        Ok(trust::evaluate(env, self.keyring()?))
    }

    pub fn outbound(&self) -> OutboundMode {
        self.config.outbound
    }

    pub fn inbound(&self) -> InboundMode {
        self.config.inbound
    }

    /// The outbound gate: open mode, or the recipient is allowlisted.
    pub fn may_send(&self, to: &str) -> bool {
        self.config.outbound == OutboundMode::Open || self.config.is_send_allowed(to)
    }

    /// Names pre-authorized for outbound, in config order.
    pub fn allow_list(&self) -> &[String] {
        &self.config.allow.send
    }

    /// The configured pickup relay url, if any.
    pub fn relay_url(&self) -> Option<String> {
        self.config.relay_url()
    }

    /// The per-recipient relay route, if known (never affects trust).
    pub fn route(&self, name: &str) -> Result<Option<String>> {
        Ok(self.keyring()?.get_route(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllowSection, Config, InboundMode, OutboundMode, RelaySection};
    use crate::envelope::{build_and_sign, NewEnvelope};
    use crate::keyring::KeyRing;
    use crate::trust::{self, TrustLevel};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    /// A root laid out exactly as the legacy files are written today.
    fn legacy_root() -> (TempDir, SigningKey) {
        let root = TempDir::new().unwrap();
        let cfg = Config {
            outbound: OutboundMode::Gated,
            inbound: InboundMode::KnownOnly,
            allow: AllowSection {
                send: vec!["zoe".into()],
            },
            relay: RelaySection {
                url: Some("https://relay.example.com".into()),
            },
            ..Config::default()
        };
        cfg.save(root.path()).unwrap();
        let alice = SigningKey::generate(&mut OsRng);
        let mut kr = KeyRing::load(root.path()).unwrap();
        kr.add("alice", &B64.encode(alice.verifying_key().as_bytes()))
            .unwrap();
        kr.set_route("alice", Some("https://alice.example.com"))
            .unwrap();
        kr.save(root.path()).unwrap();
        (root, alice)
    }

    fn signed_alice(alice: &SigningKey) -> crate::envelope::Envelope {
        build_and_sign(
            &"ab".repeat(16),
            &NewEnvelope {
                from: "alice".into(),
                from_key: B64.encode(alice.verifying_key().as_bytes()),
                to: "zoe".into(),
                kind: "note".into(),
                subject: "s".into(),
                body: "b".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            alice,
        )
        .unwrap()
    }

    #[test]
    fn seam_returns_todays_legacy_policy() {
        let (root, alice) = legacy_root();
        let policy = Policy::load(root.path()).unwrap();

        // the seam reports the same keyring, allowlist, relay and modes as the
        // legacy files it reads
        assert_eq!(policy.outbound(), OutboundMode::Gated);
        assert_eq!(policy.inbound(), InboundMode::KnownOnly);
        assert_eq!(policy.allow_list(), ["zoe".to_string()]);
        assert_eq!(
            policy.relay_url().as_deref(),
            Some("https://relay.example.com")
        );
        assert_eq!(
            policy.route("alice").unwrap().as_deref(),
            Some("https://alice.example.com")
        );
        assert_eq!(policy.route("ghost").unwrap(), None);
        assert!(policy.keyring().unwrap().get("alice").is_some());

        // outbound gate: allowlisted passes, unknown holds, open mode passes all
        assert!(policy.may_send("zoe"));
        assert!(!policy.may_send("mallory"));
        let mut open = Config::load_or_init(root.path()).unwrap();
        open.outbound = OutboundMode::Open;
        open.save(root.path()).unwrap();
        assert!(Policy::load(root.path()).unwrap().may_send("mallory"));

        // trust through the seam is exactly the trust module on that keyring
        let env = signed_alice(&alice);
        assert_eq!(
            policy.trust(&env).unwrap(),
            trust::evaluate(&env, policy.keyring().unwrap())
        );
        assert_eq!(policy.trust(&env).unwrap().level, TrustLevel::Verified);
    }

    /// A corrupt keyring must not break relay/config-only reads: `fetch`,
    /// `relay show` and the allow list never parsed it before the seam.
    #[test]
    fn corrupt_keyring_leaves_config_only_reads_working() {
        let (root, _alice) = legacy_root();
        std::fs::write(root.path().join("keyring.json"), "not json").unwrap();

        let policy = Policy::load(root.path()).unwrap();
        assert_eq!(policy.inbound(), InboundMode::KnownOnly);
        assert_eq!(policy.allow_list(), ["zoe".to_string()]);
        assert_eq!(
            policy.relay_url().as_deref(),
            Some("https://relay.example.com")
        );
        assert!(policy.may_send("zoe"));
        assert!(!policy.may_send("mallory"));

        // reads that need the keyring still fail closed
        assert!(policy.keyring().is_err());
        assert!(policy.route("alice").is_err());
    }
}
