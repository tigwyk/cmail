//! Effective-policy seam: every protected policy read goes through [`Policy`].
//!
//! Trust for a sender name comes only from the signed authority-record log
//! (a latest valid `key_add`); the legacy `keyring.json` supplies relay routes
//! and display cache and grants nothing. Config-backed reads (outbound gate,
//! relay selection) still use the root-local `config.toml`.

use crate::authority::{Authority, EffectivePolicy};
use crate::config::{Config, InboundMode, OutboundMode};
use crate::envelope::Envelope;
use crate::error::{CoreError, Result};
use crate::keyring::KeyRing;
use crate::trust::{self, TrustResult};
use std::cell::OnceCell;
use std::path::{Path, PathBuf};

pub struct Policy {
    root: PathBuf,
    config: Config,
    /// Verifies the signed record log that grants trust. Presence is never
    /// requested on this path: only the public key is read.
    authority: std::sync::Arc<dyn Authority>,
    /// Derived on first use: relay/config-only reads must not need authority
    /// material (fetch, relay show, allow list never needed it before).
    keyring: OnceCell<KeyRing>,
    /// Derived on first use. Approval release reads decisions from here.
    effective: OnceCell<EffectivePolicy>,
}

impl Policy {
    /// Load the effective policy for `root`, fresh from disk so a long-lived
    /// handle observes human edits made since it opened.
    pub fn load(root: &Path, authority: std::sync::Arc<dyn Authority>) -> Result<Self> {
        Ok(Self {
            root: root.to_path_buf(),
            config: Config::load_or_init(root)?,
            authority,
            keyring: OnceCell::new(),
            effective: OnceCell::new(),
        })
    }

    /// The effective trust keyring, derived only from valid signed records.
    /// The legacy `keyring.json` contributes relay routes and nothing else.
    ///
    /// An unavailable authority backend yields an empty keyring (no trust
    /// anchor, so nothing verifies) instead of making mail unreadable; a
    /// tampered or rolled-back log still fails closed with an error.
    pub fn keyring(&self) -> Result<&KeyRing> {
        if self.keyring.get().is_none() {
            let effective = match self.authority.load_effective_policy(&self.root) {
                Ok(policy) => KeyRing::from_decisions(&policy),
                Err(CoreError::AuthorityUnavailable(_)) => KeyRing::default(),
                Err(error) => return Err(error),
            };
            let mut effective = effective;
            // Routes are routing, never trust: a stale or hand-edited legacy
            // file can redirect mail at most, never verify a key.
            if let Ok(legacy) = KeyRing::load(&self.root) {
                effective.overlay_routes(&legacy);
            }
            // Cache success only: a tampered log cannot become valid mid-process.
            let _ = self.keyring.set(effective);
        }
        Ok(self.keyring.get().expect("keyring was just set"))
    }

    /// The effective policy derived only from valid signed records.
    ///
    /// An unavailable authority backend yields an empty policy: no decision
    /// exists, so protected actions stay refused. A tampered, truncated, or
    /// foreign-key log still fails closed with an error. Success is cached so a
    /// long-lived handle reads decisions once; callers load a fresh `Policy`
    /// when they need to observe records signed after the handle opened.
    pub fn effective(&self) -> Result<&EffectivePolicy> {
        if self.effective.get().is_none() {
            let effective = match self.authority.load_effective_policy(&self.root) {
                Ok(policy) => policy,
                Err(CoreError::AuthorityUnavailable(_)) => EffectivePolicy::default(),
                Err(error) => return Err(error),
            };
            let _ = self.effective.set(effective);
        }
        Ok(self.effective.get().expect("effective policy was just set"))
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
    use crate::authority::{Authority, AuthorityAction, InMemoryAuthority};
    use crate::config::{AllowSection, Config, InboundMode, OutboundMode, RelaySection};
    use crate::envelope::{build_and_sign, NewEnvelope};
    use crate::keyring::KeyRing;
    use crate::trust::{self, TrustLevel};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn test_authority() -> std::sync::Arc<InMemoryAuthority> {
        let authority = std::sync::Arc::new(InMemoryAuthority::new());
        authority.init().unwrap();
        authority
    }

    /// Config plus a signed `alice` grant and a legacy route cache entry.
    fn legacy_root(authority: &InMemoryAuthority) -> (TempDir, SigningKey) {
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
        let public_key = B64.encode(alice.verifying_key().as_bytes());
        let mut kr = KeyRing::load(root.path()).unwrap();
        kr.add("alice", &public_key).unwrap();
        kr.set_route("alice", Some("https://alice.example.com"))
            .unwrap();
        kr.save(root.path()).unwrap();
        authority
            .sign_action(
                root.path(),
                AuthorityAction::KeyAdd,
                &crate::adoption::key_subject("alice", &public_key),
                &serde_json::json!({ "name": "alice", "public_key": public_key }),
            )
            .unwrap();
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
    fn seam_returns_todays_policy_from_signed_grants() {
        let authority = test_authority();
        let (root, alice) = legacy_root(&authority);
        let policy = Policy::load(root.path(), authority.clone()).unwrap();

        // the seam reports the same allowlist, relay and modes as the legacy
        // config; the keyring comes from the signed log and carries the
        // non-trust route overlay
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
        assert!(Policy::load(root.path(), authority.clone())
            .unwrap()
            .may_send("mallory"));

        // trust through the seam is exactly the trust module on that keyring
        let env = signed_alice(&alice);
        assert_eq!(
            policy.trust(&env).unwrap(),
            trust::evaluate(&env, policy.keyring().unwrap())
        );
        assert_eq!(policy.trust(&env).unwrap().level, TrustLevel::Verified);
    }

    /// Hand-editing the legacy keyring cache never grants trust: only the
    /// signed log does.
    #[test]
    fn tampered_legacy_keyring_does_not_change_trust() {
        let authority = test_authority();
        let (root, alice) = legacy_root(&authority);
        let mallory = SigningKey::generate(&mut OsRng);
        let mut cache = KeyRing::load(root.path()).unwrap();
        cache.remove("alice");
        cache
            .add("alice", &B64.encode(mallory.verifying_key().as_bytes()))
            .unwrap();
        cache.save(root.path()).unwrap();

        let policy = Policy::load(root.path(), authority.clone()).unwrap();
        assert_eq!(
            policy.trust(&signed_alice(&alice)).unwrap().level,
            TrustLevel::Verified
        );
        let spoof = build_and_sign(
            &"ab".repeat(16),
            &NewEnvelope {
                from: "alice".into(),
                from_key: B64.encode(mallory.verifying_key().as_bytes()),
                to: "zoe".into(),
                kind: "note".into(),
                subject: "s".into(),
                body: "b".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            &mallory,
        )
        .unwrap();
        assert_eq!(
            policy.trust(&spoof).unwrap().level,
            TrustLevel::SpoofSuspect
        );
    }

    /// A corrupt legacy cache must not break relay/config reads or trust: the
    /// cache is routing only, and the signed log is intact.
    #[test]
    fn corrupt_keyring_leaves_config_and_trust_reads_working() {
        let authority = test_authority();
        let (root, alice) = legacy_root(&authority);
        std::fs::write(root.path().join("keyring.json"), "not json").unwrap();

        let policy = Policy::load(root.path(), authority.clone()).unwrap();
        assert_eq!(policy.inbound(), InboundMode::KnownOnly);
        assert_eq!(policy.allow_list(), ["zoe".to_string()]);
        assert_eq!(
            policy.relay_url().as_deref(),
            Some("https://relay.example.com")
        );
        assert!(policy.may_send("zoe"));
        assert!(!policy.may_send("mallory"));

        // signed trust is unaffected; only the route overlay is unavailable
        assert_eq!(
            policy.trust(&signed_alice(&alice)).unwrap().level,
            TrustLevel::Verified
        );
        assert_eq!(policy.route("alice").unwrap(), None);
    }
}
