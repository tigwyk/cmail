//! Effective-policy seam: every protected policy read goes through [`Policy`].
//!
//! Trust for a sender name, the outbound allowlist, and outbound mode come
//! only from the signed authority-record log. The legacy `keyring.json`
//! supplies relay routes and display cache and grants nothing. The legacy
//! `config.toml` allowlist and outbound mode are display/routing state only
//! and never open the outbound gate.

use crate::authority::{subject, Authority, AuthorityAction, EffectivePolicy};
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
    /// Derived on first use from the signed record log; an unavailable
    /// backend yields an empty policy so every gated read fails closed.
    effective: OnceCell<EffectivePolicy>,
    /// Derived on first use: relay/config-only reads must not need authority
    /// material (fetch, relay show, allow list never needed it before).
    keyring: OnceCell<KeyRing>,
}

impl Policy {
    /// Load the effective policy for `root`, fresh from disk so a long-lived
    /// handle observes human edits made since it opened.
    pub fn load(root: &Path, authority: std::sync::Arc<dyn Authority>) -> Result<Self> {
        Ok(Self {
            root: root.to_path_buf(),
            config: Config::load_or_init(root)?,
            authority,
            effective: OnceCell::new(),
            keyring: OnceCell::new(),
        })
    }

    /// The effective signed policy, folded from the authority-record log.
    ///
    /// An unavailable authority backend yields an **empty** policy: no trust
    /// anchor, no signed allowlist, and no signed outbound mode, so every
    /// gated read fails closed. A tampered or rolled-back log still fails
    /// closed with an error. Cached so one handle reads the log once.
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

    /// The effective trust keyring, derived only from valid signed records.
    /// The legacy `keyring.json` contributes relay routes and nothing else.
    ///
    /// An unavailable authority backend yields an empty keyring (no trust
    /// anchor, so nothing verifies) instead of making mail unreadable; a
    /// tampered or rolled-back log still fails closed with an error.
    pub fn keyring(&self) -> Result<&KeyRing> {
        if self.keyring.get().is_none() {
            let mut effective = KeyRing::from_decisions(self.effective()?);
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

    /// Trust level for `env` under this policy's keyring.
    pub fn trust(&self, env: &Envelope) -> Result<TrustResult> {
        Ok(trust::evaluate(env, self.keyring()?))
    }

    /// Legacy config outbound mode. Display only: the gate reads the signed
    /// `mode:outbound` record, never this value.
    pub fn outbound(&self) -> OutboundMode {
        self.config.outbound
    }

    pub fn inbound(&self) -> InboundMode {
        self.config.inbound
    }

    /// The signed outbound mode, if the human signed one. `None` means the
    /// gate is allowlist-only: config `[outbound]` never opens it, and an
    /// unavailable authority folds to no decision. Modes enforcement beyond
    /// this accessor belongs to ticket #15; it plugs in here.
    pub fn outbound_mode(&self) -> Option<OutboundMode> {
        let decision = self
            .effective()
            .ok()?
            .decisions
            .get(subject::OUTBOUND_MODE)?;
        serde_json::from_value(decision.payload.as_ref()?.get("mode")?.clone()).ok()
    }

    /// The outbound gate: a signed open-mode record, or a signed allow entry.
    /// The legacy `[allow] send` config and a hand-edited record log never
    /// grant a send, and an unavailable authority leaves both empty, so
    /// gated sends fail closed.
    pub fn may_send(&self, to: &str) -> bool {
        self.outbound_mode() == Some(OutboundMode::Open) || self.is_allowed(to)
    }

    /// True when the latest signed allow decision for `name` is an add.
    fn is_allowed(&self, name: &str) -> bool {
        self.effective().is_ok_and(|policy| {
            matches!(
                policy.decisions.get(&subject::allow(name)),
                Some(decision) if decision.action == AuthorityAction::AllowAdd
            )
        })
    }

    /// Names pre-authorized for outbound by signed `allow_add` records, sorted.
    pub fn allow_list(&self) -> Result<Vec<String>> {
        let policy = self.effective()?;
        let mut names: Vec<String> = policy
            .decisions
            .iter()
            .filter(|(_, decision)| decision.action == AuthorityAction::AllowAdd)
            .filter_map(|(subject, _)| subject::name_in(subject, subject::ALLOW))
            .map(str::to_string)
            .collect();
        names.sort();
        Ok(names)
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
        // The legacy config allowlist entry is display-only; the effective
        // allowlist comes from this signed record.
        authority
            .sign_action(
                root.path(),
                AuthorityAction::AllowAdd,
                &subject::allow("zoe"),
                &serde_json::json!({ "name": "zoe" }),
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

        // the signed log supplies the allowlist; config still carries the
        // display-only mode and relay; the keyring carries the route overlay
        assert_eq!(policy.outbound(), OutboundMode::Gated);
        assert_eq!(policy.inbound(), InboundMode::KnownOnly);
        assert_eq!(policy.allow_list().unwrap(), ["zoe".to_string()]);
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

        // outbound gate: signed allowlisted passes, unknown holds, and a
        // hand-edited config open mode does not open it
        assert!(policy.may_send("zoe"));
        assert!(!policy.may_send("mallory"));
        let mut open = Config::load_or_init(root.path()).unwrap();
        open.outbound = OutboundMode::Open;
        open.save(root.path()).unwrap();
        assert!(!Policy::load(root.path(), authority.clone())
            .unwrap()
            .may_send("mallory"));
        // a signed open-mode record is what opens the gate
        authority
            .sign_action(
                root.path(),
                AuthorityAction::OutboundMode,
                subject::OUTBOUND_MODE,
                &serde_json::json!({ "mode": "open" }),
            )
            .unwrap();
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
        assert_eq!(policy.allow_list().unwrap(), ["zoe".to_string()]);
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
