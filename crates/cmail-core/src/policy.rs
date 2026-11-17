//! Effective-policy seam: every protected policy read goes through [`Policy`].
//!
//! Trust for a sender name comes only from the signed authority-record log
//! (a latest valid `key_add`); the legacy `keyring.json` supplies relay routes
//! and display cache and grants nothing. Config-backed reads (outbound gate,
//! relay selection) still use the root-local `config.toml`.

use crate::authority::{subject, Authority, EffectivePolicy};
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

    /// Legacy config inbound mode. Display only: the inbox gate reads the
    /// signed `mode:inbound` record, never this value.
    pub fn inbound(&self) -> InboundMode {
        self.config.inbound
    }

    /// The signed outbound mode, if the human signed one. `None` means the
    /// gate is allowlist-only: config `[outbound]` never opens it, and an
    /// unavailable authority folds to no decision.
    pub fn outbound_mode(&self) -> Option<OutboundMode> {
        let decision = self
            .effective()
            .ok()?
            .decisions
            .get(subject::OUTBOUND_MODE)?;
        serde_json::from_value(decision.payload.as_ref()?.get("mode")?.clone()).ok()
    }

    /// The signed inbound mode. No record (including an unavailable authority)
    /// means the documented default `permissive`; an unparseable signed payload
    /// or tampered log fails closed to `known-only`.
    pub fn inbound_mode(&self) -> InboundMode {
        let Ok(policy) = self.effective() else {
            return InboundMode::KnownOnly;
        };
        let Some(decision) = policy.decisions.get(subject::INBOUND_MODE) else {
            return InboundMode::Permissive;
        };
        decision
            .payload
            .as_ref()
            .and_then(|payload| payload.get("mode"))
            .and_then(|mode| serde_json::from_value(mode.clone()).ok())
            .unwrap_or(InboundMode::KnownOnly)
    }

    /// True when the signed outbound mode is `open`. The only place a config
    /// mode could leak is [`Policy::outbound`], which this gate never reads.
    fn mode_allows(&self) -> bool {
        self.outbound_mode() == Some(OutboundMode::Open)
    }

    /// The outbound gate: signed open mode, or the recipient is allowlisted.
    /// The legacy `[allow] send` config remains for ticket #13 to replace with
    /// the signed allowlist; a hand-edited config never opens the mode gate.
    pub fn may_send(&self, to: &str) -> bool {
        self.mode_allows() || self.config.is_send_allowed(to)
    }

    /// Names pre-authorized for outbound, in config order.
    pub fn allow_list(&self) -> &[String] {
        &self.config.allow.send
    }

    /// The effective signed pickup relay url, if any. Clear means no relay;
    /// the legacy `[relay] url` config never becomes the fetch target.
    pub fn relay_url(&self) -> Option<String> {
        let decision = self.effective().ok()?.decisions.get(subject::RELAY)?;
        if decision.action != crate::authority::AuthorityAction::RelaySet {
            return None;
        }
        decision
            .payload
            .as_ref()?
            .get("url")?
            .as_str()
            .filter(|url| !url.is_empty())
            .map(str::to_string)
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

        // Legacy config still reports through the display accessors, but the
        // signed log is the only source of relay and gate behavior.
        assert_eq!(policy.outbound(), OutboundMode::Gated);
        assert_eq!(policy.inbound(), InboundMode::KnownOnly);
        assert_eq!(policy.allow_list(), ["zoe".to_string()]);
        assert_eq!(policy.relay_url(), None);
        assert_eq!(
            policy.route("alice").unwrap().as_deref(),
            Some("https://alice.example.com")
        );
        assert_eq!(policy.route("ghost").unwrap(), None);
        assert!(policy.keyring().unwrap().get("alice").is_some());

        // outbound gate: allowlisted passes, unknown holds; a hand-edited
        // config open mode never opens it.
        assert!(policy.may_send("zoe"));
        assert!(!policy.may_send("mallory"));
        let mut open = Config::load_or_init(root.path()).unwrap();
        open.outbound = OutboundMode::Open;
        open.save(root.path()).unwrap();
        assert!(!Policy::load(root.path(), authority.clone())
            .unwrap()
            .may_send("mallory"));

        // A signed open mode and a signed relay record are effective.
        authority
            .sign_action(
                root.path(),
                AuthorityAction::OutboundMode,
                subject::OUTBOUND_MODE,
                &serde_json::json!({ "mode": "open" }),
            )
            .unwrap();
        authority
            .sign_action(
                root.path(),
                AuthorityAction::RelaySet,
                subject::RELAY,
                &serde_json::json!({ "url": "https://signed.example.com" }),
            )
            .unwrap();
        let signed = Policy::load(root.path(), authority.clone()).unwrap();
        assert_eq!(signed.outbound_mode(), Some(OutboundMode::Open));
        assert!(signed.may_send("mallory"));
        assert_eq!(
            signed.relay_url().as_deref(),
            Some("https://signed.example.com")
        );

        // Latest relay decision wins: clear disables the target.
        authority
            .sign_action(
                root.path(),
                AuthorityAction::RelayClear,
                subject::RELAY,
                &serde_json::json!({}),
            )
            .unwrap();
        assert_eq!(
            Policy::load(root.path(), authority.clone())
                .unwrap()
                .relay_url(),
            None
        );

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
        assert_eq!(policy.relay_url(), None);
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
