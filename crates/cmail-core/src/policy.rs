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
    /// Verifies the signed record log that grants policy. Presence is never
    /// requested on this path: only the public key is read.
    authority: std::sync::Arc<dyn Authority>,
    /// Derived on first use from the signed record log; an unavailable
    /// backend yields an empty policy so every gated read fails closed.
    effective: OnceCell<EffectivePolicy>,
    /// Derived from `effective` on first use.
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
    /// unavailable authority folds to no decision. A tampered or rolled-back
    /// log is an integrity error, never a silent `None`.
    pub fn outbound_mode(&self) -> Result<Option<OutboundMode>> {
        let Some(decision) = self.effective()?.decisions.get(subject::OUTBOUND_MODE) else {
            return Ok(None);
        };
        Ok(decision
            .payload
            .as_ref()
            .and_then(|payload| payload.get("mode"))
            .and_then(|mode| serde_json::from_value(mode.clone()).ok()))
    }

    /// The effective inbound mode.
    ///
    /// A signed `mode:inbound` record wins. With no signed record, a
    /// reachable public key falls back to `config.inbound` only to TIGHTEN:
    /// legacy `known-only` is honored, while legacy `permissive` cannot
    /// loosen anything. An unavailable or locked key, a tampered log, or an
    /// unparseable signed payload fails closed to `known-only`.
    pub fn inbound_mode(&self) -> InboundMode {
        let Ok(policy) = self.effective() else {
            return InboundMode::KnownOnly;
        };
        let Some(decision) = policy.decisions.get(subject::INBOUND_MODE) else {
            // A reachable public key, not a status flag: Linux can report an
            // available Secret Service while the item is locked, and a locked
            // key must not fall back to legacy config.
            let available = self.authority.verifying_key().is_ok();
            return if available {
                self.config.inbound
            } else {
                InboundMode::KnownOnly
            };
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
        self.outbound_mode()
            .is_ok_and(|mode| mode == Some(OutboundMode::Open))
    }

    /// The outbound gate: a signed open-mode record, or a signed allow entry.
    /// The legacy `[allow] send` config and a hand-edited record log never
    /// grant a send, and an unavailable authority leaves both empty, so
    /// gated sends fail closed.
    pub fn may_send(&self, to: &str) -> bool {
        self.mode_allows() || self.is_allowed(to)
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

    /// The effective signed pickup relay url, if any. Clear means no relay;
    /// the legacy `[relay] url` config never becomes the fetch target. A
    /// tampered or rolled-back log is an integrity error, never `None`.
    pub fn relay_url(&self) -> Result<Option<String>> {
        let Some(decision) = self.effective()?.decisions.get(subject::RELAY) else {
            return Ok(None);
        };
        if decision.action != crate::authority::AuthorityAction::RelaySet {
            return Ok(None);
        }
        Ok(decision
            .payload
            .as_ref()
            .and_then(|payload| payload.get("url"))
            .and_then(|url| url.as_str())
            .filter(|url| !url.is_empty())
            .map(str::to_string))
    }

    /// The per-recipient relay route, if known (never affects trust).
    pub fn route(&self, name: &str) -> Result<Option<String>> {
        Ok(self.keyring()?.get_route(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        Authority, AuthorityAction, AuthorityStatus, InMemoryAuthority, LogHead,
        UnavailableAuthority,
    };
    use crate::config::{AllowSection, Config, InboundMode, OutboundMode, RelaySection};
    use crate::envelope::{build_and_sign, NewEnvelope};
    use crate::keyring::KeyRing;
    use crate::trust::{self, TrustLevel};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::{SigningKey, VerifyingKey};
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

        // Legacy config remains display-only: signed records supply the
        // allowlist, and relay/mode behavior comes only from signed records.
        assert_eq!(policy.outbound(), OutboundMode::Gated);
        assert_eq!(policy.inbound(), InboundMode::KnownOnly);
        assert_eq!(policy.allow_list().unwrap(), ["zoe".to_string()]);
        assert_eq!(policy.relay_url().unwrap(), None);
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
        assert_eq!(signed.outbound_mode().unwrap(), Some(OutboundMode::Open));
        assert!(signed.may_send("mallory"));
        assert_eq!(
            signed.relay_url().unwrap().as_deref(),
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
                .relay_url()
                .unwrap(),
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
        assert_eq!(policy.allow_list().unwrap(), ["zoe".to_string()]);
        assert_eq!(policy.relay_url().unwrap(), None);
        assert!(policy.may_send("zoe"));
        assert!(!policy.may_send("mallory"));

        // signed trust is unaffected; only the route overlay is unavailable
        assert_eq!(
            policy.trust(&signed_alice(&alice)).unwrap().level,
            TrustLevel::Verified
        );
        assert_eq!(policy.route("alice").unwrap(), None);
    }

    /// A backend whose status says available while the public key is
    /// unreachable, as Linux reports a locked Secret Service item.
    struct LockedAuthority(InMemoryAuthority);

    impl Authority for LockedAuthority {
        fn status(&self) -> Result<AuthorityStatus> {
            self.0.status()
        }
        fn init(&self) -> Result<AuthorityStatus> {
            self.0.init()
        }
        fn verifying_key(&self) -> Result<VerifyingKey> {
            Err(CoreError::AuthorityUnavailable("locked".into()))
        }
        fn sign_bytes(
            &self,
            action: AuthorityAction,
            subject: &str,
            bytes: &str,
        ) -> Result<String> {
            self.0.sign_bytes(action, subject, bytes)
        }
        fn pinned_head(&self) -> Result<Option<LogHead>> {
            self.0.pinned_head()
        }
        fn pin_head(&self, head: &LogHead) -> Result<()> {
            self.0.pin_head(head)
        }
        fn reset_credentials(&self) -> Result<()> {
            self.0.reset_credentials()
        }
    }

    fn config_inbound(root: &Path, mode: InboundMode) {
        let mut cfg = Config::load_or_init(root).unwrap();
        cfg.inbound = mode;
        cfg.save(root).unwrap();
    }

    /// Availability is the reachable public key, not the status flag: a
    /// locked backend must not fall back to legacy `permissive` config.
    #[test]
    fn locked_authority_without_a_record_stays_known_only() {
        let root = TempDir::new().unwrap();
        config_inbound(root.path(), InboundMode::Permissive);
        let inner = InMemoryAuthority::new();
        inner.init().unwrap();
        let authority = std::sync::Arc::new(LockedAuthority(inner));
        assert!(authority.status().unwrap().available);

        let policy = Policy::load(root.path(), authority).unwrap();
        assert_eq!(policy.inbound_mode(), InboundMode::KnownOnly);
    }

    /// A reachable key with no signed record still honors a tightening
    /// legacy config.
    #[test]
    fn available_authority_without_a_record_honors_legacy_permissive() {
        let root = TempDir::new().unwrap();
        config_inbound(root.path(), InboundMode::Permissive);
        let policy = Policy::load(root.path(), test_authority()).unwrap();
        assert_eq!(policy.inbound_mode(), InboundMode::Permissive);
    }

    /// An unavailable backend with no signed record fails closed.
    #[test]
    fn unavailable_authority_without_a_record_stays_known_only() {
        let root = TempDir::new().unwrap();
        config_inbound(root.path(), InboundMode::Permissive);
        let authority: std::sync::Arc<dyn Authority> = std::sync::Arc::new(UnavailableAuthority);
        let policy = Policy::load(root.path(), authority).unwrap();
        assert_eq!(policy.inbound_mode(), InboundMode::KnownOnly);
    }

    /// A tampered record log is an integrity error, never a silent `None`
    /// that makes `relay show`/`mode show` print empty values and lets the
    /// outbound gate fall back to gated.
    #[test]
    fn tampered_log_errors_on_relay_and_mode_reads_and_denies_send() {
        let authority = test_authority();
        let (root, _alice) = legacy_root(&authority);
        authority
            .sign_action(
                root.path(),
                AuthorityAction::RelaySet,
                subject::RELAY,
                &serde_json::json!({ "url": "https://signed.example.com" }),
            )
            .unwrap();
        authority
            .sign_action(
                root.path(),
                AuthorityAction::OutboundMode,
                subject::OUTBOUND_MODE,
                &serde_json::json!({ "mode": "open" }),
            )
            .unwrap();

        let path = root.path().join("authority.log");
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        let mut value: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        value["subject"] = "tampered".into();
        lines[0] = value.to_string();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let policy = Policy::load(root.path(), authority.clone()).unwrap();
        assert!(matches!(
            policy.relay_url(),
            Err(CoreError::AuthorityInvalid(_))
        ));
        assert!(matches!(
            policy.outbound_mode(),
            Err(CoreError::AuthorityInvalid(_))
        ));
        assert!(!policy.may_send("zoe"));
    }
}
