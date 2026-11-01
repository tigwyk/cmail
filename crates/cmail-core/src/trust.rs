use crate::envelope::Envelope;
use crate::identity::fingerprint_of;
use crate::keyring::KeyRing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    Verified,
    Untrusted,
    SpoofSuspect,
    Invalid,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Verified => "verified",
            TrustLevel::Untrusted => "untrusted",
            TrustLevel::SpoofSuspect => "spoof_suspect",
            TrustLevel::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrustResult {
    pub level: TrustLevel,
    pub fingerprint: String,
}

pub fn evaluate(env: &Envelope, keyring: &KeyRing) -> TrustResult {
    let fingerprint = fingerprint_of(&env.from_key);
    let level = if !env.verify_self_signature() {
        TrustLevel::Invalid
    } else if let Some(known) = keyring.get(&env.from) {
        if known.public_key == env.from_key {
            TrustLevel::Verified
        } else {
            TrustLevel::SpoofSuspect
        }
    } else {
        TrustLevel::Untrusted
    };
    TrustResult { level, fingerprint }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{build_and_sign, NewEnvelope};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn signed(from: &str, key: &SigningKey, to: &str) -> crate::envelope::Envelope {
        build_and_sign(
            &"ab".repeat(16),
            &NewEnvelope {
                from: from.into(),
                from_key: B64.encode(key.verifying_key().as_bytes()),
                to: to.into(),
                kind: "note".into(),
                subject: "s".into(),
                body: "b".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            key,
        )
        .unwrap()
    }

    fn keyring_with(name: &str, key: &SigningKey) -> (KeyRing, TempDir) {
        let root = TempDir::new().unwrap();
        let mut kr = KeyRing::default();
        kr.add(name, &B64.encode(key.verifying_key().as_bytes()))
            .unwrap();
        (kr, root)
    }

    #[test]
    fn matrix() {
        let alice = SigningKey::generate(&mut OsRng);
        let mallory = SigningKey::generate(&mut OsRng);

        // unknown sender, valid sig -> untrusted
        let (kr, _) = keyring_with("someone-else", &alice);
        let env = signed("alice", &alice, "zoe");
        assert_eq!(evaluate(&env, &kr).level, TrustLevel::Untrusted);

        // known sender, matching key -> verified
        let (kr, _) = keyring_with("alice", &alice);
        let env = signed("alice", &alice, "zoe");
        assert_eq!(evaluate(&env, &kr).level, TrustLevel::Verified);

        // known name, different key -> spoof_suspect (signed by mallory, claims alice)
        let (kr, _) = keyring_with("alice", &alice);
        let env = signed("alice", &mallory, "zoe");
        assert_eq!(evaluate(&env, &kr).level, TrustLevel::SpoofSuspect);

        // invalid self-signature -> invalid (tamper the body after signing)
        let (kr, _) = keyring_with("alice", &alice);
        let mut env = signed("alice", &alice, "zoe");
        env.body = "tampered".into();
        assert_eq!(evaluate(&env, &kr).level, TrustLevel::Invalid);
    }

    #[test]
    fn fingerprint_reported() {
        let alice = SigningKey::generate(&mut OsRng);
        let (kr, _) = keyring_with("x", &alice);
        let env = signed("alice", &alice, "zoe");
        let r = evaluate(&env, &kr);
        assert_eq!(r.fingerprint.len(), 16);
    }
}
