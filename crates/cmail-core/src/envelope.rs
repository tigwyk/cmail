use crate::canonical::canonical_json;
use crate::error::{CoreError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const KINDS: [&str; 4] = ["note", "status", "handoff", "question"];
pub const MAX_SUBJECT_LEN: usize = 200;
pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_ATTACHMENTS: usize = 8;
pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_TOTAL_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attachment {
    pub filename: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub id: String,
    pub from: String,
    pub from_key: String,
    pub to: String,
    pub kind: String,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<Attachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub created: String,
    pub sig: String,
}

pub struct NewEnvelope {
    pub from: String,
    pub from_key: String,
    pub to: String,
    pub kind: String,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<Attachment>,
    pub in_reply_to: Option<String>,
    pub created: String,
}

pub fn new_id() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn validate(p: &NewEnvelope, id: &str) -> Result<()> {
    let bad = |reason: &str| {
        Err(CoreError::InvalidEnvelope {
            reason: reason.to_string(),
        })
    };
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return bad("id must be 32 hex chars");
    }
    if !KINDS.contains(&p.kind.as_str()) {
        return bad("kind must be one of note|status|handoff|question");
    }
    if p.subject.chars().count() > MAX_SUBJECT_LEN {
        return bad("subject exceeds 200 chars");
    }
    if p.subject.contains('\n') {
        return bad("subject must be a single line");
    }
    if p.body.len() > MAX_BODY_BYTES {
        return bad("body exceeds 256 KiB");
    }
    if p.attachments.len() > MAX_ATTACHMENTS {
        return bad("more than 8 attachments");
    }
    if p.attachments.iter().any(|a| a.size > MAX_ATTACHMENT_BYTES) {
        return bad("attachment exceeds 10 MiB");
    }
    if p.attachments.iter().map(|a| a.size).sum::<u64>() > MAX_TOTAL_ATTACHMENT_BYTES {
        return bad("attachments exceed 25 MiB total");
    }
    if let Some(parent) = &p.in_reply_to {
        if parent.len() != 32 {
            return bad("in_reply_to must be a message id");
        }
    }
    Ok(())
}

impl Envelope {
    pub fn parse(raw: &str) -> Result<Self> {
        let env: Envelope = serde_json::from_str(raw)?;
        let tmp = NewEnvelope {
            from: env.from.clone(),
            from_key: env.from_key.clone(),
            to: env.to.clone(),
            kind: env.kind.clone(),
            subject: env.subject.clone(),
            body: env.body.clone(),
            attachments: env.attachments.clone(),
            in_reply_to: env.in_reply_to.clone(),
            created: env.created.clone(),
        };
        validate(&tmp, &env.id)?;
        Ok(env)
    }

    pub fn unsigned_value(&self) -> Value {
        json!({
            "id": self.id,
            "from": self.from,
            "from_key": self.from_key,
            "to": self.to,
            "kind": self.kind,
            "subject": self.subject,
            "body": self.body,
            "attachments": self.attachments,
            "in_reply_to": self.in_reply_to,
            "created": self.created,
        })
    }

    pub fn verify_self_signature(&self) -> bool {
        let Ok(pub_bytes) = B64.decode(&self.from_key) else {
            return false;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&{
            let mut b = [0u8; 32];
            if pub_bytes.len() != 32 {
                return false;
            }
            b.copy_from_slice(&pub_bytes);
            b
        }) else {
            return false;
        };
        let Ok(sig_bytes) = B64.decode(&self.sig) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let mut s = [0u8; 64];
        s.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&s);
        let msg = canonical_json(&self.unsigned_value());
        vk.verify(msg.as_bytes(), &sig).is_ok()
    }
}

pub fn build_and_sign(id: &str, p: &NewEnvelope, key: &SigningKey) -> Result<Envelope> {
    validate(p, id)?;
    let unsigned = json!({
        "id": id,
        "from": p.from,
        "from_key": p.from_key,
        "to": p.to,
        "kind": p.kind,
        "subject": p.subject,
        "body": p.body,
        "attachments": p.attachments,
        "in_reply_to": p.in_reply_to,
        "created": p.created,
    });
    let msg = canonical_json(&unsigned);
    let sig = B64.encode(key.sign(msg.as_bytes()).to_bytes());
    Ok(Envelope {
        id: id.to_string(),
        from: p.from.clone(),
        from_key: p.from_key.clone(),
        to: p.to.clone(),
        kind: p.kind.clone(),
        subject: p.subject.clone(),
        body: p.body.clone(),
        attachments: p.attachments.clone(),
        in_reply_to: p.in_reply_to.clone(),
        created: p.created.clone(),
        sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(from: &str, key_b64: &str, to: &str) -> NewEnvelope {
        NewEnvelope {
            from: from.into(),
            from_key: key_b64.into(),
            to: to.into(),
            kind: "handoff".into(),
            subject: "handoff notes".into(),
            body: "here is the state".into(),
            attachments: vec![],
            in_reply_to: None,
            created: "2026-11-01T12:00:00Z".into(),
        }
    }

    fn fixtures() -> (ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
        use rand::rngs::OsRng;
        (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        )
    }

    #[test]
    fn sign_verify_round_trip() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let env =
            build_and_sign(&"ab".repeat(16), &parts("alice", &from_key, "zoe"), &alice).unwrap();
        assert!(env.verify_self_signature());
        assert_eq!(env.id.len(), 32);
    }

    #[test]
    fn tampered_body_fails() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let mut env =
            build_and_sign(&"cd".repeat(16), &parts("alice", &from_key, "zoe"), &alice).unwrap();
        env.body = "tampered".into();
        assert!(!env.verify_self_signature());
    }

    #[test]
    fn wrong_key_fails() {
        let (alice, mallory) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let env = build_and_sign(
            &"ef".repeat(16),
            &parts("alice", &from_key, "zoe"),
            &mallory,
        )
        .unwrap();
        assert!(!env.verify_self_signature());
    }

    #[test]
    fn limits_enforced() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let mut p = parts("alice", &from_key, "zoe");
        p.subject = "s".repeat(201);
        assert!(build_and_sign(&"11".repeat(16), &p, &alice).is_err());
        let mut p = parts("alice", &from_key, "zoe");
        p.kind = "shout".into();
        assert!(build_and_sign(&"22".repeat(16), &p, &alice).is_err());
        let mut p = parts("alice", &from_key, "zoe");
        p.body = "b".repeat(MAX_BODY_BYTES + 1);
        assert!(build_and_sign(&"33".repeat(16), &p, &alice).is_err());
        let mut p = parts("alice", &from_key, "zoe");
        p.attachments = (0..9)
            .map(|i| Attachment {
                filename: format!("f{i}"),
                sha256: "0".repeat(64),
                size: 1,
            })
            .collect();
        assert!(build_and_sign(&"44".repeat(16), &p, &alice).is_err());
    }

    #[test]
    fn parse_round_trip_and_reject_garbage() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let env =
            build_and_sign(&"55".repeat(16), &parts("alice", &from_key, "zoe"), &alice).unwrap();
        let parsed = Envelope::parse(&serde_json::to_string(&env).unwrap()).unwrap();
        assert_eq!(parsed.id, env.id);
        assert!(Envelope::parse("not json").is_err());
    }
}
