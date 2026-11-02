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
/// Decoded budget for a sealed envelope's ciphertext (`enc.ct`).
pub const MAX_SEALED_CT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attachment {
    pub filename: String,
    pub sha256: String,
    pub size: u64,
}

/// Sealed-payload wire form (`enc` object). Structurally identical to
/// `crypto::SealedBox` but deliberately NOT unified with it: this is the
/// envelope wire type; conversion to/from the crypto type happens in the
/// sealing/unsealing paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealedEnc {
    pub v: u8,
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

/// Envelope content: plaintext mail fields, or a sealed payload. Untagged on
/// the wire — `Plain` serializes its fields inline (v1 shape), `Sealed`
/// serializes `{ "enc": ... }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum EnvelopeContent {
    Plain {
        kind: String,
        subject: String,
        body: String,
        attachments: Vec<Attachment>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        in_reply_to: Option<String>,
    },
    Sealed {
        enc: SealedEnc,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub id: String,
    pub from: String,
    pub from_key: String,
    pub to: String,
    // Flattened between `to` and `created` so plain envelopes serialize in
    // the exact v1 key order (byte-identical wire format).
    #[serde(flatten)]
    pub content: EnvelopeContent,
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
    validate_id_created(id, &p.created)?;
    if !KINDS.contains(&p.kind.as_str()) {
        return bad("kind must be one of note|status|handoff|question");
    }
    if p.subject.chars().count() > MAX_SUBJECT_LEN {
        return bad("subject exceeds 200 chars");
    }
    if p.subject.contains('\n') || p.subject.contains('\r') {
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
        if parent.len() != 32 || !parent.chars().all(|c| c.is_ascii_hexdigit()) {
            return bad("in_reply_to must be a message id");
        }
    }
    Ok(())
}

/// Form-independent rules: 32-hex-char id and RFC 3339 `created`.
fn validate_id_created(id: &str, created: &str) -> Result<()> {
    let bad = |reason: &str| {
        Err(CoreError::InvalidEnvelope {
            reason: reason.to_string(),
        })
    };
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return bad("id must be 32 hex chars");
    }
    if time::OffsetDateTime::parse(created, &time::format_description::well_known::Rfc3339).is_err()
    {
        return bad("created must be an RFC 3339 timestamp");
    }
    Ok(())
}

/// Sealed-form rules: version 1, epk/nonce are base64 for exactly 32/24
/// bytes, and the ciphertext decodes to at most 1 MiB.
fn validate_sealed_enc(enc: &SealedEnc) -> Result<()> {
    let bad = |reason: &str| {
        Err(CoreError::InvalidEnvelope {
            reason: reason.to_string(),
        })
    };
    let decoded_len = |s: &str| B64.decode(s).map(|b| b.len());
    if enc.v != 1 {
        return bad("enc.v must be 1");
    }
    if decoded_len(&enc.epk) != Ok(32) {
        return bad("enc.epk must be base64 for 32 bytes");
    }
    if decoded_len(&enc.nonce) != Ok(24) {
        return bad("enc.nonce must be base64 for 24 bytes");
    }
    if !matches!(decoded_len(&enc.ct), Ok(n) if n <= MAX_SEALED_CT_BYTES) {
        return bad("enc.ct must be base64 for at most 1 MiB");
    }
    Ok(())
}

/// Mixed-form guard (the untagged pitfall): untagged enum variants silently
/// ignore fields they do not know, so an envelope carrying BOTH `enc` and
/// plain content fields would deserialize as `Plain` and drop `enc` on the
/// floor — and serde offers no per-variant `deny_unknown_fields` to stop it.
/// Reject any object mixing the two forms before deserializing.
fn reject_mixed_forms(value: &Value) -> Result<()> {
    const PLAIN_FIELDS: [&str; 5] = ["kind", "subject", "body", "attachments", "in_reply_to"];
    if let Some(obj) = value.as_object() {
        if obj.contains_key("enc") && PLAIN_FIELDS.iter().any(|f| obj.contains_key(*f)) {
            return Err(CoreError::InvalidEnvelope {
                reason: "mixed plain and sealed content fields".into(),
            });
        }
    }
    Ok(())
}

impl Envelope {
    pub fn parse(raw: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(raw)?;
        reject_mixed_forms(&value)?;
        let env: Envelope = serde_json::from_value(value)?;
        match &env.content {
            EnvelopeContent::Plain {
                kind,
                subject,
                body,
                attachments,
                in_reply_to,
            } => {
                let tmp = NewEnvelope {
                    from: env.from.clone(),
                    from_key: env.from_key.clone(),
                    to: env.to.clone(),
                    kind: kind.clone(),
                    subject: subject.clone(),
                    body: body.clone(),
                    attachments: attachments.clone(),
                    in_reply_to: in_reply_to.clone(),
                    created: env.created.clone(),
                };
                validate(&tmp, &env.id)?;
            }
            EnvelopeContent::Sealed { enc } => {
                validate_id_created(&env.id, &env.created)?;
                validate_sealed_enc(enc)?;
            }
        }
        Ok(env)
    }

    pub fn unsigned_value(&self) -> Value {
        match &self.content {
            EnvelopeContent::Plain {
                kind,
                subject,
                body,
                attachments,
                in_reply_to,
            } => json!({
                "id": self.id,
                "from": self.from,
                "from_key": self.from_key,
                "to": self.to,
                "kind": kind,
                "subject": subject,
                "body": body,
                "attachments": attachments,
                "in_reply_to": in_reply_to,
                "created": self.created,
            }),
            EnvelopeContent::Sealed { enc } => json!({
                "id": self.id,
                "from": self.from,
                "from_key": self.from_key,
                "to": self.to,
                "created": self.created,
                "enc": enc,
            }),
        }
    }

    pub fn is_sealed(&self) -> bool {
        matches!(self.content, EnvelopeContent::Sealed { .. })
    }

    /// Display label for the kind: the real kind for plain mail, "sealed"
    /// for sealed mail (the kind travels inside the ciphertext).
    pub fn kind_label(&self) -> &str {
        match &self.content {
            EnvelopeContent::Plain { kind, .. } => kind,
            EnvelopeContent::Sealed { .. } => "sealed",
        }
    }

    /// Display label for the subject: the real subject for plain mail,
    /// "<sealed>" for sealed mail.
    pub fn subject_label(&self) -> &str {
        match &self.content {
            EnvelopeContent::Plain { subject, .. } => subject,
            EnvelopeContent::Sealed { .. } => "<sealed>",
        }
    }

    /// Threading reference, if any. Sealed envelopes carry it inside the
    /// ciphertext, so nothing is exposed here.
    pub fn in_reply_to_ref(&self) -> Option<&str> {
        match &self.content {
            EnvelopeContent::Plain { in_reply_to, .. } => in_reply_to.as_deref(),
            EnvelopeContent::Sealed { .. } => None,
        }
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
        content: EnvelopeContent::Plain {
            kind: p.kind.clone(),
            subject: p.subject.clone(),
            body: p.body.clone(),
            attachments: p.attachments.clone(),
            in_reply_to: p.in_reply_to.clone(),
        },
        created: p.created.clone(),
        sig,
    })
}

/// Build and sign a sealed envelope: the content is an opaque `enc` payload
/// (produced by the crypto layer); the signature covers it exactly as
/// `unsigned_value()` serializes it.
pub fn build_and_sign_sealed(
    id: &str,
    from: &str,
    from_key: &str,
    to: &str,
    created: &str,
    enc: SealedEnc,
    key: &SigningKey,
) -> Result<Envelope> {
    validate_id_created(id, created)?;
    validate_sealed_enc(&enc)?;
    let unsigned = json!({
        "id": id,
        "from": from,
        "from_key": from_key,
        "to": to,
        "created": created,
        "enc": enc,
    });
    let msg = canonical_json(&unsigned);
    let sig = B64.encode(key.sign(msg.as_bytes()).to_bytes());
    Ok(Envelope {
        id: id.to_string(),
        from: from.to_string(),
        from_key: from_key.to_string(),
        to: to.to_string(),
        content: EnvelopeContent::Sealed { enc },
        created: created.to_string(),
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
        if let EnvelopeContent::Plain { body, .. } = &mut env.content {
            *body = "tampered".into();
        }
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
    fn attachment_size_limits_enforced() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        // per-file: one attachment over 10 MiB
        let big = Attachment {
            filename: "big".into(),
            sha256: "0".repeat(64),
            size: MAX_ATTACHMENT_BYTES + 1,
        };
        let mut p = parts("alice", &from_key, "zoe");
        p.attachments = vec![big];
        assert!(build_and_sign("88".repeat(16).as_str(), &p, &alice).is_err());
        // total: 3 files of 9 MiB = 27 MiB > 25 MiB, count 3 <= 8, so the
        // TOTAL limit is what trips (9 files would hit the count limit first)
        let mid = Attachment {
            filename: "m".into(),
            sha256: "0".repeat(64),
            size: 9 * 1024 * 1024,
        };
        let mut p = parts("alice", &from_key, "zoe");
        p.attachments = vec![mid; 3];
        assert!(build_and_sign("99".repeat(16).as_str(), &p, &alice).is_err());
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

    #[test]
    fn sealed_envelope_round_trip_and_validation() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        // epk is canonically padded base64 for 32 B; nonce for 24 B ("A"*43
        // unpadded would be rejected by the STANDARD engine's padding rules)
        let enc = SealedEnc {
            v: 1,
            epk: format!("{}=", "A".repeat(43)),
            nonce: "A".repeat(32),
            ct: "QUJD".into(),
        };
        let env = build_and_sign_sealed(
            "ee".repeat(16).as_str(),
            "alice",
            &from_key,
            "zoe",
            "2026-11-01T12:00:00Z",
            enc.clone(),
            &alice,
        )
        .unwrap();
        assert!(env.is_sealed());
        assert_eq!(env.kind_label(), "sealed");
        assert_eq!(env.subject_label(), "<sealed>");
        let parsed = Envelope::parse(&serde_json::to_string(&env).unwrap()).unwrap();
        assert!(parsed.verify_self_signature());
        // unsigned_value must include enc: tampering enc breaks the signature
        let mut tampered = parsed.clone();
        if let EnvelopeContent::Sealed { enc } = &mut tampered.content {
            enc.ct = "REQA".into();
        }
        assert!(!tampered.verify_self_signature());
        // bad version rejected
        let mut bad = env.clone();
        if let EnvelopeContent::Sealed { enc } = &mut bad.content {
            enc.v = 2;
        }
        assert!(Envelope::parse(&serde_json::to_string(&bad).unwrap()).is_err());
    }

    #[test]
    fn plain_wire_format_unchanged() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let env = build_and_sign(
            "ff".repeat(16).as_str(),
            &parts("alice", &from_key, "zoe"),
            &alice,
        )
        .unwrap();
        let s = serde_json::to_string(&env).unwrap();
        // v1 key order pinned: content fields sit between "to" and "created"
        let to = s.find("\"to\":").expect("to present");
        let kind = s.find("\"kind\":").expect("kind present");
        let created = s.find("\"created\":").expect("created present");
        let sig = s.find("\"sig\":").expect("sig present");
        assert!(
            to < kind && kind < created && created < sig,
            "wire order drifted: {s}"
        );
        // no top-level enc KEY (not substring-matching base64 payloads)
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("enc").is_none());
        assert!(v.get("subject").is_some());
        assert!(Envelope::parse(&s).unwrap().verify_self_signature());
    }

    #[test]
    fn mixed_forms_are_rejected() {
        let raw = serde_json::json!({
            "id": "ab".repeat(16), "from": "a", "from_key": "AAAA", "to": "z",
            "created": "2026-11-01T12:00:00Z",
            "enc": { "v": 1, "epk": "AAAA", "nonce": "AAAA", "ct": "AAAA" },
            "body": "leaked", "kind": "note", "subject": "s", "attachments": [],
            "sig": "AAAA"
        });
        assert!(Envelope::parse(&raw.to_string()).is_err());
    }

    #[test]
    fn parse_rejects_bad_created_in_reply_to_and_cr() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let mut p = parts("alice", &from_key, "zoe");
        p.created = "not a date".into();
        assert!(build_and_sign("66".repeat(16).as_str(), &p, &alice).is_err());

        // parse-time rejection of a hand-edited envelope
        let env = build_and_sign(
            "77".repeat(16).as_str(),
            &parts("alice", &from_key, "zoe"),
            &alice,
        )
        .unwrap();
        let tamper = |env: &Envelope, field: &str, value: String| {
            let mut e = env.clone();
            match field {
                "created" => e.created = value,
                "in_reply_to" | "subject" => {
                    let EnvelopeContent::Plain {
                        in_reply_to,
                        subject,
                        ..
                    } = &mut e.content
                    else {
                        unreachable!("fixture is plain")
                    };
                    match field {
                        "in_reply_to" => *in_reply_to = Some(value),
                        "subject" => *subject = value,
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
            // re-sign so ONLY the semantic rule is under test, not the signature
            let EnvelopeContent::Plain {
                kind,
                subject,
                body,
                attachments,
                in_reply_to,
            } = &e.content
            else {
                unreachable!("fixture is plain")
            };
            build_and_sign(
                &e.id,
                &NewEnvelope {
                    from: e.from.clone(),
                    from_key: e.from_key.clone(),
                    to: e.to.clone(),
                    kind: kind.clone(),
                    subject: subject.clone(),
                    body: body.clone(),
                    attachments: attachments.clone(),
                    in_reply_to: in_reply_to.clone(),
                    created: e.created.clone(),
                },
                &alice,
            )
        };
        assert!(tamper(&env, "created", "yesterday".into()).is_err());
        assert!(tamper(&env, "in_reply_to", "zz".repeat(16)).is_err()); // right length, not hex
        assert!(tamper(&env, "in_reply_to", "ab".repeat(16)).is_ok()); // valid hex is fine
        assert!(tamper(&env, "subject", "has\rreturn".into()).is_err());
    }
}
