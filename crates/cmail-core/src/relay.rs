//! Relay wire protocol v1: parcel format + HTTP client transport
//! (spec: 2026-11-01-cmail-relays-design §2).
//!
//! A **parcel** bundles a sealed envelope with its encrypted attachment
//! frames for remote delivery. The HTTP client speaks the five-route
//! protocol: open `POST /mailbox/{fp}`, authenticated (nonce-challenge
//! Ed25519) list/fetch/ack. The relay is zero-trust: it never parses inside
//! the envelope, so this module treats the envelope as an opaque blob.
use crate::envelope::Envelope;
use crate::error::{CoreError, Result};
use crate::identity::fingerprint_of;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;

/// Parcel protocol version (spec §2.1 pins v1 for interop).
pub const PARCEL_VERSION: u8 = 1;
/// Maximum attachment frames per parcel (spec §2.1).
pub const MAX_PARCEL_ATTACHMENTS: usize = 8;
/// Maximum total decoded attachment bytes per parcel (spec §2.1: 36 MiB).
pub const MAX_PARCEL_BYTES: usize = 36 * 1024 * 1024;

/// Canonical loopback base for insecure-local testing. Plaintext HTTP is
/// allowed only for loopback (spec §2.2); [`normalize_base`] enforces it.
pub const INSECURE_LOCAL: &str = "http://127.0.0.1";

/// Per-request timeout for all relay HTTP calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Safety cap when reading response bodies (a max-size parcel is ~48 MB of
/// base64 + JSON overhead; this stops a hostile server from streaming
/// forever).
const MAX_RESPONSE_BODY: u64 = 64 * 1024 * 1024;

/// The unit of transfer: a sealed envelope plus its encrypted attachment
/// frames in one body (spec §2.1). `pubkey` is the RECIPIENT's Ed25519
/// public key (b64); the relay checks `fingerprint(pubkey) == {fp}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Parcel {
    pub v: u8,
    pub pubkey: String,
    pub envelope: Envelope,
    pub attachments: Vec<ParcelAttachment>,
}

/// One encrypted attachment frame: index `i` (matching the envelope's
/// attachment order) and the b64 of the raw `att-<i>.bin` frame bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParcelAttachment {
    pub i: usize,
    pub data: String,
}

impl Parcel {
    /// Structural validation per spec §2.1: v == 1, pubkey is b64 for 32
    /// bytes (so its fingerprint is meaningful), count <= 8, every `data`
    /// decodes as standard base64, total decoded <= 36 MiB.
    pub fn validate(&self) -> Result<()> {
        if self.v != PARCEL_VERSION {
            return Err(CoreError::InvalidEnvelope {
                reason: format!("parcel v must be 1, got {}", self.v),
            });
        }
        match B64.decode(&self.pubkey).map(|raw| raw.len()) {
            Ok(32) => {}
            _ => {
                return Err(CoreError::InvalidEnvelope {
                    reason: "parcel pubkey must be base64 for 32 bytes".into(),
                })
            }
        }
        if self.attachments.len() > MAX_PARCEL_ATTACHMENTS {
            return Err(CoreError::LimitExceeded(
                "parcel carries more than 8 attachments".into(),
            ));
        }
        let mut total = 0usize;
        for att in &self.attachments {
            let decoded = B64
                .decode(&att.data)
                .map_err(|_| CoreError::InvalidEnvelope {
                    reason: format!("parcel attachment {} data is not valid base64", att.i),
                })?;
            total += decoded.len();
        }
        if total > MAX_PARCEL_BYTES {
            return Err(CoreError::LimitExceeded(
                "parcel attachments exceed 36 MiB total".into(),
            ));
        }
        Ok(())
    }
}

/// Build a parcel for `recipient_pubkey_b64` (the mailbox owner's Ed25519
/// public key, b64) from a sealed envelope and its attachment frames
/// `(index, raw frame bytes)`; frames are b64-encoded here. Rejects bad
/// pubkeys, duplicate indices, more than 8 frames, or frames over the
/// 36 MiB budget.
pub fn build_parcel(
    env: &Envelope,
    attachment_frames: &[(usize, Vec<u8>)],
    recipient_pubkey_b64: &str,
) -> Result<Parcel> {
    if B64.decode(recipient_pubkey_b64).map(|raw| raw.len()) != Ok(32) {
        return Err(CoreError::InvalidEnvelope {
            reason: "recipient pubkey must be base64 for 32 bytes".into(),
        });
    }
    if attachment_frames.len() > MAX_PARCEL_ATTACHMENTS {
        return Err(CoreError::LimitExceeded(
            "parcel carries more than 8 attachments".into(),
        ));
    }
    let mut indices: Vec<usize> = attachment_frames.iter().map(|(i, _)| *i).collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.len() != attachment_frames.len() {
        return Err(CoreError::InvalidEnvelope {
            reason: "duplicate attachment index in parcel".into(),
        });
    }
    let attachments = attachment_frames
        .iter()
        .map(|(i, frame)| ParcelAttachment {
            i: *i,
            data: B64.encode(frame),
        })
        .collect();
    let parcel = Parcel {
        v: PARCEL_VERSION,
        pubkey: recipient_pubkey_b64.to_string(),
        envelope: env.clone(),
        attachments,
    };
    parcel.validate()?;
    Ok(parcel)
}

/// Sign a challenge nonce: b64 Ed25519 signature over the ASCII bytes of
/// the nonce string (spec §2 auth). One nonce grants ONE request.
pub fn sign_challenge(signing: &SigningKey, nonce: &str) -> String {
    B64.encode(signing.sign(nonce.as_bytes()).to_bytes())
}

/// Normalize a relay base URL: trim whitespace and trailing `/`; require
/// `https://` unless the host is loopback (`127.0.0.1` / `localhost` /
/// `[::1]`), where plaintext HTTP is allowed for insecure-local testing
/// (spec §2.2). Parsed with `url::Url` so userinfo (`http://127.0.0.1@evil.com`)
/// cannot spoof a loopback host into a plaintext exemption.
pub fn normalize_base(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let url = url::Url::parse(trimmed)
        .map_err(|e| CoreError::Config(format!("invalid relay url: {e}")))?;
    let host = url.host_str().unwrap_or_default();
    let loopback = host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost") || host == "[::1]";
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => {
            return Err(CoreError::Config(format!(
                "relay url must be https (http allowed only for loopback): {raw}"
            )))
        }
    }
    Ok(trimmed.to_string())
}

/// Client-side mirror of the relay's fp check (spec §2.1: fingerprint of
/// the parcel pubkey must equal the mailbox fp in the URL) — catches
/// misrouted parcels before any network I/O.
fn ensure_fp_matches(pubkey_b64: &str, fp: &str) -> Result<()> {
    let actual = fingerprint_of(pubkey_b64);
    if actual == fp {
        Ok(())
    } else {
        Err(CoreError::Relay(format!(
            "parcel pubkey fingerprint {actual} does not match mailbox {fp}"
        )))
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build()
}

/// `ureq::Response::into_string` caps at 10 MB — parcels reach ~36 MB
/// encoded — so read via `into_reader` with an explicit safety cap.
fn read_body(resp: ureq::Response) -> Result<String> {
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BODY)
        .read_to_end(&mut buf)
        .map_err(|e| CoreError::Relay(format!("reading relay response: {e}")))?;
    String::from_utf8(buf)
        .map_err(|e| CoreError::Relay(format!("relay response is not UTF-8: {e}")))
}

/// Error text for a non-2xx response: status plus the body (the relay's
/// `{"error": "..."}`), truncated to ~200 chars.
fn status_error(status: u16, body: &str) -> CoreError {
    CoreError::Relay(format!(
        "HTTP {status}: {}",
        body.chars().take(200).collect::<String>()
    ))
}

/// Map a finished ureq call to the response body string: 2xx → body;
/// non-2xx (ureq surfaces >= 400 as `Error::Status`) → `CoreError::Relay`
/// carrying the response body text; transport failures → `CoreError::Relay`.
fn map_ureq(result: std::result::Result<ureq::Response, ureq::Error>) -> Result<String> {
    match result {
        Ok(resp) | Err(ureq::Error::Status(_, resp)) => {
            let status = resp.status();
            let body = read_body(resp).unwrap_or_default();
            if (200..300).contains(&status) {
                Ok(body)
            } else {
                Err(status_error(status, &body))
            }
        }
        Err(e) => Err(CoreError::Relay(e.to_string())),
    }
}

/// `GET /challenge/{fp}` → the nonce string (spec §2).
fn challenge(agent: &ureq::Agent, base: &str, fp: &str) -> Result<String> {
    let body = map_ureq(agent.get(&format!("{base}/challenge/{fp}")).call())?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| CoreError::Relay(format!("bad challenge response: {e}")))?;
    let nonce = value
        .get("nonce")
        .and_then(|n| n.as_str())
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .ok_or_else(|| CoreError::Relay("challenge response missing nonce".into()))?;
    Ok(nonce)
}

/// One authenticated request (spec §2: fetch a fresh challenge per request
/// — the nonce is consumed on success). Signs the nonce, sends the method
/// with `X-cmail-Fp`/`X-cmail-Signature` headers, returns the response body.
fn authed(
    agent: &ureq::Agent,
    base: &str,
    method: &str,
    path: &str,
    fp: &str,
    signing: &SigningKey,
    body: Option<&str>,
) -> Result<String> {
    let nonce = challenge(agent, base, fp)?;
    let signature = sign_challenge(signing, &nonce);
    let url = format!("{base}{path}");
    match body {
        Some(json) => map_ureq(
            agent
                .request(method, &url)
                .set("X-cmail-Fp", fp)
                .set("X-cmail-Signature", &signature)
                .set("Content-Type", "application/json")
                .send_string(json),
        ),
        None => map_ureq(
            agent
                .request(method, &url)
                .set("X-cmail-Fp", fp)
                .set("X-cmail-Signature", &signature)
                .call(),
        ),
    }
}

/// `POST /mailbox/{fp}` with the Parcel body (open route, spec §2).
/// Client-side pre-checks: parcel validity and fingerprint(pubkey) == fp.
pub fn deposit(base_url: &str, fp: &str, parcel: &Parcel) -> Result<()> {
    let base = normalize_base(base_url)?;
    parcel.validate()?;
    ensure_fp_matches(&parcel.pubkey, fp)?;
    let body = serde_json::to_string(parcel)?;
    map_ureq(
        agent()
            .post(&format!("{base}/mailbox/{fp}"))
            .set("Content-Type", "application/json")
            .send_string(&body),
    )?;
    Ok(())
}

/// `GET /mailbox/{fp}` (auth) → pending parcel ids.
pub fn list_pending(base_url: &str, fp: &str, signing: &SigningKey) -> Result<Vec<String>> {
    let base = normalize_base(base_url)?;
    let body = authed(
        &agent(),
        &base,
        "GET",
        &format!("/mailbox/{fp}"),
        fp,
        signing,
        None,
    )?;
    #[derive(Deserialize)]
    struct IdList {
        ids: Vec<String>,
    }
    let list: IdList = serde_json::from_str(&body)
        .map_err(|e| CoreError::Relay(format!("bad mailbox listing: {e}")))?;
    Ok(list.ids)
}

/// `GET /mailbox/{fp}/{id}` (auth) → parsed + validated parcel.
pub fn fetch_parcel(base_url: &str, fp: &str, id: &str, signing: &SigningKey) -> Result<Parcel> {
    let base = normalize_base(base_url)?;
    let body = authed(
        &agent(),
        &base,
        "GET",
        &format!("/mailbox/{fp}/{id}"),
        fp,
        signing,
        None,
    )?;
    let parcel: Parcel = serde_json::from_str(&body)
        .map_err(|e| CoreError::Relay(format!("bad parcel response: {e}")))?;
    parcel.validate()?;
    ensure_fp_matches(&parcel.pubkey, fp)?;
    Ok(parcel)
}

/// `DELETE /mailbox/{fp}/{id}` (auth) → acknowledge receipt.
pub fn ack(base_url: &str, fp: &str, id: &str, signing: &SigningKey) -> Result<()> {
    let base = normalize_base(base_url)?;
    authed(
        &agent(),
        &base,
        "DELETE",
        &format!("/mailbox/{fp}/{id}"),
        fp,
        signing,
        None,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{build_and_sign, new_id, NewEnvelope};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn envelope_fixture() -> (Envelope, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let from_key = B64.encode(key.verifying_key().as_bytes());
        let env = build_and_sign(
            &new_id(),
            &NewEnvelope {
                from: "a".into(),
                from_key,
                to: "z".into(),
                kind: "note".into(),
                subject: "s".into(),
                body: "b".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            &key,
        )
        .unwrap();
        (env, key)
    }

    fn recipient_key_b64() -> String {
        B64.encode(SigningKey::generate(&mut OsRng).verifying_key().as_bytes())
    }

    #[test]
    fn parcel_round_trip_preserves_frames_byte_identically() {
        let (env, _) = envelope_fixture();
        let recipient = recipient_key_b64();
        let frames = vec![(0usize, vec![1u8, 2, 3, 4]), (1usize, vec![9u8; 40])];
        let parcel = build_parcel(&env, &frames, &recipient).unwrap();
        assert_eq!(parcel.v, 1);
        assert_eq!(parcel.attachments.len(), 2);
        let json = serde_json::to_string(&parcel).unwrap();
        let back: Parcel = serde_json::from_str(&json).unwrap();
        back.validate().unwrap();
        // frames decode byte-identically, index order preserved
        assert_eq!(back.attachments[0].i, 0);
        let d0: Vec<u8> = B64.decode(&back.attachments[0].data).unwrap();
        assert_eq!(d0, vec![1, 2, 3, 4]);
        let d1: Vec<u8> = B64.decode(&back.attachments[1].data).unwrap();
        assert_eq!(d1, vec![9u8; 40]);
    }

    #[test]
    fn parcel_validation_rejects_bad() {
        let (env, _) = envelope_fixture();
        let recipient = recipient_key_b64();
        let mut p = build_parcel(&env, &[], &recipient).unwrap();
        p.v = 2;
        assert!(p.validate().is_err());
        let mut p = build_parcel(&env, &[], &recipient).unwrap();
        p.attachments = (0..9)
            .map(|i| ParcelAttachment {
                i,
                data: "AAAA".into(),
            })
            .collect();
        assert!(p.validate().is_err());
        // b64 rejection: one VALID attachment first, then corrupt its data
        let mut p = build_parcel(&env, &[(0, vec![1u8, 2, 3])], &recipient).unwrap();
        p.attachments[0].data = "!!not b64!!".into();
        assert!(p.validate().is_err());
        // build-side guards: frame count cap and bad recipient pubkey
        let nine: Vec<(usize, Vec<u8>)> = (0..9).map(|i| (i, vec![0u8; 4])).collect();
        assert!(build_parcel(&env, &nine, &recipient).is_err());
        assert!(build_parcel(&env, &[], "not-b64!!").is_err());
        // fingerprint/pubkey mismatch rejection (spec §6)
        let fp = crate::identity::fingerprint_of(&recipient);
        assert!(ensure_fp_matches(&recipient, &fp).is_ok());
        assert!(ensure_fp_matches(&recipient, "0000000000000000").is_err());
    }

    #[test]
    fn challenge_signature_verifies() {
        let key = SigningKey::generate(&mut OsRng);
        let nonce = "abc123nonce";
        let sig_b64 = sign_challenge(&key, nonce);
        use ed25519_dalek::Verifier;
        let raw = B64.decode(&sig_b64).unwrap();
        let mut b = [0u8; 64];
        b.copy_from_slice(&raw);
        key.verifying_key()
            .verify(nonce.as_bytes(), &ed25519_dalek::Signature::from_bytes(&b))
            .unwrap();
    }

    #[test]
    fn normalize_base_enforces_tls_except_loopback() {
        assert!(normalize_base("https://relay.example.com/")
            .unwrap()
            .ends_with("relay.example.com"));
        assert_eq!(
            normalize_base("https://relay.example.com/").unwrap(),
            "https://relay.example.com"
        );
        assert_eq!(
            normalize_base("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(normalize_base("http://localhost:3000").is_ok());
        assert!(normalize_base("http://relay.example.com").is_err());
        assert!(normalize_base("ftp://relay.example.com").is_err());
        assert!(normalize_base("relay.example.com").is_err());
        assert!(
            normalize_base("http://127.0.0.1:8080@evil.com/").is_err(),
            "userinfo must not spoof loopback"
        );
        assert!(normalize_base("http://[::1]:8080").is_ok());
    }
}
