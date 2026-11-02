//! ECIES for sealed envelopes (spec: 2026-11-01-cmail-sealed-envelopes-design §2).
//!
//! X25519 keys are the Montgomery form of existing Ed25519 identity keys;
//! HKDF-SHA256 labels derive the message key and per-attachment subkeys from
//! ONE ECDH; XChaCha20-Poly1305 (ChaCha20-Poly1305 with the spec's 24-byte
//! nonce) provides the AEAD.
use crate::error::{CoreError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// HKDF info label for the message-body key.
pub const MSG_LABEL: &str = "cmail/v1/msg";

/// HKDF info label for attachment `i` (zero-based).
pub fn att_label(i: usize) -> String {
    format!("cmail/v1/att/{i}")
}

/// ECIES ciphertext (wire form): base64 ephemeral public key (32B),
/// base64 nonce (24B), base64 ciphertext+tag.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SealedBox {
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

/// X25519 secret derived deterministically from an Ed25519 signing key
/// (Montgomery conversion; pairs with [`x25519_public`]).
pub fn x25519_secret(signing: &SigningKey) -> StaticSecret {
    StaticSecret::from(signing.to_scalar_bytes())
}

/// X25519 public key derived from an Ed25519 verifying key (Montgomery form).
pub fn x25519_public(verifying: &VerifyingKey) -> PublicKey {
    PublicKey::from(verifying.to_montgomery().to_bytes())
}

/// Recipient encrypt-to key from a stored base64 Ed25519 public key.
pub fn recipient_public_from_b64(from_key_b64: &str) -> Option<PublicKey> {
    let raw = B64.decode(from_key_b64).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&raw);
    Some(x25519_public(&VerifyingKey::from_bytes(&b).ok()?))
}

/// msg/att key = HKDF-SHA256(ikm = shared, salt = SHA256(epk || recipient_pub),
/// info = label) — one ECDH per message, keys domain-separated by label.
fn derive_key(
    shared: &[u8; 32],
    epk: &[u8; 32],
    recipient_pub: &[u8; 32],
    label: &str,
) -> [u8; 32] {
    let mut salt_input = Vec::with_capacity(64);
    salt_input.extend_from_slice(epk);
    salt_input.extend_from_slice(recipient_pub);
    let salt = Sha256::digest(&salt_input);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(label.as_bytes(), &mut key)
        .expect("32-byte output is valid");
    key
}

/// One sealing session per message: a single ephemeral keypair shared by the
/// message body and every attachment, so there is exactly one ECDH.
pub struct SealSession {
    ephemeral: StaticSecret,
    epk: PublicKey,
    recipient: PublicKey,
}

impl SealSession {
    pub fn new(recipient: &PublicKey) -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let ephemeral = StaticSecret::from(secret);
        let epk = PublicKey::from(&ephemeral);
        Self {
            ephemeral,
            epk,
            recipient: *recipient,
        }
    }

    pub fn seal(&self, label: &str, plaintext: &[u8]) -> Result<SealedBox> {
        let shared = self.ephemeral.diffie_hellman(&self.recipient);
        let key = derive_key(
            shared.as_bytes(),
            self.epk.as_bytes(),
            self.recipient.as_bytes(),
            label,
        );
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ct = XChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| CoreError::DecryptFailed("encrypt failed".into()))?;
        Ok(SealedBox {
            epk: B64.encode(self.epk.as_bytes()),
            nonce: B64.encode(nonce_bytes),
            ct: B64.encode(ct),
        })
    }
}

/// Decrypt a [`SealedBox`] for the recipient holding `recipient_secret`.
/// Returns [`CoreError::DecryptFailed`] on any decode or AEAD failure
/// (wrong key, wrong label, tampered bytes).
pub fn open(recipient_secret: &StaticSecret, sealed: &SealedBox, label: &str) -> Result<Vec<u8>> {
    let fail =
        || CoreError::DecryptFailed("cannot decrypt (sealed for a different identity?)".into());
    let epk_raw = B64.decode(&sealed.epk).map_err(|_| fail())?;
    if epk_raw.len() != 32 {
        return Err(fail());
    }
    let mut epk = [0u8; 32];
    epk.copy_from_slice(&epk_raw);
    let nonce_raw = B64.decode(&sealed.nonce).map_err(|_| fail())?;
    if nonce_raw.len() != 24 {
        return Err(fail());
    }
    let ct = B64.decode(&sealed.ct).map_err(|_| fail())?;
    let epk_point = PublicKey::from(epk);
    let shared = recipient_secret.diffie_hellman(&epk_point);
    let recipient_pub = PublicKey::from(recipient_secret);
    let key = derive_key(shared.as_bytes(), &epk, recipient_pub.as_bytes(), label);
    XChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(XNonce::from_slice(&nonce_raw), ct.as_ref())
        .map_err(|_| fail())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn idpair() -> (SigningKey, SigningKey) {
        (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        )
    }

    #[test]
    fn key_conversion_is_deterministic() {
        let (a, _) = idpair();
        let s1 = x25519_secret(&a);
        let s2 = x25519_secret(&a);
        assert_eq!(s1.to_bytes(), s2.to_bytes());
        // DH symmetry: converted keys actually agree
        let (_, b) = idpair();
        let shared_ab = x25519_secret(&a).diffie_hellman(&x25519_public(&b.verifying_key()));
        let shared_ba = x25519_secret(&b).diffie_hellman(&x25519_public(&a.verifying_key()));
        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn seal_open_round_trip_and_labels_are_bound() {
        let (alice, _) = idpair();
        let recipient = x25519_public(&alice.verifying_key());
        let session = SealSession::new(&recipient);
        let sb = session.seal("cmail/v1/msg", b"payload bytes").unwrap();
        let opened = open(&x25519_secret(&alice), &sb, "cmail/v1/msg").unwrap();
        assert_eq!(opened, b"payload bytes");
        // same box, wrong label -> key mismatch -> DecryptFailed
        assert!(matches!(
            open(&x25519_secret(&alice), &sb, "cmail/v1/att/0"),
            Err(crate::error::CoreError::DecryptFailed(_))
        ));
    }

    #[test]
    fn wrong_recipient_and_tamper_fail() {
        let (alice, mallory) = idpair();
        let recipient = x25519_public(&alice.verifying_key());
        let session = SealSession::new(&recipient);
        let sb = session.seal("cmail/v1/msg", b"secret").unwrap();
        assert!(open(&x25519_secret(&mallory), &sb, "cmail/v1/msg").is_err());
        // tamper the ciphertext (flip last ct byte via b64 decode/re-encode)
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(&sb.ct)
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = SealedBox {
            epk: sb.epk.clone(),
            nonce: sb.nonce.clone(),
            ct: base64::engine::general_purpose::STANDARD.encode(raw),
        };
        assert!(matches!(
            open(&x25519_secret(&alice), &tampered, "cmail/v1/msg"),
            Err(crate::error::CoreError::DecryptFailed(_))
        ));
    }

    #[test]
    fn attachment_keys_are_independent() {
        let (alice, _) = idpair();
        let recipient = x25519_public(&alice.verifying_key());
        let session = SealSession::new(&recipient);
        let a0 = session.seal("cmail/v1/att/0", b"file zero").unwrap();
        let a1 = session.seal("cmail/v1/att/1", b"file one").unwrap();
        assert_eq!(
            open(&x25519_secret(&alice), &a0, "cmail/v1/att/0").unwrap(),
            b"file zero"
        );
        assert!(open(&x25519_secret(&alice), &a0, "cmail/v1/att/1").is_err());
        assert_eq!(
            open(&x25519_secret(&alice), &a1, "cmail/v1/att/1").unwrap(),
            b"file one"
        );
    }

    #[test]
    fn recipient_public_from_b64_round_trips() {
        let (alice, _) = idpair();
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(alice.verifying_key().as_bytes());
        assert!(recipient_public_from_b64(&b64).is_some());
        assert!(recipient_public_from_b64("not-b64!!").is_none());
    }
}
