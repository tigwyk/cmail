# cmail v1.1 — Sealed Envelopes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** End-to-end encryption of envelope content (subject/kind/body/attachments/threading) to the recipient's identity key, transparently, without changing the v1 trust machinery, CLI surface, or readability of existing mail — per spec `docs/superpowers/specs/2026-11-01-cmail-sealed-envelopes-design.md`.

**Architecture:** A new `crypto` module in `cmail-core` (ECIES: X25519 via Montgomery conversion of existing Ed25519 identity keys, HKDF-SHA256 labels, ChaCha20-Poly1305 AEAD). `Envelope` gains an untagged content enum: `Plain` (v1 wire, byte-identical) or `Sealed` (`enc` box). Send always seals; read decrypts after unchanged signature/trust verification on the visible header. One ECDH per message (shared `epk`), independent AEAD per label (`cmail/v1/msg`, `cmail/v1/att/<i>`).

**Tech Stack:** new deps `x25519-dalek` 2, `hkdf` 0.12, `chacha20poly1305` 0.10 (RustCrypto/dalek family; `sha2` already present). Everything else unchanged.

## Global Constraints

- Spec is authoritative: `docs/superpowers/specs/2026-11-01-cmail-sealed-envelopes-design.md`. Read it first.
- v1 plain envelopes remain fully readable and wire-identical; every existing test that doesn't explicitly opt into sealing must keep passing (back-compat is the proof).
- Visible header on sealed mail: `id, from, from_key, to, created, sig` + `enc`. `sig` covers `enc` (epk/nonce/ct) — unsigned_value for sealed includes `enc`, excludes content.
- HKDF labels verbatim: `"cmail/v1/msg"`, `"cmail/v1/att/<i>"` (i zero-based decimal). `salt = SHA256(epk || recipient_x25519_pub)`.
- Wire caps: `ct` ≤ 1 MiB; attachment ciphertext file ≤ `MAX_ATTACHMENT_BYTES + 1024`; plaintext caps (subject 200, body 256 KiB, ≤8 attachments, totals) enforced on plaintext after decrypt and at seal time.
- Placeholders on any non-decrypting surface: `subject: "<sealed>"`, `kind: "sealed"` (inbox/list/quarantine-list/approvals).
- Decrypt failure = `CoreError::DecryptFailed` ("cannot decrypt (sealed for a different identity?)"), message stays in place, audit `corrupt` with detail `"decrypt failed"`. Never crash on bad crypto input.
- Fingerprints remain of the Ed25519 key. No new key files, no keyring format change.
- Every task: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` clean, full `cargo test --workspace` green before commit. House style `#[expect]` > `#[allow]`.
- Version bumps to 0.2.0 in Task E7 only.
- Baseline: main @ 0e91a0f, 71 tests.

---

### Task E1: Crypto module (ECIES over converted identity keys)

**Files:**
- Create: `crates/cmail-core/src/crypto.rs`
- Modify: `crates/cmail-core/src/lib.rs` (+`pub mod crypto;`), root `Cargo.toml` (workspace deps), `crates/cmail-core/Cargo.toml`

**Interfaces:**
- Produces (exact):
  - `pub struct SealedBox { pub epk: String /*b64 32B*/, pub nonce: String /*b64 24B*/, pub ct: String /*b64*/ }`
  - `pub fn x25519_secret(signing: &ed25519_dalek::SigningKey) -> x25519_dalek::StaticSecret`
  - `pub fn x25519_public(verifying: &ed25519_dalek::VerifyingKey) -> x25519_dalek::MontgomeryPoint`
  - `pub fn recipient_public_from_b64(from_key_b64: &str) -> Option<x25519_dalek::MontgomeryPoint>` (decodes the stored Ed25519 pubkey and converts)
  - `pub struct SealSession { /* ephemeral per message */ }` with `pub fn new(recipient: &x25519_dalek::MontgomeryPoint) -> Self` and `pub fn seal(&self, label: &str, plaintext: &[u8]) -> Result<SealedBox, CoreError>`
  - `pub fn open(recipient_secret: &x25519_dalek::StaticSecret, sealed: &SealedBox, label: &str) -> Result<Vec<u8>, CoreError>` (DecryptFailed on any AEAD/decode failure)

- [ ] **Step 1: Dependencies**

Root `Cargo.toml` `[workspace.dependencies]` additions:

```toml
x25519-dalek = { version = "2", features = ["static_secrets"] }
hkdf = "0.12"
chacha20poly1305 = "0.10"
```

`crates/cmail-core/Cargo.toml` gains the three `.workspace = true` deps. Run `cargo build -p cmail-core`.

API note (verify against the crates; adjust minimally if names differ and disclose): ed25519-dalek 2.x exposes `SigningKey::to_montgomery() -> x25519_dalek::StaticSecret` and `VerifyingKey::to_montgomery() -> x25519_dalek::MontgomeryPoint`. If those methods are feature-gated or absent in the resolved version, the fallback is `curve25519_dalek::Scalar::from_bytes_mod_order` clamping of the seed — but try `to_montgomery` first.

- [ ] **Step 2: Write the failing tests** (bottom of crypto.rs)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn idpair() -> (SigningKey, SigningKey) {
        (SigningKey::generate(&mut OsRng), SigningKey::generate(&mut OsRng))
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
        let mut raw = base64::engine::general_purpose::STANDARD.decode(&sb.ct).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = SealedBox { epk: sb.epk.clone(), nonce: sb.nonce.clone(), ct: base64::engine::general_purpose::STANDARD.encode(raw) };
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
        assert_eq!(open(&x25519_secret(&alice), &a0, "cmail/v1/att/0").unwrap(), b"file zero");
        assert!(open(&x25519_secret(&alice), &a0, "cmail/v1/att/1").is_err());
        assert_eq!(open(&x25519_secret(&alice), &a1, "cmail/v1/att/1").unwrap(), b"file one");
    }

    #[test]
    fn recipient_public_from_b64_round_trips() {
        let (alice, _) = idpair();
        let b64 = base64::engine::general_purpose::STANDARD.encode(alice.verifying_key().as_bytes());
        assert!(recipient_public_from_b64(&b64).is_some());
        assert!(recipient_public_from_b64("not-b64!!").is_none());
    }
}
```

- [ ] **Step 3: Implement** (top of crypto.rs)

```rust
//! ECIES for sealed envelopes (spec: 2026-11-01-cmail-sealed-envelopes-design §2).
//! X25519 keys are the Montgomery form of existing Ed25519 identity keys;
//! HKDF-SHA256 labels derive the message key and per-attachment subkeys from
//! ONE ECDH; ChaCha20-Poly1305 provides AEAD.
use crate::error::{CoreError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng as AeadRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{MontgomeryPoint, StaticSecret};

pub const MSG_LABEL: &str = "cmail/v1/msg";
pub const ATT_LABEL: fn(usize) -> String = |i| format!("cmail/v1/att/{i}");

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SealedBox {
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

pub fn x25519_secret(signing: &SigningKey) -> StaticSecret {
    signing.to_montgomery()
}

pub fn x25519_public(verifying: &VerifyingKey) -> MontgomeryPoint {
    verifying.to_montgomery()
}

pub fn recipient_public_from_b64(from_key_b64: &str) -> Option<MontgomeryPoint> {
    let raw = B64.decode(from_key_b64).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&raw);
    Some(VerifyingKey::from_bytes(&b).ok()?.to_montgomery())
}

fn derive_key(shared: &[u8; 32], epk: &[u8; 32], recipient_pub: &[u8; 32], label: &str) -> [u8; 32] {
    let mut salt_input = Vec::with_capacity(64);
    salt_input.extend_from_slice(epk);
    salt_input.extend_from_slice(recipient_pub);
    let salt = Sha256::digest(&salt_input);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(label.as_bytes(), &mut key).expect("32-byte output is valid");
    key
}

pub struct SealSession {
    ephemeral: StaticSecret,
    epk: MontgomeryPoint,
    recipient: MontgomeryPoint,
}

impl SealSession {
    pub fn new(recipient: &MontgomeryPoint) -> Self {
        let mut secret = [0u8; 32];
        AeadRng.fill_bytes(&mut secret);
        Self { ephemeral: StaticSecret::from(secret), epk: StaticSecret::from(secret).to(), recipient: *recipient }
    }

    pub fn seal(&self, label: &str, plaintext: &[u8]) -> Result<SealedBox> {
        let shared = self.ephemeral.diffie_hellman(&self.recipient);
        let key = derive_key(shared.as_bytes(), self.epk.as_bytes(), self.recipient.as_bytes(), label);
        let mut nonce_bytes = [0u8; 24];
        AeadRng.fill_bytes(&mut nonce_bytes);
        let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(&Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| CoreError::DecryptFailed("encrypt failed".into()))?;
        Ok(SealedBox {
            epk: B64.encode(self.epk.as_bytes()),
            nonce: B64.encode(nonce_bytes),
            ct: B64.encode(ct),
        })
    }
}

pub fn open(recipient_secret: &StaticSecret, sealed: &SealedBox, label: &str) -> Result<Vec<u8>> {
    let fail = || CoreError::DecryptFailed("cannot decrypt (sealed for a different identity?)".into());
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
    let epk_point = MontgomeryPoint(epk);
    let shared = recipient_secret.diffie_hellman(&epk_point);
    let recipient_pub = recipient_secret.to(); // MontgomeryPoint
    let key = derive_key(shared.as_bytes(), &epk, recipient_pub.as_bytes(), label);
    ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&nonce_raw), ct.as_ref())
        .map_err(|_| fail())
}
```

Also add to `error.rs`:

```rust
    #[error("{0}")]
    DecryptFailed(String),
```

Note: `StaticSecret::to()` — in x25519-dalek 2.x `StaticSecret::to()` doesn't exist; the pubkey is `MontgomeryPoint::from(&secret)` or `secret.to()`. Verify the exact method when implementing (`secret.public_key()` in older versions, `secret.to()` via `Into` in 2.x); store `epk` as a `MontgomeryPoint` computed once and keep the secret separately if the API requires it. Adjust minimally, keep the SealedBox wire format and HKDF construction EXACTLY as specified.

- [ ] **Step 4: Run tests** — `cargo test -p cmail-core crypto` (5 tests PASS). Full workspace green (76 expected).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(core): ECIES crypto module (X25519 from identity keys, HKDF labels, AEAD)"
```

---

### Task E2: Envelope content enum (Plain | Sealed wire forms)

**Files:**
- Modify: `crates/cmail-core/src/envelope.rs`

**Interfaces:**
- Produces (exact):
  - `Envelope { id, from, from_key, to, created, #[serde(flatten)] content: EnvelopeContent, sig }`
  - `#[serde(untagged)] enum EnvelopeContent { Plain { kind, subject, body, attachments, in_reply_to: Option }, Sealed { enc: SealedEnc } }` — `Plain` keeps `in_reply_to`'s `skip_serializing_if = "Option::is_none"`
  - `#[derive(...)] pub struct SealedEnc { pub v: u8, pub epk: String, pub nonce: String, pub ct: String }`
  - `impl Envelope { pub fn is_sealed(&self) -> bool; pub fn kind_label(&self) -> &str; pub fn subject_label(&self) -> &str; pub fn in_reply_to_ref(&self) -> Option<&str> }` — labels return real values for Plain, `"sealed"`/`"<sealed>"` for Sealed
  - `build_and_sign` unchanged signature and Plain semantics (existing callers unaffected except field access); NEW `pub fn build_and_sign_sealed(id: &str, from: &str, from_key: &str, to: &str, created: &str, enc: SealedEnc, key: &SigningKey) -> Result<Envelope>`
  - `unsigned_value()` covers `enc` when sealed
  - validation: sealed → `enc.v == 1`, epk decodes 32B, nonce 24B, ct ≤ 1 MiB; mixed forms rejected at parse (see pitfall below); plain rules unchanged

**The serde pitfall (pre-flagged):** untagged enum variants silently IGNORE unknown fields, so a mixed envelope (`enc` + `body`) would parse as Plain and drop `enc`. Guard: after parsing, if BOTH `enc`-ish and content-ish fields were present, reject. Simplest robust approach: parse first into the untagged enum, and detect mixing by ALSO parsing into a `serde_json::Value` check — or use `#[serde(deny_unknown_fields)]` on each variant (works with flatten+untagged for the non-flattened remainder; VERIFY empirically). Whichever mechanism you choose, this test must pass:

```rust
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
```

- [ ] **Step 1: Write the failing tests** (envelope.rs test module additions)

```rust
    #[test]
    fn sealed_envelope_round_trip_and_validation() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let enc = SealedEnc { v: 1, epk: "A".repeat(43), nonce: "A".repeat(32), ct: "QUJD".into() };
        let env = build_and_sign_sealed("ee".repeat(16).as_str(), "alice", &from_key, "zoe", "2026-11-01T12:00:00Z", enc.clone(), &alice).unwrap();
        assert!(env.is_sealed());
        assert_eq!(env.kind_label(), "sealed");
        assert_eq!(env.subject_label(), "<sealed>");
        let parsed = Envelope::parse(&serde_json::to_string(&env).unwrap()).unwrap();
        assert!(parsed.verify_self_signature());
        // unsigned_value must include enc: tampering enc breaks the signature
        let mut tampered = parsed.clone();
        if let EnvelopeContent::Sealed { enc } = &mut tampered.content { enc.ct = "REQA".into(); }
        assert!(!tampered.verify_self_signature());
        // bad version rejected
        let mut bad = env.clone();
        if let EnvelopeContent::Sealed { enc } = &mut bad.content { enc.v = 2; }
        assert!(Envelope::parse(&serde_json::to_string(&bad).unwrap()).is_err());
    }

    #[test]
    fn plain_wire_format_unchanged() {
        let (alice, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let env = build_and_sign("ff".repeat(16).as_str(), &parts("alice", &from_key, "zoe"), &alice).unwrap();
        let s = serde_json::to_string(&env).unwrap();
        assert!(!s.contains("enc"));
        assert!(s.contains("\"subject\":\"s\"")); // v1 shape intact (key order sorted, no spaces)
        assert!(Envelope::parse(&s).unwrap().verify_self_signature());
    }
```

Plus the `mixed_forms_are_rejected` test above.

- [ ] **Step 2: RED** — `cargo test -p cmail-core envelope` (compile errors are the expected RED).

- [ ] **Step 3: Implement** — restructure `Envelope` per Interfaces; update `validate` (branch on content), `parse`, `unsigned_value`, `build_and_sign` internals (constructs `EnvelopeContent::Plain`), add `build_and_sign_sealed`. `verify_self_signature` unchanged (it consumes `unsigned_value`).

- [ ] **Step 4: Fix downstream compile fallout** — `service.rs`/`store.rs`/tests read `env.subject` etc. For THIS task make it compile with minimal churn: wherever code read a content field, use the new label accessors or match on content. Keep behavior for plain mail identical. (Task E5 does the real sealed behavior; here we only keep the suite green.)

- [ ] **Step 5: GREEN + gates + commit**

Run: `cargo test --workspace` (all green; count will have grown — report it).
```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(core): envelope Plain|Sealed content forms with mixed-form rejection"
```

---

### Task E3: Seal and open at the envelope layer

**Files:**
- Modify: `crates/cmail-core/src/envelope.rs`

**Interfaces:**
- Consumes: E1 `SealSession`/`open`/`SealedBox`, E2 `EnvelopeContent`.
- Produces (exact):
  - `pub struct NewSealedMessage { from, from_key, to, kind, subject, body, attachments: Vec<Attachment>, in_reply_to: Option<String> }`
  - `pub fn seal_and_sign(id: &str, parts: &NewSealedMessage, recipient_x25519: &MontgomeryPoint, created: &str, key: &SigningKey) -> Result<Envelope>` — canonical-JSON payload `{kind, subject, body, attachments, in_reply_to}` (in_reply_to key present, null when None — matching v1's unsigned_value convention) → `SealSession` with `MSG_LABEL` → `SealedEnc { v: 1, .. }` → `build_and_sign_sealed`. Payload size guard: serialized payload ≤ 1 MiB - overhead else `LimitExceeded`.
  - `pub fn open_envelope(env: &Envelope, recipient_secret: &StaticSecret) -> Result<OpenedContent>` where
    `pub struct OpenedContent { pub kind: String, pub subject: String, pub body: String, pub attachments: Vec<Attachment>, pub in_reply_to: Option<String> }`
    — plain envelopes return their content directly; sealed envelopes `open` with `MSG_LABEL`, parse payload JSON, validate plaintext limits (subject/body rules), reject payload JSON with missing fields via `DecryptFailed`-adjacent `InvalidEnvelope`.

- [ ] **Step 1: Failing tests**

```rust
    #[test]
    fn seal_and_open_round_trip() {
        let (alice, _) = fixtures(); // alice = SENDER; recipient pair needed
        let (recipient, _) = fixtures();
        let from_key = B64.encode(alice.verifying_key().as_bytes());
        let rx = crate::crypto::x25519_public(&recipient.verifying_key());
        let parts = NewSealedMessage {
            from: "alice".into(), from_key: from_key.clone(), to: "zoe".into(),
            kind: "handoff".into(), subject: "s".into(), body: "the state".into(),
            attachments: vec![Attachment { filename: "notes.txt".into(), sha256: "0".repeat(64), size: 3 }],
            in_reply_to: None,
        };
        let env = seal_and_sign("aa".repeat(16).as_str(), &parts, &rx, "2026-11-01T12:00:00Z", &alice).unwrap();
        assert!(env.is_sealed());
        // raw wire carries no plaintext
        let wire = serde_json::to_string(&env).unwrap();
        assert!(!wire.contains("the state") && !wire.contains("handoff"));
        let opened = open_envelope(&env, &crate::crypto::x25519_secret(&recipient)).unwrap();
        assert_eq!(opened.body, "the state");
        assert_eq!(opened.kind, "handoff");
        assert_eq!(opened.attachments.len(), 1);
        // wrong identity cannot open
        let (other, _) = fixtures();
        assert!(open_envelope(&env, &crate::crypto::x25519_secret(&other)).is_err());
        // plain envelopes pass through unchanged
        let plain = build_and_sign("bb".repeat(16).as_str(), &parts2("alice", &from_key, "zoe"), &alice).unwrap();
        let opened = open_envelope(&plain, &crate::crypto::x25519_secret(&other)).unwrap();
        assert_eq!(opened.body, "b");
    }
```

(`parts2` = the existing `parts` fixture; reuse whatever exists.)

- [ ] **Step 2: RED → Step 3: implement per Interfaces → Step 4: GREEN** (`cargo test -p cmail-core envelope`).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(core): seal_and_sign/open_envelope with plaintext-limit enforcement"
```

---

### Task E4: Sealed attachment storage

**Files:**
- Modify: `crates/cmail-core/src/store.rs`, `crates/cmail-core/src/service.rs` (send-side call site only)

**Interfaces:**
- Consumes: E1 `SealSession`, `open`, `ATT_LABEL`.
- Produces (exact): `MailStore::seal_attachments(&self, session: &SealSession, id: &str, paths: &[PathBuf]) -> Result<Vec<Attachment>>` — reads each file, enforces v1 plaintext caps (count/per-file/total), AEADs with `ATT_LABEL(i)` to `attachments/<id>/att-<i>.bin`, returns metadata `{filename, sha256(plaintext), size(plaintext)}`; `MailStore::open_attachment(&self, recipient_secret: &StaticSecret, id: &str, index: usize) -> Result<Vec<u8>>` — reads `att-<i>.bin`, `open`s, verifies plaintext sha256 against nothing at this layer (caller holds metadata), returns bytes (DecryptFailed on failure); rollback semantics identical to `copy_attachments` (cleanup on any failure, count check before dir creation).

- [ ] **Step 1: Failing tests** (store.rs)

```rust
    #[test]
    fn seal_attachments_round_trip() {
        let root = TempDir::new().unwrap();
        let store = MailStore::new(root.path());
        let (recipient, _) = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng); // placeholder: see note
        let session = crate::crypto::SealSession::new(&crate::crypto::x25519_public(&recipient.verifying_key()));
        let src = root.path().join("plain.txt");
        fs::write(&src, b"hello attachment").unwrap();
        let meta = store.seal_attachments(&session, "att1", &[src]).unwrap();
        assert_eq!(meta[0].filename, "plain.txt");
        assert_eq!(meta[0].size, 17);
        // on-disk bytes are ciphertext
        let raw = fs::read(store.attachments_dir("att1").join("att-0.bin")).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"hello "));
        let opened = store.open_attachment(&crate::crypto::x25519_secret(&recipient), "att1", 0).unwrap();
        assert_eq!(opened, b"hello attachment");
        // wrong key fails
        let (other, _) = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        assert!(store.open_attachment(&crate::crypto::x25519_secret(&other), "att1", 0).is_err());
    }
```

(Use the test module's existing key-generation idiom instead of the inline placeholder lines.)

- [ ] **Step 2: RED → Step 3: implement** (mirror `copy_attachments`' H3 structure: early count check, `seal_attachments_inner`, rollback wrapper). Plaintext per-file/total caps enforced BEFORE sealing each file.

- [ ] **Step 4: GREEN + gates + commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(core): sealed attachment storage (att-<i>.bin, per-index subkeys)"
```

---

### Task E5: Service — transparent sealing and opening

**Files:**
- Modify: `crates/cmail-core/src/service.rs`

**Interfaces:**
- Consumes: E1-E4.
- Produces: no public signature changes. Behavior: `send` always seals (recipient key from `identities/<to>`, else keyring entry via `recipient_public_from_b64`); `read_message` decrypts (wrong-identity → `DecryptFailed`, audited `corrupt`/"decrypt failed", message stays in inbox); `inbox`/`list`/`quarantine_list` use `kind_label()`/`subject_label()`; `approvals` shows `"<sealed>"` subject for sealed; `reply` loads parent via `open_envelope` and re-seals; `quarantine_show` decrypts, wraps per trust as today.

- [ ] **Step 1: Failing tests** (service.rs test module)

```rust
    #[test]
    fn send_seals_and_read_opens() {
        let (_root, c) = svc();
        c.keyring_add("alice").unwrap();
        c.allow_add("zoe").unwrap();
        let SendOutcome::Sent { id } = c.send(Some("alice"), "zoe", "handoff", "proj", "the state", &[], None).unwrap() else { panic!() };
        // wire: sealed, no plaintext
        let raw = c.store.read_raw(&c.store.inbox_dir("zoe"), &id).unwrap();
        assert!(raw.contains("\"enc\""));
        assert!(!raw.contains("the state"));
        // listings use placeholders
        let inbox = c.inbox(Some("zoe")).unwrap();
        assert_eq!(inbox[0].subject, "<sealed>");
        assert_eq!(inbox[0].kind, "sealed");
        // read decrypts: first message is from trusted alice (keyring_add above)
        let msg = c.read_message(Some("zoe"), &id).unwrap();
        assert_eq!(msg.body, "the state");
        assert_eq!(msg.kind, "handoff");
        assert_eq!(msg.attachments, Vec::<String>::new());
        // second send arrives AFTER removing alice's trust -> untrusted, fenced post-decrypt
        let mut kr = crate::keyring::KeyRing::load(&_root.path()).unwrap();
        kr.remove("alice");
        kr.save(&_root.path()).unwrap();
        let SendOutcome::Sent { id: id2 } = c.send(Some("alice"), "zoe", "note", "s2", "secret2", &[], None).unwrap() else { panic!() };
        let msg2 = c.read_message(Some("zoe"), &id2).unwrap();
        assert!(msg2.body.contains("UNTRUSTED MAIL BODY"));
        assert!(msg2.body.contains("secret2"));
    }

    #[test]
    fn decrypt_failure_is_clean_and_audited() {
        let (_root, c) = svc();
        c.allow_add("zoe").unwrap();
        let SendOutcome::Sent { id } = c.send(Some("alice"), "zoe", "note", "s", "b", &[], None).unwrap() else { panic!() };
        // re-seal for a DIFFERENT recipient by swapping in a foreign inbox: simulate by
        // delivering into mallory's mailbox instead (mallory has no matching key)
        c.init("mallory").unwrap();
        let raw = c.store.read_raw(&c.store.inbox_dir("zoe"), &id).unwrap();
        std::fs::write(c.store.inbox_dir("mallory").join(format!("{id}.mail")), raw).unwrap();
        let err = c.read_message(Some("mallory"), &id).unwrap_err();
        assert!(matches!(err, CoreError::DecryptFailed(_)), "{err}");
        // message stays in place
        assert!(c.store.inbox_dir("mallory").join(format!("{id}.mail")).exists());
        let recs = c.audit_tail(5).unwrap();
        assert!(recs.iter().any(|r| r.detail.as_deref() == Some("decrypt failed")));
    }

    #[test]
    fn reply_from_sealed_parent_and_sealed_approvals_subject() {
        let (_root, c) = svc();
        let SendOutcome::Held { id, .. } = c.send(Some("alice"), "zoe", "note", "s", "b", &[], None).unwrap() else { panic!() };
        let apps = c.approvals(None).unwrap();
        assert_eq!(apps[0].subject, "<sealed>");
        c.approve(&id, true).unwrap();
        c.keyring_add("zoe").unwrap();
        c.allow_add("alice").unwrap(); // allow zoe->alice for the reply to send directly
        let out = c.reply(Some("zoe"), &id, "roger", None).unwrap();
        assert!(matches!(out, SendOutcome::Sent { .. }));
        // reply envelope is sealed with in_reply_to set (check wire on alice's side)
        let ids = c.store.list_ids(&c.store.inbox_dir("alice"));
        let raw = c.store.read_raw(&c.store.inbox_dir("alice"), &ids[0]).unwrap();
        assert!(raw.contains("\"enc\""));
    }

    #[test]
    fn spoof_of_sealed_mail_quarantines_without_decryption() {
        let (_root, c) = svc();
        c.keyring_add("alice").unwrap();
        c.init("mallory").unwrap();
        let mallory = crate::identity::load_identity(&_root.path(), "mallory").unwrap();
        let rx = crate::crypto::recipient_public_from_b64(
            &crate::identity::load_identity(&_root.path(), "zoe").unwrap().public_key_b64(),
        ).unwrap();
        let parts = crate::envelope::NewSealedMessage {
            from: "alice".into(), from_key: mallory.public_key_b64(), to: "zoe".into(),
            kind: "note".into(), subject: "fake".into(), body: "imposter".into(),
            attachments: vec![], in_reply_to: None,
        };
        let env = crate::envelope::seal_and_sign(&crate::envelope::new_id(), &parts, &rx, "2026-11-01T12:00:00Z", &mallory.signing).unwrap();
        c.store.ensure_mailbox("zoe").unwrap();
        c.store.write_envelope(&c.store.inbox_dir("zoe"), &env).unwrap();
        assert!(c.inbox(Some("zoe")).unwrap().is_empty());
        assert_eq!(c.store.list_ids(&c.store.quarantine_dir("zoe")), vec![env.id.clone()]);
    }
```

- [ ] **Step 2: RED** → **Step 3: Implement.** Key mechanics:
  - `send`: replace the plain `build_and_sign` call with: load recipient Ed25519 pubkey (identity file, else keyring `public_key` field) → `recipient_public_from_b64` → `SealSession` → `seal_attachments` (if any) → `seal_and_sign`. `send_gated` stays verbatim (it only moves the envelope).
  - `read_message`: after existing sig/trust computation, `open_envelope(&env, &x25519_secret(&my_signing))`; map `Err` → audit `corrupt`/"decrypt failed" + return the DecryptFailed error BEFORE the inbox→archive move (message stays in place). Body wrapping rule unchanged (wrap unless Verified).
  - `reply`: load parent envelope, `open_envelope` to obtain `in_reply_to`/sender (in_reply_to = parent id; subject default `"re: <sealed>"` when parent sealed), then normal gated send.
  - `inbox`/`list`/`quarantine_list`/`approvals`: use label accessors / `subject_label()`.

- [ ] **Step 4: GREEN + gates + commit**

Run: `cargo test -p cmail-core service -- --test-threads=1`, then full suite.
```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(core): transparent send-sealing, read-decryption, sealed listings, sealed spoof quarantine"
```

---

### Task E6: MCP descriptions, CLI passthrough, existing-test reconciliation

**Files:**
- Modify: `crates/cmail-mcp/src/tools.rs` (descriptions only), `crates/cmail-cli/tests/lifecycle.rs` (tamper helper + sealed assertions)

**Interfaces:** none new.

- [ ] **Step 1: tools.rs descriptions** — append to `cmail_send`: `"Content is end-to-end encrypted to the recipient's identity key."` and to `cmail_read`: `"Sealed messages are decrypted automatically; decryption failures surface as errors."` No behavior changes.

- [ ] **Step 2: lifecycle.rs reconciliation** — the tamper helper currently rewrites `"subject": ""` (sealed envelopes have no top-level subject). Re-point the corrupt-path test at a field that exists on both forms: tamper the `created` value (`"created": "2026-"` → `"created": "1999-"` via the same guarded `assert_ne!` string-replace on the raw file). Then extend the main lifecycle test: after approve, read the raw inbox file and assert it contains `"enc"` and does NOT contain the sent body string; `--json read` returns the plaintext body (fenced, untrusted); `inbox` shows `"<sealed>"`/`"sealed"`. The untrusted-wrapping + fingerprint assertions stay as-is.

- [ ] **Step 3: GREEN + gates + commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add -A && git commit -m "feat(cli+mcp): sealed-aware tests and tool descriptions; tamper helper retargeted"
```

---

### Task E7: Docs, version 0.2.0, final verification

**Files:**
- Modify: `README.md`, `AGENTS.md`, root `Cargo.toml` (`version.workspace` → `0.2.0`)

- [ ] **Step 1: README** — trust-model table note + new "Encryption" subsection under the trust model: what's sealed (subject/kind/body/attachments/threading), what stays visible (from/to/timestamps/sizes), keys are your identity keys, no forward secrecy, v1 mail stays readable. Install examples updated `v0.1.0` → `v0.2.0` filename only if trivially greppable (leave version pinning to release day otherwise).
- [ ] **Step 2: AGENTS.md** — add two lines under "Trust rules": bodies are end-to-end encrypted to recipients; nothing changes for you (read/send are transparent).
- [ ] **Step 3: Version bump** — root `Cargo.toml` `version = "0.2.0"` (propagates via workspace).
- [ ] **Step 4: Final gates** — `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` — report the final count; run the v1 quickstart manually on a fresh root (`--root target/e7`) and confirm sealed-on-disk + transparent read.
- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs+version: E2E encryption documented; v0.2.0"
```

---

## Self-review notes (applied while writing)

- Spec §4.4 `<sealed>`/`sealed` placeholder rule → E2 accessors + E5 listings/approvals. Spec §2.2 labels/salt → E1 verbatim. Spec §2.3 sig-covers-enc → E2 `unsigned_value` + tamper test. Spec §3 caps → E2 (ct) + E3 (plaintext) + E4 (attachment files). Spec §5 DecryptFailed semantics → E1 error variant + E5 test. Spec §7 ct-swap test → E2; wrong-recipient → E1/E3; raw-file-no-plaintext → E3/E5/E6.
- Pre-flagged implementation warts: x25519 pubkey-from-secret API name (E1 note), untagged-flatten mixed rejection (E2 pitfall + test), lifecycle tamper helper's subject dependency (E6), `NewSealedMessage` field parity with `NewEnvelope` (E3 struct listed in full).
- Deliberately out of scope (spec §8): metadata privacy, ratchets, multi-recipient, retro-sealing, passphrase sealing.
