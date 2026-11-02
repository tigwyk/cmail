# cmail v1.1 — Sealed Envelopes (End-to-End Encryption): Design

Date: 2026-11-01
Status: Approved by user (design review)
Builds on: cmail v1.0 spec (`2026-11-01-cmail-design.md`), as amended through the
hardening pass. Version becomes 0.2.0.

## 1. Overview

Sealed envelopes add content confidentiality to cmail without changing the trust
machinery, the CLI surface, or the readability of existing mail. Everything a
relay, a synced-folder reader, or a mailbox-root thief could previously read —
subject, kind, body, attachments, threading — becomes ciphertext. Everything the
v1 trust model operates on — `id`, `from`, `to`, `created`, `from_key`, `sig` —
stays visible by design, so petname keyring lookup, self-describing signature
verification, spoof detection, and quarantine routing work on sealed mail
**without decrypting it**.

Design pillars carried over from v1: agent-first, zero-framework adoption,
permissioning first. Sealing is transparent — no new commands, no new flags, no
key ceremonies.

### What this does and does not provide (threat model, spec §10 amendment)

Gained: content confidentiality against relays, synced-folder readers, and
anyone holding the mailbox root.

NOT gained (documented honestly in README):
- **Metadata privacy** — who mailed whom, when, message and ciphertext sizes
  remain visible on the wire and at rest.
- **Forward secrecy** — no ratchet. A stolen recipient identity key decrypts
  mail sealed to that identity. (Async store-and-forward mail has no session
  to ratchet over; this is the accepted trade-off for v1.1.)
- **Sender anonymity** — `from`/`from_key` are visible by design.

## 2. Cryptography

### 2.1 Key derivation — Ed25519 identities do double duty

Each identity's Ed25519 key converts deterministically to an X25519 key
(Montgomery form; `ed25519_dalek` exposes the conversion). No new key files, no
new fingerprints (fingerprints remain hashes of the Ed25519 public key), no
keyring format change. The recipient's encrypt-to key is the Montgomery form of
their existing public key, sourced from `identities/<to>/` on the local root,
falling back to the keyring entry (the cross-machine case) if no local identity
exists.

### 2.2 Construction (ECIES, dalek/RustCrypto family)

Per message:
1. Fresh ephemeral X25519 keypair → `epk` (32 bytes, base64).
2. `ikm = X25519(ephemeral_secret, recipient_x25519_public)`.
3. `salt = SHA256(epk || recipient_x25519_public)`.
4. `msg_key = HKDF-SHA256(ikm, salt, info="cmail/v1/msg")` → XChaCha20-Poly1305
   key (the 24-byte-nonce variant of ChaCha20-Poly1305).
5. AEAD-encrypt the canonical-JSON payload (§3) with a fresh 24-byte `nonce`.

Per attachment (index `i`, zero-based): `att_key_i = HKDF-SHA256(ikm, salt,
info="cmail/v1/att/<i>")` — derived directly from the same ECDH `ikm` with the
label as domain separator (equivalent independence to key-chaining, one less
derivation layer); AEAD-encrypt the file bytes with a fresh nonce per file. One
ECDH per message; independent AEAD per attachment.

New dependencies: `x25519-dalek`, `hkdf`, `chacha20poly1305` (`sha2` already
present). All RustCrypto/dalek-family, consistent with the existing tree.

### 2.3 Signature placement

The existing Ed25519 `sig` covers the visible header **including `enc`**
(epk/nonce/ct) — so a ciphertext cannot be swapped between envelopes without
breaking the signature — and does **not** cover the plaintext. Consequence:
recipients verify authenticity and compute trust *before* decryption, and spoof
detection works on sealed mail. Payload integrity is provided by the AEAD tag
(verifying the signature is not necessary to trust the ciphertext's origin —
the header sig already binds it — but plaintext tampering is impossible by
construction anyway).

## 3. Wire format (envelope v2, back-compatible)

Sealed envelope:

```json
{
  "id": "<32 hex>", "from": "<name>", "from_key": "<b64>", "to": "<name>",
  "created": "<RFC3339>",
  "enc": { "v": 1, "epk": "<b64 32B>", "nonce": "<b64 24B>", "ct": "<b64>" },
  "sig": "<b64 64B over canonical JSON of all fields except sig>"
}
```

Plaintext payload inside `ct` (canonical JSON):

```json
{ "kind": "…", "subject": "…", "body": "…",
  "attachments": [ { "filename": "…", "sha256": "<plaintext hash>", "size": <plaintext bytes> } ],
  "in_reply_to": "<32 hex or absent>" }
```

v1 (plain) envelopes are byte-identical to today and remain fully supported.

Rules:
- A sealed envelope MUST NOT carry `kind`/`subject`/`body`/`attachments`/
  `in_reply_to` at the top level; a plain envelope MUST carry them (as today).
  Mixed envelopes fail validation (`InvalidEnvelope`).
- `enc.v == 1` (unknown versions rejected as unparseable → existing corrupt
  routing).
- Caps: `ct` ≤ 1 MiB (the payload carries no file bytes, so this is generous
  against body ≤ 256 KiB + metadata); per-attachment ciphertext file ≤
  `MAX_ATTACHMENT_BYTES + 1024`; count and total-plaintext caps as v1, enforced
  on the **plaintext** after decryption (and on the payload metadata at
  seal time).
- Attachment payload files are stored as `attachments/<id>/att-<index>.bin`
  (index-named — real filenames are inside the payload). Plaintext sha256 and
  size are recorded in the payload metadata only.
- `unsigned_value()` (the canonical signing input) for a sealed envelope
  includes `id, from, from_key, to, created, enc` — content fields are absent.

## 4. Behavior and flows

### 4.1 Send (transparent sealing)

`send` builds the payload from the same arguments, loads the recipient's public
key (identity file, else keyring), seals content + attachments, signs the
header, and proceeds through the v1 outbound gate unchanged. Sealing always
happens when a recipient key is available — which is always true on a local
root; there is deliberately no opt-out flag (unsealed mail remains readable for
back-compat, but new mail is always sealed).

### 4.2 Read

`read` verifies the signature and computes trust from the visible header
(unchanged), then decrypts if `enc` is present, validates plaintext limits, and
presents exactly as v1 — including UNTRUSTED fencing for unverified senders and
the fingerprint display (still the Ed25519 fingerprint). Decryption failure
(wrong identity, corrupted ciphertext) is a clean `CoreError::DecryptFailed`
error ("cannot decrypt (sealed for a different identity?)"); the message stays
in place and the attempt is audited as `corrupt` with detail
`"decrypt failed"`. Quarantine routing, inbox scans, wait, and listing are
unchanged — they read only the visible header.

### 4.3 Reply

Unchanged flow: loads the parent (decrypting it if sealed), sends to
`parent.from` with `in_reply_to` set; the reply is sealed like any send.

### 4.4 Approvals / quarantine / audit / listings

Held-mail approval shows only `from`/`to`/`created` for sealed mail (subject is
inside the ciphertext — approvals display `"<sealed>"` as the subject
placeholder). The same placeholder rule applies to every surface that shows
content fields without decrypting: `inbox`, `list`, and `quarantine list`
display `subject: "<sealed>"` and `kind: "sealed"` for sealed envelopes (the
real values appear only in `read`/`show`, after decryption). Quarantine `show`
requires decryption to display; a sealed quarantined message shows its header
plus a decrypt attempt, fenced per trust level as today. No new audit events;
decrypt failures reuse `corrupt` with detail.

### 4.5 MCP

No surface change. Tools return the same shapes; `cmail_read` returns decrypted
content fenced by trust exactly as the CLI. Tool descriptions unchanged except
one added line on `cmail_send`/`cmail_read`: content is end-to-end encrypted to
the recipient.

## 5. Error handling

- Mixed/plain-field violations → `InvalidEnvelope` at parse.
- Unknown `enc.v` → unparseable (corrupt routing, as today).
- AEAD failure or wrong-identity decrypt → `DecryptFailed`; message stays in
  place; audited `corrupt`/`decrypt failed`; never crashes.
- Missing recipient key at send (neither identity nor keyring) — cannot happen
  on a local root (recipient identity must exist, checked before sealing); the
  keyring fallback covers future synced roots.
- Limits: plaintext caps enforced post-decrypt; oversized plaintext →
  `InvalidEnvelope` (the message stays in place, flagged in the read error).

## 6. Compatibility and versioning

- Crate version bumps to 0.2.0; release via the existing tag process
  (`v0.2.0`).
- v1 envelopes: forever readable; new writes are sealed.
- Storage layout: unchanged (attachment files gain the `att-<n>.bin` naming
  alongside v1's name-based files; both readers coexist).
- Spec amendments: §3.2 (envelope format — this document supersedes the content
  section), §10 (threat model gains/limits above), §11 note: "end-to-end
  encryption has landed; relays remain blind to content by construction."

## 7. Testing strategy

- **Unit (crypto):** key conversion round-trip (Ed25519↔X25519 determinism);
  seal/open round-trip; wrong-recipient key cannot open; ct tamper fails AEAD;
  attachment subkey independence (decrypting att-0 with att-1's key fails).
- **Envelope:** sealed parse rejects top-level content fields; unknown enc.v
  rejected; plain v1 parse unchanged; unsigned_value includes `enc` (signature
  binding — swapping ct between two sealed envelopes fails signature
  verification).
- **Service:** send produces sealed envelope on disk (no plaintext content in
  the .mail file — asserted by reading the raw file); read decrypts and fences
  untrusted sealed mail; decrypt-failure path (deliver to wrong identity)
  errors cleanly + audits; approvals shows `"<sealed>"` subject; reply threads
  from a sealed parent; spoof of a sealed envelope (impostor from, valid
  self-sig) still quarantined without decryption.
- **CLI/MCP:** lifecycle test extended — after approve, the raw inbox file
  contains an `enc` block and no `body`; `read` returns the plaintext body
  fenced; MCP `cmail_read` same. Existing tests otherwise unchanged and green
  (back-compat proof).
- Gates: fmt, clippy `--all-targets -D warnings`, full suite.

## 8. Explicit non-goals (v1.1)

- Metadata privacy / sealed-sender (would rework the trust model).
- Forward secrecy / ratchets.
- Encrypting to multiple recipients or group keys.
- Sealing v1 messages retroactively or a migration command.
- Password/passphrase sealing (identity-key recipients only).
