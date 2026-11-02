# cmail v0.3 — Internet Delivery via Zero-Trust Relays: Design

Date: 2026-11-01
Status: Approved by user (design review)
Builds on: v1.0 (`2026-11-01-cmail-design.md`, as amended), v1.1 sealed envelopes
(`2026-11-01-cmail-sealed-envelopes-design.md`). Version becomes 0.3.0.

## 1. Overview

The FidoNet tier from v1.0 §11: two agents on different machines exchange mail
through a dumb relay that is cryptographically unable to forge, read, or grant
trust. Ships three pieces: the wire protocol (versioned, for third-party
relays), a reference server (`cmail relay-serve`, same binary), and the client
(routing in the keyring, `cmail fetch`).

Model, unchanged from spec §11: identity = keys, names are local petnames,
delivery is BY KEY (mailbox = key fingerprint), relays are config entries not
accounts. Relay-to-relay forwarding and the envelope `route` field remain
future work (v0.4+) — sender POSTs directly to the recipient's known relay.

### What the relay sees (honest edges, README'd)

Fingerprints, ciphertext, sizes, and deposit/fetch timing — AND, because sealed
envelopes keep their header in the clear (v1.1's by-design choice so trust
works without decrypting), every parcel's plaintext `from`/`to` petnames,
sender `from_key`, and `created` timestamp. What sealing (v0.2.0) protects:
subject, kind, body, attachments, threading — content, never. A malicious
relay can delay, drop, or refuse — never forge (Ed25519), never read content
(X25519+AEAD), never alter trust (keyrings are local). No metadata-anonymity
is claimed: fetch and deposit timing is visible to the relay operator.

## 2. Wire protocol (v1)

HTTPS JSON. `{fp}` = 16-hex fingerprint of the recipient's Ed25519 public key
(first 16 hex chars of SHA-256, same as `fingerprint_of`). All bodies JSON.

```
GET    /challenge/{fp}          → 200 {"nonce": "<b64 32B>", "expires": "<RFC3339>"}
                                nonce single-use, 5-minute TTL, ≤8 outstanding per fp

POST   /mailbox/{fp}            body: Parcel (§2.1)          [open]
GET    /mailbox/{fp}            → 200 {"ids": ["<32hex>", …]}            [auth]
GET    /mailbox/{fp}/{id}       → 200 Parcel                             [auth]
DELETE /mailbox/{fp}/{id}       → 200 {"deleted": true}                  [auth]
```

**Auth** (list/fetch/delete): `X-cmail-Fp: {fp}` + `X-cmail-Signature: {b64
Ed25519 signature over the ASCII bytes of the nonce}` — signed with the mailbox
identity's key; verified against the pubkey stored at first deposit. One nonce
grants ONE authenticated request (fetch a fresh challenge per request; the
nonce is consumed on success).

Status codes: 200 ok; 400 malformed body / fp≠fingerprint(pubkey) / bad
parcel; 401 auth failed or nonce expired/consumed; 404 unknown mailbox or id;
413 over size cap; 429 too many outstanding nonces. Errors carry
`{"error": "..."}`.

### 2.1 Parcel format (v1, pinned for interop)

The unit of transfer is a **parcel** — a sealed envelope plus its encrypted
attachment frames in one body (attachments are separate files on disk since
v1.1; remote delivery bundles them):

```json
{ "v": 1,
  "pubkey": "<recipient Ed25519 pubkey, b64>",
  "envelope": { <full envelope JSON, sealed form> },
  "attachments": [ { "i": 0, "data": "<b64 of the raw att-<i>.bin frame>" } ] }
```

Rules: `v == 1` (unknown → 400); relay verifies `fingerprint(pubkey) == {fp}`
of the URL (400 otherwise); envelope is stored/fetched opaquely (the relay
NEVER parses inside it); attachment entries are keyed by index, count ≤ 8,
total DECODED attachment payload ≤ 36 MiB (validated post-parse → 413); the
ENCODED request body is prechecked against 64 MiB before reading (413) — b64
expansion means a decoded-36-MiB parcel encodes to ~48 MiB, so the encoded
precheck must be the larger number. The client-side reconstruction writes
`attachments/<id>/att-<i>.bin` verbatim from `data`.

### 2.2 Server behavior (reference implementation contract)

- File-backed under a relay root: `mailboxes/{fp}/meta.json` (pubkey, created),
  `mailboxes/{fp}/{id}.parcel`, `nonces/{fp}/{nonce-hash}.json` (expiry).
- Nonces: 32 random bytes b64, single-use, 5-min TTL, max 8 outstanding per
  fp; consumed exactly on a successful authed request; garbage-collected
  lazily on every request touching `{fp}`.
- Retention: entries older than `--retention-days` (default **7**) are deleted
  lazily on mailbox access and on deposit, PLUS a periodic sweep of ALL
  mailboxes (every 10 minutes) so abandoned mailboxes cannot accumulate
  unbounded across fingerprints; empty mailboxes are pruned.
- Caps, status semantics: **413 = size** (encoded body precheck 64 MiB;
  decoded payload 36 MiB; per-mailbox 256 MiB), **429 = count** (1000 entries
  per mailbox; 8 outstanding nonces per fp).
- No accounts, no admin API, no relay-to-relay. TLS is the deployer's
  responsibility (reverse proxy or `--tls-cert/--tls-key` flags on the
  reference server); the protocol REQUIRES TLS in production — plaintext HTTP
  is allowed only for `--insecure-local` (loopback testing).

## 3. Client

### 3.1 Keyring gains routes (format change, back-compatible)

`keyring.json` entries gain `route: Option<String>` (a relay base URL,
e.g. `https://relay.example.com`). Old keyrings parse unchanged (`serde`
default). Fingerprint stays of the Ed25519 key; routes are pure routing hints
and never affect trust.

New CLI: `cmail keyring route <name> <url>` sets it, `cmail keyring route
<name> --clear` clears it; `cmail keyring add <name> [--route <url> …]`
accepts it at add time; `keyring list` shows routes. New audit event
`key_route` (set/clear both).

### 3.2 Send: local first, then routed relay POST

Resolution order for recipient `<to>`:
1. Local identity exists → local inbox delivery (exactly as today, even if a
   route is also known — local always wins).
2. Else keyring entry exists **and** has a route → outbound gate as usual
   (held mail is held BEFORE any network I/O; approve of a routed held message
   performs the POST) → seal to the keyring key (already implemented) →
   `POST /mailbox/{fp}` with the Parcel → audit `send_relay` (actor sender,
   counterpart recipient, msg id).
3. Else → `UnknownRecipient` (unchanged).

POST failure surfaces as a CLI/MCP error; nothing is written locally on
failure. Retries are manual (re-send) — no client-side queue in v0.3.

### 3.3 Fetch: explicit, authenticated, by key

Config: `[relay] url = ""` — my pickup relay (`cmail relay set <url>` /
`cmail relay clear`; new audit event `relay_set`).

`cmail fetch [--timeout 30s]` (identity via `--as` as usual):
1. For each pending id from `GET /mailbox/{fp-of-my-identity}`:
   fetch the Parcel; verify `Envelope::parse` + `verify_self_signature()`
   (bad parcels are skipped and NOT acked — left for retry/manual inspection);
   write the envelope into my `inbox/` and attachment frames into
   `attachments/<id>/`; on success `DELETE` (ack).
2. Incoming remote mail then flows through the NORMAL inbound machinery on the
   next scan: trust computed from my keyring, untrusted wrapped, spoof
   quarantined, strict mode honored. Names in `to`/`from` are the SENDER's
   petnames and are displayed as-is — delivery was by key, and decryption
   success is the proof of addressing (documented in README).
3. Audit `fetch` once per run (actor identity, detail "n fetched, m kept").
`--wait` polls the relay list every 5s up to the timeout, fetching as mail
arrives.

**MCP**: one new agent-safe tool `cmail_fetch` (inbound + own-key
authenticated; no human-only power). Description notes it contacts the
configured network relay.

### 3.4 New audit events

`send_relay`, `fetch`, `key_route`, `relay_set` — added to the v1.0 §4.4 list.

## 4. Dependencies

`ureq` (client; rustls, no default TLS) and `tiny_http` (reference server;
sync, no async runtime) — both minimal-tree, house style. JSON via existing
serde. New `cmail-relay` crate? No — client code in `cmail-core`
(`relay.rs`: parcel + HTTP client), server in a new thin crate
`crates/cmail-relayd` (binary `cmail-relayd`, also invoked as `cmail
relay-serve` delegating to the crate) — server code must not live in core so
agents can never import it via MCP surface accidents. CLI surfaces:
`relay-serve|relay|keyring route|fetch`.

## 5. Error handling

- Relay unreachable/TLS error → clean CLI error, exit 1, nothing local
  written; `fetch` continues to next entry on per-entry errors.
- 401/404/413/429 surfaced with the relay's error text.
- Parcel integrity: signature-failed parcels are skipped + audited `corrupt`
  (detail "remote parcel failed verification"), never acked, never delivered.
- Server: malformed requests never crash; body-size checked before full read
  where the HTTP layer allows (Content-Length precheck), 413 otherwise.

## 6. Testing

- **Unit (relay.rs)**: parcel round-trip (envelope + attachment frames → JSON
  → back, byte-identical frames); fingerprint/pubkey mismatch rejection;
  nonce-signature construction.
- **Integration (relayd)**: spin the server on `127.0.0.1:0` (insecure-local
  mode), full lifecycle: deposit → challenge/auth → list/fetch/ack; wrong-key
  auth 401; nonce single-use; retention GC (tiny retention for test); size
  caps; fp-mismatch 400.
- **Cross-machine simulation (core/CLI)**: two temp roots + one local relayd;
  sender keyring-promotes recipient WITH route → send → parcel on relay →
  recipient `fetch` → verified read; untrusted remote sender (no keyring
  entry) arrives wrapped; impostor (wrong from_key for known name) →
  quarantine after fetch; held-to-routed-recipient → approve performs POST.
- CLI/MCP: `fetch` shapes; `cmail_fetch` tool present and human-only surface
  unchanged.

## 7. Non-goals (v0.3)

- Relay-to-relay forwarding, the envelope `route` field, nodelists.
- Client-side retry queues or background sync (explicit fetch only).
- Relay discovery/directory (routes are shared out-of-band, e.g. in the README
  of whoever runs it).
- Metadata privacy/anonymity (fetch timing is visible to the relay).
- Multiple pickup relays per identity (one `[relay] url`).
