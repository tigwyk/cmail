# cmail v0.3 — Relay Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Internet delivery via zero-trust relays — wire protocol v1 (parcel format, fingerprint-keyed mailboxes, nonce auth), a reference server (`cmail-relayd` / `cmail relay-serve`), and the client (keyring routes, relay-POST on send, `cmail fetch`) — per spec `docs/superpowers/specs/2026-11-01-cmail-relays-design.md`.

**Architecture:** Client transport lives in `cmail-core/src/relay.rs` (parcel build/explode, HTTP client via `ureq`); the reference server is a NEW crate `crates/cmail-relayd` (lib+bin, `tiny_http`, file-backed) so server code can never leak into agent-facing surfaces; service wiring extends `send` (local→routed resolution) and adds `fetch`; CLI gains `fetch`/`relay set|clear`/`keyring route`/`relay-serve`; MCP gains `cmail_fetch`.

**Tech Stack:** new deps `ureq` (rustls, client) + `tiny_http` (server); everything else existing.

## Global Constraints

- Spec authoritative: `docs/superpowers/specs/2026-11-01-cmail-relays-design.md` (read first). v1 spec CLI table + §4.4 audit list get amended by R6.
- Protocol details VERBATIM: nonce = 32 random bytes b64, single-use, 5-min TTL, ≤8 per fp; `X-cmail-Fp` + `X-cmail-Signature` = b64 Ed25519 over the ASCII bytes of the nonce string; status codes 200/400/401/404/413/429 with `{"error": "..."}` bodies; parcel = `{v:1, pubkey, envelope, attachments:[{i, data:b64}]}`; caps: parcel ≤ 36 MiB, mailbox ≤ 256 MiB / 1000 entries; retention default 7 days (lazy GC).
- Trust invariants: relays never parse inside envelopes; fetch delivers BY KEY (envelope `to` petnames displayed as-is); remote mail flows through the EXISTING inbound trust machinery (wrap/quarantine/strict-mode unchanged); held mail is held BEFORE any network I/O; approving a routed held message performs the POST.
- v1/v1.1 contracts intact: all 89 existing tests keep passing unless a task says otherwise; JSON shapes unchanged except documented additions; human-only MCP surface unchanged (only `cmail_fetch` is added).
- Every task: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` clean, full `cargo test --workspace` green before commit. `#[expect]` > `#[allow]`.
- Version bumps to 0.3.0 in R6 only. Baseline: branch start 197f4e3, 89 tests.

---

### Task R1: Parcel format + client transport types (`cmail-core/src/relay.rs`)

**Files:**
- Create: `crates/cmail-core/src/relay.rs`
- Modify: `crates/cmail-core/src/lib.rs` (+`pub mod relay;`), root `Cargo.toml` (workspace dep `ureq = { version = "2", default-features = false, features = ["tls", "json"] }`), `crates/cmail-core/Cargo.toml` (+ureq)

**Interfaces:**
- Produces (exact):
  - `pub struct Parcel { pub v: u8, pub pubkey: String, pub envelope: Envelope, pub attachments: Vec<ParcelAttachment> }` with `#[derive(Serialize, Deserialize)]`; `pub struct ParcelAttachment { pub i: usize, pub data: String }`
  - `pub fn build_parcel(env: &Envelope, attachment_frames: &[(usize, Vec<u8>)]) -> Result<Parcel>` — validates v=1 convention, ≤8 attachments, frames b64-encoded; `Parcel::validate(&self) -> Result<()>` (v==1, count ≤ 8, b64 data decodes, total decoded ≤ 36 MiB)
  - `pub fn sign_challenge(signing: &ed25519_dalek::SigningKey, nonce: &str) -> String` — b64 Ed25519 signature over `nonce.as_bytes()`
  - HTTP client fns (ureq, 30s timeout, errors mapped to `CoreError::Config`-style `CoreError::Relay(String)` — NEW error variant `#[error("relay: {0}")] Relay(String)` in error.rs):
    - `pub fn deposit(base_url: &str, fp: &str, parcel: &Parcel) -> Result<()>` — `POST {base}/mailbox/{fp}`, 2xx ok, else Err with body text
    - `pub fn list_pending(base_url: &str, fp: &str, signing: &ed25519_dalek::SigningKey) -> Result<Vec<String>>` — challenge → GET list with auth headers
    - `pub fn fetch_parcel(base_url: &str, fp: &str, id: &str, signing: &SigningKey) -> Result<Parcel>` — challenge → GET → parse+validate
    - `pub fn ack(base_url: &str, fp: &str, id: &str, signing: &SigningKey) -> Result<()>` — challenge → DELETE
    - shared `fn authed<T>(method, url, fp, signing, body: Option<&Parcel>) -> Result<T>`; `fn challenge(base_url, fp) -> Result<String>` (GET `/challenge/{fp}`, returns nonce string)
  - URL handling: `base_url` trimmed of trailing `/`; scheme must be `https` OR the caller passed `allow_http: true` (const `pub const INSECURE_LOCAL: &str = "http://127.0.0.1"` prefix check — simplest: a `pub fn normalize_base(url) -> Result<String>` rejecting non-https unless host is 127.0.0.1/localhost).

- [ ] **Step 1: Write failing tests** (bottom of relay.rs)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{build_and_sign, new_id, Attachment, NewEnvelope};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn envelope_fixture() -> (Envelope, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let from_key = crate::crypto::recipient_pubkey_b64_of(&key); // or inline b64 of verifying key
        let env = build_and_sign(
            &new_id(),
            &NewEnvelope { from: "a".into(), from_key, to: "z".into(), kind: "note".into(),
                subject: "s".into(), body: "b".into(), attachments: vec![], in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into() },
            &key,
        ).unwrap();
        (env, key)
    }

    #[test]
    fn parcel_round_trip_preserves_frames_byte_identically() {
        let (env, _) = envelope_fixture();
        let frames = vec![(0usize, vec![1u8, 2, 3, 4]), (1usize, vec![9u8; 40])];
        let parcel = build_parcel(&env, &frames).unwrap();
        assert_eq!(parcel.v, 1);
        assert_eq!(parcel.attachments.len(), 2);
        let json = serde_json::to_string(&parcel).unwrap();
        let back: Parcel = serde_json::from_str(&json).unwrap();
        back.validate().unwrap();
        // frames decode byte-identically, index order preserved
        assert_eq!(back.attachments[0].i, 0);
        let d0: Vec<u8> = base64::engine::general_purpose::STANDARD.decode(&back.attachments[0].data).unwrap();
        assert_eq!(d0, vec![1, 2, 3, 4]);
    }

    #[test]
    fn parcel_validation_rejects_bad() {
        let (env, _) = envelope_fixture();
        let mut p = build_parcel(&env, &[]).unwrap();
        p.v = 2; assert!(p.validate().is_err());
        let mut p = build_parcel(&env, &[]).unwrap();
        p.attachments = (0..9).map(|i| ParcelAttachment { i, data: "AAAA".into() }).collect();
        assert!(p.validate().is_err());
        let mut p = build_parcel(&env, &[]).unwrap();
        p.attachments[0].data = "!!not b64!!".into(); // only if build added one; else push one first
        assert!(p.validate().is_err());
    }

    #[test]
    fn challenge_signature_verifies() {
        let key = SigningKey::generate(&mut OsRng);
        let nonce = "abc123nonce";
        let sig_b64 = sign_challenge(&key, nonce);
        use ed25519_dalek::Verifier;
        let raw = base64::engine::general_purpose::STANDARD.decode(&sig_b64).unwrap();
        let mut b = [0u8; 64]; b.copy_from_slice(&raw);
        key.verifying_key().verify(nonce.as_bytes(), &ed25519_dalek::Signature::from_bytes(&b)).unwrap();
    }

    #[test]
    fn normalize_base_enforces_tls_except_loopback() {
        assert!(normalize_base("https://relay.example.com/").unwrap().ends_with("relay.example.com"));
        assert!(normalize_base("http://127.0.0.1:8080").is_ok());
        assert!(normalize_base("http://relay.example.com").is_err());
    }
}
```

(Adapt fixture helpers to the real crypto-module API — e.g. use `identity::Identity::generate` + `public_key_b64()` rather than inventing helpers; the assertion intent is the contract. The "!!not b64!!" case must construct a parcel WITH one valid attachment first.)

- [ ] **Step 2: RED** (compile errors) → **Step 3: implement** per Interfaces. ureq notes: `ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build()`; `agent.request("DELETE", url).set("X-cmail-Fp", fp).set("X-cmail-Signature", &sig).call()` — map non-2xx via `response.status()` and `response.into_string()`. Body JSON via `serde_json::to_string` + `.send_string(...)` with Content-Type header. Agent stored in a `thread_local!` or constructed per call (per call is fine).

- [ ] **Step 4: GREEN** — `cargo test -p cmail-core relay` (4 tests), full workspace green (93 expected).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): parcel format + relay client transport (challenge auth, ureq)"`

---

### Task R2: Reference relay server (`crates/cmail-relayd`, lib+bin)

**Files:**
- Create: `crates/cmail-relayd/Cargo.toml`, `crates/cmail-relayd/src/lib.rs`, `crates/cmail-relayd/src/server.rs`, `crates/cmail-relayd/src/store.rs`, `crates/cmail-relayd/tests/server_tests.rs`; workspace `members` + workspace deps `tiny_http = "0.12"`
- Test: `crates/cmail-relayd/tests/server_tests.rs`

**Interfaces:**
- Consumes: R1 `Parcel` (as an opaque validated JSON body — relayd depends on cmail-core ONLY for `Parcel::validate`, `fingerprint_of`, and signature verification of challenges; it must never inspect envelope interiors).
- Produces (exact):
  - `pub struct RelayServer` with `pub fn start(addr: &str, root: std::path::PathBuf, retention_days: u64) -> anyhow::Result<RelayServer>` — binds (use `0.0.0.0:0`-style addr; for tests pass `127.0.0.1:0`) and spawns handler threads (4); `pub fn base_url(&self) -> String` — `http://127.0.0.1:{port}` (test/insecure mode); `pub fn wait(&self)` (joins; tests use `std::mem::forget` or keep alive).
  - `server.rs`: request loop matching the 5 routes (§2), status/`{"error":…}` bodies per spec; `store.rs`: file layout `mailboxes/{fp}/meta.json`, `mailboxes/{fp}/{id}.parcel`, `nonces/{fp}/{sha256(nonce)[0..16]}.json` with expiry; methods `deposit(fp, pubkey, parcel_bytes) -> Result<(), StoreError>` (StoreError::{Bad, Full, Conflict}), `list(fp) -> Vec<String>`, `get(fp,id) -> Option<Vec<u8>>`, `delete(fp,id) -> bool`, `nonce(fp) -> String`, `consume_nonce(fp, nonce_b64, sig_b64, pubkey_b64) -> bool` (verifies Ed25519 over nonce ASCII with the mailbox pubkey), `gc(fp)` (retention + nonce sweep), caps: parcel ≤ 36 MiB, mailbox ≤ 256 MiB / 1000 entries.
- `main.rs` (bin `cmail-relayd`): flags `--root <dir>` (required), `--addr <ip:port>` default `127.0.0.1:8080`, `--retention-days` default 7; prints bound address and exits on SIGINT naturally. TLS flags are STUBBED with a clear `--tls-cert/--tls-key coming in a follow-up; run behind a TLS reverse proxy` error if passed (spec defers TLS termination).

- [ ] **Step 1: Write failing integration tests** (`tests/server_tests.rs`)

```rust
use cmail_relayd::RelayServer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

struct Fix { server: RelayServer, key: SigningKey, fp: String, client: ureq::Agent }

fn fix() -> Fix {
    let root = tempfile::tempdir().unwrap();
    let server = RelayServer::start("127.0.0.1:0", root.path().to_path_buf().keep(), 7).unwrap();
    let key = SigningKey::generate(&mut OsRng);
    let fp = cmail_core::identity::fingerprint_of(&b64(key.verifying_key().as_bytes()));
    Fix { server, key, fp, client: ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(5)).build() }
}

#[test]
fn full_lifecycle_deposit_list_fetch_ack() {
    let f = fix();
    let parcel = minimal_parcel(&f); // helper: build_parcel on a plain envelope fixture (reuse core helpers)
    // deposit (open)
    f.client.post(format!("{}/mailbox/{}", f.server.base_url(), f.fp))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::to_string(&parcel).unwrap()).unwrap();
    // list (authed)
    let ids: Vec<String> = authed(&f, "GET", &format!("/mailbox/{}", f.fp), None);
    assert_eq!(ids.len(), 1);
    // fetch
    let got: cmail_core::relay::Parcel = authed(&f, "GET", &format!("/mailbox/{}/{}", f.fp, ids[0]), None);
    assert_eq!(got.envelope.id, parcel.envelope.id);
    // ack
    authed::<serde_json::Value>(&f, "DELETE", &format!("/mailbox/{}/{}", f.fp, ids[0]), None);
    let ids2: Vec<String> = authed(&f, "GET", &format!("/mailbox/{}", f.fp), None);
    assert!(ids2.is_empty());
}

#[test]
fn wrong_key_and_nonce_semantics() {
    let f = fix();
    deposit_minimal(&f);
    // wrong key -> 401
    let other = SigningKey::generate(&mut OsRng);
    let nonce: String = f.client.get(...challenge...).call().unwrap... ;
    let sig = cmail_core::relay::sign_challenge(&other, &nonce);
    let resp = f.client.get(list_url).set("X-cmail-Fp", &f.fp).set("X-cmail-Signature", &sig).call().unwrap();
    assert_eq!(resp.status(), 401);
    // nonce single-use: replay the GOOD signature -> 401 second time
    // (get fresh nonce, auth once successfully, replay -> 401)
}

#[test]
fn fp_mismatch_rejected_400_and_caps_enforced() {
    let f = fix();
    let mut p = minimal_parcel(&f); // carries f.key's pubkey
    let wrong_fp = "0".repeat(16);
    let resp = deposit(f.server.base_url(), &wrong_fp, &p);
    assert_eq!(resp.status(), 400);
    // oversize parcel -> 413 (build a >36MiB attachments blob is slow; instead
    // test the store cap unit-wise or with a 36MiB+1KB body via raw JSON string)
}
```

(Concrete-ify the helpers when implementing: `authed` performs challenge→signed request; `deposit` returns the `ureq::Response` for status asserts. The lifecycle/wrong-key/replay/mismatch/caps intents are the contract; add retention-GC with `retention_days: 0` + a pre-dated parcel file written directly into the store layout.)

- [ ] **Step 2: RED → Step 3: implement** store.rs then server.rs. tiny_http notes: `Server::http(addr)` returns `Server`; bound port via `server.server_addr()` → `to_string()` parse or `HttpListener` — retrieve actual port for the `:0` case; loop `for request in server.incoming_requests()`; read body `request.as_reader().read_to_end`; respond `request.respond(Response::from_string(body).with_status_code(n).with_header(Content-Type json))`. 4 worker threads each running the accept loop guarded by an `Arc<Server>` (tiny_http Server is Sync; `incoming_requests` from multiple threads is supported).

- [ ] **Step 4: GREEN** — `cargo test -p cmail-relayd` (5+ tests), workspace green (98+ expected).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(relayd): reference relay server (tiny_http, nonce auth, retention GC, caps)"`

---

### Task R3: Keyring routes + relay config + audit events

**Files:**
- Modify: `crates/cmail-core/src/keyring.rs`, `config.rs`, `audit.rs`, `service.rs`; `crates/cmail-cli/src/main.rs`, `crates/cmail-cli/src/commands/admin.rs`

**Interfaces:**
- Produces:
  - `KeyEntry { public_key, first_seen, #[serde(default, skip_serializing_if = "Option::is_none")] route: Option<String> }` — old keyrings parse unchanged
  - `KeyRing::set_route(name, url: Option<&str>) -> Result<()>` (None clears; errors if name absent → `CoreError::Config`); `get_route(name) -> Option<String>`
  - `Config` gains `#[serde(default)] pub relay: RelaySection` with `RelaySection { #[serde(default)] url: Option<String> }`; generated default config.toml gains `[relay]\nurl = ""`; `Config::relay_url() -> Option<String>` (non-empty)
  - `AuditEvent::{KeyRoute, RelaySet, SendRelay, Fetch}` (serde: `key_route`, `relay_set`, `send_relay`, `fetch`) — extend the 12-name golden test to 16
  - Service: `Cmail::keyring_route(name, url: Option<&str>) -> Result<()>` (audits `key_route`), `Cmail::relay_set(url: Option<&str>) -> Result<()>` (audits `relay_set`)
  - CLI: `Keyring` gains `Route { name: String, url: Option<String>, #[arg(long)] clear: bool }`; `Relay { #[command(subcommand)] cmd: RelayCommand }` with `Set { url: String } | Clear | Show`; `keyring add` gains `--route <url>`; `keyring list --json` entries gain `"route"`; human list appends ` -> {url}`.

- [ ] **Step 1: Failing tests** (keyring.rs + config.rs test modules + one CLI lifecycle addition asserting `keyring route` + `relay set` round-trip and the amended 16-name audit pin) — write them per the Interfaces above, mirroring existing test style.
- [ ] **Step 2: RED → Step 3: implement** (config default text updated — keep the existing generated-file equality test passing by regenerating expected).
- [ ] **Step 4: GREEN** — workspace green (101+ expected).
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core+cli): keyring routes, relay url config, 4 audit events"`

---

### Task R4: Send-to-route (POST through the outbound gate)

**Files:**
- Modify: `crates/cmail-core/src/service.rs`

**Interfaces:**
- Consumes: R1 `relay::{deposit, build_parcel, normalize_base}`, R3 `KeyRing::get_route`.
- Produces: `Cmail::send` resolution per spec §3.2: (1) local identity → today's local path VERBATIM; (2) keyring-known with route → seal to keyring key (existing `recipient_x25519`) → gate (held BEFORE network; `approve` of a routed held message performs the POST after its recipient re-check) → `build_parcel` (with attachment frames read from `attachments/<id>/att-*.bin`) → `deposit` → audit `send_relay` (actor from, counterpart to, msg id) → `SendOutcome::Sent`; deposit failure → clean `CoreError::Relay` error, nothing local written; (3) else UnknownRecipient (unchanged). New private `fn send_remote(...) -> Result<SendOutcome>` handling the routed branch incl. parcel assembly and the approve path (`approve` checks: routed held envelope (recipient has no local identity but has keyring+route at approve time) → deposit instead of local move; audit `send_relay`).

- [ ] **Step 1: Failing tests** (service tests; use `cmail-relayd` as a dev-dependency of cmail-core to run an in-process server)

Add to `crates/cmail-core/Cargo.toml` `[dev-dependencies]`: `cmail-relayd = { path = "../cmail-relayd" }`.

```rust
    fn relay_fix() -> (tempfile::TempDir, Cmail, cmail_relayd::RelayServer, String /*base*/) {
        let root = tempfile::tempdir().unwrap();
        let rroot = tempfile::tempdir().unwrap();
        let server = cmail_relayd::RelayServer::start("127.0.0.1:0", rroot.path().to_path_buf(), 7).unwrap();
        let base = server.base_url();
        (root, Cmail::open(root.path()).unwrap(), server, base)
    }

    #[test]
    fn send_to_routed_recipient_deposits_parcel_and_fetches_back() {
        let (_r, sender, _s, base) = relay_fix();
        let (_r2, recipient, _s2, _b2) = relay_fix(); // SEPARATE root = separate machine
        // recipient publishes: sender's human learns zoe's key + route out-of-band
        let zoe = crate::identity::create_identity(_r2.path(), "zoe").unwrap();
        sender.keyring_add("zoe", KeySource::KeyFile(keyfile_of(&zoe))).unwrap();
        sender.keyring_route("zoe", Some(&base)).unwrap();
        let out = sender.send(Some("alice"), "zoe", "note", "remote", "hello machine", &[], None).unwrap();
        assert!(matches!(out, SendOutcome::Sent { .. }));
        // recipient fetches (fetch itself lands in R5 — here verify the PARCEL is on the relay via core relay client)
        let fp = zoe.fingerprint();
        let ids = crate::relay::list_pending(&base, &fp, &zoe.signing).unwrap();
        assert_eq!(ids.len(), 1);
        let parcel = crate::relay::fetch_parcel(&base, &fp, &ids[0], &zoe.signing).unwrap();
        assert!(parcel.envelope.is_sealed());
    }

    #[test]
    fn routed_send_is_gated_before_network() {
        let (_r, sender, _s, base) = relay_fix();
        let (_r2, recipient, _s2, _) = relay_fix();
        let zoe = crate::identity::create_identity(_r2.path(), "zoe").unwrap();
        sender.keyring_add("zoe", KeySource::KeyFile(keyfile_of(&zoe))).unwrap();
        sender.keyring_route("zoe", Some(&base)).unwrap();
        let out = sender.send(Some("alice"), "zoe", "note", "s", "b", &[], None).unwrap();
        assert!(matches!(out, SendOutcome::Held { .. })); // gate BEFORE network
        let id = match out { SendOutcome::Held { id, .. } => id, _ => unreachable!() };
        // nothing on the relay yet
        assert!(crate::relay::list_pending(&base, &zoe.fingerprint(), &zoe.signing).unwrap().is_empty());
        sender.approve(&id, true).unwrap(); // approve performs the POST
        assert_eq!(crate::relay::list_pending(&base, &zoe.fingerprint(), &zoe.signing).unwrap().len(), 1);
        let recs = sender.audit_tail(5).unwrap();
        assert!(recs.iter().any(|r| r.event == AuditEvent::SendRelay));
    }

    #[test]
    fn routed_send_failure_writes_nothing_local() {
        // route to a dead port: send errors cleanly, no pending/inbox writes
        let (_r, sender, _s, _b) = relay_fix();
        let (_r2, recipient, _s2, _) = relay_fix();
        let zoe = crate::identity::create_identity(_r2.path(), "zoe").unwrap();
        sender.keyring_add("zoe", KeySource::KeyFile(keyfile_of(&zoe))).unwrap();
        sender.keyring_route("zoe", Some("http://127.0.0.1:9")).unwrap(); // port 9 = discard, refused
        sender.allow_add("zoe").unwrap();
        let err = sender.send(Some("alice"), "zoe", "note", "s", "b", &[], None).unwrap_err();
        assert!(matches!(err, CoreError::Relay(_)), "{err}");
        assert!(sender.store.list_ids(&sender.store.pending_dir("alice")).is_empty());
    }
```

(`keyfile_of` helper writes the b64 pubkey to a temp file; mirror existing fixtures. Attachment-carrying routed send: extend test 1 with one attachment, asserting the parcel carries the frame and `fetch_parcel` decodes it.)

- [ ] **Step 2: RED → Step 3: implement** — restructure `send`'s recipient resolution into the three-branch form; keep the local branch byte-identical (context lines in review); `send_remote` builds the parcel from the envelope + `attachments/<id>/att-*.bin` frames (sorted by index).
- [ ] **Step 4: GREEN** — `cargo test -p cmail-core service -- --test-threads=1`, workspace green (104+ expected).
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): routed send (gate-first, parcel POST, approve delivers remotely)"`

---

### Task R5: Fetch + CLI + MCP

**Files:**
- Modify: `crates/cmail-core/src/service.rs`, `crates/cmail-cli/src/main.rs`, `crates/cmail-cli/src/commands/mail.rs`, `crates/cmail-mcp/src/tools.rs`, `crates/cmail-mcp/tests/server.rs`, `crates/cmail-cli/tests/lifecycle.rs`

**Interfaces:**
- Produces:
  - `Cmail::fetch(&self, as_name: Option<&str>, wait: bool, timeout: Duration) -> Result<FetchReport>` with `pub struct FetchReport { pub fetched: usize, pub kept_on_relay: usize }` (serde for CLI/MCP). Behavior per spec §3.3: resolve identity → fp → `[relay] url` required (else clean error "no relay configured; run cmail relay set <url>") → loop `list_pending` → per id: `fetch_parcel` → `Envelope::parse` + `verify_self_signature` (fail → skip, kept_on_relay++, audit `corrupt`/"remote parcel failed verification", NO ack) → write envelope to my `inbox/` + frames to `attachments/<id>/att-<i>.bin` → `ack`. Then audit one `fetch` record (detail `"n fetched, m kept"`). `wait=true`: poll list every 5s until new id or timeout, fetching as they arrive.
  - CLI: `cmail fetch [--wait] [--timeout 30]` → human `fetched n (m kept on relay)` / `--json` FetchReport. MCP: tool `cmail_fetch` (args `wait: bool?`, `timeout_seconds: int?` — clamped 600) description: "Pull pending mail from YOUR configured network relay (contacts the relay). Remote mail goes through normal trust rules."
  - Trusted-tool list assertion updated to include `cmail_fetch` (7 tools now).

- [ ] **Step 1: Failing tests** (service: the cross-machine completion — extends R4's `relay_fix`: after R4's deposit, `recipient.fetch(...)` → inbox item present (trust "untrusted" — remote sender unknown) → `read_message` decrypts (sealed to zoe's key) and wraps; bad-parcel case: hand-deposit garbage via `relay::deposit` with a malformed-but-v1 parcel? simpler: deposit a parcel whose envelope was tampered post-signing (raw string edit on the stored parcel file in relay root) → fetch keeps it on relay + audits corrupt. CLI lifecycle: `fetch` JSON shape; MCP: tool present + `cmail_fetch` returns FetchReport on a live relay fixture — MCP tests may instead assert tool presence + spec shape with a stubbed empty relay (no relay configured → isError).)
- [ ] **Step 2: RED → Step 3: implement.**
- [ ] **Step 4: GREEN** — workspace green (108+ expected).
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: cmail fetch (CLI+MCP) — verified remote delivery through local trust machinery"`

---

### Task R6: `cmail relay-serve`, docs, spec amendments, v0.3.0

**Files:**
- Modify: `crates/cmail-cli/src/main.rs` (new subcommand), `README.md`, `AGENTS.md`, root `Cargo.toml` (0.3.0), `docs/superpowers/specs/2026-11-01-cmail-design.md`

- [ ] **Step 1: `cmail relay-serve`** — CLI subcommand delegating to `cmail_relayd::run_server(args)` (extract the bin's main-loop into `pub fn run_server(root, addr, retention_days) -> anyhow::Result<()>` in relayd lib). Flags: `--root <dir>` required, `--addr` default `127.0.0.1:8080`, `--retention-days` default 7, `--tls-cert/--tls-key` stub errors per R2.
- [ ] **Step 2: README** — new "Two machines, no servers" replacement section: "Two machines, one relay" (run `cmail relay-serve`, share your fingerprint+route, keyring add --route, send, fetch); relay honest-edges paragraph (what the relay sees); fetch in the quickstart; install URLs → v0.3.0. AGENTS.md: fetch line ("if your human configured a relay, `cmail fetch` pulls new mail — trust rules unchanged").
- [ ] **Step 3: Spec amendments (v1.0 spec)** — §4.4 event list + CLI table rows (`fetch`, `relay set|clear|show`, `keyring route`, `relay-serve`); §11 mark "SHIPPED (v0.3): client + reference server + protocol v1; relay-to-relay forwarding remains future".
- [ ] **Step 4: Final gates + demo** — `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` (report count); manual demo: terminal 1 `cmail relay-serve --root target/relaydemo --addr 127.0.0.1:18080`; roots A and B: A keyring-adds B's key+route, sends, approves; B `relay set` + `cmail fetch` + `read` — record transcript.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat+docs: cmail relay-serve; relay guide; v0.3.0"`

---

## Self-review notes (applied while writing)

- Spec §2/§2.1 protocol details → R1 (types/client) + R2 (server) with matching tests on both sides; §2.2 server behavior → R2; §3.1 keyring routes → R3; §3.2 send resolution (gate-first, approve-POST, failure-nothing-local) → R4 (three tests pin each); §3.3 fetch (+kept-on-relay semantics, petnames note) → R5; §3.4 audit events → R3/R4/R5; §4 deps/deps-layout → R1/R2 (relayd OUT of core); §5 error handling → R1 (Relay variant), R2 (status mapping), R4 (failure test), R5 (skip-no-ack); §6 testing matrix → R1-R5 tests incl. cross-machine simulation and bad-parcel retention; §7 non-goals respected (no forwarding, no auto-poll beyond --wait, single relay URL).
- Pre-flagged warts: tiny_http bound-port retrieval + multi-thread accept (R2); ureq 2.x API shape (R1); config default-file text change must regenerate the equality test expectation (R3); core dev-dep on relayd for in-process fixtures (R4/R5 — dev-only, no production coupling); MCP fetch test avoids requiring a live relay via the no-relay-configured error path (R5).
- Deliberately out of scope: TLS termination (documented reverse-proxy guidance), retry queues, multiple relays, relay-to-relay.
