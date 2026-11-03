# cmail-relay-cf Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Cloudflare Worker implementation of the cmail relay protocol (v1 wire contract, zero deviations) — Rust via worker-rs, Durable Object per mailbox, R2 parcel blobs, alarm-based retention — shipped as v0.3.1 with a runtime-agnostic conformance suite both relay implementations must pass.

**Architecture:** New crate `crates/cmail-relay-cf` (lib + worker entry; wasm32 target). The Worker parses routes and owns the R2 bindings; a per-fingerprint Durable Object (SQLite storage) is the sole consistency point per mailbox (meta/entries/nonces, caps, alarm retention). **No existing crate is modified** — the cf crate carries its own `Parcel`/fingerprint/validation code (cmail-core is not wasm-compatible due to ureq/std-fs), and the conformance suite is the parity guard.

**Tech Stack:** `worker` (worker-rs 0.4+ — verify resolved API shapes), `ed25519-dalek`/`sha2`/`serde`/`serde_json`/`base64` (wasm-fine), wrangler CLI for dev/deploy.

## Global Constraints

- Spec authoritative: `docs/superpowers/specs/2026-11-02-cmail-relay-cf-design.md` + wire contract `2026-11-01-cmail-relays-design.md` §2 (as amended). ZERO wire deviations — route table, status codes (413=size incl. per-mailbox 256 MiB; 429=count: 1000 entries, 8 nonces), body shapes (`{"ids":[…]}` ascending, `{"nonce","expires"}`, `{"deleted":true}`, `{"error":…}`), opaque-parcel rule.
- Protocol numbers verbatim: nonce 32B b64 / single-use / 5-min TTL / ≤8 per fp; encoded precheck 64 MiB before read; decoded ≤ 36 MiB; retention default 7 (`CMAIL_RETENTION_DAYS`).
- Auth order on authed routes: verify Ed25519 (ASCII nonce bytes, stored pubkey) BEFORE consuming the nonce; failed signature never burns a nonce.
- No existing crate changes. New deps in cf crate only. Dev-deps (host-target tests): ureq, tempfile, serde_json.
- wasm build: `rustup target add wasm32-unknown-unknown` (once); cf crate builds with `wrangler deploy --dry-run --outdir=dist` (requires local wrangler/npx — if unavailable in an environment, `cargo build -p cmail-relay-cf --target wasm32-unknown-unknown` is the fallback gate; disclose which ran).
- Every task: `cargo fmt --all` + `cargo clippy --workspace --all-targets -- -D warnings` clean (cf crate included via a host-target shim — see C1) + full `cargo test --workspace` green. `#[expect]` > `#[allow]`.
- DO name: `id_from_name(sha256(fp))`. Blob key: `{fp}/{id}`. DO tables: `cmail_meta`, `cmail_entries(id,size,received_unix)`, `cmail_nonces(hash,expires_unix)` with hash = 16-hex SHA-256(nonce).
- Version stays 0.3.0 until C6 bumps to 0.3.1. Baseline: branch start 01f94ad, 128 tests.
- Process note: never leave `wrangler dev` running (kill by recorded PID) — same discipline as relayd.

---

### Task C1: Crate scaffold, wasm/host split, route layer

**Files:**
- Create: `crates/cmail-relay-cf/Cargo.toml`, `src/lib.rs`, `src/routes.rs`, `src/paths.rs`, `tests/routes_unit.rs`
- Modify: root `Cargo.toml` (workspace members + dep entries: `worker = "0.4"` — verify latest 0.x; `ed25519-dalek`, `sha2`, `hex`, `base64`, `serde`, `serde_json`, `anyhow` via workspace), `.gitignore` (+`/dist`)

**Interfaces:**
- Produces (exact):
  - `paths.rs`: `pub fn valid_fp(s: &str) -> bool` (16 hex), `pub fn valid_id(s: &str) -> bool` (32 hex), `pub fn do_name(fp: &str) -> String` (hex sha256(fp)), `pub fn blob_key(fp: &str, id: &str) -> String` (`{fp}/{id}`)
  - `routes.rs`: `pub enum Route { Challenge { fp: String }, Deposit { fp: String }, List { fp: String }, Fetch { fp: String, id: String }, Ack { fp: String, id: String } }`, `pub fn parse(method: &str, path: &str) -> Option<Route>` (query strings stripped; paths must be exact after split; invalid fp/id → None → caller 404s... NO: malformed fp/id return `Some` error distinction — use `pub enum ParseOutcome { Route(Route), NotFound }` so malformed segments are NotFound, matching relayd's behavior of not revealing validity)
  - `lib.rs`: `#[event(fetch)] pub fn main(req: Request, env: Env, ctx: Context) -> Result<Response>` initially wiring only route parsing to `not_found()`/`bad_request()` responders; `pub fn json_response(status: u16, body: serde_json::Value) -> Response` helper
  - Host-test shim: unit tests live in `tests/routes_unit.rs` (host target — the crate compiles for host too because `worker` deps are gated; VERIFY worker crate builds on host — if not, gate `worker`-dependent code behind `#[cfg(target_arch = "wasm32")]` and keep routes/paths cfg-free; disclose which shape worked)

- [ ] **Step 1: Scaffold** — crate + workspace wiring; `cargo build -p cmail-relay-cf` on HOST green (that's the CI-clippy-compatible target).

- [ ] **Step 2: Failing tests** (`tests/routes_unit.rs`)

```rust
use cmail_relay_cf::paths::{blob_key, do_name, valid_fp, valid_id};
use cmail_relay_cf::routes::{parse, ParseOutcome, Route};

#[test]
fn validation_matches_protocol_shapes() {
    assert!(valid_fp(&"a".repeat(16)) && !valid_fp(&"a".repeat(15)) && !valid_fp("zz".repeat(8)));
    assert!(valid_id(&"f".repeat(32)) && !valid_id(&"f".repeat(31)) && !valid_id("../evil".repeat(4)));
}

#[test]
fn route_table_matches_spec() {
    let ok = |m: &str, p: &str| match parse(m, p) {
        ParseOutcome::Route(r) => Some(r),
        ParseOutcome::NotFound => None,
    };
    assert!(matches!(ok("GET", "/challenge/aaaaaaaaaaaaaaaa"), Some(Route::Challenge { .. })));
    assert!(matches!(ok("POST", "/mailbox/aaaaaaaaaaaaaaaa"), Some(Route::Deposit { .. })));
    assert!(matches!(ok("GET", "/mailbox/aaaaaaaaaaaaaaaa"), Some(Route::List { .. })));
    assert!(matches!(ok("GET", "/mailbox/aaaaaaaaaaaaaaaa/ffffffffffffffffffffffffffffffff"), Some(Route::Fetch { .. })));
    assert!(matches!(ok("DELETE", "/mailbox/aaaaaaaaaaaaaaaa/ffffffffffffffffffffffffffffffff"), Some(Route::Ack { .. })));
    // wrong methods / unknown / malformed segments / query stripped
    assert!(ok("PUT", "/mailbox/aaaaaaaaaaaaaaaa").is_none());
    assert!(ok("GET", "/").is_none());
    assert!(ok("GET", "/mailbox/zz").is_none());
    assert!(ok("GET", "/mailbox/aaaaaaaaaaaaaaaa?x=1"), Some(Route::List { .. }) != None);
}

#[test]
fn do_name_hashes_and_blob_keys_are_stable() {
    assert_eq!(do_name("a".repeat(16)), hex::encode(sha2::Sha256::digest("a".repeat(16).as_bytes())));
    assert_eq!(blob_key("a".repeat(16), &"f".repeat(32)), format!("{}/{}", "a".repeat(16), "f".repeat(32)));
}
```

- [ ] **Step 3: RED → implement** paths.rs/routes.rs + the cfg-split lib.rs. **Step 4: GREEN** (`cargo test -p cmail-relay-cf`; full workspace 131 expected).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(relay-cf): crate scaffold, route layer, path validation (wasm/host split)"`

---

### Task C2: Parcel + fingerprint parity (cf-local)

**Files:**
- Create: `crates/cmail-relay-cf/src/parcel.rs`
- Test: `crates/cmail-relay-cf/tests/parcel_unit.rs`

**Interfaces:**
- Produces: `pub struct Parcel { pub v: u8, pub pubkey: String, pub envelope: serde_json::Value, pub attachments: Vec<ParcelAttachment> }` + `pub struct ParcelAttachment { pub i: usize, pub data: String }` (serde derives; envelope deliberately a `Value` — cf NEVER parses inside it, stricter than core's typed field); `pub fn fingerprint_of(pubkey_b64: &str) -> Option<String>` (16-hex sha256 of decoded key bytes; None on bad b64); `impl Parcel { pub fn validate(&self) -> Result<(), String> }` — v==1, pubkey b64-for-32B, ≤8 attachments, every data b64-decodes, total decoded ≤ 36 MiB, `i` values unique and 0..len (stricter than core: canonical index set).

- [ ] **Step 1: Failing tests** — mirror `cmail-core/src/relay.rs`'s parcel tests against the cf types: round-trip via serde_json preserves frames byte-identically; v≠1 rejected; >8 rejected; non-b64 rejected; decoded-total cap (three 12-MiB+1KiB... in-test big allocations are fine on host: use exactly-over-cap sums); `fingerprint_of` matches core's for the same key (hardcode a known key's expected fp — generate once with `cmail_core` in the test via dev-dep on cmail-core HOST-side: add `cmail-core = { path = "../cmail-core" }` to cf dev-deps; this is a dev-only dependency, permitted — production wasm code does NOT link core).
- [ ] **Step 2: RED → Step 3: implement → Step 4: GREEN** (134 expected).
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(relay-cf): parcel validation + fingerprint parity with core (dev-dep parity tests)"`

---

### Task C3: Durable Object — mailbox storage, caps, nonces, alarm

**Files:**
- Create: `crates/cmail-relay-cf/src/mailbox.rs` (cfg wasm)
- Test: covered by C5 conformance (DO storage can't run on host); pure logic (cap arithmetic, expiry math) extracted into `src/calc.rs` with host unit tests

**Interfaces:**
- Produces: `#[durable_object] pub struct Mailbox` implementing `DurableObject` (`fetch` dispatching sub-commands via an internal path convention — e.g. `/cmd/meta`, `/cmd/deposit {id,size,received}`, `/cmd/list`, `/cmd/get {id}`, `/cmd/delete {id}`, `/cmd/challenge`, `/cmd/consume {hash}` — the WORKER calls these; external routes never reach the DO directly) plus `alarm()`. Storage ops: meta upsert/get; entry insert with cap checks (count ≤ 1000 → 429, summed size ≤ 256 MiB → 413); list ascending; get/delete; nonce create (sweep expired, ≤8 outstanding → 429, return fresh 32B-b64 + expires); nonce consume (transactional single-use: delete-where-hash-and-not-expired; false → 401). Alarm: delete expired entries (returning their ids so the worker deletes R2 blobs) + prune empty mailbox + cancel alarm when empty. Alarm scheduling on deposit: `set_alarm(min(existing_or_none, now + retention))` — shortest wait wins.
- `calc.rs` (cfg-free, host-tested): `pub fn cap_status(count: usize, total_bytes: u64) -> Option<u16>` (None ok / Some(429) count / Some(413) size — count checked first), `pub fn is_expired(received_unix: i64, retention_days: u64, now_unix: i64) -> bool`, nonce-count check helper.

- [ ] **Step 1: Failing tests** for `calc.rs` (cap ordering: 1001 entries at tiny size → 429, 1000 entries at 257 MiB → 413, both over → 429 wins; expiry math; boundary 256 MiB exactly → ok).
- [ ] **Step 2: RED → Step 3: implement calc.rs + mailbox.rs** (wasm-cfg'd; verify against the resolved `worker` crate's DO API — method names for storage (`sql`/`get`/`put`), `set_alarm`, `alarm()` signature — adjust minimally, disclose). **Step 4: GREEN** (host tests; workspace green).
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(relay-cf): mailbox durable object (caps, transactional nonces, alarm retention)"`

---

### Task C4: Worker handlers — full route wiring with R2

**Files:**
- Modify: `crates/cmail-relay-cf/src/lib.rs`
- Create: `crates/cmail-relay-cf/wrangler.toml`, `crates/cmail-relay-cf/migrations/0001_mailbox.sql` (per resolved worker-rs DO migration convention)

**Interfaces:**
- Produces: complete `main` wiring per spec §2/§5: challenge → DO nonce; deposit → Content-Length precheck (absent/chunked → bounded read 64 MiB+1 then 413), parse+validate parcel (400), `fingerprint_of(pubkey)==fp` (400), R2 put `blob_key` (stream body re-serialized? NO — store the RAW request body bytes and validate on a parsed COPY; the blob must be byte-identical to what was deposited), DO index insert (413/429 from caps); authed routes → fetch pubkey from DO (404), verify signature (401), consume nonce (401), then list/fetch(R2 get, stream)/ack(R2 delete then DO delete). `wrangler.toml`: bindings `MAILBOX` (new_sqlite_classes), `PARCELS` (R2), `vars.CMAIL_RETENTION_DAYS="7"`, compat date = latest.

- [ ] **Step 1: Implement** (conformance C5 is the test cycle — TDD here is C5's suite; write handlers first, then C5 immediately).
- [ ] **Step 2: Verify build** — `wrangler deploy --dry-run --outdir=dist` if wrangler/npx available; else `cargo build -p cmail-relay-cf --target wasm32-unknown-unknown`. Disclose which.
- [ ] **Step 3: Commit** — `git add -A && git commit -m "feat(relay-cf): worker route handlers with R2 blobs and DO coordination"`

---

### Task C5: Runtime-agnostic conformance suite

**Files:**
- Create: `crates/cmail-relay-cf/tests/conformance.rs`
- Modify: `.github/workflows/ci.yml` (optional ubuntu job, below)

**Interfaces:**
- Produces: the spec §6 matrix, gated `#[ignore]`-by-default via env: tests read `CMAIL_RELAY_URL` and skip (pass with a printed note) when unset. Assertions twin `cmail-relayd/tests/server_tests.rs`: full lifecycle (deposit → authed list/fetch → byte-identical blob round-trip → ack → empty); wrong-key 401; nonce replay 401; fp-mismatch 400; 413 encoded (Content-Length lie via raw TCP — port relayd's raw-socket technique — else oversized real body), 413 decoded (valid-b64 over-cap attachments), 413 mailbox-size, 429 entry-count, 429 nonce-cap; retention (only when `CMAIL_RELAY_RETENTION_DAYS=0` env also set — deposit, sweep wait or manual re-touch, gone); `{"ids":[...]}` ascending shape; 404s. Fixtures use `ed25519_dalek` (host dev-dep) + cf's own `parcel`/`fingerprint` builders.
- CI job `conformance` (ubuntu, after test job): `if: github.repository == 'tigwyk/cmail'`-free (public repo) — steps: checkout, setup-node 20, `npx wrangler --version`, `npx wrangler dev --port 8787 &` in cf dir (env `CMAIL_RETENTION_DAYS=7`), sleep for boot, `CMAIL_RELAY_URL=http://127.0.0.1:8787 cargo test -p cmail-relay-cf --test conformance`, kill wrangler (always step).

- [ ] **Step 1: Write the suite** (host target). **Step 2: Local run** — with wrangler available: start `npx wrangler dev` (record PID), run suite against it, iterate handlers (C4) until green; kill wrangler. If wrangler is unavailable locally, the suite skips and CI becomes the first run — flag this loudly in the report.
- [ ] **Step 3: Commit** — `git add -A && git commit -m "test(relay-cf): runtime-agnostic conformance suite + CI wrangler-dev job"`

---

### Task C6: Docs, version 0.3.1, final verification

**Files:**
- Modify: `README.md`, root `Cargo.toml` (0.3.1), `.github/workflows/release.yml` (nothing — cf deploys, doesn't install; confirm no accidental inclusion)

- [ ] **Step 1: README** — new "Running a relay on Cloudflare" subsection inside the relay section: `crates/cmail-relay-cf`, `wrangler deploy` steps (bindings auto-provisioned by wrangler), `CMAIL_RETENTION_DAYS` var, free-tier economics table (100k req/day Workers; DO SQLite free tier; R2 10 GB + zero egress), the honest note that Cloudflare sees request metadata like any relay operator, and "same protocol, pick either implementation".
- [ ] **Step 2: Version 0.3.1**; **Step 3: Final gates** — fmt/clippy/--all-targets, full suite, wasm build (dry-run or target build), plus a final `wrangler dev` conformance run if tooling available.
- [ ] **Step 4: Commit** — `git add -A && git commit -m "docs+version: cloudflare relay guide; v0.3.1"`

---

## Self-review notes (applied while writing)

- Spec §1 no-changes-to-existing-crates → cf-local Parcel/fingerprint with dev-dep parity tests (C2); spec §2 routing/auth-order → C1/C4; §3 data model → C3; §4 alarms → C3; §5 zero-deviation wire → C4 + C5 as the enforcement; §6 conformance → C5 + CI job; §7 packaging → C4 wrangler.toml + C6 README + CI dry-run... (dry-run in CI comes with C5's job which runs wrangler dev; add `--dry-run` to the conformance job's first step); §8 testing → C1/C2/C3 host units + C5 black-box; §9 non-goals respected.
- Pre-flagged warts: worker-rs DO/alarm/storage API shapes (C3 — verify against resolved version, disclose), host-vs-wasm crate split (C1 cfg strategy — pick empirically), wrangler availability in dev/CI environments (C4/C5 fallback gates), raw-TCP Content-Length test portability on CI (C5 — keep relayd's technique, ubuntu job only), DO internal command routing is an implementation detail (never externally reachable — the Worker is the only client).
