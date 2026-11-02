# cmail-relay-cf — Cloudflare Worker Relay: Design

Date: 2026-11-02
Status: Approved by user (design review)
Builds on: relay protocol v1 (`2026-11-01-cmail-relays-design.md`, as amended —
authoritative wire contract). Ships as v0.3.1; no existing crate changes.

## 1. Overview

A second implementation of the cmail relay protocol as a Cloudflare Worker —
the "dumb post office" with **zero idle cost**. Wire-identical to the
reference `cmail-relayd`: same 5 routes, status codes (413 = size, 429 =
count), challenge auth, response shapes, opaque-parcel rule, and caps. Any
cmail client (CLI/MCP) works against either implementation unchanged.

Stack: **Rust via `worker-rs`** (house language; `ed25519-dalek` + `sha2`
verify/fingerprint in wasm — no WebCrypto dependency), **Durable Object per
mailbox fingerprint** (SQLite-backed: index + nonces, strong per-mailbox
consistency), **R2** for parcel blobs (full 36 MiB decoded / 64 MiB encoded
parity), **DO alarms** for retention. No cron, no accounts, no admin API.

Documented fallback (only if worker-rs DO ergonomics prove blocking during
implementation): TypeScript port of the same design. Switching is a spec
amendment, not a silent substitution.

## 2. Architecture

```
Client ──HTTPS──> Worker fetch handler (route parse: 5 routes)
                     │  open routes: challenge, deposit
                     │  authed routes: list, fetch, ack  (verify sig first)
                     ▼
        DurableObject stub keyed by sha256(fp)[..]  (id_from_name, per-{fp})
                     │  DO storage (SQLite): meta, entries, nonces
                     │  R2 put/get/delete: blobs at key `{fp}/{id}`
                     ▼
                R2 bucket (parcel bytes, never parsed)
```

- **Routing**: the Worker parses `{fp}` from the URL and obtains the DO stub
  via `id_from_name(sha256(fp))` (hashing so the DO name never carries the
  raw fingerprint). All five routes delegate to that DO's methods — the DO is
  the sole consistency point for a mailbox (nonce single-use, entry/size
  caps, index), exactly the invariants the file-based store enforces with
  `remove_file().is_ok()`-style commits.
- **Auth order** (authed routes): the DO returns the stored pubkey (404 if no
  mailbox), the Worker verifies the Ed25519 signature over the ASCII nonce,
  then asks the DO to consume the nonce (transactional single-use). Verify
  BEFORE consume so a failed signature never burns a nonce.
- **Blobs**: deposit streams the request body; the DO records the index entry
  only after the R2 put succeeds; fetch streams R2 → response; ack deletes
  R2 object then index entry (blob-first so an index entry always has a
  blob; a stray orphan blob is alarm-GC'd).

## 3. Data model (DO SQLite storage)

Tables (namespaced under cmail_):
- `cmail_meta(key TEXT PRIMARY KEY, value TEXT)` — `pubkey` (b64), `created`.
- `cmail_entries(id TEXT PRIMARY KEY, size INTEGER, received_unix INTEGER)` —
  id = 32-hex (validated), size = encoded bytes.
- `cmail_nonces(hash TEXT PRIMARY KEY, expires_unix INTEGER)` — hash =
  16-hex of SHA-256(nonce) (nonce values never stored, mirroring the
  reference's hash-addressed files).

Caps tracked from `cmail_entries`: count ≤ 1000 (429), summed size ≤ 256 MiB
(413). Nonces: ≤ 8 unexpired per fp (429), TTL 5 min, expired rows swept on
every touch.

## 4. Retention — DO alarms

- On first deposit in a mailbox: `set_alarm(now + retention)`, refreshed on
  later deposits (no earlier than the existing alarm — shortest wait wins).
- Alarm handler: delete expired entries (received_unix + retention ≤ now) +
  their R2 objects; prune the mailbox entirely (meta included) when empty;
  clear the alarm when nothing remains. Retention comes from a Worker env
  var `CMAIL_RETENTION_DAYS` (default **7**) read at boot and passed to the
  DO with each request (env vars aren't visible inside DOs directly).

## 5. Wire conformance (no deviations permitted)

Route table, status codes, and bodies exactly as spec'd in
`2026-11-01-cmail-relays-design.md` §2 (as amended): `GET /challenge/{fp}` →
`{"nonce","expires"}`; open `POST /mailbox/{fp}`; authed `GET /mailbox/{fp}`
→ `{"ids":[…]}`, `GET /mailbox/{fp}/{id}`, `DELETE` → `{"deleted":true}`;
400 malformed/fp-mismatch; 401 auth/nonce; 404 unknown mailbox/id; 413 size
(encoded precheck 64 MiB before read, decoded 36 MiB post-parse, per-mailbox
256 MiB); 429 count (1000 entries, 8 nonces). Body-limit notes: Workers'
100 MB request cap accommodates the 64 MiB precheck; reads are bounded by the
precheck (Content-Length absent/chunked → bounded buffered read + reject).

Implementation notes:
- `fingerprint_of(pubkey) == {fp}` verified at deposit (400) — same
  double-guard as the reference.
- Challenge nonces: 32 random bytes b64 from the DO (per-mailbox uniqueness
  via the hash-keyed table), single-use consumed only on successful auth.
- `{"ids":[…]}` order: ascending id, matching the reference's sorted listing.

## 6. Conformance suite

The `cmail-relayd` integration matrix gets a **runtime-agnostic twin**: the
same black-box HTTP assertions (lifecycle deposit/list/fetch/ack; wrong-key
+ nonce replay; fp-mismatch; encoded/decoded size caps; count caps 429;
retention; 404 paths; `{"ids"}` shape) parameterized by `CMAIL_RELAY_URL`.
Targets:
- Local: `wrangler dev` (started by the developer or CI; tests skip cleanly
  when the URL is unset).
- CI: optional job in `ci.yml` — install node + wrangler, `wrangler dev` in
  the background, run the suite, kill it. Runs on ubuntu only.
Both implementations passing one suite is the release gate for this crate.

## 7. Packaging & deploy

- Crate `crates/cmail-relay-cf` (lib + `#[event(fetch)]` entry) building via
  `workers.rs` (`wrangler deploy` runs the cargo-build step). NOT part of the
  release binary matrix (it deploys, not installs); CI builds it
  (`wrangler deploy --dry-run --outdir=dist`) to catch regressions.
- `wrangler.toml`: `main`, compatibility date, durable_object binding
  `MAILBOX` (SQLite-backed: `new_sqlite_classes`), R2 binding `PARCELS`,
  `vars.CMAIL_RETENTION_DAYS = "7"`, migrations for the DO class.
- README section "Running a relay on Cloudflare": `wrangler deploy` steps,
  bindings provisioning, the free-tier economics table (100k req/day Workers
  free, DO SQLite free tier, R2 10 GB + zero egress), and the honest note
  that Cloudflare sees request metadata (same class as any relay operator).

## 8. Testing

- Conformance suite (§6) against `wrangler dev`.
- Unit tests where worker-rs permits (pure helpers: route parsing, fp/id
  validation, cap arithmetic, nonce hash) — DO/R2 interactions covered by
  conformance, not unit mocks.
- Full existing workspace suite stays green (no existing crate touched).

## 9. Non-goals

- Any wire deviation from protocol v1 (that's the point).
- Rate limiting beyond the spec caps; abuse protection beyond R2/DO quotas.
- Custom domains/TLS configuration guidance beyond one README paragraph.
- Migration tooling between relayd files and R2/DO.
- KV-based variant (rejected for consistency; documented here so it isn't
  re-litigated).
