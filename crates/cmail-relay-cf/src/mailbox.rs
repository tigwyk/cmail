//! The per-mailbox Durable Object (spec §2/§3/§4): SQLite-backed index,
//! nonces, caps, and alarm-driven retention.
//!
//! THIS OBJECT HAS NO EXTERNAL ROUTES. Only the Worker (this crate's `main`,
//! wired in task C4) holds the DO stub — obtained via
//! `id_from_name(sha256(fp))` — and calls the internal command paths routed
//! in [`Mailbox::fetch`]. Client requests can never reach a DO directly; the
//! Worker owns all relay-protocol wire shaping. Command bodies and responses
//! below are an internal contract with the Worker, not the public wire.
//!
//! Storage = the DO SQL API (`state.storage().sql()`), the spec §3 tables:
//! - `cmail_meta(key, value)` — `pubkey` + `created_unix` (pinned at first
//!   deposit, relayd never rewrites them), `retention_days` (latest deposit
//!   wins; the alarm needs it and requests are its only delivery path),
//!   `swept_empty` (see alarm below).
//! - `cmail_entries(id, size, received_unix)` — one row per parcel; `id` is
//!   the 32-hex blob key the Worker already R2-put at `{fp}/{id}`.
//! - `cmail_nonces(hash, nonce, expires_unix)` — `hash` =
//!   sha256(nonce_b64)[..16] hex, mirroring relayd's hash-addressed files.
//!   The b64 VALUE is also stored (like relayd's file contents): wire v1
//!   clients send `X-cmail-Signature` WITHOUT echoing the nonce, so auth must
//!   re-verify the signature over each candidate nonce — see `/consume`.
//! - `cmail_orphans(id, marked_unix)` — blob ids whose index entry the alarm
//!   deleted. The alarm cannot R2-delete (the DO has no R2 binding by
//!   design); the Worker claims markers via `/sweep-pending` and deletes the
//!   blobs, so an index entry always has a blob and a deleted one is reaped.
//!
//! Consistency: a DO executes one event at a time per instance, so each
//! `fetch`/`alarm` handler runs serialized — multi-statement sequences below
//! (cap check → insert; verify → delete) are atomic exactly like relayd's
//! file-lock commits.

use crate::calc::{
    cap_status, is_expired, nonce_slot_available, DEFAULT_RETENTION_DAYS, MAX_MAILBOX_ENTRIES,
    NONCE_TTL_SECS,
};
use crate::{bad_request, json_response, not_found};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use worker::durable_object;
use worker::{DurableObject, Request, Response, Result, State};
use worker::{SqlCursor, SqlStorageValue};

/// Parse one command body; a malformed one answers 400 without touching the
/// handler (the Worker is the only caller, so this is a contract violation).
async fn read_body<T: DeserializeOwned>(req: &mut Request) -> std::result::Result<T, Response> {
    req.json().await.map_err(|_| bad_request())
}

/// How long an unswept orphan marker survives (the Worker never came back to
/// claim the blob deletion). After that the marker is dropped and the R2 blob
/// leaks — accepted, bounded, and honest: the alternative (R2 lifecycle rules)
/// is explicitly out of scope per the design decision this implements.
const MARKER_TTL_SECS: i64 = 7 * 86400;
/// Upper bound on orphan markers handed out per `/sweep-pending` (one marker
/// round per Worker request, per the internal contract).
const SWEEP_CLAIM_LIMIT: i64 = 64;
const DAY_SECS: i64 = 86400;

/// Ed25519-verify `sig_b64` over the nonce's ASCII bytes with the b64 pubkey —
/// byte-for-byte relayd's `verify_challenge_sig` (a failed verify never
/// mutates storage).
pub fn verify_challenge_sig(nonce: &str, sig_b64: &str, pubkey_b64: &str) -> bool {
    let pubkey = match B64.decode(pubkey_b64) {
        Ok(p) if p.len() == 32 => p,
        _ => return false,
    };
    let sig = match B64.decode(sig_b64) {
        Ok(s) if s.len() == 64 => s,
        _ => return false,
    };
    let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&pubkey[..32].try_into().unwrap())
    else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig) else {
        return false;
    };
    use ed25519_dalek::Verifier;
    verifying.verify(nonce.as_bytes(), &sig).is_ok()
}

/// Wall-clock unix seconds inside the Workers runtime.
fn now_unix() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

/// `crypto.getRandomValues` via js_sys reflection — worker 0.8 exposes no
/// typed binding (its web-sys features lack `Crypto`), and this crate adds no
/// dependencies for it. Bounded well under the 65536-byte API limit.
fn random_bytes(len: u32) -> Result<Vec<u8>> {
    use worker::js_sys::{global, Reflect, Uint8Array};
    use worker::wasm_bindgen::{JsCast, JsValue};
    let err = |e: JsValue| worker::Error::from(e);
    let crypto = Reflect::get(&global(), &JsValue::from_str("crypto")).map_err(err)?;
    let f = Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .map_err(err)?
        .dyn_into::<worker::js_sys::Function>()
        .map_err(err)?;
    let buf = Uint8Array::new_with_length(len);
    f.call1(&crypto, &buf).map_err(err)?;
    Ok(buf.to_vec())
}

// --- internal command bodies (the Worker is the only client) ---

#[derive(Deserialize)]
struct DepositBody {
    /// Blob id the Worker already R2-put (32 hex). On a non-200 answer the
    /// Worker MUST R2-delete that blob — index and blob never both persist.
    id: String,
    /// Encoded parcel bytes (the size the 256 MiB cap accounts against).
    size: u64,
    received_unix: i64,
    /// Recipient pubkey (b64) to pin at first deposit; the Worker has already
    /// verified fingerprint(pubkey) == fp (400 on mismatch, wire-side).
    pubkey: String,
    /// From the Worker env var; persisted here because `alarm()` has no
    /// request to carry it (spec §4).
    retention_days: u64,
}

#[derive(Deserialize)]
struct IdBody {
    id: String,
}

#[derive(Deserialize)]
struct ConsumeBody {
    /// b64 Ed25519 signature over the nonce ASCII bytes. NOT a nonce hash:
    /// wire v1 clients never echo the nonce, so the Worker cannot know which
    /// hash to consume — the DO re-verifies against its stored nonce values
    /// (relayd's `consume_nonce_by_signature` parity) and deletes exactly the
    /// verified row.
    signature: String,
}

// --- SQL row shapes ---

#[derive(Deserialize)]
struct ValueRow {
    value: String,
}
#[derive(Deserialize)]
struct CountRow {
    n: i64,
}
#[derive(Deserialize)]
struct CapsRow {
    n: i64,
    total: i64,
}
#[derive(Deserialize)]
struct IdRow {
    id: String,
}
#[derive(Deserialize)]
struct EntryRow {
    size: i64,
    received_unix: i64,
}
#[derive(Deserialize)]
struct NonceRow {
    hash: String,
    nonce: String,
}
#[derive(Deserialize)]
struct ExpiredRow {
    id: String,
    received_unix: i64,
}
#[derive(Deserialize)]
struct MinRow {
    m: Option<i64>,
}

/// One mailbox's consistency point. Keyed by `id_from_name(sha256(fp))`.
#[durable_object(alarm)]
pub struct Mailbox {
    state: State,
}

impl DurableObject for Mailbox {
    fn new(state: State, _env: worker::Env) -> Self {
        Self { state }
    }

    /// Internal command dispatch. The paths and bodies are private contract
    /// with the Worker (C4); anything else 404s.
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.ensure_schema()?;
        let method = req.method().as_ref().to_owned();
        let path = req.path();
        match (method.as_str(), path.as_str()) {
            ("GET", "/meta") => self.cmd_meta().await,
            ("POST", "/deposit") => match read_body::<DepositBody>(&mut req).await {
                Ok(b) => self.cmd_deposit(b).await,
                Err(resp) => Ok(resp),
            },
            ("POST", "/list") => self.cmd_list().await,
            ("POST", "/get") => match read_body::<IdBody>(&mut req).await {
                Ok(b) => self.cmd_get(b).await,
                Err(resp) => Ok(resp),
            },
            ("POST", "/delete") => match read_body::<IdBody>(&mut req).await {
                Ok(b) => self.cmd_delete(b).await,
                Err(resp) => Ok(resp),
            },
            ("POST", "/challenge") => self.cmd_challenge().await,
            ("POST", "/consume") => match read_body::<ConsumeBody>(&mut req).await {
                Ok(b) => self.cmd_consume(b).await,
                Err(resp) => Ok(resp),
            },
            ("POST", "/sweep-pending") => self.cmd_sweep_pending().await,
            _ => Ok(not_found()),
        }
    }

    /// Retention alarm (spec §4): expire entries (recording orphan markers
    /// for the Worker's blob sweep), sweep expired nonces, TTL stale
    /// markers, then reschedule — to the next entry expiry, or to the marker
    /// TTL, or prune the mailbox entirely when a sweep emptied it and the
    /// Worker has claimed every marker (relayd's "emptied by the sweep"
    /// prune; a mailbox emptied by acks keeps its meta).
    async fn alarm(&self) -> Result<Response> {
        self.ensure_schema()?;
        let now = now_unix();
        let retention_days = self
            .meta_get("retention_days")?
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RETENTION_DAYS);
        let retention_secs = (retention_days as i64).saturating_mul(DAY_SECS);

        // Expired entries → orphan markers (blobs are Worker/R2-only), then
        // deleted index rows. The SQL comparison is a prefilter; the
        // boundary-inclusive cutoff itself is calc::is_expired — the same
        // host-tested rule relayd's gc applies.
        let cutoff = now.saturating_sub(retention_secs);
        let expired = self
            .query(
                "SELECT id, received_unix FROM cmail_entries WHERE received_unix <= ?",
                vec![cutoff.into()],
            )?
            .to_array::<ExpiredRow>()?;
        // relayd prunes only mailboxes the SWEEP itself emptied — never one
        // emptied by acks (those keep their meta so the owner can keep
        // listing). The flag below carries that distinction through to the
        // deferred prune.
        let sweep_emptied = !expired.is_empty();
        for row in expired {
            if !is_expired(row.received_unix, retention_days, now) {
                continue;
            }
            self.query(
                "INSERT OR IGNORE INTO cmail_orphans(id, marked_unix) VALUES(?, ?)",
                vec![row.id.clone().into(), now.into()],
            )?;
            self.query(
                "DELETE FROM cmail_entries WHERE id = ?",
                vec![row.id.into()],
            )?;
        }
        if sweep_emptied && self.count("cmail_entries")? == 0 {
            self.meta_put("swept_empty", "1")?;
        }

        // Expired nonces never count toward the outstanding cap anywhere.
        self.query(
            "DELETE FROM cmail_nonces WHERE expires_unix <= ?",
            vec![now.into()],
        )?;
        // Stale unswept markers: drop them (their blobs leak — see MARKER_TTL).
        self.query(
            "DELETE FROM cmail_orphans WHERE marked_unix <= ?",
            vec![now.saturating_sub(MARKER_TTL_SECS).into()],
        )?;

        let entries = self.count("cmail_entries")?;
        let orphans = self.count("cmail_orphans")?;
        let storage = self.state.storage();
        if entries > 0 {
            // Shortest wait wins: next alarm at the oldest remaining expiry.
            let min_received = self
                .query("SELECT MIN(received_unix) AS m FROM cmail_entries", vec![])?
                .to_array::<MinRow>()?
                .into_iter()
                .next()
                .and_then(|r| r.m)
                .unwrap_or(now);
            storage
                .set_alarm(
                    min_received
                        .saturating_add(retention_secs)
                        .saturating_mul(1000),
                )
                .await?;
        } else if orphans > 0 {
            // Nothing left to expire; reap the marker TTL later (or get
            // pruned sooner when the Worker claims the last marker).
            storage
                .set_alarm(now.saturating_add(MARKER_TTL_SECS).saturating_mul(1000))
                .await?;
        } else {
            self.prune_if_sweep_emptied().await?;
        }
        Response::empty()
    }
}

impl Mailbox {
    // --- plumbing ---

    fn query(&self, text: &str, binds: Vec<SqlStorageValue>) -> Result<SqlCursor> {
        self.state.storage().sql().exec(text, Some(binds))
    }

    /// Idempotent schema (SQLite-backed DO class; spec §3 tables).
    fn ensure_schema(&self) -> Result<()> {
        self.query(
            "CREATE TABLE IF NOT EXISTS cmail_meta(\
             key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            vec![],
        )?;
        self.query(
            "CREATE TABLE IF NOT EXISTS cmail_entries(\
             id TEXT PRIMARY KEY, size INTEGER NOT NULL, received_unix INTEGER NOT NULL)",
            vec![],
        )?;
        self.query(
            "CREATE TABLE IF NOT EXISTS cmail_nonces(\
             hash TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires_unix INTEGER NOT NULL)",
            vec![],
        )?;
        self.query(
            "CREATE TABLE IF NOT EXISTS cmail_orphans(\
             id TEXT PRIMARY KEY, marked_unix INTEGER NOT NULL)",
            vec![],
        )?;
        Ok(())
    }

    fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .query(
                "SELECT value FROM cmail_meta WHERE key = ?",
                vec![key.into()],
            )?
            .to_array::<ValueRow>()?
            .into_iter()
            .next()
            .map(|r| r.value))
    }

    fn meta_put(&self, key: &str, value: &str) -> Result<()> {
        self.query(
            "INSERT OR REPLACE INTO cmail_meta(key, value) VALUES(?, ?)",
            vec![key.into(), value.into()],
        )?;
        Ok(())
    }

    fn count(&self, table: &str) -> Result<i64> {
        // `table` is a literal from this file, never user input.
        let text = format!("SELECT COUNT(*) AS n FROM {table}");
        Ok(self
            .query(&text, vec![])?
            .to_array::<CountRow>()?
            .into_iter()
            .next()
            .map(|r| r.n)
            .unwrap_or(0))
    }

    fn has_meta(&self) -> Result<bool> {
        Ok(self.meta_get("pubkey")?.is_some())
    }

    /// relayd prune rule: only a mailbox the retention sweep emptied is
    /// deleted outright (meta included); one emptied by acks keeps its meta.
    /// Runs once every marker is claimed, so the last thing to go is the
    /// record of blobs that still needed deleting.
    async fn prune_if_sweep_emptied(&self) -> Result<()> {
        if self.count("cmail_entries")? == 0
            && self.count("cmail_orphans")? == 0
            && self.count("cmail_nonces")? == 0
            && self.meta_get("swept_empty")?.as_deref() == Some("1")
        {
            let storage = self.state.storage();
            storage.delete_all().await?;
            storage.delete_alarm().await?;
        }
        Ok(())
    }

    // --- commands ---

    /// `GET /meta` → `{pubkey, created_unix}` | 404. The Worker's auth step
    /// (404 unknown mailbox BEFORE any signature check, relayd parity).
    async fn cmd_meta(&self) -> Result<Response> {
        match (self.meta_get("pubkey")?, self.meta_get("created_unix")?) {
            (Some(pubkey), Some(created)) => Ok(json_response(
                200,
                json!({"pubkey": pubkey, "created_unix": created.parse::<i64>().unwrap_or(0)}),
            )),
            _ => Ok(not_found()),
        }
    }

    /// `POST /deposit {id,size,received_unix,pubkey,retention_days}`:
    /// cap-check the POST-deposit state (count-first 429, then 413 — relayd
    /// error texts so the Worker can forward bodies verbatim), pin meta at
    /// first deposit, insert the index row, schedule the alarm
    /// shortest-wins. The blob is the Worker's problem; on non-200 it MUST
    /// R2-delete it.
    async fn cmd_deposit(&self, b: DepositBody) -> Result<Response> {
        if !crate::paths::valid_id(&b.id) {
            return Ok(bad_request());
        }
        let caps = self
            .query(
                "SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS total FROM cmail_entries",
                vec![],
            )?
            .to_array::<CapsRow>()?
            .into_iter()
            .next()
            .map(|r| (r.n.max(0) as usize, r.total.max(0) as u64))
            .unwrap_or((0, 0));
        if let Some(status) = cap_status(caps.0 + 1, caps.1.saturating_add(b.size)) {
            let msg = if status == 429 {
                format!("too many entries: mailbox is full ({MAX_MAILBOX_ENTRIES} entries)")
            } else {
                "over size cap: mailbox exceeds the 256 MiB size cap".to_string()
            };
            return Ok(json_response(status, json!({ "error": msg })));
        }

        // Meta pinned at first deposit (relayd never rewrites pubkey/created);
        // retention follows the latest deposit, and a fresh deposit un-marks
        // sweep-emptiness (the mailbox is populated again).
        self.query(
            "INSERT OR IGNORE INTO cmail_meta(key, value) VALUES('pubkey', ?)",
            vec![b.pubkey.into()],
        )?;
        self.query(
            "INSERT OR IGNORE INTO cmail_meta(key, value) VALUES('created_unix', ?)",
            vec![now_unix().to_string().into()],
        )?;
        self.meta_put("retention_days", &b.retention_days.to_string())?;
        self.meta_put("swept_empty", "0")?;
        self.query(
            "INSERT INTO cmail_entries(id, size, received_unix) VALUES(?, ?, ?)",
            vec![b.id.into(), (b.size as i64).into(), b.received_unix.into()],
        )?;

        // Shortest wait wins (spec §4): only pull the alarm in.
        let retention_secs = (b.retention_days as i64).saturating_mul(DAY_SECS);
        let candidate_ms = b
            .received_unix
            .saturating_add(retention_secs)
            .saturating_mul(1000);
        let storage = self.state.storage();
        match storage.get_alarm().await? {
            Some(existing) if existing <= candidate_ms => {}
            _ => storage.set_alarm(candidate_ms).await?,
        }
        Ok(json_response(200, json!({ "ok": true })))
    }

    /// `POST /list` → `{"ids":[...]}` ascending (relayd's sorted listing).
    async fn cmd_list(&self) -> Result<Response> {
        if !self.has_meta()? {
            return Ok(not_found());
        }
        let ids: Vec<String> = self
            .query("SELECT id FROM cmail_entries ORDER BY id ASC", vec![])?
            .to_array::<IdRow>()?
            .into_iter()
            .map(|r| r.id)
            .collect();
        Ok(json_response(200, json!({ "ids": ids })))
    }

    /// `POST /get {id}` → `{id,size,received_unix}` | 404 (the Worker streams
    /// the blob from R2; this answers existence + metadata).
    async fn cmd_get(&self, b: IdBody) -> Result<Response> {
        match self
            .query(
                "SELECT size, received_unix FROM cmail_entries WHERE id = ?",
                vec![b.id.clone().into()],
            )?
            .to_array::<EntryRow>()?
            .into_iter()
            .next()
        {
            Some(e) => Ok(json_response(
                200,
                json!({"id": b.id, "size": e.size, "received_unix": e.received_unix}),
            )),
            None => Ok(not_found()),
        }
    }

    /// `POST /delete {id}` → `{"deleted":true}` | 404. The Worker deletes the
    /// R2 blob FIRST (blob-before-index: an entry always has a blob; a stray
    /// orphan blob is the alarm's problem, never a dangling index).
    async fn cmd_delete(&self, b: IdBody) -> Result<Response> {
        let existed = self
            .query(
                "SELECT id FROM cmail_entries WHERE id = ?",
                vec![b.id.clone().into()],
            )?
            .to_array::<IdRow>()?
            .into_iter()
            .next()
            .is_some();
        if !existed {
            return Ok(not_found());
        }
        self.query("DELETE FROM cmail_entries WHERE id = ?", vec![b.id.into()])?;
        Ok(json_response(200, json!({ "deleted": true })))
    }

    /// `POST /challenge` → `{nonce, expires_unix}` | 429. Sweep expired
    /// nonces, enforce the outstanding cap, issue 32 random bytes b64 with a
    /// 5-minute TTL. Does NOT require a mailbox (relayd issues nonces for any
    /// valid fp). `expires_unix` is internal; the Worker renders the wire's
    /// RFC3339 `expires` field.
    async fn cmd_challenge(&self) -> Result<Response> {
        let now = now_unix();
        self.query(
            "DELETE FROM cmail_nonces WHERE expires_unix <= ?",
            vec![now.into()],
        )?;
        let outstanding = self.count("cmail_nonces")?;
        if !nonce_slot_available(outstanding.max(0) as usize) {
            return Ok(json_response(
                429,
                json!({"error": "too many outstanding nonces"}),
            ));
        }
        let nonce = B64.encode(random_bytes(32)?);
        let hash = hex::encode(Sha256::digest(nonce.as_bytes()))[..16].to_string();
        let expires = now.saturating_add(NONCE_TTL_SECS);
        self.query(
            "INSERT INTO cmail_nonces(hash, nonce, expires_unix) VALUES(?, ?, ?)",
            vec![hash.into(), nonce.clone().into(), expires.into()],
        )?;
        Ok(json_response(
            200,
            json!({"nonce": nonce, "expires_unix": expires}),
        ))
    }

    /// `POST /consume {signature}` → `{"consumed":true}` | 401. The Worker
    /// calls this after `/meta` (404 unknown mailbox first). Single-use is
    /// the delete of the verified row inside this serialized request: verify
    /// FIRST over each candidate nonce so a bad signature never burns one
    /// (relayd's `consume_nonce_by_signature` parity — the wire never echoes
    /// the nonce, so only the DO can match signature to value).
    async fn cmd_consume(&self, b: ConsumeBody) -> Result<Response> {
        let now = now_unix();
        self.query(
            "DELETE FROM cmail_nonces WHERE expires_unix <= ?",
            vec![now.into()],
        )?;
        let Some(pubkey) = self.meta_get("pubkey")? else {
            return Ok(json_response(
                401,
                json!({"error": "auth failed (bad signature, or nonce expired/consumed)"}),
            ));
        };
        let candidates = self
            .query(
                "SELECT hash, nonce FROM cmail_nonces ORDER BY hash ASC",
                vec![],
            )?
            .to_array::<NonceRow>()?;
        for row in candidates {
            if verify_challenge_sig(&row.nonce, &b.signature, &pubkey) {
                // The single-use commit: delete exactly the verified row.
                self.query(
                    "DELETE FROM cmail_nonces WHERE hash = ?",
                    vec![row.hash.into()],
                )?;
                return Ok(json_response(200, json!({ "consumed": true })));
            }
        }
        Ok(json_response(
            401,
            json!({"error": "auth failed (bad signature, or nonce expired/consumed)"}),
        ))
    }

    /// `POST /sweep-pending` → `{"ids":[...]}`: claim up to
    /// [`SWEEP_CLAIM_LIMIT`] orphan markers (deleting the claimed rows) whose
    /// R2 blobs the Worker must now delete at `{fp}/{id}`. Claiming before
    /// the Worker's R2 delete means a crash in between leaks those blobs —
    /// bounded, disclosed, and the reason claims are per-request-capped.
    /// Prunes the mailbox when the last marker of a sweep-emptied one leaves.
    async fn cmd_sweep_pending(&self) -> Result<Response> {
        let ids: Vec<String> = self
            .query(
                "SELECT id FROM cmail_orphans ORDER BY marked_unix ASC LIMIT ?",
                vec![SWEEP_CLAIM_LIMIT.into()],
            )?
            .to_array::<IdRow>()?
            .into_iter()
            .map(|r| r.id)
            .collect();
        for id in &ids {
            self.query(
                "DELETE FROM cmail_orphans WHERE id = ?",
                vec![id.as_str().into()],
            )?;
        }
        self.prune_if_sweep_emptied().await?;
        Ok(json_response(200, json!({ "ids": ids })))
    }
}
