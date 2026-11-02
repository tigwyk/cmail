//! cmail-relay-cf — the cmail relay protocol as a Cloudflare Worker.
//!
//! Wire-identical twin of `cmail-relayd` (spec: relay protocol v1 §2, as
//! amended). This crate compiles both on the host (route/path unit tests,
//! CI clippy) and on `wasm32-unknown-unknown` (`wrangler deploy`).
//!
//! The Worker owns ALL wire shaping (spec §2/§5): it parses the five-route
//! table, enforces the encoded-body precheck, renders the challenge's
//! RFC3339 expiry, and streams R2 blobs. The per-mailbox Durable Object
//! ([`mailbox`]) is the sole consistency point and is reachable ONLY through
//! the internal command paths called below — its responses already carry
//! relayd-identical error texts, so cap/auth answers forward verbatim.

pub mod calc;
pub mod mailbox;
pub mod parcel;
pub mod paths;
pub mod routes;

use parcel::{fingerprint_of, Parcel};
use paths::{blob_key, do_name};
use routes::{ParseOutcome, Route};
use serde::Deserialize;
use serde_json::json;
use worker::{event, Request, Response};

/// JSON responder shared by every handler. `{"error": msg}` bodies match
/// relayd's shape exactly.
pub fn json_response(status: u16, body: serde_json::Value) -> Response {
    Response::from_json(&body)
        .expect("serializing a serde_json::Value cannot fail")
        .with_status(status)
}

/// 404 responder for unknown routes (unknown mailbox/id get relayd's more
/// specific texts via [`error_response`]; malformed fp/id fold into this —
/// the routing layer's deliberate no-validity-oracle, C1).
pub fn not_found() -> Response {
    json_response(404, serde_json::json!({ "error": "not found" }))
}

/// 400 responder for contract-violating DO answers at deposit (e.g. a
/// duplicate blob id); every client-caused 400 carries relayd's specific
/// text via [`error_response`] instead.
pub fn bad_request() -> Response {
    json_response(400, serde_json::json!({ "error": "bad request" }))
}

/// Error responder with relayd's exact message texts (spec §5: the two
/// relays are indistinguishable on the wire).
fn error_response(status: u16, message: &str) -> Response {
    json_response(status, json!({ "error": message }))
}

/// Encoded request-body cap (relay protocol v1 §2.1: 64 MiB — the larger of
/// the two caps because b64 expansion maps a decoded-36 MiB parcel to ~48 MiB
/// on the wire). relayd `MAX_BODY_BYTES` parity.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Fake absolute origin for internal DO requests: workerd's `Request`
/// constructor needs a parseable URL, but a DO stub routes by object id — the
/// host is never resolved, only the path reaches [`mailbox::Mailbox::fetch`].
const DO_ORIGIN: &str = "https://cmail-do.internal";

/// `{"ids": [...]}` shape returned by the DO's `/sweep-pending` (and echoed
/// by `/list`, which is forwarded instead of re-parsed).
#[derive(Deserialize)]
struct IdsBody {
    ids: Vec<String>,
}

/// RFC3339 rendering of arbitrary unix seconds — byte-for-byte relayd's
/// `rfc3339` helper (the `time` crate is already a workspace dep and
/// wasm-compatible; `unwrap_or_default` degrades to "" only for
/// out-of-range timestamps, exactly like the reference).
fn rfc3339(ts: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(ts)
        .map(|t| t.format(&Rfc3339).unwrap_or_default())
        .unwrap_or_default()
}

/// Wall-clock unix seconds inside the Workers runtime (the same clock the
/// DO's deposit/alarm paths read).
fn now_unix() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

/// Retention in days from `CMAIL_RETENTION_DAYS` (spec §4: default 7), read
/// and parsed once per request — cheap, and the DO persists it per deposit
/// because its alarm has no request to carry it.
fn retention_days(env: &worker::Env) -> u64 {
    env.var("CMAIL_RETENTION_DAYS")
        .map(|v| v.to_string())
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(calc::DEFAULT_RETENTION_DAYS)
}

/// Content-Length when the client sent one (absent for chunked bodies — then
/// only the post-read length check enforces the cap).
fn content_length(req: &Request) -> Option<usize> {
    req.headers()
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
}

/// The DO stub for one mailbox, keyed by `id_from_name(sha256(fp))` (spec
/// §2: the DO name never carries the raw fingerprint).
fn mailbox_stub(env: &worker::Env, fp: &str) -> worker::Result<worker::Stub> {
    env.durable_object("MAILBOX")?
        .id_from_name(&do_name(fp))?
        .get_stub()
}

/// Internal GET to the mailbox DO (`/meta`).
async fn do_get(stub: &worker::Stub, path: &str) -> worker::Result<Response> {
    stub.fetch_with_str(&format!("{DO_ORIGIN}{path}")).await
}

/// Internal POST to the mailbox DO with a JSON body (worker 0.8's stub has
/// no `post(path, body)` helper, so the `Request` is built by hand — body as
/// a JS string, which the DO's `req.json()` parses).
async fn do_post(
    stub: &worker::Stub,
    path: &str,
    body: serde_json::Value,
) -> worker::Result<Response> {
    let mut init = worker::RequestInit::new();
    init.method = worker::Method::Post;
    init.body = Some(worker::wasm_bindgen::JsValue::from_str(&body.to_string()));
    let req = worker::Request::new_with_init(&format!("{DO_ORIGIN}{path}"), &init)?;
    stub.fetch_with_request(req).await
}

/// Re-emit a DO response with status and body intact — the DO emits
/// relayd-identical texts for 401/413/429, so error bodies forward verbatim —
/// plus the JSON content type every relay response carries.
async fn forward(mut resp: Response) -> worker::Result<Response> {
    let status = resp.status_code();
    let body = resp.bytes().await?;
    let headers = worker::Headers::new();
    headers.set("Content-Type", "application/json")?;
    Ok(Response::from_bytes(body)?
        .with_status(status)
        .with_headers(headers))
}

/// The two protocol-limit failures of [`Parcel::validate`] (count > 8,
/// decoded total > 36 MiB) are relayd's `LimitExceeded` → 413; every other
/// validation failure is a 400. Matched on parcel.rs's exact messages (same
/// crate); C5's decoded-cap conformance test guards the coupling.
fn is_limit_violation(msg: &str) -> bool {
    msg.starts_with("parcel carries more than 8") || msg.starts_with("parcel attachments exceed")
}

/// Fresh 32-hex blob id from 16 random bytes (relayd's store assigns ids;
/// here the Worker does, because it R2-puts the blob BEFORE the DO indexes
/// it and the DO's `/deposit` takes the id as input).
fn new_parcel_id() -> worker::Result<String> {
    Ok(hex::encode(mailbox::random_bytes(16)?))
}

/// One orphan-marker round per mailbox touch (the DO's `/sweep-pending`
/// claims markers destructively, ≤64 at a time): claim, then R2-delete each
/// claimed blob at `{fp}/{id}` — the Worker holds the R2 binding, the DO
/// never does. Best effort by design: a failure here never fails the
/// request, and a blob that survives its claim just joins the disclosed
/// bounded-leak window (marker TTL) instead.
async fn sweep_orphans(stub: &worker::Stub, bucket: &worker::Bucket, fp: &str) {
    let Ok(mut resp) = do_post(stub, "/sweep-pending", json!({})).await else {
        return;
    };
    if resp.status_code() != 200 {
        return;
    }
    let Ok(claimed) = resp.json::<IdsBody>().await else {
        return;
    };
    for id in claimed.ids {
        let _ = bucket.delete(blob_key(fp, &id)).await;
    }
}

#[event(fetch)]
pub async fn main(
    req: Request,
    env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<Response> {
    let route = match routes::parse(req.method().as_ref(), &req.path()) {
        ParseOutcome::Route(route) => route,
        ParseOutcome::NotFound => return Ok(not_found()),
    };
    match route {
        Route::Challenge { fp } => challenge(&env, &fp).await,
        Route::Deposit { fp } => deposit(req, &env, &fp).await,
        Route::List { fp } => authed(&req, &env, &fp, None, false).await,
        Route::Fetch { fp, id } => authed(&req, &env, &fp, Some(&id), false).await,
        Route::Ack { fp, id } => authed(&req, &env, &fp, Some(&id), true).await,
    }
}

/// `GET /challenge/{fp}` (spec §2): the DO issues the nonce (sweeping
/// expired ones and enforcing the ≤8-outstanding cap → 429, whose body
/// forwards verbatim); 200 renders the wire's `{"nonce","expires"}` with the
/// DO's unix-second expiry converted to RFC3339.
async fn challenge(env: &worker::Env, fp: &str) -> worker::Result<Response> {
    let stub = mailbox_stub(env, fp)?;
    let mut resp = do_post(&stub, "/challenge", json!({})).await?;
    if resp.status_code() != 200 {
        return forward(resp).await;
    }
    let body: serde_json::Value = resp.json().await?;
    let nonce = body
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let expires_unix = body
        .get("expires_unix")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    Ok(json_response(
        200,
        json!({ "nonce": nonce, "expires": rfc3339(expires_unix) }),
    ))
}

/// `POST /mailbox/{fp}` (open; spec §2/§5): Content-Length precheck before
/// reading (413), bounded read + length re-check (chunked/absent-length
/// bodies), parse+validate the parcel (400, protocol limits 413),
/// `fingerprint_of(pubkey) == fp` (400), R2-put the RAW body bytes at
/// `{fp}/{id}` — byte-identical storage: the body is read to a `Vec` once,
/// parsed by reference, and the same `Vec` is stored — then the DO indexes
/// it; on any non-200 DO answer the blob is deleted BEFORE the error is
/// forwarded (an index entry always has a blob, never vice versa).
async fn deposit(mut req: Request, env: &worker::Env, fp: &str) -> worker::Result<Response> {
    // relayd parity: reject an over-cap body before reading it.
    if let Some(len) = content_length(&req) {
        if len > MAX_BODY_BYTES {
            return Ok(error_response(413, "body exceeds the size cap"));
        }
    }
    // workerd caps request bodies (100 MB) and worker 0.8 exposes no partial
    // read, so relayd's "+1 byte then stop" becomes read-then-length-check
    // on the collected Vec — over-cap bodies are still rejected before R2
    // or the DO is ever touched.
    let body = match req.bytes().await {
        Ok(b) => b,
        Err(_) => return Ok(error_response(400, "unreadable request body")),
    };
    if body.len() > MAX_BODY_BYTES {
        return Ok(error_response(413, "body exceeds the size cap"));
    }
    let parcel: Parcel = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return Ok(error_response(400, &format!("malformed parcel: {e}"))),
    };
    match parcel.validate() {
        Ok(()) => {}
        Err(e) if is_limit_violation(&e) => {
            return Ok(error_response(413, "parcel exceeds protocol limits"));
        }
        Err(e) => return Ok(error_response(400, &format!("invalid parcel: {e}"))),
    }
    if fingerprint_of(&parcel.pubkey).as_deref() != Some(fp) {
        return Ok(error_response(
            400,
            "fingerprint(parcel pubkey) does not match the mailbox",
        ));
    }

    let stub = mailbox_stub(env, fp)?;
    let bucket = env.bucket("PARCELS")?;
    // relayd gc-position parity: retention reaping rides on the deposit —
    // claim (and R2-delete) orphan blobs left by the DO's alarm sweeps.
    sweep_orphans(&stub, &bucket, fp).await;

    let id = new_parcel_id()?;
    let key = blob_key(fp, &id);
    let size = body.len() as u64;
    bucket.put(&key, body).execute().await?;

    let deposit = do_post(
        &stub,
        "/deposit",
        json!({
            "id": id,
            "size": size,
            "received_unix": now_unix(),
            "pubkey": parcel.pubkey,
            "retention_days": retention_days(env),
        }),
    )
    .await;
    match deposit {
        // 200 → `{"ok":true}` (relayd's deposit body).
        Ok(resp) if resp.status_code() == 200 => Ok(json_response(200, json!({ "ok": true }))),
        // Caps (429 count / 413 size, relayd's texts) or a contract
        // violation: the blob must not survive an unindexed deposit.
        Ok(resp) => {
            bucket.delete(&key).await?;
            Ok(forward(resp).await?)
        }
        // Transport/SQL failure after the R2 put (e.g. a duplicate blob id —
        // 2^-128 per pair, but handled): clean up, then 400 like relayd's
        // bad-store paths.
        Err(_) => {
            bucket.delete(&key).await?;
            Ok(bad_request())
        }
    }
}

/// Authed routes (spec §2): list (`id: None`), fetch (`id`, `false`), ack
/// (`id`, `true`). Order is load-bearing: unknown-mailbox 404 BEFORE any
/// signature check, then header presence, then the DO's verify+consume (one
/// serialized request — a failed signature never burns a nonce), and only
/// then the operation. Blob-before-index holds on ack: R2 delete first, DO
/// index delete second.
async fn authed(
    req: &Request,
    env: &worker::Env,
    fp: &str,
    id: Option<&str>,
    delete: bool,
) -> worker::Result<Response> {
    let stub = mailbox_stub(env, fp)?;

    // 404-before-auth (relayd parity): an unknown mailbox never reveals
    // whether the signature was any good.
    if do_get(&stub, "/meta").await?.status_code() != 200 {
        return Ok(error_response(404, "unknown mailbox"));
    }

    // Header checks at the edge: `X-cmail-Fp` must equal the URL fp and the
    // signature must be present (relayd checks both before any verify).
    let fp_header = req.headers().get("X-cmail-Fp").ok().flatten();
    if fp_header.as_deref() != Some(fp) {
        return Ok(error_response(401, "missing or mismatched auth headers"));
    }
    let Some(signature) = req.headers().get("X-cmail-Signature").ok().flatten() else {
        return Ok(error_response(401, "missing or mismatched auth headers"));
    };

    // Verify + consume in the DO (C3 contract: wire v1 clients never echo
    // the nonce, so only the DO can match signature to stored value; the
    // verified row is deleted inside the same serialized request). Its 401
    // body is relayd's text verbatim.
    let consume = do_post(&stub, "/consume", json!({ "signature": signature })).await?;
    if consume.status_code() != 200 {
        return forward(consume).await;
    }

    // Blob-orphan reaping rides on this touch like relayd's lazy gc.
    let bucket = env.bucket("PARCELS")?;
    sweep_orphans(&stub, &bucket, fp).await;

    match id {
        // `{"ids":[...]}` ascending — the DO already sorts; forward as-is.
        None => forward(do_post(&stub, "/list", json!({})).await?).await,
        Some(id) if delete => {
            // Blob BEFORE index: an entry always has a blob; a stray orphan
            // blob is the sweep's problem, never a dangling index row. R2
            // delete of a missing key is a no-op, so unknown ids fall
            // through to the DO's 404 below.
            bucket.delete(blob_key(fp, id)).await?;
            let resp = do_post(&stub, "/delete", json!({ "id": id })).await?;
            if resp.status_code() == 200 {
                Ok(json_response(200, json!({ "deleted": true })))
            } else {
                Ok(error_response(404, "unknown id"))
            }
        }
        Some(id) => {
            // Existence + metadata from the index first (404 unknown id),
            // then the bytes from R2 — streamed, never parsed, with the
            // JSON content type every relay response carries.
            let resp = do_post(&stub, "/get", json!({ "id": id })).await?;
            if resp.status_code() != 200 {
                return Ok(error_response(404, "unknown id"));
            }
            // `Object::body()` borrows the object, so both are held live
            // until `response_body()` detaches the body handle.
            let Some(object) = bucket.get(blob_key(fp, id)).execute().await? else {
                // Index/blob divergence (the alarm reaped the row between
                // `/get` and here, or storage lost the blob): 404, exactly
                // like relayd's missing-file case.
                return Ok(error_response(404, "unknown id"));
            };
            let Some(body) = object.body() else {
                return Ok(error_response(404, "unknown id"));
            };
            let headers = worker::Headers::new();
            headers.set("Content-Type", "application/json")?;
            Ok(Response::from_body(body.response_body()?)?.with_headers(headers))
        }
    }
}
