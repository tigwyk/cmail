//! Runtime-agnostic conformance suite (spec §6): ONE matrix, TWO runtimes.
//!
//! Every scenario below runs against
//! 1. `cmail-relayd` spawned in-process on `127.0.0.1:0` (always — this is
//!    the permanent parity proof and runs in the ordinary workspace test
//!    job), and
//! 2. a live deployment of THIS Worker, when `CMAIL_RELAY_URL` is set
//!    (the CI `conformance` job runs it against `npx wrangler dev`; locally:
//!    `cd crates/cmail-relay-cf && npx wrangler dev --port 8787 &`, then
//!    `CMAIL_RELAY_URL=http://127.0.0.1:8787 cargo test -p cmail-relay-cf
//!    --test conformance --test-threads=1`).
//!
//! The assertions twin `cmail-relayd/tests/server_tests.rs` (the reference
//! behavior): full lifecycle with a byte-identical blob round-trip,
//! wrong-key/nonce-replay 401s, fp-mismatch 400, the encoded cap (413 on a
//! raw-TCP Content-Length lie, before the body is read), the decoded cap
//! (413 on a valid-b64 over-limit parcel), mailbox-size 413 + entry-count
//! 429 + nonce-cap 429, `{"ids":[...]}` ascending shape, and the 404s.
//! Retention-0 sweeping needs a retention-0 server and (on cf) the Durable
//! Object alarm to fire, so that scenario is `#[ignore]`d and documented
//! below — everything else is status/body-level and runtime-agnostic.
//!
//! Fixtures use `ed25519-dalek` + this crate's own `Parcel`/`fingerprint_of`
//! builders (core's signed-envelope builder supplies the opaque envelope
//! value; relayd parses it typed, cf never parses inside it).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cmail_relay_cf::parcel::{fingerprint_of, Parcel, ParcelAttachment};
use cmail_relayd::RelayServer;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::io::{Read, Write};
use std::sync::OnceLock;
use std::time::Duration;
use ureq::Agent;

/// Encoded request-body cap (relay protocol v1 §2.1: 64 MiB) — protocol
/// constant pinned here so the suite judges BOTH runtimes by the spec, not
/// by either one's source.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Per-mailbox total encoded parcel bytes (§2.2: 256 MiB; over → 413).
const MAX_MAILBOX_BYTES: u64 = 256 * 1024 * 1024;
/// Per-mailbox entry count (§2.2: 1000; over → 429).
const MAX_MAILBOX_ENTRIES: usize = 1000;
/// Max outstanding challenge nonces per fingerprint (§2.2: 8).
const MAX_OUTSTANDING_NONCES: usize = 8;

/// One relay under test: a base URL plus a freshly generated mailbox
/// identity (so scenarios never collide on server-side state, whatever its
/// lifetime — wrangler dev persists between runs).
struct Target {
    label: &'static str,
    base: String,
    key: SigningKey,
    fp: String,
    client: Agent,
    /// Whether a raw-TCP Content-Length lie can prove 413-before-reading:
    /// relayd answers from the header alone; workerd (wrangler dev and
    /// production alike) buffers the announced body before the Worker is
    /// dispatched, so the lie only hangs and pre-read rejection is
    /// unobservable through the platform front door (verified live against
    /// wrangler 4.156.2: the request never reaches the Worker). cf targets
    /// get the honest over-cap body instead — same Content-Length precheck
    /// branch, same 413.
    proves_pre_read_rejection: bool,
}

fn new_target(label: &'static str, base: String, proves_pre_read_rejection: bool) -> Target {
    let key = SigningKey::generate(&mut OsRng);
    let fp = fingerprint_of(&B64.encode(key.verifying_key().as_bytes()))
        .expect("b64 of 32 bytes is b64");
    let client = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    Target {
        label,
        base,
        key,
        fp,
        client,
        proves_pre_read_rejection,
    }
}

/// A relayd spun up in-process (insecure-local mode) plus the tempdir its
/// store lives in; both must outlive the scenario.
struct RelaydFix {
    _root: tempfile::TempDir,
    _server: RelayServer,
    target: Target,
}

fn relayd_target(retention_days: u64) -> RelaydFix {
    let root = tempfile::tempdir().unwrap();
    let server =
        RelayServer::start("127.0.0.1:0", root.path().to_path_buf(), retention_days).unwrap();
    let target = new_target("relayd", server.base_url(), true);
    RelaydFix {
        _root: root,
        _server: server,
        target,
    }
}

/// `CMAIL_RELAY_URL` (normalized once): the live cf Worker to also run every
/// scenario against. Unset → the cf side of each test prints a skip note and
/// passes; the relayd side above is still the full parity proof.
fn cf_base() -> Option<&'static str> {
    static BASE: OnceLock<Option<String>> = OnceLock::new();
    BASE.get_or_init(|| {
        std::env::var("CMAIL_RELAY_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
    })
    .as_deref()
}

/// Run one scenario against every available runtime: relayd (always), then
/// the cf Worker when `CMAIL_RELAY_URL` is set.
fn for_each_relay(scenario: fn(&Target)) {
    let relayd = relayd_target(7);
    scenario(&relayd.target);
    match cf_base() {
        Some(base) => scenario(&new_target("cf", base.to_string(), false)),
        None => eprintln!(
            "skipped [cf]: CMAIL_RELAY_URL not set — relayd side above is the parity proof"
        ),
    }
}

// --- fixtures ---

/// A minimal well-formed parcel addressed to `t`'s mailbox owner, via cf's
/// own builders (the envelope value itself comes from core's signed-envelope
/// builder — relayd deserializes it typed; cf treats it as opaque).
fn minimal_parcel(t: &Target) -> Parcel {
    parcel_with(t, vec![])
}

/// A parcel for `t`'s pubkey with the given (index, raw-frame) attachments.
fn parcel_with(t: &Target, frames: Vec<(usize, Vec<u8>)>) -> Parcel {
    let sender = SigningKey::generate(&mut OsRng);
    let env = cmail_core::envelope::build_and_sign(
        &cmail_core::envelope::new_id(),
        &cmail_core::envelope::NewEnvelope {
            from: "a".into(),
            from_key: B64.encode(sender.verifying_key().as_bytes()),
            to: "z".into(),
            kind: "note".into(),
            subject: "s".into(),
            body: "b".into(),
            attachments: vec![],
            in_reply_to: None,
            created: "2026-11-01T12:00:00Z".into(),
        },
        &sender,
    )
    .unwrap();
    Parcel {
        v: 1,
        pubkey: B64.encode(t.key.verifying_key().as_bytes()),
        envelope: serde_json::to_value(&env).unwrap(),
        attachments: frames
            .into_iter()
            .map(|(i, d)| ParcelAttachment {
                i,
                data: B64.encode(d),
            })
            .collect(),
    }
}

/// b64 Ed25519 signature over the nonce ASCII bytes (the wire's
/// `X-cmail-Signature`) — same construction as core's `sign_challenge`.
fn sign_challenge(key: &SigningKey, nonce: &str) -> String {
    B64.encode(key.sign(nonce.as_bytes()).to_bytes())
}

// --- HTTP helpers (twin cmail-relayd/tests/server_tests.rs) ---

/// Issue a request; return `(status, body)` without holding the fat
/// `Result<_, ureq::Error>` (its Err variant is 272 bytes).
fn request(
    t: &Target,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, Option<String>) {
    let mut req = t.client.request(method, &format!("{}{path}", t.base));
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let result = match body {
        Some(b) => req.set("Content-Type", "application/json").send_string(b),
        None => req.call(),
    };
    match result {
        Ok(resp) => (resp.status(), resp.into_string().ok()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().ok()),
        Err(e) => panic!("[{}] transport error on {method} {path}: {e}", t.label),
    }
}

/// Open deposit of a parcel's wire JSON; returns the status.
fn deposit_wire(t: &Target, fp: &str, wire: &str) -> u16 {
    request(t, "POST", &format!("/mailbox/{fp}"), &[], Some(wire)).0
}

/// Fresh challenge nonce (asserts 200 — callers that want the cap path use
/// [`challenge_status`]).
fn challenge(t: &Target, fp: &str) -> String {
    let (code, body) = request(t, "GET", &format!("/challenge/{fp}"), &[], None);
    assert_eq!(code, 200, "[{}] challenge {fp}: {body:?}", t.label);
    let v: serde_json::Value = serde_json::from_str(&body.unwrap_or_default()).unwrap();
    v["nonce"].as_str().unwrap().to_string()
}

fn challenge_status(t: &Target, fp: &str) -> (u16, Option<String>) {
    request(t, "GET", &format!("/challenge/{fp}"), &[], None)
}

/// One fully authenticated request with a fresh nonce: `(status, body)`.
fn authed_call(t: &Target, method: &str, path: &str) -> (u16, Option<String>) {
    let nonce = challenge(t, &t.fp);
    let sig = sign_challenge(&t.key, &nonce);
    request(
        t,
        method,
        path,
        &[
            ("X-cmail-Fp", t.fp.as_str()),
            ("X-cmail-Signature", sig.as_str()),
        ],
        None,
    )
}

fn authed<T: DeserializeOwned>(t: &Target, method: &str, path: &str) -> T {
    let (code, body) = authed_call(t, method, path);
    assert_eq!(code, 200, "[{}] authed {method} {path}: {body:?}", t.label);
    serde_json::from_str(&body.unwrap_or_default()).unwrap()
}

#[derive(serde::Deserialize)]
struct Ids {
    ids: Vec<String>,
}

fn ids(t: &Target) -> Vec<String> {
    authed::<Ids>(t, "GET", &format!("/mailbox/{}", t.fp)).ids
}

/// Raw-socket POST that announces a huge Content-Length but sends almost
/// nothing — proves the server checks Content-Length BEFORE reading the body
/// (the 413 must come back without the client ever streaming the bytes).
/// Ported from relayd's server_tests; works against any HTTP/1.1 listener,
/// wrangler dev included.
fn raw_post_oversize_status(t: &Target, fp: &str, content_length: usize) -> u16 {
    let addr = t
        .base
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = format!(
        "POST /mailbox/{fp} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(head.as_bytes()).unwrap();
    // One body byte so the parser delivers the request; the rest never arrives.
    s.write_all(b"x").unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    text.split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("[{}] no status line in {text:?}", t.label))
        .parse()
        .unwrap()
}

/// A valid-shaped 16-hex fingerprint that is NOT `fp` (first hex char
/// flipped) — for the fp-mismatch deposit.
fn wrong_fp(fp: &str) -> String {
    let flip = if fp.starts_with('0') { '1' } else { '0' };
    format!("{flip}{}", &fp[1..])
}

// --- the spec §6 matrix ---

#[test]
fn full_lifecycle_deposit_list_fetch_ack() {
    for_each_relay(|t| {
        // challenge wire shape: {"nonce": b64(32B), "expires": RFC3339}
        let (code, body) = challenge_status(t, &t.fp);
        assert_eq!(code, 200, "[{}] challenge: {body:?}", t.label);
        let v: serde_json::Value = serde_json::from_str(&body.unwrap_or_default()).unwrap();
        let nonce = v["nonce"].as_str().expect("nonce field");
        assert_eq!(
            B64.decode(nonce).map(|b| b.len()),
            Ok(32),
            "[{}] nonce is b64 for 32 bytes",
            t.label
        );
        let expires = v["expires"].as_str().expect("expires field");
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|e| panic!("[{}] expires {expires:?} is not RFC3339: {e}", t.label));

        // deposit (open) → 200 {"ok":true}
        let parcel = minimal_parcel(t);
        let wire = serde_json::to_string(&parcel).unwrap();
        let (code, body) = request(t, "POST", &format!("/mailbox/{}", t.fp), &[], Some(&wire));
        assert_eq!(code, 200, "[{}] deposit: {body:?}", t.label);
        assert_eq!(
            body.as_deref(),
            Some(r#"{"ok":true}"#),
            "[{}] deposit body",
            t.label
        );

        // list (authed) → exactly the parcel's id
        let listed = ids(t);
        assert_eq!(listed.len(), 1, "[{}] exactly one parcel pending", t.label);

        // fetch (authed) — BYTE-IDENTICAL round trip of the stored blob
        let nonce = challenge(t, &t.fp);
        let sig = sign_challenge(&t.key, &nonce);
        let resp = t
            .client
            .get(&format!("{}/mailbox/{}/{}", t.base, t.fp, listed[0]))
            .set("X-cmail-Fp", t.fp.as_str())
            .set("X-cmail-Signature", sig.as_str())
            .call()
            .unwrap_or_else(|e| panic!("[{}] fetch: {e}", t.label));
        assert_eq!(resp.status(), 200, "[{}] fetch", t.label);
        assert_eq!(
            resp.header("Content-Type"),
            Some("application/json"),
            "[{}] fetch content type",
            t.label
        );
        let raw = resp.into_string().unwrap();
        assert_eq!(raw, wire, "[{}] byte-identical blob round-trip", t.label);

        // ack (authed) → {"deleted":true}, then the mailbox is empty
        let deleted: serde_json::Value =
            authed(t, "DELETE", &format!("/mailbox/{}/{}", t.fp, listed[0]));
        assert_eq!(deleted["deleted"], json!(true), "[{}] ack body", t.label);
        assert!(ids(t).is_empty(), "[{}] mailbox empty after ack", t.label);
    });
}

#[test]
fn wrong_key_and_nonce_replay_rejected() {
    for_each_relay(|t| {
        assert_eq!(
            deposit_wire(
                t,
                &t.fp,
                &serde_json::to_string(&minimal_parcel(t)).unwrap()
            ),
            200
        );

        // no auth headers at all → 401 (after the mailbox is known to exist)
        let (code, body) = request(t, "GET", &format!("/mailbox/{}", t.fp), &[], None);
        assert_eq!(code, 401, "[{}] headerless list: {body:?}", t.label);

        // wrong key: signature does not verify against the mailbox pubkey → 401
        let other = SigningKey::generate(&mut OsRng);
        let nonce = challenge(t, &t.fp);
        let bad_sig = sign_challenge(&other, &nonce);
        let (code, body) = request(
            t,
            "GET",
            &format!("/mailbox/{}", t.fp),
            &[
                ("X-cmail-Fp", t.fp.as_str()),
                ("X-cmail-Signature", bad_sig.as_str()),
            ],
            None,
        );
        assert_eq!(code, 401, "[{}] wrong key: {body:?}", t.label);

        // the good key still works (a bad attempt never bricks the mailbox)
        assert_eq!(ids(t).len(), 1, "[{}] good key after bad attempt", t.label);

        // nonce single-use: sign ONE nonce, use it successfully, replay → 401
        let nonce = challenge(t, &t.fp);
        let sig = sign_challenge(&t.key, &nonce);
        let path = format!("/mailbox/{}", t.fp);
        let (ok, _) = request(
            t,
            "GET",
            &path,
            &[
                ("X-cmail-Fp", t.fp.as_str()),
                ("X-cmail-Signature", sig.as_str()),
            ],
            None,
        );
        assert_eq!(ok, 200, "[{}] first use of the nonce", t.label);
        let (replay, body) = request(
            t,
            "GET",
            &path,
            &[
                ("X-cmail-Fp", t.fp.as_str()),
                ("X-cmail-Signature", sig.as_str()),
            ],
            None,
        );
        assert_eq!(replay, 401, "[{}] nonce replay: {body:?}", t.label);
    });
}

#[test]
fn fp_mismatch_and_malformed_parcel_rejected() {
    for_each_relay(|t| {
        let parcel = minimal_parcel(t); // carries t.key's pubkey
        let wire = serde_json::to_string(&parcel).unwrap();

        // fp != fingerprint(pubkey) → 400
        let bad = wrong_fp(&t.fp);
        let (code, body) = request(t, "POST", &format!("/mailbox/{bad}"), &[], Some(&wire));
        assert_eq!(code, 400, "[{}] fp mismatch: {body:?}", t.label);

        // malformed body → 400
        let (code, body) = request(
            t,
            "POST",
            &format!("/mailbox/{}", t.fp),
            &[],
            Some("this is not json"),
        );
        assert_eq!(code, 400, "[{}] malformed parcel: {body:?}", t.label);

        // structurally invalid (v=2) → 400, not a limit → not 413
        let mut v2 = parcel.clone();
        v2.v = 2;
        let (code, body) = request(
            t,
            "POST",
            &format!("/mailbox/{}", t.fp),
            &[],
            Some(&serde_json::to_string(&v2).unwrap()),
        );
        assert_eq!(code, 400, "[{}] v=2 parcel: {body:?}", t.label);
    });
}

/// 413 encoded: the Content-Length precheck rejects an over-64 MiB body.
/// Both runtimes get an HONEST over-cap body (header and body agree) — the
/// precheck branch answers from the header. relayd additionally gets the
/// raw-TCP LIE (huge announced Content-Length, bytes never sent), proving it
/// 413s BEFORE reading; through workerd that lie is unobservable (the
/// platform buffers announced bodies before the Worker runs — see
/// [`Target::proves_pre_read_rejection`]).
#[test]
fn encoded_cap_413_before_body_read() {
    for_each_relay(|t| {
        let over_cap = "x".repeat(MAX_BODY_BYTES + 1024);
        let (code, body) = request(
            t,
            "POST",
            &format!("/mailbox/{}", t.fp),
            &[],
            Some(&over_cap),
        );
        assert_eq!(code, 413, "[{}] honest over-cap body: {body:?}", t.label);

        if t.proves_pre_read_rejection {
            assert_eq!(
                raw_post_oversize_status(t, &t.fp, MAX_BODY_BYTES + 1024),
                413,
                "[{}] Content-Length lie must 413 before reading",
                t.label
            );
        } else {
            eprintln!(
                "[{}] raw-TCP lie skipped: workerd buffers announced bodies before dispatch",
                t.label
            );
        }
    });
}

/// 413 decoded: a valid-b64, well-formed parcel over the 36 MiB decoded
/// attachment budget (count axis: 9 > 8; byte axis: 36 MiB + 1 KiB).
#[test]
fn decoded_cap_413_on_valid_b64_parcels() {
    for_each_relay(|t| {
        // one good deposit first, so "nothing else was stored" is observable
        assert_eq!(
            deposit_wire(
                t,
                &t.fp,
                &serde_json::to_string(&minimal_parcel(t)).unwrap()
            ),
            200
        );

        // count axis: 9 valid attachments > 8
        let p9 = parcel_with(t, (0..9).map(|i| (i, vec![0u8; 4])).collect());
        let (code, body) = request(
            t,
            "POST",
            &format!("/mailbox/{}", t.fp),
            &[],
            Some(&serde_json::to_string(&p9).unwrap()),
        );
        assert_eq!(code, 413, "[{}] 9 attachments: {body:?}", t.label);

        // byte axis: two frames summing to 36 MiB + 1 KiB (valid b64)
        let over: usize = 36 * 1024 * 1024 + 1024;
        let p = parcel_with(
            t,
            vec![(0, vec![0u8; over / 2]), (1, vec![0u8; over - over / 2])],
        );
        let (code, body) = request(
            t,
            "POST",
            &format!("/mailbox/{}", t.fp),
            &[],
            Some(&serde_json::to_string(&p).unwrap()),
        );
        assert_eq!(code, 413, "[{}] decoded 36 MiB+1 KiB: {body:?}", t.label);

        // only the first, good parcel is stored
        assert_eq!(
            ids(t).len(),
            1,
            "[{}] rejected parcels were not stored",
            t.label
        );
    });
}

/// 429 entry-count: the 1001st deposit into one mailbox is refused (and the
/// 1000 before it all landed).
#[test]
fn entry_cap_is_429() {
    for_each_relay(|t| {
        let wire = serde_json::to_string(&minimal_parcel(t)).unwrap();
        for i in 1..=MAX_MAILBOX_ENTRIES {
            assert_eq!(
                deposit_wire(t, &t.fp, &wire),
                200,
                "[{}] deposit #{i} must be under the cap",
                t.label
            );
        }
        let (code, body) = request(t, "POST", &format!("/mailbox/{}", t.fp), &[], Some(&wire));
        assert_eq!(code, 429, "[{}] deposit #1001: {body:?}", t.label);
        assert!(body.unwrap_or_default().contains("error"));
        assert_eq!(
            ids(t).len(),
            MAX_MAILBOX_ENTRIES,
            "[{}] cap keeps the 1000",
            t.label
        );
    });
}

/// 413 mailbox-size: deposits of ~5.3 MiB encoded parcels accumulate against
/// the 256 MiB per-mailbox budget; the crossing deposit 413s, exactly at the
/// boundary.
#[test]
fn mailbox_size_cap_is_413() {
    for_each_relay(|t| {
        // 4 MiB decoded → ~5.34 MiB encoded per parcel (well under the
        // 64 MiB per-body cap; ~49 deposits cross 256 MiB).
        let wire =
            serde_json::to_string(&parcel_with(t, vec![(0, vec![0u8; 4 * 1024 * 1024])])).unwrap();
        let each = wire.len() as u64;
        let mut accepted = 0u64;
        loop {
            let code = deposit_wire(t, &t.fp, &wire);
            if code == 413 {
                break;
            }
            assert_eq!(
                code,
                200,
                "[{}] size-cap fill deposit #{}",
                t.label,
                accepted + 1
            );
            accepted += 1;
            assert!(accepted < 80, "[{}] never hit the size cap", t.label);
        }
        assert!(
            accepted * each <= MAX_MAILBOX_BYTES && (accepted + 1) * each > MAX_MAILBOX_BYTES,
            "[{}] 413 must be exactly at the 256 MiB boundary (accepted={accepted}, each={each})",
            t.label
        );
    });
}

/// 429 nonce-cap: 8 outstanding challenge nonces; the 9th → 429; a different
/// fingerprint is unaffected.
#[test]
fn challenge_nonce_cap_is_429() {
    for_each_relay(|t| {
        for i in 1..=MAX_OUTSTANDING_NONCES {
            let (code, body) = challenge_status(t, &t.fp);
            assert_eq!(code, 200, "[{}] challenge #{i}: {body:?}", t.label);
        }
        let (code, body) = challenge_status(t, &t.fp);
        assert_eq!(code, 429, "[{}] 9th outstanding nonce: {body:?}", t.label);
        let other = SigningKey::generate(&mut OsRng);
        let other_fp = fingerprint_of(&B64.encode(other.verifying_key().as_bytes())).unwrap();
        let (code, _) = challenge_status(t, &other_fp);
        assert_eq!(code, 200, "[{}] other fp unaffected", t.label);
    });
}

/// `{"ids":[...]}` ascending shape: ids are 32-hex, unique, and listed in
/// ascending order (server-assigned ids, sorted by the relay).
#[test]
fn list_ids_shape_is_ascending() {
    for_each_relay(|t| {
        let wire = serde_json::to_string(&minimal_parcel(t)).unwrap();
        for _ in 0..3 {
            assert_eq!(deposit_wire(t, &t.fp, &wire), 200);
        }
        let listed = ids(t);
        assert_eq!(listed.len(), 3, "[{}] three deposits listed", t.label);
        assert!(
            listed
                .iter()
                .all(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())),
            "[{}] ids are 32 hex chars: {listed:?}",
            t.label
        );
        assert!(
            listed.windows(2).all(|w| w[0] < w[1]),
            "[{}] ids ascend: {listed:?}",
            t.label
        );
    });
}

#[test]
fn not_found_paths() {
    for_each_relay(|t| {
        // authed route on an unknown mailbox → 404 (before any auth)
        let stranger = SigningKey::generate(&mut OsRng);
        let stranger_fp = fingerprint_of(&B64.encode(stranger.verifying_key().as_bytes())).unwrap();
        let (code, _) = authed_call(t, "GET", &format!("/mailbox/{stranger_fp}"));
        assert_eq!(code, 404, "[{}] unknown mailbox", t.label);

        // unknown id after a real deposit → 404 on fetch and on ack
        assert_eq!(
            deposit_wire(
                t,
                &t.fp,
                &serde_json::to_string(&minimal_parcel(t)).unwrap()
            ),
            200
        );
        let ghost = "d".repeat(32);
        let (code, _) = authed_call(t, "GET", &format!("/mailbox/{}/{}", t.fp, ghost));
        assert_eq!(code, 404, "[{}] unknown id fetch", t.label);
        let (code, _) = authed_call(t, "DELETE", &format!("/mailbox/{}/{}", t.fp, ghost));
        assert_eq!(code, 404, "[{}] unknown id ack", t.label);

        // unknown route → 404 with an error body
        let (code, body) = request(t, "GET", "/nope", &[], None);
        assert_eq!(code, 404, "[{}] unknown route", t.label);
        assert!(
            body.unwrap_or_default().contains("error"),
            "[{}] 404 body",
            t.label
        );

        // malformed fp folds into 404 on both relays (status-only assert:
        // relayd says "unknown mailbox", cf's router says "not found" — the
        // C1 no-validity-oracle decision, disclosed there)
        let (code, _) = request(t, "GET", "/mailbox/zz", &[], None);
        assert_eq!(code, 404, "[{}] malformed fp", t.label);
    });
}

/// Retention 0: a deposited parcel expires immediately; after the sweep
/// (lazy on access for relayd, the DO alarm + one more authed touch on cf)
/// the mailbox is gone entirely — authed requests 404 and the id is never
/// listed again.
///
/// MANUAL, `#[ignore]`d: the DO alarm — not a request — performs the
/// deletion on cf and needs real seconds to fire, so the cf side additionally
/// requires BOTH `CMAIL_RELAY_RETENTION_DAYS=0` in the test env (the go
/// signal) AND `CMAIL_RELAY_URL` pointed at a wrangler dev started with
/// `--var CMAIL_RETENTION_DAYS:0` (wrangler.toml pins "7"; the CLI override
/// wins). With the fix that schedules alarms as offsets, the overdue
/// retention-0 alarm fires within seconds, so the 120 s poll is generous.
/// Run manually:
/// `cargo test -p cmail-relay-cf --test conformance -- --ignored --test-threads=1`
/// The relayd side always runs under `--ignored` (its sweep is lazy and
/// deterministic; relayd's own server_tests also cover it).
#[test]
#[ignore = "manual: cf side needs CMAIL_RELAY_URL + CMAIL_RELAY_RETENTION_DAYS=0 and a wrangler dev with --var CMAIL_RETENTION_DAYS:0 (DO alarm needs seconds); see the doc comment"]
fn retention_zero_sweeps_and_prunes() {
    let relayd = relayd_target(0);
    retention_zero_scenario(&relayd.target);
    let cf_ready = cf_base().is_some()
        && std::env::var("CMAIL_RELAY_RETENTION_DAYS").ok().as_deref() == Some("0");
    match (cf_base(), cf_ready) {
        (Some(base), true) => retention_zero_scenario(&new_target("cf", base.to_string(), false)),
        _ => eprintln!(
            "skipped [cf]: set CMAIL_RELAY_URL and CMAIL_RELAY_RETENTION_DAYS=0 \
             (server: wrangler dev --var CMAIL_RETENTION_DAYS:0) — relayd side ran above"
        ),
    }
}

fn retention_zero_scenario(t: &Target) {
    assert_eq!(
        deposit_wire(
            t,
            &t.fp,
            &serde_json::to_string(&minimal_parcel(t)).unwrap()
        ),
        200,
        "[{}] deposit under retention 0",
        t.label
    );

    // With retention 0 everything is already expired. The shared, honest
    // invariant: the mailbox is eventually swept AND pruned — authed
    // requests start 404ing and never see the parcel again. relayd gets
    // there via lazy GC (the first list access sweeps; the next authed
    // request 404s — its own server_tests assert the same). cf gets there
    // via the DO alarm (real seconds to fire) plus one more authed touch to
    // claim the orphan marker and prune, so poll with a generous deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut saw_swept_empty = false;
    loop {
        let (code, body) = authed_call(t, "GET", &format!("/mailbox/{}", t.fp));
        match code {
            200 => {
                let l: Ids = serde_json::from_str(&body.unwrap_or_default()).unwrap();
                if l.ids.is_empty() {
                    saw_swept_empty = true;
                } else {
                    assert!(
                        !saw_swept_empty,
                        "[{}] expired parcel reappeared after being swept",
                        t.label
                    );
                }
            }
            404 => break, // swept AND pruned: the mailbox is unknown
            other => panic!(
                "[{}] unexpected {other} while waiting for the prune: {body:?}",
                t.label
            ),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "[{}] mailbox was not pruned within 120s (retention 0)",
            t.label
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    // Pruned is pruned: a further authed request still 404s (never resurrects).
    let (code, _) = authed_call(t, "GET", &format!("/mailbox/{}", t.fp));
    assert_eq!(code, 404, "[{}] pruned mailbox stays unknown", t.label);
}
