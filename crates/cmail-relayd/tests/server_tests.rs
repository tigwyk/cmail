//! Integration tests for the reference relay server (spec §2/§2.2): spin the
//! server in-process on `127.0.0.1:0` (insecure-local mode) and exercise the
//! five routes over real HTTP — full lifecycle, challenge auth semantics,
//! fp-mismatch/size caps, retention GC, and the outstanding-nonce cap.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cmail_core::envelope::{build_and_sign, new_id, NewEnvelope};
use cmail_core::identity::fingerprint_of;
use cmail_core::relay::{build_parcel, sign_challenge, Parcel, ParcelAttachment};
use cmail_relayd::store::{RelayStore, StoreError, MAX_BODY_BYTES, MAX_OUTSTANDING_NONCES};
use cmail_relayd::RelayServer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::io::{Read, Write};
use std::time::Duration;

struct Fix {
    /// Held so the relay root outlives the server (TempDir deletes on drop).
    _root: tempfile::TempDir,
    server: RelayServer,
    key: SigningKey,
    fp: String,
    client: ureq::Agent,
}

fn fix_retention(retention_days: u64) -> Fix {
    let root = tempfile::tempdir().unwrap();
    let server =
        RelayServer::start("127.0.0.1:0", root.path().to_path_buf(), retention_days).unwrap();
    let key = SigningKey::generate(&mut OsRng);
    let fp = fingerprint_of(&B64.encode(key.verifying_key().as_bytes()));
    let client = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    Fix {
        _root: root,
        server,
        key,
        fp,
        client,
    }
}

fn fix() -> Fix {
    fix_retention(7)
}

/// A minimal well-formed parcel addressed to `f.key`'s pubkey (plain envelope
/// fixture via core helpers; the relay treats the envelope opaquely).
fn minimal_parcel(f: &Fix) -> Parcel {
    let sender = SigningKey::generate(&mut OsRng);
    let env = build_and_sign(
        &new_id(),
        &NewEnvelope {
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
    let recipient = B64.encode(f.key.verifying_key().as_bytes());
    build_parcel(&env, &[], &recipient).unwrap()
}

fn status(result: Result<ureq::Response, ureq::Error>) -> u16 {
    match result {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("transport error: {e}"),
    }
}

/// Open deposit: POST the parcel JSON, return the HTTP status.
fn deposit(f: &Fix, fp: &str, parcel: &Parcel) -> u16 {
    status(
        f.client
            .post(&format!("{}/mailbox/{fp}", f.server.base_url()))
            .set("Content-Type", "application/json")
            .send_string(&serde_json::to_string(parcel).unwrap()),
    )
}

fn challenge(f: &Fix, fp: &str) -> String {
    let resp = f
        .client
        .get(&format!("{}/challenge/{fp}", f.server.base_url()))
        .call()
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.into_json::<serde_json::Value>().unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_string()
}

/// One fully authenticated request: fresh challenge → signed request →
/// status (no body parsing — for raw asserts like nonce replay).
fn authed_status(f: &Fix, method: &str, path: &str, sig: &str) -> u16 {
    status(
        f.client
            .request(method, &format!("{}{path}", f.server.base_url()))
            .set("X-cmail-Fp", &f.fp)
            .set("X-cmail-Signature", sig)
            .call(),
    )
}

/// One fully authenticated request with a fresh nonce: returns
/// `(status, body)` so callers can assert either without holding a
/// `Result<_, ureq::Error>` (its Err variant is 272 bytes).
fn authed_call(f: &Fix, method: &str, path: &str) -> (u16, Option<String>) {
    let nonce = challenge(f, &f.fp);
    let sig = sign_challenge(&f.key, &nonce);
    let result = f
        .client
        .request(method, &format!("{}{path}", f.server.base_url()))
        .set("X-cmail-Fp", &f.fp)
        .set("X-cmail-Signature", &sig)
        .call();
    match result {
        Ok(resp) => (resp.status(), resp.into_string().ok()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().ok()),
        Err(e) => panic!("transport error on authed {method} {path}: {e}"),
    }
}

fn authed<T: DeserializeOwned>(f: &Fix, method: &str, path: &str) -> T {
    let (code, body) = authed_call(f, method, path);
    assert_eq!(code, 200, "authed {method} {path} failed: {body:?}");
    serde_json::from_str(&body.unwrap_or_default()).unwrap()
}

#[derive(serde::Deserialize)]
struct Ids {
    ids: Vec<String>,
}

fn ids(f: &Fix) -> Vec<String> {
    authed::<Ids>(f, "GET", &format!("/mailbox/{}", f.fp)).ids
}

/// Raw-socket POST that announces a huge Content-Length but sends almost
/// nothing — proves the server checks Content-Length BEFORE reading the body
/// (the 413 comes back without the client ever streaming the bytes).
fn raw_post_oversize_status(f: &Fix, fp: &str, content_length: usize) -> u16 {
    let addr = f
        .server
        .base_url()
        .trim_start_matches("http://")
        .to_string();
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
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
        .unwrap_or_else(|| panic!("no status line in {text:?}"))
        .parse()
        .unwrap()
}

#[test]
fn full_lifecycle_deposit_list_fetch_ack() {
    let f = fix();
    let parcel = minimal_parcel(&f);

    // deposit (open)
    assert_eq!(deposit(&f, &f.fp, &parcel), 200);

    // list (authed)
    let listed = ids(&f);
    assert_eq!(listed.len(), 1, "exactly one parcel pending");

    // fetch (authed) — byte-identical round-trip of the stored parcel
    let (code, raw) = authed_call(&f, "GET", &format!("/mailbox/{}/{}", f.fp, listed[0]));
    assert_eq!(code, 200);
    let raw = raw.unwrap();
    assert_eq!(raw, serde_json::to_string(&parcel).unwrap());
    let got: Parcel = serde_json::from_str(&raw).unwrap();
    assert_eq!(got.envelope.id, parcel.envelope.id);
    assert_eq!(got.pubkey, parcel.pubkey);

    // ack (authed)
    let deleted: serde_json::Value =
        authed(&f, "DELETE", &format!("/mailbox/{}/{}", f.fp, listed[0]));
    assert_eq!(deleted["deleted"], json!(true));
    assert!(ids(&f).is_empty(), "mailbox empty after ack");
}

#[test]
fn wrong_key_and_nonce_replay_rejected() {
    let f = fix();
    assert_eq!(deposit(&f, &f.fp, &minimal_parcel(&f)), 200);

    // wrong key: signature does not verify against the mailbox pubkey → 401
    let other = SigningKey::generate(&mut OsRng);
    let nonce = challenge(&f, &f.fp);
    let bad_sig = sign_challenge(&other, &nonce);
    assert_eq!(
        authed_status(&f, "GET", &format!("/mailbox/{}", f.fp), &bad_sig),
        401
    );

    // the good key still works (bad attempt did not brick the mailbox)
    assert_eq!(ids(&f).len(), 1);

    // nonce single-use: sign ONE nonce, use it successfully, replay → 401
    let nonce = challenge(&f, &f.fp);
    let sig = sign_challenge(&f.key, &nonce);
    let path = format!("/mailbox/{}", f.fp);
    assert_eq!(authed_status(&f, "GET", &path, &sig), 200);
    assert_eq!(authed_status(&f, "GET", &path, &sig), 401, "nonce replay");
}

#[test]
fn fp_mismatch_rejected_and_size_caps_enforced() {
    let f = fix();
    let parcel = minimal_parcel(&f); // carries f.key's pubkey

    // fp != fingerprint(pubkey) → 400
    let wrong_fp = "0123456789abcdef";
    assert_eq!(deposit(&f, wrong_fp, &parcel), 400);
    // nothing was stored for the wrong mailbox
    let root = f._root.path();
    assert!(!root.join("mailboxes").join(wrong_fp).exists());

    // Content-Length over the body cap → 413 before reading the body
    assert_eq!(
        raw_post_oversize_status(&f, &f.fp, MAX_BODY_BYTES + 1024),
        413
    );

    // parcel over protocol limits (9 attachments > 8) → 413
    let mut p9 = parcel.clone();
    p9.attachments = (0..9)
        .map(|i| ParcelAttachment {
            i,
            data: "AAAA".into(),
        })
        .collect();
    assert_eq!(deposit(&f, &f.fp, &p9), 413);

    // malformed body → 400
    let resp = f
        .client
        .post(&format!("{}/mailbox/{}", f.server.base_url(), f.fp))
        .set("Content-Type", "application/json")
        .send_string("this is not json");
    assert_eq!(status(resp), 400);
}

#[test]
fn retention_gc_removes_expired_and_prunes_empty_mailbox() {
    // retention 7: a pre-dated entry planted directly in the store layout is
    // swept on mailbox access; a fresh one survives.
    let f = fix_retention(7);
    assert_eq!(deposit(&f, &f.fp, &minimal_parcel(&f)), 200);
    let fresh = ids(&f);
    assert_eq!(fresh.len(), 1);
    let old_id = "e".repeat(32);
    let mbox = f._root.path().join("mailboxes").join(&f.fp);
    std::fs::write(mbox.join(format!("{old_id}.parcel")), br#"{"v":1}"#).unwrap();
    std::fs::write(
        mbox.join(format!("{old_id}.meta.json")),
        br#"{"received_unix":0}"#,
    )
    .unwrap();
    let after = ids(&f); // list triggers lazy GC
    assert!(after.contains(&fresh[0]), "fresh parcel survives");
    assert!(!after.contains(&old_id), "expired parcel is swept");
    assert!(!mbox.join(format!("{old_id}.parcel")).exists());

    // retention 0: everything is expired on access; the emptied mailbox is
    // pruned, so a subsequent authed request 404s.
    let f0 = fix_retention(0);
    assert_eq!(deposit(&f0, &f0.fp, &minimal_parcel(&f0)), 200);
    assert!(ids(&f0).is_empty(), "retention 0 sweeps on access");
    let nonce = challenge(&f0, &f0.fp);
    let sig = sign_challenge(&f0.key, &nonce);
    assert_eq!(
        authed_status(&f0, "GET", &format!("/mailbox/{}", f0.fp), &sig),
        404,
        "pruned mailbox is unknown"
    );
}

#[test]
fn periodic_sweep_collects_untouched_mailboxes_and_stale_nonce_dirs() {
    // deposit-and-abandon + challenge-flood leftovers: those fps are never
    // revisited, so lazy GC never fires for them — one pass of the periodic
    // sweep (spec §2.2: ALL mailboxes every 10 minutes) must collect both.
    let f = fix_retention(0);
    assert_eq!(deposit(&f, &f.fp, &minimal_parcel(&f)), 200);

    // expired nonce under a ghost fp that only ever requested challenges
    let ghost = "0123456789abcdef";
    let ndir = f._root.path().join("nonces").join(ghost);
    std::fs::create_dir_all(&ndir).unwrap();
    std::fs::write(
        ndir.join("deadbeefdeadbeef.json"),
        br#"{"nonce":"x","expires_unix":0}"#,
    )
    .unwrap();

    // deliberately NO mailbox access after the deposit: lazy GC cannot fire
    let mbox = f._root.path().join("mailboxes").join(&f.fp);
    assert!(mbox.exists(), "deposit-and-abandon entry is on disk");
    f.server.sweep_now(); // one synchronous periodic sweep
    assert!(!mbox.exists(), "abandoned mailbox swept and pruned");
    assert!(
        !ndir.exists(),
        "expired nonce swept, empty nonce dir pruned"
    );
    // the store still serves after a sweep
    assert_eq!(deposit(&f, &f.fp, &minimal_parcel(&f)), 200);
}

#[test]
fn challenge_outstanding_nonce_cap_is_429() {
    let f = fix();
    for _ in 0..MAX_OUTSTANDING_NONCES {
        challenge(&f, &f.fp);
    }
    let resp = f
        .client
        .get(&format!("{}/challenge/{}", f.server.base_url(), f.fp))
        .call();
    assert_eq!(status(resp), 429);
    // a different fp is unaffected
    let other = SigningKey::generate(&mut OsRng);
    let other_fp = fingerprint_of(&B64.encode(other.verifying_key().as_bytes()));
    assert_eq!(
        f.client
            .get(&format!("{}/challenge/{other_fp}", f.server.base_url()))
            .call()
            .unwrap()
            .status(),
        200
    );
}

#[test]
fn store_entry_cap_is_429() {
    let root = tempfile::tempdir().unwrap();
    let store = RelayStore::new(root.path().to_path_buf(), 7);
    let key = SigningKey::generate(&mut OsRng);
    let pubkey = B64.encode(key.verifying_key().as_bytes());
    let fp = fingerprint_of(&pubkey);
    for _ in 0..1000 {
        store.deposit(&fp, &pubkey, br#"{"v":1}"#).unwrap();
    }
    assert_eq!(store.list(&fp).len(), 1000);
    let err = store.deposit(&fp, &pubkey, br#"{"v":1}"#).unwrap_err();
    assert!(matches!(err, StoreError::TooMany(_)), "got {err:?}");
    assert_eq!(err.http_status(), 429);
    // pubkey not fingerprinting to fp → Bad (defensive double guard)
    let err = store.deposit(&fp, "AAAA", br#"{"v":1}"#).unwrap_err();
    assert!(matches!(err, StoreError::Bad(_)), "got {err:?}");
    assert_eq!(err.http_status(), 400);
}

#[test]
fn not_found_paths() {
    let f = fix();

    // authed route on an unknown mailbox → 404
    assert_eq!(authed_call(&f, "GET", &format!("/mailbox/{}", f.fp)).0, 404);

    // unknown id after a real deposit → 404
    assert_eq!(deposit(&f, &f.fp, &minimal_parcel(&f)), 200);
    let ghost = "d".repeat(32);
    assert_eq!(
        authed_call(&f, "GET", &format!("/mailbox/{}/{}", f.fp, ghost)).0,
        404
    );

    // unknown route → 404 with an error body
    let resp = match f
        .client
        .get(&format!("{}/nope", f.server.base_url()))
        .call()
    {
        Err(ureq::Error::Status(404, resp)) => resp,
        other => panic!("expected 404, got {:?}", other.map(|r| r.status())),
    };
    assert!(resp.into_string().unwrap().contains("error"));
}
