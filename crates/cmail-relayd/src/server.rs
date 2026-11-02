//! Reference relay server (wire protocol v1, spec §2): five routes on
//! `tiny_http`, nonce-challenge Ed25519 auth, Content-Length precheck,
//! lazy per-access GC plus a periodic all-mailbox sweep, and caps.
//! Plaintext HTTP only — the protocol requires TLS in production; loopback
//! is the insecure-local test mode.

use crate::store::{
    now_unix, rfc3339, valid_fp, RelayStore, MAX_BODY_BYTES, MAX_OUTSTANDING_NONCES, NONCE_TTL_SECS,
};
use anyhow::{anyhow, Context, Result};
use cmail_core::relay::Parcel;
use serde_json::json;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

/// Handler threads accepting requests (tiny_http `recv` is thread-safe).
const WORKERS: usize = 4;

/// Periodic all-fingerprint GC interval (spec §2.2: every 10 minutes).
const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// A running relay server. `start` spawns the workers and the periodic
/// sweep thread; tests hold the struct (and the relay root) alive, and
/// `Drop` stops everything.
pub struct RelayServer {
    server: Arc<Server>,
    base_url: String,
    workers: Mutex<Vec<JoinHandle<()>>>,
    stop: Arc<AtomicBool>,
    store: Arc<RelayStore>,
    /// Shutdown signal + handle for the periodic sweep thread (joined on Drop).
    sweeper: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
}

impl RelayServer {
    /// Bind `addr` (use `127.0.0.1:0` for an ephemeral test port), serve the
    /// relay protocol out of the file-backed store under `root`, retaining
    /// parcels for `retention_days`.
    pub fn start(addr: &str, root: PathBuf, retention_days: u64) -> Result<RelayServer> {
        let server = Server::http(addr).map_err(|e| anyhow!("binding relay on {addr}: {e}"))?;
        let bound = server
            .server_addr()
            .to_ip()
            .context("relay bound to a non-IP socket")?;
        let ip = bound.ip();
        // Report a connectable host: unspecified binds become loopback so
        // `base_url()` is always usable for insecure-local testing.
        let host = if ip.is_unspecified() {
            "127.0.0.1".to_string()
        } else if matches!(ip, IpAddr::V6(_)) {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        let base_url = format!("http://{host}:{port}", port = bound.port());

        let store = Arc::new(RelayStore::new(root, retention_days));
        let stop = Arc::new(AtomicBool::new(false));
        let server = Arc::new(server);
        let workers = (0..WORKERS)
            .map(|_| {
                let server = Arc::clone(&server);
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                std::thread::Builder::new()
                    .name("cmail-relayd-worker".into())
                    .spawn(move || worker_loop(server, store, stop))
                    .expect("spawn relay worker thread")
            })
            .collect();
        // Periodic GC sweep of ALL fingerprints (spec §2.2): lazy per-access
        // GC never fires for abandoned mailboxes or challenge-flooded fps.
        let (sweep_tx, sweep_rx) = mpsc::channel::<()>();
        let sweeper = std::thread::Builder::new()
            .name("cmail-relayd-sweeper".into())
            .spawn({
                let store = Arc::clone(&store);
                move || sweep_loop(store, sweep_rx)
            })
            .expect("spawn relay sweep thread");
        Ok(RelayServer {
            server,
            base_url,
            workers: Mutex::new(workers),
            stop,
            store,
            sweeper: Some((sweep_tx, sweeper)),
        })
    }

    /// The bound base URL, e.g. `http://127.0.0.1:39219` (test/insecure mode).
    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    /// Run one synchronous all-fingerprint GC pass — the same routine the
    /// sweep thread runs every [`SWEEP_INTERVAL`]. Test hook for driving the
    /// periodic sweep deterministically.
    pub fn sweep_now(&self) {
        self.store.sweep_all();
    }

    /// Block until all worker threads exit (after a stop signal).
    pub fn wait(&self) {
        if let Ok(mut workers) = self.workers.lock() {
            for handle in workers.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let n = self.workers.lock().map(|w| w.len()).unwrap_or(0);
        // One unblock() releases one blocked recv(); one per worker.
        for _ in 0..n {
            self.server.unblock();
        }
        // Wake the sweep thread out of its interval wait and join it so no
        // thread outlives the server.
        if let Some((tx, handle)) = self.sweeper.take() {
            let _ = tx.send(());
            let _ = handle.join();
        }
    }
}

/// Periodic GC: one all-fingerprint sweep ([`RelayStore::sweep_all`]) every
/// [`SWEEP_INTERVAL`], waking immediately on the shutdown signal (or sender
/// drop) so shutdown is never delayed by the interval.
fn sweep_loop(store: Arc<RelayStore>, shutdown: mpsc::Receiver<()>) {
    // Timeout → run one sweep; shutdown signal or sender drop → exit.
    while let Err(RecvTimeoutError::Timeout) = shutdown.recv_timeout(SWEEP_INTERVAL) {
        store.sweep_all();
    }
}

fn worker_loop(server: Arc<Server>, store: Arc<RelayStore>, stop: Arc<AtomicBool>) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match server.recv() {
            Ok(request) => route(&store, request),
            // Either a shutdown unblock or a dead listener — stop either way.
            Err(_) => break,
        }
    }
}

/// Dispatch the five routes (spec §2). Anything else is 404.
fn route(store: &RelayStore, request: Request) {
    let path = request.url().split('?').next().unwrap_or("").to_string();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match (segments.as_slice(), request.method()) {
        (["challenge", fp], method) if *method == Method::Get => {
            challenge_route(store, request, fp);
        }
        (["mailbox", fp], method) if *method == Method::Post => {
            deposit_route(store, request, fp);
        }
        (["mailbox", fp], method) if *method == Method::Get => {
            authed_route(store, request, fp, None, false);
        }
        (["mailbox", fp, id], method) if *method == Method::Get => {
            authed_route(store, request, fp, Some(id), false);
        }
        (["mailbox", fp, id], method) if *method == Method::Delete => {
            authed_route(store, request, fp, Some(id), true);
        }
        _ => respond(request, 404, &error_body("not found")),
    }
}

/// `GET /challenge/{fp}` → 200 `{"nonce", "expires"}`; 429 over the
/// outstanding-nonce cap. Nonce files are swept lazily here.
fn challenge_route(store: &RelayStore, request: Request, fp: &str) {
    if !valid_fp(fp) {
        return respond(request, 404, &error_body("unknown mailbox"));
    }
    store.gc_nonces(fp);
    if store.nonce_count(fp) >= MAX_OUTSTANDING_NONCES {
        return respond(request, 429, &error_body("too many outstanding nonces"));
    }
    let nonce = store.nonce(fp);
    let body = json!({
        "nonce": nonce,
        "expires": rfc3339(now_unix() + NONCE_TTL_SECS),
    })
    .to_string();
    respond(request, 200, &body);
}

/// `POST /mailbox/{fp}` (open). Content-Length is checked BEFORE the body is
/// read (413), the parcel is validated (`Parcel::validate`: over-limit → 413,
/// bad shape → 400), `fingerprint(pubkey) == {fp}` (400), then stored raw.
fn deposit_route(store: &RelayStore, mut request: Request, fp: &str) {
    if !valid_fp(fp) {
        return respond(request, 404, &error_body("unknown mailbox"));
    }
    if let Some(len) = request.body_length() {
        if len > MAX_BODY_BYTES {
            return respond(request, 413, &error_body("body exceeds the size cap"));
        }
    }
    let mut body = Vec::new();
    // +1 so an over-cap (e.g. chunked) body is detected, never buffered whole.
    if request
        .as_reader()
        .take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return respond(request, 400, &error_body("unreadable request body"));
    }
    if body.len() > MAX_BODY_BYTES {
        return respond(request, 413, &error_body("body exceeds the size cap"));
    }
    let parcel: Parcel = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return respond(request, 400, &error_body(&format!("malformed parcel: {e}"))),
    };
    match parcel.validate() {
        Ok(()) => {}
        Err(cmail_core::CoreError::LimitExceeded(_)) => {
            return respond(request, 413, &error_body("parcel exceeds protocol limits"));
        }
        Err(e) => return respond(request, 400, &error_body(&format!("invalid parcel: {e}"))),
    }
    if cmail_core::identity::fingerprint_of(&parcel.pubkey) != fp {
        return respond(
            request,
            400,
            &error_body("fingerprint(parcel pubkey) does not match the mailbox"),
        );
    }
    store.gc(fp); // lazy retention + nonce sweep on deposit
    match store.deposit(fp, &parcel.pubkey, &body) {
        Ok(()) => respond(request, 200, r#"{"ok":true}"#),
        Err(e) => respond(request, e.http_status(), &error_body(&e.to_string())),
    }
}

/// Authed routes: `GET /mailbox/{fp}` (list), `GET /mailbox/{fp}/{id}`
/// (fetch), `DELETE /mailbox/{fp}/{id}` (ack). Unknown mailbox → 404 BEFORE
/// auth; auth = `X-cmail-Fp` must equal the URL fp and `X-cmail-Signature`
/// must verify (and consume) one outstanding nonce → else 401.
fn authed_route(store: &RelayStore, request: Request, fp: &str, id: Option<&str>, delete: bool) {
    let Some(pubkey) = store.mailbox_pubkey(fp) else {
        return respond(request, 404, &error_body("unknown mailbox"));
    };
    let signature = header(&request, "X-cmail-Signature");
    if header(&request, "X-cmail-Fp") != Some(fp) || signature.is_none() {
        return respond(
            request,
            401,
            &error_body("missing or mismatched auth headers"),
        );
    }
    if !store.consume_nonce_by_signature(fp, signature.unwrap(), &pubkey) {
        return respond(
            request,
            401,
            &error_body("auth failed (bad signature, or nonce expired/consumed)"),
        );
    }
    store.gc(fp); // lazy retention + nonce sweep on mailbox access
    match id {
        None => {
            let body = json!({"ids": store.list(fp)}).to_string();
            respond(request, 200, &body);
        }
        Some(id) if delete => {
            if store.delete(fp, id) {
                respond(request, 200, r#"{"deleted":true}"#)
            } else {
                respond(request, 404, &error_body("unknown id"))
            }
        }
        Some(id) => match store.get(fp, id).and_then(|b| String::from_utf8(b).ok()) {
            Some(body) => respond(request, 200, &body),
            None => respond(request, 404, &error_body("unknown id")),
        },
    }
}

fn header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

fn error_body(message: &str) -> String {
    json!({"error": message}).to_string()
}

fn respond(request: Request, status_code: u16, body: &str) {
    let content_type = Header::from_bytes("Content-Type", "application/json")
        .expect("static header bytes are valid");
    let _ = request.respond(
        Response::from_string(body.to_string())
            .with_status_code(status_code)
            .with_header(content_type),
    );
}
