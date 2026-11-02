//! cmail-relay-cf — the cmail relay protocol as a Cloudflare Worker.
//!
//! Wire-identical twin of `cmail-relayd` (spec: relay protocol v1 §2, as
//! amended). This crate compiles both on the host (route/path unit tests,
//! CI clippy) and on `wasm32-unknown-unknown` (`wrangler deploy`).

pub mod calc;
pub mod mailbox;
pub mod parcel;
pub mod paths;
pub mod routes;

use worker::{event, Request, Response};

/// JSON responder shared by every handler. `{"error": msg}` bodies match
/// relayd's shape exactly.
pub fn json_response(status: u16, body: serde_json::Value) -> Response {
    Response::from_json(&body)
        .expect("serializing a serde_json::Value cannot fail")
        .with_status(status)
}

/// 404 responder (unknown mailbox/id, unknown routes).
pub fn not_found() -> Response {
    json_response(404, serde_json::json!({ "error": "not found" }))
}

/// 400 responder (malformed request bodies / fp mismatch in later tasks).
pub fn bad_request() -> Response {
    json_response(400, serde_json::json!({ "error": "bad request" }))
}

#[event(fetch)]
pub async fn main(
    req: Request,
    _env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<Response> {
    // Handlers arrive in C2/C3; for now every parse outcome is answered by
    // the not-found responder so the worker entry is wired end to end.
    match routes::parse(req.method().as_ref(), &req.path()) {
        routes::ParseOutcome::Route(_) | routes::ParseOutcome::NotFound => Ok(not_found()),
    }
}
