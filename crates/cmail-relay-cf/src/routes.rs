//! The five-route table (relay protocol v1 §2), parsed from (method, path).
//!
//! Semantics mirror relayd's `route` dispatcher: query strings are stripped,
//! empty path segments are dropped, and anything that isn't exactly one of
//! the five (method, segments) shapes — including malformed fingerprints and
//! ids — is `NotFound`. There is deliberately no validity oracle: a caller
//! cannot distinguish "malformed fp" from "unknown route" from "no such
//! mailbox".

use crate::paths::{valid_fp, valid_id};

pub enum Route {
    Challenge { fp: String },
    Deposit { fp: String },
    List { fp: String },
    Fetch { fp: String, id: String },
    Ack { fp: String, id: String },
}

pub enum ParseOutcome {
    Route(Route),
    NotFound,
}

/// Parse `(method, path)` against the route table:
///
/// - `GET    /challenge/{fp}`          → Challenge
/// - `POST   /mailbox/{fp}`            → Deposit   (open)
/// - `GET    /mailbox/{fp}`            → List      (authed)
/// - `GET    /mailbox/{fp}/{id}`       → Fetch     (authed)
/// - `DELETE /mailbox/{fp}/{id}`       → Ack       (authed)
///
/// Malformed segments and unknown shapes alike are `NotFound`, exactly like
/// relayd's 404 fallthrough.
pub fn parse(method: &str, path: &str) -> ParseOutcome {
    let path = path.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let route = match (segments.as_slice(), method) {
        (["challenge", fp], "GET") if valid_fp(fp) => Route::Challenge { fp: fp.to_string() },
        (["mailbox", fp], "POST") if valid_fp(fp) => Route::Deposit { fp: fp.to_string() },
        (["mailbox", fp], "GET") if valid_fp(fp) => Route::List { fp: fp.to_string() },
        (["mailbox", fp, id], "GET") if valid_fp(fp) && valid_id(id) => Route::Fetch {
            fp: fp.to_string(),
            id: id.to_string(),
        },
        (["mailbox", fp, id], "DELETE") if valid_fp(fp) && valid_id(id) => Route::Ack {
            fp: fp.to_string(),
            id: id.to_string(),
        },
        _ => return ParseOutcome::NotFound,
    };
    ParseOutcome::Route(route)
}
