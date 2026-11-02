//! Host-target unit tests for the pure route/path layer (no worker runtime).

use cmail_relay_cf::paths::{blob_key, do_name, valid_fp, valid_id};
use cmail_relay_cf::routes::{parse, ParseOutcome, Route};
use sha2::Digest;

#[test]
fn validation_matches_protocol_shapes() {
    assert!(valid_fp(&"a".repeat(16)) && !valid_fp(&"a".repeat(15)) && !valid_fp(&"zz".repeat(8)));
    assert!(
        valid_id(&"f".repeat(32)) && !valid_id(&"f".repeat(31)) && !valid_id(&"../evil".repeat(4))
    );
}

#[test]
fn route_table_matches_spec() {
    let ok = |m: &str, p: &str| match parse(m, p) {
        ParseOutcome::Route(r) => Some(r),
        ParseOutcome::NotFound => None,
    };
    assert!(matches!(
        ok("GET", "/challenge/aaaaaaaaaaaaaaaa"),
        Some(Route::Challenge { .. })
    ));
    assert!(matches!(
        ok("POST", "/mailbox/aaaaaaaaaaaaaaaa"),
        Some(Route::Deposit { .. })
    ));
    assert!(matches!(
        ok("GET", "/mailbox/aaaaaaaaaaaaaaaa"),
        Some(Route::List { .. })
    ));
    assert!(matches!(
        ok(
            "GET",
            "/mailbox/aaaaaaaaaaaaaaaa/ffffffffffffffffffffffffffffffff"
        ),
        Some(Route::Fetch { .. })
    ));
    assert!(matches!(
        ok(
            "DELETE",
            "/mailbox/aaaaaaaaaaaaaaaa/ffffffffffffffffffffffffffffffff"
        ),
        Some(Route::Ack { .. })
    ));
    // wrong methods / unknown / malformed segments / query stripped
    assert!(ok("PUT", "/mailbox/aaaaaaaaaaaaaaaa").is_none());
    assert!(ok("GET", "/").is_none());
    assert!(ok("GET", "/mailbox/zz").is_none());
    assert!(matches!(
        parse("GET", "/mailbox/aaaaaaaaaaaaaaaa?x=1"),
        ParseOutcome::Route(Route::List { .. })
    ));
}

#[test]
fn do_name_hashes_and_blob_keys_are_stable() {
    assert_eq!(
        do_name(&"a".repeat(16)),
        hex::encode(sha2::Sha256::digest("a".repeat(16).as_bytes()))
    );
    assert_eq!(
        blob_key(&"a".repeat(16), &"f".repeat(32)),
        format!("{}/{}", "a".repeat(16), "f".repeat(32))
    );
}
