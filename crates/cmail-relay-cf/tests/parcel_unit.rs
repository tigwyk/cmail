//! Host-target unit tests for the cf parcel layer, including PARITY tests
//! against `cmail-core` (dev-dependency, host only — production wasm code
//! never links core; `cargo check -p cmail-relay-cf --target
//! wasm32-unknown-unknown` proves it).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cmail_relay_cf::parcel::{fingerprint_of, Parcel, ParcelAttachment};

/// b64 of the fixed 32-byte key `[7u8; 32]`.
const KEY_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
/// sha256([7u8; 32])[..8] as hex, pinned so fingerprint drift is detectable
/// even if both implementations were wrong the same way.
const KEY_FP: &str = "4bb06f8e4e3a7715";

/// cf NEVER parses inside the envelope — any JSON blob is a valid stand-in.
fn envelope_value() -> serde_json::Value {
    serde_json::json!({ "id": "0123456789abcdef", "enc": "opaque-sealed-blob" })
}

fn frame(i: usize, data: &[u8]) -> ParcelAttachment {
    ParcelAttachment {
        i,
        data: B64.encode(data),
    }
}

fn parcel(atts: Vec<ParcelAttachment>) -> Parcel {
    Parcel {
        v: 1,
        pubkey: KEY_B64.into(),
        envelope: envelope_value(),
        attachments: atts,
    }
}

#[test]
fn parcel_round_trip_preserves_frames_byte_identically() {
    let frames: Vec<(usize, Vec<u8>)> =
        vec![(0, vec![1, 2, 3, 4]), (1, vec![9u8; 40]), (2, Vec::new())];
    let p = parcel(frames.iter().map(|(i, d)| frame(*i, d)).collect());
    p.validate().unwrap();
    let json = serde_json::to_string(&p).unwrap();
    let back: Parcel = serde_json::from_str(&json).unwrap();
    back.validate().unwrap();
    // frames decode byte-identically, index order preserved
    assert_eq!(back.attachments.len(), frames.len());
    for ((i, d), att) in frames.iter().zip(&back.attachments) {
        assert_eq!(att.i, *i);
        assert_eq!(&B64.decode(&att.data).unwrap(), d);
    }
}

#[test]
fn parcel_validation_rejects_bad() {
    // v != 1
    let mut p = parcel(vec![]);
    p.v = 2;
    assert!(p.validate().is_err(), "v != 1 must be rejected");
    // pubkey: not base64 / base64 but wrong byte length
    let mut p = parcel(vec![]);
    p.pubkey = "!!not b64!!".into();
    assert!(p.validate().is_err(), "non-b64 pubkey must be rejected");
    let mut p = parcel(vec![]);
    p.pubkey = B64.encode([1u8; 16]);
    assert!(p.validate().is_err(), "16-byte pubkey must be rejected");
    // more than 8 attachments
    let p = parcel((0..9).map(|i| frame(i, &[0, 0, 0, 0])).collect());
    assert!(p.validate().is_err(), ">8 attachments must be rejected");
    // non-b64 data: build from one VALID attachment, then corrupt it
    let mut p = parcel(vec![frame(0, &[1, 2, 3])]);
    p.attachments[0].data = "!!not b64!!".into();
    assert!(p.validate().is_err(), "non-b64 frame data must be rejected");
    // decoded-total cap: two entries summing to exactly 36 MiB pass…
    let half = 18 * 1024 * 1024;
    let p = parcel(vec![frame(0, &vec![0u8; half]), frame(1, &vec![0u8; half])]);
    p.validate()
        .expect("exactly 36 MiB decoded is at the cap, not over");
    // …but 36 MiB + 1 KiB across two entries is rejected
    let p = parcel(vec![
        frame(0, &vec![0u8; half]),
        frame(1, &vec![0u8; half + 1024]),
    ]);
    assert!(p.validate().is_err(), "36 MiB + 1 KiB must be rejected");
    // index set (stricter than core): duplicate i rejected…
    let p = parcel(vec![frame(0, &[1]), frame(0, &[2])]);
    assert!(p.validate().is_err(), "duplicate index must be rejected");
    // …and a gap rejected (canonical set is exactly 0..len)
    let p = parcel(vec![frame(0, &[1]), frame(2, &[2])]);
    assert!(p.validate().is_err(), "index gap must be rejected");
}

/// A real, signed, plain envelope from core + the fixed recipient key.
fn core_fixture() -> (cmail_core::envelope::Envelope, String) {
    let sender = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
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
    (env, KEY_B64.to_string())
}

#[test]
fn fingerprint_and_parcel_parity_with_core() {
    // fingerprint parity for a fixed key, against a pinned constant…
    assert_eq!(fingerprint_of(KEY_B64).as_deref(), Some(KEY_FP));
    // …and against core's implementation for the same key
    assert_eq!(
        fingerprint_of(KEY_B64),
        Some(cmail_core::identity::fingerprint_of(KEY_B64))
    );
    // cf is stricter on bad b64: None (core fingerprints the empty decode)
    assert_eq!(fingerprint_of("!!not b64!!"), None);

    // core -> cf: a core-built parcel's JSON parses + validates as a cf Parcel
    let (env, recipient) = core_fixture();
    let frames = vec![(0usize, vec![1u8, 2, 3, 4]), (1usize, vec![9u8; 40])];
    let core_parcel = cmail_core::relay::build_parcel(&env, &frames, &recipient).unwrap();
    let json = serde_json::to_string(&core_parcel).unwrap();
    let cf_p: Parcel = serde_json::from_str(&json).unwrap();
    cf_p.validate().unwrap();
    assert_eq!(
        &B64.decode(&cf_p.attachments[0].data).unwrap(),
        &frames[0].1
    );

    // cf -> core: cf-built from the same parts round-trips through core's
    // validate (cf's envelope is an opaque Value; core re-parses it typed)
    let cf_p = Parcel {
        v: 1,
        pubkey: recipient,
        envelope: serde_json::to_value(&env).unwrap(),
        attachments: frames.iter().map(|(i, d)| frame(*i, d)).collect(),
    };
    let json = serde_json::to_string(&cf_p).unwrap();
    let back: cmail_core::relay::Parcel = serde_json::from_str(&json).unwrap();
    back.validate().unwrap();
    assert_eq!(back.attachments[1].i, 1);
}
