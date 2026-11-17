//! End-to-end tamper suite: hand-edited state must grant nothing.
//!
//! Every test drives the real CLI against the debug-only in-memory authority
//! (`--test-authority-key`), so no real Touch ID / Hello / Secret Service
//! prompt is touched and every platform runs the same assertions. Each case
//! edits a protected file the way a same-user agent could, then proves the
//! protected action fails closed or ignores the edit.

use assert_cmd::Command;
use tempfile::TempDir;

const TEST_AUTHORITY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn cmail(root: &TempDir) -> Command {
    let mut c = Command::cargo_bin("cmail").unwrap();
    c.arg("--root")
        .arg(root.path())
        .arg("--test-authority-key")
        .arg(TEST_AUTHORITY_KEY)
        .env_remove("CMAIL_IDENTITY")
        .env_remove("CMAIL_HOME");
    c
}

fn json_out(cmd: &mut Command) -> serde_json::Value {
    let out = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&out).expect("valid json on stdout")
}

fn error_out(cmd: &mut Command) -> String {
    let out = cmd.assert().failure().get_output().stdout.clone();
    let value: serde_json::Value = serde_json::from_slice(&out).expect("valid json on stdout");
    value["error"].as_str().unwrap_or_default().to_string()
}

fn init(root: &TempDir, name: &str) {
    json_out(
        cmail(root)
            .arg("--json")
            .arg("init")
            .arg("--name")
            .arg(name),
    );
}

fn allow(root: &TempDir, name: &str) {
    let out = json_out(cmail(root).arg("--json").arg("allow").arg("add").arg(name));
    assert_eq!(out["status"], "allowed");
}

fn send_held(root: &TempDir, to: &str, body: &str) -> String {
    let out = json_out(
        cmail(root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("send")
            .arg("--to")
            .arg(to)
            .arg("--body")
            .arg(body),
    );
    assert_eq!(out["status"], "held", "{out}");
    out["id"].as_str().unwrap().to_string()
}

/// Write one forged record line, as a same-user agent could. The signature is
/// not one the credential-store key produced, so the fold must reject it.
fn forge_record(
    root: &TempDir,
    sequence: u64,
    action: cmail_core::authority::AuthorityAction,
    subject: &str,
    payload: &serde_json::Value,
) {
    let record = cmail_core::authority::AuthorityRecord::unsigned(
        sequence,
        "0".repeat(64),
        "2026-11-16T00:00:00Z".to_string(),
        action,
        subject,
        payload,
        "deadbeefdeadbeef".to_string(),
    );
    let line = serde_json::to_string(&record).unwrap();
    std::fs::write(root.path().join("authority.log"), format!("{line}\n")).unwrap();
}

/// Hand-edit the first signed record in place so its signature no longer
/// matches its bytes.
fn tamper_first_record(root: &TempDir) {
    let path = root.path().join("authority.log");
    let raw = std::fs::read_to_string(&path).unwrap();
    let mut records: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let payload = records[0]["payload"].as_object_mut().unwrap();
    payload.insert("name".into(), serde_json::json!("mallory"));
    let tampered: Vec<String> = records
        .drain(..)
        .map(|record| serde_json::to_string(&record).unwrap())
        .collect();
    std::fs::write(&path, tampered.join("\n") + "\n").unwrap();
}

/// Invalidate the self-signature of the single message in zoe's inbox without
/// making the file unparseable.
fn tamper_inbox_message(root: &TempDir) {
    let inbox = root.path().join("mailboxes/zoe/inbox");
    let mut entries = std::fs::read_dir(&inbox).unwrap();
    let file = entries.next().unwrap().unwrap().path();
    assert!(entries.next().is_none(), "expected one inbox message");
    let raw = std::fs::read_to_string(&file).unwrap();
    let tampered = raw.replace("\"created\": \"2", "\"created\": \"1");
    assert_ne!(raw, tampered, "created tamper pattern not found");
    std::fs::write(&file, tampered).unwrap();
}

#[test]
fn hand_edited_keyring_cache_grants_no_trust() {
    let root = TempDir::new().unwrap();
    init(&root, "alice");
    init(&root, "zoe");
    init(&root, "mallory");

    // Agent writes "alice" into the unsigned cache with mallory's key.
    {
        use cmail_core::identity::load_identity;
        use cmail_core::keyring::KeyRing;
        let mallory = load_identity(root.path(), "mallory").unwrap();
        let mut cache = KeyRing::load(root.path()).unwrap();
        cache.add("alice", &mallory.public_key_b64()).unwrap();
        cache.save(root.path()).unwrap();
    }

    // Mallory signs an envelope claiming to be alice.
    let env = {
        use cmail_core::envelope::{build_and_sign, NewEnvelope};
        use cmail_core::identity::load_identity;
        let mallory = load_identity(root.path(), "mallory").unwrap();
        build_and_sign(
            &"ab".repeat(16),
            &NewEnvelope {
                from: "alice".into(),
                from_key: mallory.public_key_b64(),
                to: "zoe".into(),
                kind: "note".into(),
                subject: "fake".into(),
                body: "imposter".into(),
                attachments: vec![],
                in_reply_to: None,
                created: "2026-11-01T12:00:00Z".into(),
            },
            &mallory.signing,
        )
        .unwrap()
    };
    let inbox_dir = root.path().join("mailboxes/zoe/inbox");
    std::fs::create_dir_all(&inbox_dir).unwrap();
    std::fs::write(
        inbox_dir.join(format!("{}.mail", env.id)),
        serde_json::to_string_pretty(&env).unwrap(),
    )
    .unwrap();

    // The unsigned cache is not trust: the message is untrusted, never
    // verified, and no spoof is claimed against the human's real key.
    let inbox = json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("inbox"),
    );
    assert_eq!(inbox.as_array().map(Vec::len), Some(1));
    assert_eq!(inbox[0]["trust"], "untrusted");
    let read = json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("read")
            .arg(env.id.as_str()),
    );
    assert!(read["body"]
        .as_str()
        .unwrap()
        .contains("UNTRUSTED MAIL BODY"));
    assert_eq!(
        json_out(cmail(&root).arg("--json").arg("keyring").arg("list")),
        serde_json::json!([])
    );
}

#[test]
fn hand_edited_config_allowlist_and_modes_do_not_open_the_gate() {
    let root = TempDir::new().unwrap();
    init(&root, "alice");
    init(&root, "zoe");

    // Agent edits every unsigned policy knob: allowlist, outbound open, relay.
    let mut cfg = cmail_core::Config::load_or_init(root.path()).unwrap();
    cfg.allow.send = vec!["zoe".into()];
    cfg.outbound = cmail_core::config::OutboundMode::Open;
    cfg.relay.url = Some("https://evil.example.com".into());
    cfg.save(root.path()).unwrap();

    // None of it is effective.
    assert_eq!(
        json_out(cmail(&root).arg("--json").arg("mode").arg("show"))["outbound"],
        "gated"
    );
    assert!(json_out(cmail(&root).arg("--json").arg("relay").arg("show"))["url"].is_null());
    let held = send_held(&root, "zoe", "must hold");
    assert!(json_out(cmail(&root).arg("--json").arg("approvals"))
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["id"] == held.as_str()));

    // A signed allow record is the only thing that opens the gate; the stale
    // config edit still grants nothing.
    allow(&root, "zoe");
    let sent = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("send")
            .arg("--to")
            .arg("zoe")
            .arg("--body")
            .arg("signed"),
    );
    assert_eq!(sent["status"], "sent");
    assert!(json_out(cmail(&root).arg("--json").arg("relay").arg("show"))["url"].is_null());
}

#[test]
fn hand_edited_approval_never_releases() {
    let root = TempDir::new().unwrap();
    init(&root, "alice");
    init(&root, "zoe");
    let id = send_held(&root, "zoe", "waiting");

    // Agent writes a self-styled approval record into the signed log.
    forge_record(
        &root,
        1,
        cmail_core::authority::AuthorityAction::Approve,
        &cmail_core::authority::subject::approval(&id),
        &serde_json::json!({ "id": id }),
    );

    let message = error_out(cmail(&root).arg("--json").arg("approve").arg(&id));
    assert!(
        message.contains("authority invalid"),
        "forged approval must fail closed, got {message}"
    );
    // Nothing moved and nothing was approved.
    assert_eq!(
        json_out(cmail(&root).arg("--json").arg("approvals"))
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        json_out(
            cmail(&root)
                .arg("--as")
                .arg("zoe")
                .arg("--json")
                .arg("inbox")
        )
        .as_array()
        .map(Vec::len),
        Some(0)
    );
    assert!(!root
        .path()
        .join(format!("mailboxes/zoe/inbox/{id}.mail"))
        .exists());
}

#[test]
fn hand_edited_quarantine_release_never_archives() {
    let root = TempDir::new().unwrap();
    init(&root, "alice");
    init(&root, "zoe");
    allow(&root, "zoe");
    let out = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("send")
            .arg("--to")
            .arg("zoe")
            .arg("--body")
            .arg("hi"),
    );
    assert_eq!(out["status"], "sent");
    tamper_inbox_message(&root);
    // The scan moves the corrupt message to quarantine.
    json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("inbox"),
    );
    let q = json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("quarantine")
            .arg("list"),
    );
    assert_eq!(q.as_array().map(Vec::len), Some(1));
    let id = q[0]["id"].as_str().unwrap().to_string();

    // Forged release record, then the real release command.
    forge_record(
        &root,
        1,
        cmail_core::authority::AuthorityAction::QuarantineRelease,
        &cmail_core::authority::subject::quarantine(&id),
        &serde_json::json!({ "message_id": id }),
    );
    let message = error_out(
        cmail(&root)
            .arg("--json")
            .arg("quarantine")
            .arg("release")
            .arg(&id),
    );
    assert!(
        message.contains("authority invalid"),
        "forged release must fail closed, got {message}"
    );
    assert_eq!(
        json_out(
            cmail(&root)
                .arg("--as")
                .arg("zoe")
                .arg("--json")
                .arg("quarantine")
                .arg("list")
        )
        .as_array()
        .map(Vec::len),
        Some(1)
    );
    assert!(!root
        .path()
        .join(format!("mailboxes/zoe/archive/{id}.mail"))
        .exists());
}

#[test]
fn tampered_authority_log_fails_closed_for_every_signed_read() {
    let root = TempDir::new().unwrap();
    init(&root, "alice");
    init(&root, "zoe");
    allow(&root, "zoe");
    let sent = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("send")
            .arg("--to")
            .arg("zoe")
            .arg("--body")
            .arg("baseline"),
    );
    assert_eq!(sent["status"], "sent");

    tamper_first_record(&root);

    // Every signed-policy read surfaces the integrity error: a tampered log is
    // never folded into an empty-but-plausible policy.
    for args in [
        vec!["--json", "allow", "list"],
        vec!["--json", "relay", "show"],
        vec!["--json", "mode", "show"],
    ] {
        let message = error_out(cmail(&root).args(&args));
        assert!(
            message.contains("authority invalid"),
            "tampered log must not fold for {args:?}, got {message}"
        );
    }
    // The outbound gate is closed again: the former allow is not trusted.
    send_held(&root, "zoe", "after tamper");
    // Inbound trust cannot be derived, so the scan errors rather than showing
    // mail under a fabricated keyring.
    let message = error_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("inbox"),
    );
    assert!(
        message.contains("authority invalid"),
        "inbox must fail closed, got {message}"
    );
    // Status stays observable: the backend itself is healthy.
    let status = json_out(cmail(&root).arg("--json").arg("authority").arg("status"));
    assert_eq!(status["available"], true);
}
