//! Regression cover for the ordinary agent surface under a valid signed
//! policy: send, read, reply, wait, list, and fetch all still work when the
//! human has signed the required decisions.
//!
//! Uses the debug-only in-memory authority so no real Touch ID / Hello /
//! Secret Service prompt runs, and the same assertions hold on every CI OS.

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

#[test]
fn local_mail_operations_under_signed_policy() {
    let root = TempDir::new().unwrap();
    init(&root, "alice");
    init(&root, "zoe");
    // The human signs both directions so reply is not held.
    allow(&root, "zoe");
    allow(&root, "alice");

    let sent = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("send")
            .arg("--to")
            .arg("zoe")
            .arg("--subject")
            .arg("handoff")
            .arg("--body")
            .arg("state v1"),
    );
    assert_eq!(sent["status"], "sent");
    let id = sent["id"].as_str().unwrap().to_string();

    // wait (zero timeout) returns the delivered mail.
    let waited = json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("wait")
            .arg("--timeout")
            .arg("0"),
    );
    assert_eq!(waited.as_array().map(Vec::len), Some(1));
    assert_eq!(waited[0]["id"], id);

    // inbox + read
    let inbox = json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("inbox"),
    );
    assert_eq!(inbox[0]["trust"], "untrusted");
    let read = json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("read")
            .arg(&id),
    );
    assert!(read["body"]
        .as_str()
        .unwrap()
        .contains("UNTRUSTED MAIL BODY"));
    assert!(read["body"].as_str().unwrap().contains("state v1"));

    // reply is a normal gated send; alice is allowlisted, so it goes out.
    let reply = json_out(
        cmail(&root)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("reply")
            .arg(&id)
            .arg("--body")
            .arg("roger"),
    );
    assert_eq!(reply["status"], "sent");
    let reply_id = reply["id"].as_str().unwrap().to_string();

    let alice_inbox = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("inbox"),
    );
    assert_eq!(alice_inbox.as_array().map(Vec::len), Some(1));
    assert_eq!(alice_inbox[0]["id"], reply_id);
    let alice_read = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("read")
            .arg(&reply_id),
    );
    assert_eq!(alice_read["in_reply_to"], id.as_str());

    // list and list --all keep working (the read reply is archived).
    let listed = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("list"),
    );
    assert_eq!(listed.as_array().map(Vec::len), Some(0));
    let all = json_out(
        cmail(&root)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("list")
            .arg("--all"),
    );
    assert!(all
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == reply_id.as_str()));
}

#[test]
fn fetch_under_signed_relay_policy() {
    let relay_root = TempDir::new().unwrap();
    let relay = cmail_relayd::RelayServer::start("127.0.0.1:0", relay_root.path().to_path_buf(), 7)
        .unwrap();
    let base = relay.base_url();

    // Two machines: alice's root and zoe's root. They share zoe's public key
    // out of band and a relay route (routing and encryption, never trust).
    let sender = TempDir::new().unwrap();
    let recipient = TempDir::new().unwrap();
    init(&sender, "alice");
    init(&recipient, "zoe");
    let zoe_key = cmail_core::identity::load_identity(recipient.path(), "zoe")
        .unwrap()
        .public_key_b64();
    // Key trust is a signed decision; the relay route is cache-only routing.
    let key_file = sender.path().join("zoe-pub.b64");
    std::fs::write(&key_file, &zoe_key).unwrap();
    let added = json_out(
        cmail(&sender)
            .arg("--json")
            .arg("keyring")
            .arg("add")
            .arg("zoe")
            .arg("--key-file")
            .arg(&key_file),
    );
    assert_eq!(added["status"], "trusted");
    {
        use cmail_core::keyring::KeyRing;
        let mut cache = KeyRing::load(sender.path()).unwrap();
        cache.set_route("zoe", Some(&base)).unwrap();
        cache.save(sender.path()).unwrap();
    }
    allow(&sender, "zoe");

    // Normal send: passes the signed outbound gate, then deposits on the relay
    // because zoe is keyring-known with a route.
    let sent = json_out(
        cmail(&sender)
            .arg("--as")
            .arg("alice")
            .arg("--json")
            .arg("send")
            .arg("--to")
            .arg("zoe")
            .arg("--body")
            .arg("remote hi"),
    );
    assert_eq!(sent["status"], "sent");

    // Normal fetch: the signed relay record is the fetch target, and the
    // parcel verifies, decrypts, and lands in zoe's inbox.
    let set = json_out(
        cmail(&recipient)
            .arg("--json")
            .arg("relay")
            .arg("set")
            .arg(&base),
    );
    assert_eq!(set["url"], base.as_str());
    let report = json_out(
        cmail(&recipient)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("fetch"),
    );
    assert_eq!(report["fetched"], 1);
    assert_eq!(report["kept_on_relay"], 0);

    let inbox = json_out(
        cmail(&recipient)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("inbox"),
    );
    assert_eq!(inbox.as_array().map(Vec::len), Some(1));
    assert_eq!(inbox[0]["trust"], "untrusted");
    let id = inbox[0]["id"].as_str().unwrap().to_string();
    let read = json_out(
        cmail(&recipient)
            .arg("--as")
            .arg("zoe")
            .arg("--json")
            .arg("read")
            .arg(&id),
    );
    assert!(read["body"].as_str().unwrap().contains("remote hi"));
}
