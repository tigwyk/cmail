use std::io::Cursor;

fn drive(root: &std::path::Path, lines: &[&str]) -> Vec<serde_json::Value> {
    let input = lines.join("\n");
    let mut out = Vec::new();
    let writer = Vec::new();
    let result = {
        let mut writer = Cursor::new(writer);
        let r = cmail_mcp::run_server(
            root.to_path_buf(),
            Some("zoe".into()),
            Cursor::new(input),
            &mut writer,
        );
        r.unwrap();
        writer
    };
    let text = String::from_utf8(result.into_inner()).unwrap();
    for line in text.lines().filter(|l| !l.is_empty()) {
        out.push(serde_json::from_str(line).unwrap());
    }
    out
}

fn setup() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let c = cmail_core::Cmail::open(root.path()).unwrap();
    c.init("alice").unwrap();
    c.init("zoe").unwrap();
    root
}

#[test]
fn initialize_and_tools_list() {
    let root = setup();
    let out = drive(
        root.path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ],
    );
    assert_eq!(out.len(), 2); // notification got no reply
    assert_eq!(out[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(out[0]["result"]["serverInfo"]["name"], "cmail");
    let tools = out[1]["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "cmail_send",
            "cmail_inbox",
            "cmail_read",
            "cmail_reply",
            "cmail_wait",
            "cmail_approvals"
        ]
    );
}

#[test]
fn human_only_tools_are_absent() {
    let specs = cmail_mcp::tools::tool_specs();
    let names: Vec<&str> = specs.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for forbidden in [
        "approve",
        "reject",
        "allow",
        "keyring",
        "quarantine",
        "config",
    ] {
        assert!(
            !names.iter().any(|n| n.contains(forbidden)),
            "forbidden surface leaked: {names:?}"
        );
    }
}

#[test]
fn send_held_then_read_via_mcp() {
    let root = setup();
    let out = drive(
        root.path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cmail_send","arguments":{"to":"zoe","kind":"status","subject":"s","body":"b"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cmail_approvals","arguments":{}}}"#,
        ],
    );
    // Server identity is zoe sending to zoe: the recipient exists but is not
    // allowlisted, so the outbound gate holds the message for human approval.
    // Responses: [initialize, send, approvals] — notifications get no reply.
    let send_result = &out[1]["result"];
    let text = send_result["content"][0]["text"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["status"], "held");
    // Spec §6: held outcomes carry guidance pointing the agent at its human.
    assert!(parsed["guidance"]
        .as_str()
        .expect("held outcome must carry guidance")
        .contains("cmail approvals"));
    let apps = out[2]["result"]["content"][0]["text"].as_str().unwrap();
    let apps: serde_json::Value = serde_json::from_str(apps).unwrap();
    assert_eq!(apps.as_array().map(Vec::len), Some(1));
}

#[test]
fn human_only_tool_call_is_unknown_tool() {
    // Pins the human-only boundary from the call side, not just tools/list:
    // `cmail_approve` must fail like any unknown tool, never execute.
    let root = setup();
    let out = drive(
        root.path(),
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cmail_approve","arguments":{"id":"whatever"}}}"#,
        ],
    );
    let resp = &out[1];
    assert!(
        resp.get("error").is_none(),
        "tool failure must be JSON-RPC success"
    );
    assert_eq!(resp["result"]["isError"], true);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("unknown tool"), "got: {text}");
}

#[test]
fn unknown_method_is_minus_32601() {
    let root = setup();
    let out = drive(
        root.path(),
        &[r#"{"jsonrpc":"2.0","id":9,"method":"bogus"}"#],
    );
    assert_eq!(out[0]["error"]["code"], -32601);
}
