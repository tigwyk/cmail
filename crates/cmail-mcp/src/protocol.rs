use crate::tools;
use cmail_core::service::Cmail;
use serde_json::{json, Value};

pub fn handle_line(line: &str, svc: &Cmail, as_name: Option<&str>) -> Option<Value> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            return Some(json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": "parse error"}
            }))
        }
    };
    let id = msg.get("id").cloned();

    // Notifications never get responses.
    let id = id?;

    // A request must carry a string `method` (JSON-RPC 2.0 invalid request).
    let method = match msg.get("method") {
        Some(Value::String(s)) => s.clone(),
        _ => {
            return Some(json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32600, "message": "invalid request: missing or non-string method"}
            }))
        }
    };
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    let result_or_error: Result<Value, (i64, String)> = match method.as_str() {
        "initialize" => {
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05");
            Ok(json!({
                "protocolVersion": requested,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cmail", "version": env!("CARGO_PKG_VERSION")}
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools::tool_specs() })),
        "tools/call" => Ok(tools::call(svc, as_name, &params)),
        other => Err((-32601, format!("method not found: {other}"))),
    };

    Some(match result_or_error {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": code, "message": message}
        }),
    })
}
