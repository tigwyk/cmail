use serde::Serialize;

pub fn print_json<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string(value).unwrap_or_else(|_| "{}".into())
    );
}

pub fn fail_json(msg: &str) {
    println!("{}", serde_json::json!({ "error": msg }));
}
