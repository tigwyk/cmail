use serde_json::Value;

/// Deterministic serialization for signing: keys sorted recursively,
/// no insignificant whitespace, minimal string escaping, integers only
/// (the envelope contains no floats). serde_json's Map is BTreeMap-backed
/// unless `preserve_order` is enabled — this workspace never enables it —
/// so `to_string` of a `Value` is already canonical for our types.
pub fn canonical_json(value: &Value) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_matter() {
        let a = json!({"z": "1", "a": {"y": 2, "b": [1, 2]}});
        let b = json!({"a": {"b": [1, 2], "y": 2}, "z": "1"});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(canonical_json(&a), r#"{"a":{"b":[1,2],"y":2},"z":"1"}"#);
    }

    #[test]
    fn round_trips_through_value() {
        let v = json!({"subject": "hi\nthere", "n": 7});
        let s = canonical_json(&v);
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(canonical_json(&back), s);
    }

    #[test]
    fn unicode_survives_deterministically() {
        let v = json!({"body": "héllo — ✅"});
        let s1 = canonical_json(&v);
        let s2 = canonical_json(&serde_json::from_str::<Value>(&s1).unwrap());
        assert_eq!(s1, s2);
    }
}
