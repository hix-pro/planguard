pub mod exposure;
pub mod iam;
pub mod lifecycle;
pub mod network;
pub mod secrets;

use serde_json::Value;

use crate::model::Finding;
use crate::plan::{Plan, ResourceChange};

/// Runs every check and returns findings in a deterministic order.
pub fn run(plan: &Plan) -> Vec<Finding> {
    let mut findings = Vec::new();
    lifecycle::check(plan, &mut findings);
    network::check(plan, &mut findings);
    iam::check(plan, &mut findings);
    exposure::check(plan, &mut findings);
    secrets::check(plan, &mut findings);

    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then(left.kind.cmp(&right.kind))
            .then(left.target().cmp(right.target()))
            .then(left.attribute.cmp(&right.attribute))
            .then(left.detail.cmp(&right.detail))
    });
    findings
}

pub fn before_attr<'a>(change: &'a ResourceChange, key: &str) -> Option<&'a Value> {
    change.change.before().and_then(|value| value.get(key))
}

pub fn after_attr<'a>(change: &'a ResourceChange, key: &str) -> Option<&'a Value> {
    change.change.after().and_then(|value| value.get(key))
}

pub fn object_at<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    value.and_then(|value| value.get(key))
}

pub fn bool_at(value: Option<&Value>, key: &str) -> Option<bool> {
    value
        .and_then(|value| value.get(key))
        .and_then(Value::as_bool)
}

pub fn str_at(value: Option<&Value>, key: &str) -> Option<String> {
    value.and_then(|value| value.get(key)).and_then(scalar)
}

pub fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(scalar).collect(),
        Some(Value::String(value)) => vec![value.clone()],
        _ => Vec::new(),
    }
}

pub fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub fn as_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
    })
}

pub fn is_open_source(source: &str) -> bool {
    matches!(
        source.trim().to_ascii_lowercase().as_str(),
        "0.0.0.0/0" | "::/0" | "*" | "any" | "internet"
    )
}

/// Joins an attribute path for reports, e.g. `inline_policy[0].policy`.
pub fn join_path(base: &str, key: &str) -> String {
    if base.is_empty() {
        key.to_owned()
    } else {
        format!("{base}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn open_sources_cover_ipv4_ipv6_and_any() {
        assert!(is_open_source("0.0.0.0/0"));
        assert!(is_open_source("::/0"));
        assert!(is_open_source("*"));
        assert!(is_open_source("Internet"));
        assert!(!is_open_source("10.0.0.0/8"));
        assert!(!is_open_source(""));
    }

    #[test]
    fn scalars_and_lists_are_normalized() {
        assert_eq!(scalar(&json!(443)), Some("443".to_owned()));
        assert_eq!(scalar(&json!(true)), Some("true".to_owned()));
        assert_eq!(
            strings(Some(&json!(["0.0.0.0/0", "::/0"]))),
            vec!["0.0.0.0/0", "::/0"]
        );
        assert_eq!(strings(Some(&json!("10.0.0.0/8"))), vec!["10.0.0.0/8"]);
        assert!(strings(None).is_empty());
    }

    #[test]
    fn integers_accept_strings_from_providers() {
        assert_eq!(as_i64(Some(&json!(22))), Some(22));
        assert_eq!(as_i64(Some(&json!("22"))), Some(22));
        assert_eq!(as_i64(Some(&json!("twenty-two"))), None);
    }

    #[test]
    fn paths_join_without_a_leading_dot() {
        assert_eq!(join_path("", "policy"), "policy");
        assert_eq!(
            join_path("inline_policy[0]", "policy"),
            "inline_policy[0].policy"
        );
    }
}
