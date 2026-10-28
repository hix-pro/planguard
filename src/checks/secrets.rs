use std::collections::BTreeMap;

use serde_json::Value;

use crate::checks::join_path;
use crate::model::{Action, Finding, FindingKind, Severity};
use crate::plan::Plan;

pub fn check(plan: &Plan, out: &mut Vec<Finding>) {
    for change in &plan.changes {
        if !change.is_managed()
            || !matches!(
                change.action(),
                Action::Create | Action::Update | Action::Replace
            )
        {
            continue;
        }

        let mut after = BTreeMap::new();
        walk(change.change.after(), "", &mut after);
        if after.is_empty() {
            continue;
        }

        let mut before = BTreeMap::new();
        walk(change.change.before(), "", &mut before);

        for (path, value) in after {
            if before.get(&path) == Some(&value) {
                continue;
            }
            out.push(
                Finding::resource(
                    FindingKind::Secret,
                    Severity::Info,
                    &change.address,
                    change.type_name(),
                    change.action(),
                    "the plan contains this value in plaintext; treat the plan file as a secret",
                )
                .attribute(path),
            );
        }
    }
}

fn walk(value: Option<&Value>, base: &str, secrets: &mut BTreeMap<String, String>) {
    match value {
        Some(Value::Object(map)) => {
            for (key, value) in map {
                let path = join_path(base, key);
                if is_secret_key(key) {
                    if let Some(text) = value.as_str() {
                        if looks_like_plaintext(text) {
                            secrets.insert(path.clone(), text.to_owned());
                        }
                    }
                }
                walk(Some(value), &path, secrets);
            }
        }
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                walk(Some(item), &format!("{base}[{index}]"), secrets);
            }
        }
        _ => {}
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();

    const NOT_SECRET_SUFFIXES: &[&str] = &[
        "_algorithm",
        "_arn",
        "_count",
        "_enabled",
        "_expiration",
        "_expires",
        "_file",
        "_filename",
        "_fingerprint",
        "_format",
        "_hash",
        "_id",
        "_ids",
        "_length",
        "_mode",
        "_name",
        "_names",
        "_path",
        "_policies",
        "_policy",
        "_prefix",
        "_ref",
        "_reference",
        "_required",
        "_source",
        "_suffix",
        "_template",
        "_ttl",
        "_type",
        "_uri",
        "_url",
        "_version",
    ];
    if NOT_SECRET_SUFFIXES
        .iter()
        .any(|suffix| key.ends_with(suffix))
    {
        return false;
    }
    if matches!(
        key.as_str(),
        "password_policy" | "secret_name" | "secret_id"
    ) {
        return false;
    }

    if matches!(key.as_str(), "secret_string" | "secret_binary") {
        return true;
    }

    const SECRET_KEYS: &[&str] = &[
        "access_key",
        "admin_password",
        "api_key",
        "apikey",
        "auth_token",
        "bearer_token",
        "client_secret",
        "connection_string",
        "credentials",
        "db_password",
        "master_password",
        "passwd",
        "password",
        "private_key",
        "sas_token",
        "secret",
        "secret_key",
        "token",
    ];
    if SECRET_KEYS.contains(&key.as_str()) {
        return true;
    }

    const SECRET_SUFFIXES: &[&str] = &[
        "access_key",
        "api_key",
        "apikey",
        "client_secret",
        "connection_string",
        "passwd",
        "password",
        "private_key",
        "secret",
        "token",
    ];
    SECRET_SUFFIXES
        .iter()
        .any(|suffix| key.ends_with(&format!("_{suffix}")))
}

fn looks_like_plaintext(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if value == "(sensitive value)" || value == "(known after apply)" {
        return false;
    }
    if value.eq_ignore_ascii_case("redacted") {
        return false;
    }
    if value.starts_with("${") || value.starts_with('<') {
        return false;
    }
    if value.chars().all(|character| character == '*') {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan_with(change: Value) -> Plan {
        let document = json!({
            "format_version": "1.2",
            "resource_changes": [change]
        });
        crate::plan::parse(&document.to_string(), "plan.json").unwrap()
    }

    fn secret_findings(plan: &Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        check(plan, &mut findings);
        findings
    }

    #[test]
    fn newly_created_password_is_an_info_finding() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.main",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["create"],
                "after": {"username": "app", "password": "correct horse battery staple"}
            }
        }));

        let findings = secret_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::Secret);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].attribute.as_deref(), Some("password"));
        assert!(!findings[0].detail.contains("correct horse"));
    }

    #[test]
    fn unchanged_password_is_not_reported_again() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.main",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["update"],
                "before": {"password": "same"},
                "after": {"password": "same", "engine_version": "16.4"}
            }
        }));

        assert!(secret_findings(&plan).is_empty());
    }

    #[test]
    fn changed_password_is_reported() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.main",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["update"],
                "before": {"password": "old"},
                "after": {"password": "new"}
            }
        }));

        assert_eq!(secret_findings(&plan).len(), 1);
    }

    #[test]
    fn references_and_redacted_values_are_ignored() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.main",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["create"],
                "after": {
                    "password": "${var.password}",
                    "secret": "(sensitive value)",
                    "token": "********"
                }
            }
        }));

        assert!(secret_findings(&plan).is_empty());
    }

    #[test]
    fn metadata_keys_are_not_mistaken_for_secrets() {
        let plan = plan_with(json!({
            "address": "aws_secretsmanager_secret.main",
            "mode": "managed",
            "type": "aws_secretsmanager_secret",
            "change": {
                "actions": ["create"],
                "after": {
                    "secret_arn": "arn:aws:secretsmanager:...",
                    "secret_id": "secret-id",
                    "private_key_id": "key-id",
                    "token_url": "https://example.com/token",
                    "encryption_algorithm": "AES256"
                }
            }
        }));

        assert!(secret_findings(&plan).is_empty());
    }

    #[test]
    fn nested_secret_paths_are_reported() {
        let plan = plan_with(json!({
            "address": "azurerm_windows_web_app.main",
            "mode": "managed",
            "type": "azurerm_windows_web_app",
            "change": {
                "actions": ["create"],
                "after": {
                    "site_config": [{
                        "app_settings": {
                            "DB_PASSWORD": "hunter2"
                        }
                    }]
                }
            }
        }));

        let findings = secret_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].attribute.as_deref(),
            Some("site_config[0].app_settings.DB_PASSWORD")
        );
    }

    #[test]
    fn deleted_resources_are_not_scanned() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.main",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["delete"],
                "before": {"password": "secret"},
                "after": null
            }
        }));

        assert!(secret_findings(&plan).is_empty());
    }

    #[test]
    fn secret_string_is_detected() {
        let plan = plan_with(json!({
            "address": "aws_secretsmanager_secret_version.main",
            "mode": "managed",
            "type": "aws_secretsmanager_secret_version",
            "change": {
                "actions": ["create"],
                "after": {"secret_string": "{\"api_key\":\"abc\"}"}
            }
        }));

        let findings = secret_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attribute.as_deref(), Some("secret_string"));
    }
}
