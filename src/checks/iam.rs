use std::collections::BTreeSet;

use serde_json::Value;

use crate::checks::{join_path, scalar, strings};
use crate::model::{Action, Finding, FindingKind, Severity};
use crate::plan::{Plan, ResourceChange};

#[derive(Debug, Clone)]
struct Issue {
    fingerprint: String,
    severity: Severity,
    attribute: String,
    detail: String,
}

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

        let new = collect(change, change.change.after());
        if new.is_empty() {
            continue;
        }
        let old: BTreeSet<String> = collect(change, change.change.before())
            .into_iter()
            .map(|issue| issue.fingerprint)
            .collect();

        for issue in new {
            if old.contains(&issue.fingerprint) {
                continue;
            }
            out.push(
                Finding::resource(
                    FindingKind::IamPolicy,
                    issue.severity,
                    &change.address,
                    change.type_name(),
                    change.action(),
                    issue.detail,
                )
                .attribute(issue.attribute),
            );
        }
    }
}

fn collect(change: &ResourceChange, value: Option<&Value>) -> Vec<Issue> {
    let Some(value) = value else {
        return Vec::new();
    };
    let mut issues = Vec::new();
    if is_gcp_iam(change.type_name()) {
        collect_gcp(change.type_name(), value, &mut issues);
    }
    collect_policy_documents(value, "", &mut issues);
    issues
}

fn is_gcp_iam(type_name: &str) -> bool {
    type_name.ends_with("_iam_binding")
        || type_name.ends_with("_iam_member")
        || type_name.ends_with("_iam_policy")
}

fn collect_gcp(type_name: &str, value: &Value, issues: &mut Vec<Issue>) {
    if type_name.ends_with("_iam_policy") {
        if let Some(policy) = value.get("policy_data").and_then(parse_document) {
            if let Some(bindings) = policy.get("bindings").and_then(Value::as_array) {
                for binding in bindings {
                    inspect_gcp_binding(binding, "policy_data", issues);
                }
            }
        }
        return;
    }

    let role = value
        .get("role")
        .and_then(scalar)
        .unwrap_or_else(|| "a role".to_owned());
    let mut members = strings(value.get("members"));
    if let Some(member) = value.get("member").and_then(scalar) {
        members.push(member);
    }
    let attribute = if value.get("member").is_some() {
        "member"
    } else {
        "members"
    };
    for member in members {
        push_gcp_issue(&role, &member, attribute, issues);
    }
}

fn inspect_gcp_binding(binding: &Value, attribute: &str, issues: &mut Vec<Issue>) {
    let role = binding
        .get("role")
        .and_then(scalar)
        .unwrap_or_else(|| "a role".to_owned());
    for member in strings(binding.get("members")) {
        push_gcp_issue(&role, &member, attribute, issues);
    }
}

fn push_gcp_issue(role: &str, member: &str, attribute: &str, issues: &mut Vec<Issue>) {
    let public = matches!(member, "allUsers" | "allAuthenticatedUsers");
    let (severity, detail) = if public {
        (
            Severity::Critical,
            format!("grants {role} to {member}; anyone on the internet can use it"),
        )
    } else if role == "roles/owner" {
        (
            Severity::Error,
            "grants roles/owner, which includes full control of the project".to_owned(),
        )
    } else if role == "roles/editor" {
        (
            Severity::Warning,
            "grants roles/editor, which can change most resources in the project".to_owned(),
        )
    } else {
        return;
    };
    issues.push(Issue {
        fingerprint: format!("gcp|{role}|{member}"),
        severity,
        attribute: attribute.to_owned(),
        detail,
    });
}

fn collect_policy_documents(value: &Value, base: &str, issues: &mut Vec<Issue>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let path = join_path(base, key);
                let lower = key.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "policy"
                        | "assume_role_policy"
                        | "access_policies"
                        | "policy_document"
                        | "policy_json"
                ) {
                    if let Some(document) = parse_document(value) {
                        inspect_document(&document, &path, issues);
                    }
                }
                collect_policy_documents(value, &path, issues);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_policy_documents(item, &format!("{base}[{index}]"), issues);
            }
        }
        _ => {}
    }
}

fn parse_document(value: &Value) -> Option<Value> {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
                return None;
            }
            serde_json::from_str(trimmed).ok()
        }
        Value::Object(_) | Value::Array(_) => Some(value.clone()),
        _ => None,
    }
}

fn inspect_document(document: &Value, attribute: &str, issues: &mut Vec<Issue>) {
    let Some(statements) = document.get("Statement") else {
        return;
    };
    match statements {
        Value::Array(statements) => {
            for statement in statements {
                inspect_statement(statement, attribute, issues);
            }
        }
        Value::Object(_) => inspect_statement(statements, attribute, issues),
        _ => {}
    }
}

fn inspect_statement(statement: &Value, attribute: &str, issues: &mut Vec<Issue>) {
    if !statement
        .get("Effect")
        .and_then(Value::as_str)
        .is_some_and(|effect| effect.eq_ignore_ascii_case("allow"))
    {
        return;
    }

    let condition = statement
        .get("Condition")
        .is_some_and(|condition| !condition.is_null());
    let canonical = serde_json::to_string(statement).unwrap_or_default();

    if let Some(principal) = statement.get("Principal") {
        if principal_is_public(principal) {
            let severity = if condition {
                Severity::Error
            } else {
                Severity::Critical
            };
            let mut detail = "policy allows a public principal".to_owned();
            if condition {
                detail.push_str(" under a condition");
            }
            issues.push(Issue {
                fingerprint: format!("principal|{canonical}"),
                severity,
                attribute: attribute.to_owned(),
                detail,
            });
        }
    }

    let actions = string_values(statement.get("Action"));
    let star = actions.iter().any(|action| action == "*");
    let service = actions
        .iter()
        .find(|action| action.ends_with(":*"))
        .cloned();
    if !star && service.is_none() {
        return;
    }

    let resource_any = resource_is_any(statement.get("Resource"));
    let (severity, detail) = if star {
        match (resource_any, condition) {
            (true, false) => (
                Severity::Critical,
                "policy allows Action \"*\" on every resource".to_owned(),
            ),
            (true, true) => (
                Severity::Error,
                "policy allows Action \"*\" on every resource under a condition".to_owned(),
            ),
            (false, false) => (
                Severity::Error,
                "policy allows Action \"*\" on the scoped resources".to_owned(),
            ),
            (false, true) => (
                Severity::Warning,
                "policy allows Action \"*\" on the scoped resources under a condition".to_owned(),
            ),
        }
    } else {
        let action = service.unwrap_or_default();
        match (resource_any, condition) {
            (true, false) => (
                Severity::Error,
                format!("policy allows {action} on every resource"),
            ),
            (true, true) => (
                Severity::Warning,
                format!("policy allows {action} on every resource under a condition"),
            ),
            (false, false) => (
                Severity::Warning,
                format!("policy allows {action} on the scoped resources"),
            ),
            (false, true) => (
                Severity::Info,
                format!("policy allows {action} on the scoped resources under a condition"),
            ),
        }
    };

    issues.push(Issue {
        fingerprint: format!("wildcard|{canonical}"),
        severity,
        attribute: attribute.to_owned(),
        detail,
    });
}

fn string_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(value)) => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn resource_is_any(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(value)) => value == "*",
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some("*")),
        _ => false,
    }
}

fn principal_is_public(value: &Value) -> bool {
    match value {
        Value::String(value) => value == "*",
        Value::Array(items) => items.iter().any(principal_is_public),
        Value::Object(map) => map.values().any(principal_is_public),
        _ => false,
    }
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

    fn iam_findings(plan: &Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        check(plan, &mut findings);
        findings
    }

    fn aws_policy(actions: Value, resource: Value) -> Value {
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": actions,
                "Resource": resource
            }]
        });
        json!({
            "address": "aws_iam_policy.deploy",
            "mode": "managed",
            "type": "aws_iam_policy",
            "change": {
                "actions": ["create"],
                "after": {"name": "deploy", "policy": policy.to_string()}
            }
        })
    }

    #[test]
    fn wildcard_action_on_every_resource_is_critical() {
        let plan = plan_with(aws_policy(json!("*"), json!("*")));
        let findings = iam_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].kind, FindingKind::IamPolicy);
        assert_eq!(findings[0].attribute.as_deref(), Some("policy"));
    }

    #[test]
    fn wildcard_action_on_scoped_resources_is_an_error() {
        let plan = plan_with(aws_policy(json!("*"), json!("arn:aws:s3:::logs/*")));
        let findings = iam_findings(&plan);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn service_wildcard_is_detected() {
        let plan = plan_with(aws_policy(json!("s3:*"), json!("*")));
        let findings = iam_findings(&plan);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].detail.contains("s3:*"));
    }

    #[test]
    fn conditions_downgrade_the_severity() {
        let policy = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}
            }]
        });
        let plan = plan_with(json!({
            "address": "aws_iam_policy.deploy",
            "mode": "managed",
            "type": "aws_iam_policy",
            "change": {
                "actions": ["create"],
                "after": {"policy": policy.to_string()}
            }
        }));
        let findings = iam_findings(&plan);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].detail.contains("condition"));
    }

    #[test]
    fn public_bucket_principal_is_critical() {
        let policy = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::assets/*"
            }]
        });
        let plan = plan_with(json!({
            "address": "aws_s3_bucket_policy.assets",
            "mode": "managed",
            "type": "aws_s3_bucket_policy",
            "change": {
                "actions": ["create"],
                "after": {"bucket": "assets", "policy": policy.to_string()}
            }
        }));
        let findings = iam_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].detail.contains("public principal"));
    }

    #[test]
    fn safe_policy_is_ignored() {
        let plan = plan_with(aws_policy(
            json!(["s3:GetObject", "s3:ListBucket"]),
            json!("arn:aws:s3:::assets/*"),
        ));
        assert!(iam_findings(&plan).is_empty());
    }

    #[test]
    fn unchanged_policy_is_not_reported_on_update() {
        let policy = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        })
        .to_string();
        let plan = plan_with(json!({
            "address": "aws_iam_policy.deploy",
            "mode": "managed",
            "type": "aws_iam_policy",
            "change": {
                "actions": ["update"],
                "before": {"policy": policy.clone()},
                "after": {"policy": policy}
            }
        }));
        assert!(iam_findings(&plan).is_empty());
    }

    #[test]
    fn inline_role_policies_are_scanned_with_their_path() {
        let policy = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        });
        let plan = plan_with(json!({
            "address": "aws_iam_role.deploy",
            "mode": "managed",
            "type": "aws_iam_role",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "deploy",
                    "assume_role_policy": "{\"Statement\":[]}",
                    "inline_policy": [{"name": "admin", "policy": policy.to_string()}]
                }
            }
        }));
        let findings = iam_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].attribute.as_deref(),
            Some("inline_policy[0].policy")
        );
    }

    #[test]
    fn gcp_public_and_owner_bindings_are_reported() {
        let plan = plan_with(json!({
            "address": "google_project_iam_binding.public",
            "mode": "managed",
            "type": "google_project_iam_binding",
            "change": {
                "actions": ["create"],
                "after": {
                    "role": "roles/viewer",
                    "members": ["allUsers"]
                }
            }
        }));
        let findings = iam_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);

        let owner = plan_with(json!({
            "address": "google_project_iam_member.owner",
            "mode": "managed",
            "type": "google_project_iam_member",
            "change": {
                "actions": ["create"],
                "after": {
                    "role": "roles/owner",
                    "member": "user:dev@example.com"
                }
            }
        }));
        let findings = iam_findings(&owner);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].attribute.as_deref(), Some("member"));
    }
}
