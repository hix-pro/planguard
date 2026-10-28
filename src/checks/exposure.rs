use serde_json::Value;

use crate::checks::{after_attr, before_attr, bool_at, str_at};
use crate::model::{Action, Finding, FindingKind, Severity};
use crate::plan::{Plan, ResourceChange};

const PUBLIC_ACCESS_BLOCK_FLAGS: &[&str] = &[
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
];

const PUBLIC_DATABASES: &[&str] = &["aws_db_instance", "aws_mq_broker", "aws_redshift_cluster"];

pub fn check(plan: &Plan, out: &mut Vec<Finding>) {
    for change in &plan.changes {
        if !change.is_managed() {
            continue;
        }

        match change.action() {
            Action::Create | Action::Update | Action::Replace => {
                check_public_acl(change, out);
                check_public_access_block(change, out);
                check_public_database(change, out);
                check_encryption(change, out);
                check_google_bucket(change, out);
                check_azure_storage(change, out);
            }
            Action::Delete if change.type_name() == "aws_s3_bucket_public_access_block" => {
                out.push(
                    Finding::resource(
                        FindingKind::PublicAccess,
                        Severity::Error,
                        &change.address,
                        change.type_name(),
                        change.action(),
                        "the public access block is being removed; public bucket policies and ACLs are no longer blocked",
                    )
                    .attribute("public_access_block"),
                );
            }
            _ => {}
        }
    }
}

fn check_public_acl(change: &ResourceChange, out: &mut Vec<Finding>) {
    if !matches!(change.type_name(), "aws_s3_bucket" | "aws_s3_bucket_acl") {
        return;
    }
    let before = str_at(change.change.before(), "acl");
    let after = str_at(change.change.after(), "acl");
    if is_public_acl(after.as_deref()) && !is_public_acl(before.as_deref()) {
        let acl = after.unwrap_or_default();
        out.push(
            Finding::resource(
                FindingKind::PublicAccess,
                Severity::Critical,
                &change.address,
                change.type_name(),
                change.action(),
                format!("bucket ACL is {acl}; anyone can read or write objects in the bucket"),
            )
            .attribute("acl"),
        );
    }
}

fn is_public_acl(acl: Option<&str>) -> bool {
    matches!(acl, Some("public-read" | "public-read-write"))
}

fn check_public_access_block(change: &ResourceChange, out: &mut Vec<Finding>) {
    if change.type_name() != "aws_s3_bucket_public_access_block" {
        return;
    }

    if change.action() == Action::Create {
        let disabled: Vec<&str> = PUBLIC_ACCESS_BLOCK_FLAGS
            .iter()
            .copied()
            .filter(|flag| bool_at(change.change.after(), flag) == Some(false))
            .collect();
        if !disabled.is_empty() {
            out.push(
                Finding::resource(
                    FindingKind::PublicAccess,
                    Severity::Warning,
                    &change.address,
                    change.type_name(),
                    change.action(),
                    format!(
                        "new public access block leaves {} disabled",
                        disabled.join(", ")
                    ),
                )
                .attribute("public_access_block"),
            );
        }
        return;
    }

    let disabled: Vec<&str> = PUBLIC_ACCESS_BLOCK_FLAGS
        .iter()
        .copied()
        .filter(|flag| {
            bool_at(change.change.before(), flag) == Some(true)
                && bool_at(change.change.after(), flag) != Some(true)
        })
        .collect();
    if !disabled.is_empty() {
        out.push(
            Finding::resource(
                FindingKind::PublicAccess,
                Severity::Error,
                &change.address,
                change.type_name(),
                change.action(),
                format!(
                    "public access protection is being disabled ({})",
                    disabled.join(", ")
                ),
            )
            .attribute("public_access_block"),
        );
    }
}

fn check_public_database(change: &ResourceChange, out: &mut Vec<Finding>) {
    if !PUBLIC_DATABASES.contains(&change.type_name()) {
        return;
    }
    let before = before_attr(change, "publicly_accessible").and_then(Value::as_bool);
    let after = after_attr(change, "publicly_accessible").and_then(Value::as_bool);
    if after == Some(true) && before != Some(true) {
        out.push(
            Finding::resource(
                FindingKind::PublicAccess,
                Severity::Critical,
                &change.address,
                change.type_name(),
                change.action(),
                "publicly_accessible is enabled; the database accepts connections from the internet",
            )
            .attribute("publicly_accessible"),
        );
    }
}

fn check_encryption(change: &ResourceChange, out: &mut Vec<Finding>) {
    let encryption: Option<(&str, &str)> = match change.type_name() {
        "aws_db_instance" => Some((
            "storage_encrypted",
            "database storage encryption is disabled",
        )),
        "aws_ebs_volume" => Some(("encrypted", "volume encryption is disabled")),
        "aws_efs_file_system" => Some(("encrypted", "file system encryption is disabled")),
        "aws_redshift_cluster" => Some(("encrypted", "cluster encryption is disabled")),
        _ => None,
    };

    if let Some((attribute, detail)) = encryption {
        let before = before_attr(change, attribute).and_then(Value::as_bool);
        let after = after_attr(change, attribute).and_then(Value::as_bool);
        if after == Some(false) && before != Some(false) {
            out.push(
                Finding::resource(
                    FindingKind::Encryption,
                    Severity::Error,
                    &change.address,
                    change.type_name(),
                    change.action(),
                    detail,
                )
                .attribute(attribute),
            );
        }
    }

    if change.type_name() == "aws_elasticache_replication_group" {
        for (attribute, severity, detail) in [
            (
                "at_rest_encryption_enabled",
                Severity::Error,
                "at-rest encryption is disabled",
            ),
            (
                "transit_encryption_enabled",
                Severity::Warning,
                "in-transit encryption is disabled",
            ),
        ] {
            let before = before_attr(change, attribute).and_then(Value::as_bool);
            let after = after_attr(change, attribute).and_then(Value::as_bool);
            if after == Some(false) && before != Some(false) {
                out.push(
                    Finding::resource(
                        FindingKind::Encryption,
                        severity,
                        &change.address,
                        change.type_name(),
                        change.action(),
                        detail,
                    )
                    .attribute(attribute),
                );
            }
        }
    }
}

fn check_google_bucket(change: &ResourceChange, out: &mut Vec<Finding>) {
    if change.type_name() != "google_storage_bucket" {
        return;
    }
    let before = str_at(change.change.before(), "public_access_prevention");
    let after = str_at(change.change.after(), "public_access_prevention");
    if before.as_deref() == Some("enforced") && after.as_deref() != Some("enforced") {
        out.push(
            Finding::resource(
                FindingKind::PublicAccess,
                Severity::Error,
                &change.address,
                change.type_name(),
                change.action(),
                "public access prevention is no longer enforced on the bucket",
            )
            .attribute("public_access_prevention"),
        );
    }
}

fn check_azure_storage(change: &ResourceChange, out: &mut Vec<Finding>) {
    if change.type_name() == "azurerm_storage_account" {
        for (attribute, label) in [
            (
                "allow_nested_items_to_be_public",
                "nested items can now be made public",
            ),
            (
                "public_network_access_enabled",
                "public network access is now enabled",
            ),
        ] {
            let before = before_attr(change, attribute).and_then(Value::as_bool);
            let after = after_attr(change, attribute).and_then(Value::as_bool);
            if before == Some(false) && after == Some(true) {
                out.push(
                    Finding::resource(
                        FindingKind::PublicAccess,
                        Severity::Warning,
                        &change.address,
                        change.type_name(),
                        change.action(),
                        label,
                    )
                    .attribute(attribute),
                );
            }
        }
    }

    if change.type_name() == "azurerm_storage_container" {
        let before = str_at(change.change.before(), "container_access_type");
        let after = str_at(change.change.after(), "container_access_type");
        let public = matches!(after.as_deref(), Some("blob" | "container"));
        let was_public = matches!(before.as_deref(), Some("blob" | "container"));
        if public && !was_public {
            let access = after.unwrap_or_default();
            out.push(
                Finding::resource(
                    FindingKind::PublicAccess,
                    Severity::Critical,
                    &change.address,
                    change.type_name(),
                    change.action(),
                    format!("container access is {access}; blobs are publicly readable"),
                )
                .attribute("container_access_type"),
            );
        }
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

    fn exposure_findings(plan: &Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        check(plan, &mut findings);
        findings
    }

    #[test]
    fn public_bucket_acl_is_critical() {
        let plan = plan_with(json!({
            "address": "aws_s3_bucket_acl.assets",
            "mode": "managed",
            "type": "aws_s3_bucket_acl",
            "change": {
                "actions": ["create"],
                "after": {"bucket": "assets", "acl": "public-read"}
            }
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].kind, FindingKind::PublicAccess);
    }

    #[test]
    fn existing_public_acl_is_not_reported_again() {
        let plan = plan_with(json!({
            "address": "aws_s3_bucket_acl.assets",
            "mode": "managed",
            "type": "aws_s3_bucket_acl",
            "change": {
                "actions": ["update"],
                "before": {"acl": "public-read"},
                "after": {"acl": "public-read"}
            }
        }));

        assert!(exposure_findings(&plan).is_empty());
    }

    #[test]
    fn disabling_public_access_block_flags_every_disabled_flag() {
        let plan = plan_with(json!({
            "address": "aws_s3_bucket_public_access_block.logs",
            "mode": "managed",
            "type": "aws_s3_bucket_public_access_block",
            "change": {
                "actions": ["update"],
                "before": {
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "ignore_public_acls": true,
                    "restrict_public_buckets": true
                },
                "after": {
                    "block_public_acls": false,
                    "block_public_policy": false,
                    "ignore_public_acls": true,
                    "restrict_public_buckets": true
                }
            }
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].detail.contains("block_public_acls"));
        assert!(findings[0].detail.contains("block_public_policy"));
    }

    #[test]
    fn deleting_the_public_access_block_is_an_error() {
        let plan = plan_with(json!({
            "address": "aws_s3_bucket_public_access_block.logs",
            "mode": "managed",
            "type": "aws_s3_bucket_public_access_block",
            "change": {"actions": ["delete"], "before": {"block_public_acls": true}}
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn public_database_is_critical() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.analytics",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["create"],
                "after": {"publicly_accessible": true, "storage_encrypted": true}
            }
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::PublicAccess);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn disabled_encryption_is_an_error() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.analytics",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["create"],
                "after": {"publicly_accessible": false, "storage_encrypted": false}
            }
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::Encryption);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn encryption_that_was_already_off_is_not_reported_again() {
        let plan = plan_with(json!({
            "address": "aws_ebs_volume.data",
            "mode": "managed",
            "type": "aws_ebs_volume",
            "change": {
                "actions": ["update"],
                "before": {"encrypted": false},
                "after": {"encrypted": false, "size": 20}
            }
        }));

        assert!(exposure_findings(&plan).is_empty());
    }

    #[test]
    fn elasticache_reports_at_rest_and_transit_encryption() {
        let plan = plan_with(json!({
            "address": "aws_elasticache_replication_group.cache",
            "mode": "managed",
            "type": "aws_elasticache_replication_group",
            "change": {
                "actions": ["create"],
                "after": {
                    "at_rest_encryption_enabled": false,
                    "transit_encryption_enabled": false
                }
            }
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[1].severity, Severity::Warning);
    }

    #[test]
    fn google_public_access_prevention_removal_is_an_error() {
        let plan = plan_with(json!({
            "address": "google_storage_bucket.assets",
            "mode": "managed",
            "type": "google_storage_bucket",
            "change": {
                "actions": ["update"],
                "before": {"public_access_prevention": "enforced"},
                "after": {"public_access_prevention": "inherited"}
            }
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn azure_nested_public_access_transition_is_a_warning() {
        let plan = plan_with(json!({
            "address": "azurerm_storage_account.assets",
            "mode": "managed",
            "type": "azurerm_storage_account",
            "change": {
                "actions": ["update"],
                "before": {"allow_nested_items_to_be_public": false},
                "after": {"allow_nested_items_to_be_public": true}
            }
        }));

        let findings = exposure_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn safe_encrypted_resources_are_ignored() {
        let plan = plan_with(json!({
            "address": "aws_db_instance.main",
            "mode": "managed",
            "type": "aws_db_instance",
            "change": {
                "actions": ["create"],
                "after": {
                    "publicly_accessible": false,
                    "storage_encrypted": true,
                    "deletion_protection": true
                }
            }
        }));

        assert!(exposure_findings(&plan).is_empty());
    }
}
