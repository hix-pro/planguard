use serde_json::Value;

use crate::checks::{after_attr, before_attr};
use crate::model::{Action, Finding, FindingKind, Severity};
use crate::plan::{Plan, ResourceChange};

pub fn check(plan: &Plan, out: &mut Vec<Finding>) {
    if plan.info.errored == Some(true) {
        out.push(Finding::plan(
            FindingKind::PlanErrored,
            Severity::Critical,
            "the plan reports an error; do not apply it without investigating the failure",
        ));
    }
    if plan.info.complete == Some(false) {
        out.push(Finding::plan(
            FindingKind::PlanIncomplete,
            Severity::Warning,
            "the plan is incomplete; Terraform expects at least one more plan/apply round",
        ));
    }

    for change in &plan.changes {
        if !change.is_managed() {
            continue;
        }

        match change.action() {
            Action::Delete => push_destroy(change, out),
            Action::Replace => push_replace(change, out),
            _ => {}
        }

        check_deletion_protection(change, out);
    }

    for drift in &plan.drift {
        if !drift.is_managed() || !drift.action().changes_state() {
            continue;
        }
        let detail = format!(
            "changed outside Terraform ({}){}",
            drift.action().as_str(),
            reason_suffix(drift.action_reason.as_deref())
        );
        out.push(
            Finding::resource(
                FindingKind::Drift,
                Severity::Warning,
                &drift.address,
                drift.type_name(),
                drift.action(),
                detail,
            )
            .attribute("resource"),
        );
    }
}

fn push_destroy(change: &ResourceChange, out: &mut Vec<Finding>) {
    let stateful = is_stateful(change.type_name());
    let (severity, detail) = if stateful {
        (
            Severity::Critical,
            "deleting a stateful resource destroys data that this plan cannot recover".to_owned(),
        )
    } else {
        (Severity::Warning, "destroys this resource".to_owned())
    };
    let detail = append_context(detail, change, false);
    out.push(Finding::resource(
        FindingKind::Destroy,
        severity,
        &change.address,
        change.type_name(),
        change.action(),
        detail,
    ));
}

fn push_replace(change: &ResourceChange, out: &mut Vec<Finding>) {
    let stateful = is_stateful(change.type_name());
    let (severity, mut detail) = if stateful {
        (
            Severity::Error,
            "replaces a stateful resource; the old object and its data are destroyed".to_owned(),
        )
    } else {
        (
            Severity::Warning,
            "replaces this resource (delete and create)".to_owned(),
        )
    };
    if let Some(paths) = replace_paths_label(change) {
        detail.push_str(&format!(" (forced by {paths})"));
    } else {
        detail.push_str(&reason_suffix(change.action_reason.as_deref()));
    }
    if change.deposed.is_some() {
        detail.push_str(" (deposed object)");
    }
    out.push(
        Finding::resource(
            FindingKind::Replace,
            severity,
            &change.address,
            change.type_name(),
            change.action(),
            detail,
        )
        .attribute("lifecycle"),
    );
}

fn check_deletion_protection(change: &ResourceChange, out: &mut Vec<Finding>) {
    if change.action() == Action::Update {
        let attrs: &[&str] = match change.type_name() {
            "aws_dynamodb_table" => &["deletion_protection_enabled"],
            "aws_db_instance" | "aws_rds_cluster" | "google_sql_database_instance" => {
                &["deletion_protection"]
            }
            _ => &[],
        };
        for attribute in attrs {
            let before = before_attr(change, attribute).and_then(Value::as_bool);
            let after = after_attr(change, attribute).and_then(Value::as_bool);
            if before == Some(true) && after != Some(true) {
                out.push(
                    Finding::resource(
                        FindingKind::DeletionProtection,
                        Severity::Warning,
                        &change.address,
                        change.type_name(),
                        change.action(),
                        "deletion protection is being turned off; an accidental destroy will no longer be blocked",
                    )
                    .attribute(*attribute),
                );
            }
        }
    }

    if change.type_name() == "aws_s3_bucket" {
        let before = before_attr(change, "force_destroy").and_then(Value::as_bool);
        let after = after_attr(change, "force_destroy").and_then(Value::as_bool);
        if after == Some(true) && before != Some(true) {
            out.push(
                Finding::resource(
                    FindingKind::DeletionProtection,
                    Severity::Warning,
                    &change.address,
                    change.type_name(),
                    change.action(),
                    "force_destroy allows Terraform to delete the bucket and every object in it",
                )
                .attribute("force_destroy"),
            );
        }
    }
}

fn append_context(mut detail: String, change: &ResourceChange, include_paths: bool) -> String {
    if include_paths {
        if let Some(paths) = replace_paths_label(change) {
            detail.push_str(&format!(" (forced by {paths})"));
        }
    }
    detail.push_str(&reason_suffix(change.action_reason.as_deref()));
    if change.deposed.is_some() {
        detail.push_str(" (deposed object)");
    }
    detail
}

fn reason_suffix(reason: Option<&str>) -> String {
    let label = match reason {
        Some("replace_because_tainted") => "tainted",
        Some("replace_because_cannot_update") => "provider requires replacement",
        Some("replace_by_request") => "replacement requested",
        Some("delete_because_no_resource_config") => "removed from configuration",
        Some("delete_because_no_module") => "module removed",
        Some("delete_because_count_index") => "count shrank",
        Some("delete_because_each_key") => "for_each key removed",
        Some("delete_because_wrong_repetition") => "repetition mode changed",
        _ => return String::new(),
    };
    format!(" ({label})")
}

fn replace_paths_label(change: &ResourceChange) -> Option<String> {
    let paths: Vec<String> = change
        .change
        .replace_paths
        .iter()
        .filter_map(path_label)
        .take(3)
        .collect();
    if paths.is_empty() {
        None
    } else {
        Some(paths.join(", "))
    }
}

fn path_label(path: &Value) -> Option<String> {
    let steps = path.as_array()?;
    let mut label = String::new();
    for step in steps {
        match step {
            Value::String(name) => {
                if !label.is_empty() {
                    label.push('.');
                }
                label.push_str(name);
            }
            Value::Number(index) => {
                label.push('[');
                label.push_str(&index.to_string());
                label.push(']');
            }
            _ => {}
        }
    }
    if label.is_empty() { None } else { Some(label) }
}

/// Stateful resources keep data that outlives the Terraform object.
pub fn is_stateful(type_name: &str) -> bool {
    const STATEFUL: &[&str] = &[
        "aws_backup_vault",
        "aws_cloudwatch_log_group",
        "aws_db_instance",
        "aws_docdb_cluster",
        "aws_dynamodb_table",
        "aws_ebs_volume",
        "aws_efs_file_system",
        "aws_elasticache_cluster",
        "aws_elasticache_replication_group",
        "aws_fsx_windows_file_system",
        "aws_glacier_vault",
        "aws_kinesis_stream",
        "aws_kms_key",
        "aws_mq_broker",
        "aws_neptune_cluster",
        "aws_rds_cluster",
        "aws_redshift_cluster",
        "aws_s3_bucket",
        "aws_secretsmanager_secret",
        "aws_sns_topic",
        "aws_sqs_queue",
        "aws_ssm_parameter",
        "azurerm_cosmosdb_account",
        "azurerm_key_vault",
        "azurerm_key_vault_secret",
        "azurerm_managed_disk",
        "azurerm_mssql_database",
        "azurerm_mssql_server",
        "azurerm_mysql_flexible_server",
        "azurerm_mysql_server",
        "azurerm_postgresql_flexible_server",
        "azurerm_postgresql_server",
        "azurerm_storage_account",
        "docker_volume",
        "google_bigquery_dataset",
        "google_bigtable_instance",
        "google_firestore_database",
        "google_kms_crypto_key",
        "google_pubsub_topic",
        "google_spanner_instance",
        "google_sql_database",
        "google_sql_database_instance",
        "google_storage_bucket",
        "kubernetes_persistent_volume",
        "kubernetes_persistent_volume_claim",
        "kubernetes_secret",
    ];

    if STATEFUL.contains(&type_name) {
        return true;
    }

    if type_name.ends_with("_snapshot") || type_name.contains("persistent_volume") {
        return true;
    }
    if type_name.ends_with("_volume") && !type_name.ends_with("_volume_attachment") {
        return true;
    }
    if type_name.ends_with("_bucket") && !type_name.contains("bucket_") {
        return true;
    }
    if type_name.ends_with("_file_system") || type_name.ends_with("_filesystem") {
        return true;
    }
    if type_name.ends_with("_secret") && !type_name.ends_with("_secret_policy") {
        return true;
    }
    if type_name.ends_with("_secret_version") {
        return true;
    }
    if type_name.ends_with("_storage_account") {
        return true;
    }
    if type_name.ends_with("_db_instance")
        || type_name.ends_with("_rds_cluster")
        || type_name.ends_with("_dynamodb_table")
        || type_name.ends_with("_sql_database")
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan_with(resource_changes: Vec<Value>, resource_drift: Vec<Value>) -> Plan {
        let document = json!({
            "format_version": "1.2",
            "resource_changes": resource_changes,
            "resource_drift": resource_drift
        });
        crate::plan::parse(&document.to_string(), "plan.json").unwrap()
    }

    fn lifecycle_findings(plan: &Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        check(plan, &mut findings);
        findings
    }

    #[test]
    fn stateful_detection_covers_data_stores_and_skips_attachments() {
        assert!(is_stateful("aws_db_instance"));
        assert!(is_stateful("aws_s3_bucket"));
        assert!(is_stateful("google_storage_bucket"));
        assert!(is_stateful("azurerm_storage_account"));
        assert!(is_stateful("aws_ebs_volume"));
        assert!(is_stateful("aws_db_snapshot"));
        assert!(is_stateful("aws_secretsmanager_secret_version"));
        assert!(!is_stateful("aws_s3_bucket_policy"));
        assert!(!is_stateful("aws_ebs_volume_attachment"));
        assert!(!is_stateful("aws_instance"));
    }

    #[test]
    fn destroy_severity_depends_on_statefulness() {
        let plan = plan_with(
            vec![
                json!({
                    "address": "aws_db_instance.main",
                    "mode": "managed",
                    "type": "aws_db_instance",
                    "action_reason": "delete_because_no_resource_config",
                    "change": {"actions": ["delete"], "before": {"id": "db-1"}}
                }),
                json!({
                    "address": "aws_instance.web",
                    "mode": "managed",
                    "type": "aws_instance",
                    "change": {"actions": ["delete"], "before": {"id": "i-1"}}
                }),
            ],
            vec![],
        );

        let findings = lifecycle_findings(&plan);
        let database = findings
            .iter()
            .find(|finding| finding.target() == "aws_db_instance.main")
            .unwrap();
        let instance = findings
            .iter()
            .find(|finding| finding.target() == "aws_instance.web")
            .unwrap();

        assert_eq!(database.severity, Severity::Critical);
        assert_eq!(database.kind, FindingKind::Destroy);
        assert!(database.detail.contains("removed from configuration"));
        assert_eq!(instance.severity, Severity::Warning);
    }

    #[test]
    fn replace_includes_the_path_that_forced_it() {
        let plan = plan_with(
            vec![json!({
                "address": "aws_ebs_volume.data",
                "mode": "managed",
                "type": "aws_ebs_volume",
                "change": {
                    "actions": ["delete", "create"],
                    "replace_paths": [["availability_zone"], ["size"]],
                    "before": {"id": "vol-1"},
                    "after": {"id": null}
                }
            })],
            vec![],
        );

        let findings = lifecycle_findings(&plan);
        let replace = findings
            .iter()
            .find(|finding| finding.kind == FindingKind::Replace)
            .unwrap();
        assert_eq!(replace.severity, Severity::Error);
        assert!(replace.detail.contains("availability_zone, size"));
    }

    #[test]
    fn replacement_of_an_untracked_change_is_warning() {
        let plan = plan_with(
            vec![json!({
                "address": "aws_instance.web",
                "mode": "managed",
                "type": "aws_instance",
                "action_reason": "replace_because_tainted",
                "change": {"actions": ["delete", "create"]}
            })],
            vec![],
        );

        let findings = lifecycle_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].detail.contains("tainted"));
    }

    #[test]
    fn deletion_protection_removal_is_flagged_only_when_turned_off() {
        let plan = plan_with(
            vec![
                json!({
                    "address": "aws_db_instance.main",
                    "mode": "managed",
                    "type": "aws_db_instance",
                    "change": {
                        "actions": ["update"],
                        "before": {"deletion_protection": true},
                        "after": {"deletion_protection": false}
                    }
                }),
                json!({
                    "address": "aws_db_instance.other",
                    "mode": "managed",
                    "type": "aws_db_instance",
                    "change": {
                        "actions": ["update"],
                        "before": {"deletion_protection": false},
                        "after": {"deletion_protection": false}
                    }
                }),
            ],
            vec![],
        );

        let findings = lifecycle_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::DeletionProtection);
        assert_eq!(
            findings[0].attribute.as_deref(),
            Some("deletion_protection")
        );
    }

    #[test]
    fn force_destroy_is_flagged_when_enabled() {
        let plan = plan_with(
            vec![json!({
                "address": "aws_s3_bucket.logs",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["update"],
                    "before": {"force_destroy": false},
                    "after": {"force_destroy": true}
                }
            })],
            vec![],
        );

        let findings = lifecycle_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].detail.contains("force_destroy"));
    }

    #[test]
    fn drift_and_incomplete_plans_are_reported() {
        let document = json!({
            "format_version": "1.2",
            "complete": false,
            "resource_changes": [],
            "resource_drift": [{
                "address": "aws_security_group.legacy",
                "mode": "managed",
                "type": "aws_security_group",
                "change": {"actions": ["update"]}
            }]
        });
        let plan = crate::plan::parse(&document.to_string(), "plan.json").unwrap();

        let findings = lifecycle_findings(&plan);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == FindingKind::PlanIncomplete)
        );
        assert!(findings.iter().any(|f| {
            f.kind == FindingKind::Drift && f.target() == "aws_security_group.legacy"
        }));
    }

    #[test]
    fn no_op_resources_are_ignored() {
        let plan = plan_with(
            vec![json!({
                "address": "aws_instance.web",
                "mode": "managed",
                "type": "aws_instance",
                "change": {"actions": ["no-op"], "before": {"id": "i-1"}, "after": {"id": "i-1"}}
            })],
            vec![],
        );

        assert!(lifecycle_findings(&plan).is_empty());
    }
}
