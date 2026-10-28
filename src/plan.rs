use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::model::{Action, PlanInfo};

#[derive(Debug, Clone)]
pub struct Plan {
    pub info: PlanInfo,
    pub changes: Vec<ResourceChange>,
    pub drift: Vec<ResourceChange>,
}

impl Plan {
    pub fn change_counts(&self) -> crate::model::ChangeCounts {
        let mut counts = crate::model::ChangeCounts::default();
        for change in &self.changes {
            counts.add(change.change.action());
        }
        counts
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourceChange {
    pub address: String,
    #[serde(default)]
    pub previous_address: Option<String>,
    #[serde(default)]
    pub module_address: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(rename = "type", default)]
    pub resource_type: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub index: Option<Value>,
    #[serde(default)]
    pub deposed: Option<String>,
    #[serde(default)]
    pub provider_name: Option<String>,
    #[serde(default)]
    pub action_reason: Option<String>,
    #[serde(default)]
    pub change: Change,
}

impl ResourceChange {
    /// Data sources are read, not managed; they are not part of the risk review.
    pub fn is_managed(&self) -> bool {
        self.mode.as_deref() != Some("data")
    }

    /// Falls back to the address when an older plan omits the `type` field.
    pub fn type_name(&self) -> &str {
        if self.resource_type.is_empty() {
            self.address
                .rsplit('.')
                .nth(1)
                .unwrap_or(self.address.as_str())
        } else {
            &self.resource_type
        }
    }

    pub fn action(&self) -> Action {
        self.change.action()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Change {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub before: Option<Value>,
    #[serde(default)]
    pub after: Option<Value>,
    #[serde(default)]
    pub after_unknown: Option<Value>,
    #[serde(default)]
    pub before_sensitive: Option<Value>,
    #[serde(default)]
    pub after_sensitive: Option<Value>,
    #[serde(default)]
    pub replace_paths: Vec<Value>,
}

impl Change {
    pub fn action(&self) -> Action {
        Action::from_actions(&self.actions)
    }

    pub fn before(&self) -> Option<&Value> {
        self.before.as_ref().filter(|value| !value.is_null())
    }

    pub fn after(&self) -> Option<&Value> {
        self.after.as_ref().filter(|value| !value.is_null())
    }
}

#[derive(Debug, Deserialize)]
struct RawPlan {
    #[serde(default)]
    format_version: Option<String>,
    #[serde(default)]
    terraform_version: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    applyable: Option<bool>,
    #[serde(default)]
    complete: Option<bool>,
    #[serde(default)]
    errored: Option<bool>,
    #[serde(default)]
    resource_changes: Option<Vec<ResourceChange>>,
    #[serde(default)]
    resource_drift: Option<Vec<ResourceChange>>,
    #[serde(default)]
    output_changes: BTreeMap<String, Value>,
    #[serde(default)]
    variables: BTreeMap<String, Value>,
    // Only used to tell a state document apart from a plan document.
    #[serde(default)]
    values: Option<Value>,
    #[serde(default)]
    planned_values: Option<Value>,
    #[serde(default)]
    configuration: Option<Value>,
}

/// Reads a plan from a file, or from stdin when `path` is `-`.
pub fn load(path: &str) -> Result<Plan> {
    let text = if path == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("failed to read the plan from stdin")?;
        text
    } else {
        std::fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read {path}; if this is a binary plan file, run \
                 `terraform show -json {path}` first"
            )
        })?
    };

    parse(&text, path)
}

pub fn parse(text: &str, display_path: &str) -> Result<Plan> {
    let raw: RawPlan = serde_json::from_str(text)
        .with_context(|| format!("{display_path} is not valid Terraform plan JSON"))?;

    let has_plan_fields = raw.resource_changes.is_some()
        || raw.planned_values.is_some()
        || raw.configuration.is_some()
        || !raw.output_changes.is_empty()
        || !raw.variables.is_empty();

    if raw.values.is_some() && !has_plan_fields {
        bail!(
            "{display_path} is Terraform state JSON, not a plan; run \
             `terraform plan -out=tfplan` and `terraform show -json tfplan`"
        );
    }
    if !has_plan_fields && raw.format_version.is_none() {
        bail!(
            "{display_path} is not a Terraform plan JSON document; generate one with \
             `terraform show -json <planfile>`"
        );
    }

    if let Some(version) = &raw.format_version {
        let major = version
            .split('.')
            .next()
            .and_then(|major| major.parse::<u32>().ok());
        if major != Some(1) {
            bail!("unsupported plan format version {version}; PlanGuard supports format 1.x");
        }
    }

    let path = if display_path == "-" {
        "stdin".to_owned()
    } else {
        display_path.to_owned()
    };
    let info = PlanInfo {
        path,
        format_version: raw.format_version,
        terraform_version: raw.terraform_version,
        timestamp: raw.timestamp,
        applyable: raw.applyable,
        complete: raw.complete,
        errored: raw.errored,
        outputs_changed: raw
            .output_changes
            .values()
            .filter(|value| output_changed(value))
            .count(),
        variables: raw.variables.len(),
    };

    Ok(Plan {
        info,
        changes: raw.resource_changes.unwrap_or_default(),
        drift: raw.resource_drift.unwrap_or_default(),
    })
}

fn output_changed(value: &Value) -> bool {
    let change = value.get("change").unwrap_or(value);
    change
        .get("actions")
        .and_then(Value::as_array)
        .is_some_and(|actions| {
            actions
                .iter()
                .filter_map(Value::as_str)
                .any(|action| action != "no-op" && action != "read")
        })
}

/// The plan path as it should appear in a SARIF artifact location.
pub fn sarif_uri(path: &str) -> String {
    if path == "-" || path == "stdin" {
        return "terraform-plan.json".to_owned();
    }
    let normalized = path.replace('\\', "/");
    let relative = normalized.strip_prefix("./").unwrap_or(&normalized);
    if relative.starts_with('/') {
        return Path::new(relative)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("terraform-plan.json")
            .to_owned();
    }
    relative.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MINIMAL: &str = r#"{
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "resource_changes": [],
        "resource_drift": []
    }"#;

    #[test]
    fn parses_a_minimal_plan() {
        let plan = parse(MINIMAL, "plan.json").unwrap();
        assert_eq!(plan.info.path, "plan.json");
        assert_eq!(plan.info.format_version.as_deref(), Some("1.2"));
        assert_eq!(plan.info.terraform_version.as_deref(), Some("1.9.5"));
        assert!(plan.changes.is_empty());
    }

    #[test]
    fn rejects_state_documents_with_a_plan_hint() {
        let error = parse(r#"{"format_version":"1.0","values":{}}"#, "state.json")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Terraform state JSON"));
        assert!(error.contains("terraform plan"));
    }

    #[test]
    fn rejects_a_future_format_version() {
        let error = parse(r#"{"format_version":"2.0"}"#, "plan.json")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported plan format version 2.0"));
    }

    #[test]
    fn rejects_plain_json() {
        let error = parse(r#"{"hello":"world"}"#, "plan.json")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a Terraform plan JSON document"));
    }

    #[test]
    fn type_falls_back_to_the_address() {
        let change: ResourceChange = serde_json::from_value(json!({
            "address": "module.data.aws_instance.web[0]",
            "change": {"actions": ["create"]}
        }))
        .unwrap();
        assert_eq!(change.type_name(), "aws_instance");
        assert!(change.is_managed());
    }

    #[test]
    fn data_sources_are_not_managed() {
        let change: ResourceChange = serde_json::from_value(json!({
            "address": "data.aws_ami.ubuntu",
            "mode": "data",
            "type": "aws_ami",
            "change": {"actions": ["read"]}
        }))
        .unwrap();
        assert!(!change.is_managed());
        assert_eq!(change.action(), Action::Read);
    }

    #[test]
    fn output_changes_support_both_shapes() {
        let direct = json!({"actions": ["update"]});
        let wrapped = json!({"change": {"actions": ["create"]}});
        let noop = json!({"actions": ["no-op"]});
        assert!(output_changed(&direct));
        assert!(output_changed(&wrapped));
        assert!(!output_changed(&noop));
    }

    #[test]
    fn sarif_uri_is_repository_friendly() {
        assert_eq!(sarif_uri("-"), "terraform-plan.json");
        assert_eq!(sarif_uri("./plans/tfplan.json"), "plans/tfplan.json");
        assert_eq!(sarif_uri("/tmp/work/tfplan.json"), "tfplan.json");
        assert_eq!(
            sarif_uri(r"plans\windows\plan.json"),
            "plans/windows/plan.json"
        );
    }
}
