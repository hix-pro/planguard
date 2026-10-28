use serde::Serialize;

/// Ordered from most to least urgent; the order is used for report grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Info,
}

impl Severity {
    pub const ALL: [Self; 4] = [Self::Critical, Self::Error, Self::Warning, Self::Info];

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Destroy,
    Replace,
    Drift,
    PublicIngress,
    IamPolicy,
    PublicAccess,
    Encryption,
    DeletionProtection,
    Secret,
    PlanErrored,
    PlanIncomplete,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Destroy => "destroy",
            Self::Replace => "replace",
            Self::Drift => "drift",
            Self::PublicIngress => "public_ingress",
            Self::IamPolicy => "iam_policy",
            Self::PublicAccess => "public_access",
            Self::Encryption => "encryption",
            Self::DeletionProtection => "deletion_protection",
            Self::Secret => "secret",
            Self::PlanErrored => "plan_errored",
            Self::PlanIncomplete => "plan_incomplete",
        }
    }

    /// Stable identifier used in SARIF rule IDs.
    pub fn id(self) -> &'static str {
        match self {
            Self::Destroy => "destroy",
            Self::Replace => "replace",
            Self::Drift => "drift",
            Self::PublicIngress => "public-ingress",
            Self::IamPolicy => "iam-policy",
            Self::PublicAccess => "public-access",
            Self::Encryption => "encryption",
            Self::DeletionProtection => "deletion-protection",
            Self::Secret => "secret",
            Self::PlanErrored => "plan-errored",
            Self::PlanIncomplete => "plan-incomplete",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Destroy => "Destroy",
            Self::Replace => "Replace",
            Self::Drift => "Drift",
            Self::PublicIngress => "Public ingress",
            Self::IamPolicy => "IAM policy",
            Self::PublicAccess => "Public access",
            Self::Encryption => "Encryption",
            Self::DeletionProtection => "Deletion protection",
            Self::Secret => "Secret in plan",
            Self::PlanErrored => "Errored plan",
            Self::PlanIncomplete => "Incomplete plan",
        }
    }
}

/// The effective Terraform action for a resource change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Action {
    #[serde(rename = "no-op")]
    NoOp,
    #[serde(rename = "create")]
    Create,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "update")]
    Update,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "replace")]
    Replace,
}

impl Action {
    pub fn from_actions(actions: &[String]) -> Self {
        let has_create = actions.iter().any(|action| action == "create");
        let has_delete = actions.iter().any(|action| action == "delete");
        if has_create && has_delete {
            Self::Replace
        } else if has_create {
            Self::Create
        } else if has_delete {
            Self::Delete
        } else if actions.iter().any(|action| action == "update") {
            Self::Update
        } else if actions.iter().any(|action| action == "read") {
            Self::Read
        } else {
            Self::NoOp
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoOp => "no-op",
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Replace => "replace",
        }
    }

    /// Reads and no-ops are part of the plan but change no managed state.
    pub fn changes_state(self) -> bool {
        !matches!(self, Self::NoOp | Self::Read)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    pub detail: String,
}

impl Finding {
    pub fn plan(kind: FindingKind, severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            kind,
            severity,
            address: None,
            resource_type: None,
            action: None,
            attribute: None,
            detail: detail.into(),
        }
    }

    pub fn resource(
        kind: FindingKind,
        severity: Severity,
        address: impl Into<String>,
        resource_type: impl Into<String>,
        action: Action,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            severity,
            address: Some(address.into()),
            resource_type: Some(resource_type.into()),
            action: Some(action),
            attribute: None,
            detail: detail.into(),
        }
    }

    pub fn attribute(mut self, attribute: impl Into<String>) -> Self {
        self.attribute = Some(attribute.into());
        self
    }

    pub fn target(&self) -> &str {
        self.address.as_deref().unwrap_or("plan")
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ChangeCounts {
    pub create: usize,
    pub update: usize,
    pub delete: usize,
    pub replace: usize,
    pub read: usize,
    pub no_op: usize,
}

impl ChangeCounts {
    pub fn add(&mut self, action: Action) {
        match action {
            Action::NoOp => self.no_op += 1,
            Action::Create => self.create += 1,
            Action::Read => self.read += 1,
            Action::Update => self.update += 1,
            Action::Delete => self.delete += 1,
            Action::Replace => self.replace += 1,
        }
    }

    pub fn total_changes(&self) -> usize {
        self.create + self.update + self.delete + self.replace
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total: usize,
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
    pub resources: usize,
    pub changes: ChangeCounts,
    pub drift: usize,
}

impl Summary {
    pub fn new(
        findings: &[Finding],
        resources: usize,
        changes: ChangeCounts,
        drift: usize,
    ) -> Self {
        let count = |severity: Severity| {
            findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .count()
        };
        Self {
            total: findings.len(),
            critical: count(Severity::Critical),
            error: count(Severity::Error),
            warning: count(Severity::Warning),
            info: count(Severity::Info),
            resources,
            changes,
            drift,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanInfo {
    pub path: String,
    pub format_version: Option<String>,
    pub terraform_version: Option<String>,
    pub timestamp: Option<String>,
    pub applyable: Option<bool>,
    pub complete: Option<bool>,
    pub errored: Option<bool>,
    pub outputs_changed: usize,
    pub variables: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub plan: PlanInfo,
    pub ignored: Vec<String>,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_parsing_handles_replacements_and_reads() {
        assert_eq!(Action::from_actions(&["no-op".into()]), Action::NoOp);
        assert_eq!(Action::from_actions(&["create".into()]), Action::Create);
        assert_eq!(Action::from_actions(&["read".into()]), Action::Read);
        assert_eq!(Action::from_actions(&["update".into()]), Action::Update);
        assert_eq!(Action::from_actions(&["delete".into()]), Action::Delete);
        assert_eq!(
            Action::from_actions(&["delete".into(), "create".into()]),
            Action::Replace
        );
        assert_eq!(
            Action::from_actions(&["create".into(), "delete".into()]),
            Action::Replace
        );
        assert!(!Action::NoOp.changes_state());
        assert!(!Action::Read.changes_state());
        assert!(Action::Update.changes_state());
    }

    #[test]
    fn finding_kinds_have_stable_ids_and_labels() {
        assert_eq!(FindingKind::PublicIngress.id(), "public-ingress");
        assert_eq!(FindingKind::IamPolicy.as_str(), "iam_policy");
        assert_eq!(
            FindingKind::DeletionProtection.label(),
            "Deletion protection"
        );
        assert_eq!(FindingKind::PlanErrored.id(), "plan-errored");
    }

    #[test]
    fn summary_counts_findings_and_changes() {
        let findings = vec![
            Finding::plan(FindingKind::PlanIncomplete, Severity::Warning, "incomplete"),
            Finding::plan(FindingKind::Secret, Severity::Info, "secret"),
        ];
        let mut changes = ChangeCounts::default();
        changes.add(Action::Create);
        changes.add(Action::Replace);
        changes.add(Action::NoOp);

        let summary = Summary::new(&findings, 3, changes, 1);

        assert_eq!(summary.total, 2);
        assert_eq!(summary.warning, 1);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.changes.total_changes(), 2);
        assert_eq!(summary.resources, 3);
        assert_eq!(summary.drift, 1);
    }
}
