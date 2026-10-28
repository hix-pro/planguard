use crate::checks;
use crate::model::{Analysis, Finding, Summary};
use crate::plan::Plan;

/// Runs the checks, applies ignores, and builds the report summary.
pub fn analyze(plan: &Plan, ignored: &[String]) -> Analysis {
    let mut findings = checks::run(plan);
    if !ignored.is_empty() {
        findings.retain(|finding| !ignored.iter().any(|pattern| matches(finding, pattern)));
    }

    let resources = plan
        .changes
        .iter()
        .filter(|change| change.is_managed())
        .count();
    let drift = plan
        .drift
        .iter()
        .filter(|change| change.is_managed() && change.action().changes_state())
        .count();
    let summary = Summary::new(&findings, resources, plan.change_counts(), drift);

    Analysis {
        plan: plan.info.clone(),
        ignored: ignored.to_vec(),
        summary,
        findings,
    }
}

fn matches(finding: &Finding, pattern: &str) -> bool {
    finding.address.as_deref() == Some(pattern)
        || finding.resource_type.as_deref() == Some(pattern)
        || finding.kind.id() == pattern
        || finding.kind.as_str() == pattern
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::parse;
    use serde_json::json;

    fn plan() -> Plan {
        let document = json!({
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_db_instance.main",
                    "mode": "managed",
                    "type": "aws_db_instance",
                    "change": {"actions": ["delete"], "before": {"id": "db-1"}}
                },
                {
                    "address": "aws_instance.web",
                    "mode": "managed",
                    "type": "aws_instance",
                    "change": {"actions": ["update"], "before": {}, "after": {}}
                },
                {
                    "address": "aws_security_group.web",
                    "mode": "managed",
                    "type": "aws_security_group",
                    "change": {
                        "actions": ["create"],
                        "after": {"ingress": [{
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"]
                        }]}
                    }
                }
            ]
        });
        parse(&document.to_string(), "plan.json").unwrap()
    }

    #[test]
    fn ignore_accepts_addresses_types_and_kinds() {
        let by_address = analyze(&plan(), &["aws_db_instance.main".to_owned()]);
        assert!(
            by_address
                .findings
                .iter()
                .all(|finding| finding.target() != "aws_db_instance.main")
        );

        let by_type = analyze(&plan(), &["aws_security_group".to_owned()]);
        assert!(
            by_type
                .findings
                .iter()
                .all(|finding| finding.target() != "aws_security_group.web")
        );

        let by_kind = analyze(&plan(), &["destroy".to_owned()]);
        assert!(
            by_kind
                .findings
                .iter()
                .all(|finding| finding.kind != crate::model::FindingKind::Destroy)
        );
    }

    #[test]
    fn summary_uses_filtered_findings() {
        let analysis = analyze(&plan(), &["aws_db_instance.main".to_owned()]);
        assert_eq!(analysis.summary.total, analysis.findings.len());
        assert_eq!(analysis.summary.critical, 1);
        assert_eq!(analysis.summary.resources, 3);
        assert_eq!(analysis.summary.changes.create, 1);
        assert_eq!(analysis.summary.changes.update, 1);
        assert_eq!(analysis.summary.changes.delete, 1);
    }
}
