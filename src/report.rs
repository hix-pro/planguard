use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::IsTerminal;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::model::{Action, Analysis, Finding, FindingKind, PlanInfo, Severity, Summary};
use crate::plan::sarif_uri;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    tool: ToolInfo,
    plan: &'a PlanInfo,
    ignored: &'a [String],
    summary: &'a Summary,
    findings: &'a [Finding],
}

#[derive(Debug, Clone, Serialize)]
struct ToolInfo {
    name: &'static str,
    version: &'static str,
}

pub fn render_json(analysis: &Analysis) -> Result<String> {
    let report = JsonReport {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "planguard",
            version: env!("CARGO_PKG_VERSION"),
        },
        plan: &analysis.plan,
        ignored: &analysis.ignored,
        summary: &analysis.summary,
        findings: &analysis.findings,
    };
    let mut output = serde_json::to_string_pretty(&report)?;
    output.push('\n');
    Ok(output)
}

pub struct TextOptions<'a> {
    pub color: bool,
    pub fail_on: Option<&'a str>,
    pub failing: bool,
}

pub fn color_enabled() -> bool {
    std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM")
            .map(|term| term != "dumb")
            .unwrap_or(true)
}

pub fn render_text(analysis: &Analysis, options: TextOptions<'_>) -> String {
    let style = Style::new(options.color);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{}{} {}",
        style.bold("PlanGuard"),
        style.dim(" ·"),
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(out, "{:<9} {}", style.dim("Plan"), analysis.plan.path);

    let mut platform = Vec::new();
    if let Some(version) = &analysis.plan.terraform_version {
        platform.push(format!("Terraform {version}"));
    }
    if let Some(version) = &analysis.plan.format_version {
        platform.push(format!("format {version}"));
    }
    if !platform.is_empty() {
        let _ = writeln!(out, "{:<9} {}", style.dim("Tooling"), platform.join(" · "));
    }
    let _ = writeln!(
        out,
        "{:<9} {}",
        style.dim("Resources"),
        analysis.summary.resources
    );
    let _ = writeln!(
        out,
        "{:<9} {}",
        style.dim("Changes"),
        format_changes(&analysis.summary)
    );
    if !analysis.ignored.is_empty() {
        let _ = writeln!(
            out,
            "{:<9} {}",
            style.dim("Ignored"),
            analysis.ignored.join(", ")
        );
    }
    out.push('\n');

    if analysis.findings.is_empty() {
        out.push_str("No risky changes detected.\n\n");
    } else {
        for severity in Severity::ALL {
            let group: Vec<&Finding> = analysis
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .collect();
            if group.is_empty() {
                continue;
            }
            let heading = format!("{} ({})", severity.label(), group.len());
            let _ = writeln!(out, "{}", style.severity(severity, &heading));
            for finding in group {
                push_text_finding(&mut out, finding, &style);
            }
            out.push('\n');
        }
    }

    let _ = writeln!(out, "{}", style.bold(&format_summary(&analysis.summary)));
    let result = match options.fail_on {
        None => {
            "Result: report only (use --fail-on critical|error|warning|any to gate CI)".to_owned()
        }
        Some(threshold) if options.failing => {
            format!("Result: fail (--fail-on {threshold} matched findings)")
        }
        Some(threshold) => {
            format!("Result: pass (--fail-on {threshold} found no matching findings)")
        }
    };
    let _ = writeln!(out, "{result}");

    out
}

fn push_text_finding(out: &mut String, finding: &Finding, style: &Style) {
    let attribute = finding
        .attribute
        .as_deref()
        .map(|attribute| format!(" ({attribute})"))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "  {:<19} {}{}",
        style.dim(finding.kind.id()),
        style.bold(finding.target()),
        style.dim(&attribute)
    );
    let _ = writeln!(out, "    {}", finding.detail);
}

pub fn render_markdown(analysis: &Analysis) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# PlanGuard report\n");
    let _ = writeln!(out, "| Field | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(out, "| Plan | `{}` |", analysis.plan.path);
    if let Some(version) = &analysis.plan.terraform_version {
        let _ = writeln!(out, "| Terraform | {version} |");
    }
    if let Some(version) = &analysis.plan.format_version {
        let _ = writeln!(out, "| Plan format | {version} |");
    }
    let _ = writeln!(out, "| Resources | {} |", analysis.summary.resources);
    let _ = writeln!(out, "| Changes | {} |", format_changes(&analysis.summary));
    if analysis.summary.drift > 0 {
        let _ = writeln!(out, "| Drift | {} |", analysis.summary.drift);
    }
    if !analysis.ignored.is_empty() {
        let _ = writeln!(out, "| Ignored | {} |", analysis.ignored.join(", "));
    }
    let _ = writeln!(out, "\n**{}**\n", format_summary(&analysis.summary));

    if analysis.findings.is_empty() {
        out.push_str("No risky changes detected.\n");
        return out;
    }

    for severity in Severity::ALL {
        let group: Vec<&Finding> = analysis
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "## {} ({})\n",
            title_case(severity.label()),
            group.len()
        );
        let _ = writeln!(out, "| Resource | Finding | Attribute | Detail |");
        let _ = writeln!(out, "| --- | --- | --- | --- |");
        for finding in group {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                finding.target(),
                finding.kind.label(),
                finding
                    .attribute
                    .as_deref()
                    .map(|attribute| format!("`{attribute}`"))
                    .unwrap_or_else(|| "-".to_owned()),
                escape_markdown(&finding.detail)
            );
        }
        out.push('\n');
    }
    out
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|")
}

fn format_changes(summary: &Summary) -> String {
    let changes = summary.changes.total_changes();
    if changes == 0 {
        return "no changes".to_owned();
    }

    let mut kinds = Vec::new();
    for (count, label) in [
        (summary.changes.create, "create"),
        (summary.changes.update, "update"),
        (summary.changes.delete, "delete"),
        (summary.changes.replace, "replace"),
    ] {
        if count > 0 {
            kinds.push(format!("{count} {label}"));
        }
    }
    format!(
        "{changes} {} ({})",
        if changes == 1 { "change" } else { "changes" },
        kinds.join(", ")
    )
}

fn format_resources(summary: &Summary) -> String {
    if summary.resources == 1 {
        "1 resource".to_owned()
    } else {
        format!("{} resources", summary.resources)
    }
}

fn format_summary(summary: &Summary) -> String {
    let mut parts = vec![format_resources(summary), format_changes(summary)];
    if summary.total == 0 {
        parts.push("no findings".to_owned());
        return format!("Summary: {}", parts.join(" · "));
    }

    let mut counts = Vec::new();
    for (count, label) in [
        (summary.critical, "critical"),
        (summary.error, "error"),
        (summary.warning, "warning"),
        (summary.info, "info"),
    ] {
        if count > 0 {
            counts.push(format!(
                "{count} {}",
                if count == 1 { label } else { plural(label) }
            ));
        }
    }
    let findings = if summary.total == 1 {
        "1 finding".to_owned()
    } else {
        format!("{} findings", summary.total)
    };
    parts.push(findings);
    format!("Summary: {} ({})", parts.join(" · "), counts.join(", "))
}

fn plural(label: &str) -> &str {
    match label {
        "error" => "errors",
        "warning" => "warnings",
        _ => label,
    }
}

fn title_case(value: &str) -> String {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), characters.as_str()),
        None => String::new(),
    }
}

#[derive(Debug, Clone, Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: &'static str,
    short_description: SarifText,
    help_uri: String,
}

#[derive(Debug, Clone, Serialize)]
struct SarifText {
    text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: &'static str,
    message: SarifText,
    locations: Vec<SarifLocation>,
    properties: SarifProperties,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Debug, Clone, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
}

#[derive(Debug, Clone, Serialize)]
struct SarifProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attribute: Option<String>,
    severity: Severity,
}

pub fn render_sarif(analysis: &Analysis) -> Result<String> {
    let uri = sarif_uri(&analysis.plan.path);
    let mut kinds = BTreeSet::new();
    for finding in &analysis.findings {
        kinds.insert(finding.kind);
    }

    let rules = kinds
        .into_iter()
        .map(|kind| SarifRule {
            id: format!("planguard/{}", kind.id()),
            name: kind.label(),
            short_description: SarifText {
                text: kind_description(kind).to_owned(),
            },
            help_uri: format!("https://github.com/hix-pro/planguard#{}", kind.id()),
        })
        .collect();

    let results = analysis
        .findings
        .iter()
        .map(|finding| SarifResult {
            rule_id: format!("planguard/{}", finding.kind.id()),
            level: sarif_level(finding.severity),
            message: SarifText {
                text: format!("{}: {}", finding.target(), finding.detail),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation { uri: uri.clone() },
                    region: SarifRegion { start_line: 1 },
                },
            }],
            properties: SarifProperties {
                address: finding.address.clone(),
                resource_type: finding.resource_type.clone(),
                action: finding.action,
                attribute: finding.attribute.clone(),
                severity: finding.severity,
            },
        })
        .collect();

    let log = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "PlanGuard",
                    information_uri: "https://github.com/hix-pro/planguard",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
        }],
    };

    let mut output = serde_json::to_string_pretty(&log)?;
    output.push('\n');
    Ok(output)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

fn kind_description(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::Destroy => "A resource is being destroyed.",
        FindingKind::Replace => "A resource is being replaced (deleted and recreated).",
        FindingKind::Drift => "A resource changed outside Terraform.",
        FindingKind::PublicIngress => "A network rule allows traffic from the internet.",
        FindingKind::IamPolicy => "An IAM policy grants broad or public access.",
        FindingKind::PublicAccess => "Storage or a database is exposed publicly.",
        FindingKind::Encryption => "Encryption is disabled on a resource that stores data.",
        FindingKind::DeletionProtection => "A guard against accidental deletion is weakened.",
        FindingKind::Secret => "A sensitive value is present in the plan JSON.",
        FindingKind::PlanErrored => "The plan reports an error.",
        FindingKind::PlanIncomplete => "The plan is not complete.",
    }
}

struct Style {
    enabled: bool,
}

impl Style {
    fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    fn severity(&self, severity: Severity, text: &str) -> String {
        match severity {
            Severity::Critical => self.paint("1;31", text),
            Severity::Error => self.paint("31", text),
            Severity::Warning => self.paint("33", text),
            Severity::Info => self.paint("34", text),
        }
    }
}

/// Only used by tests and callers that need to inspect a report payload.
pub fn report_value(analysis: &Analysis) -> Result<Value> {
    Ok(serde_json::from_str(&render_json(analysis)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::plan::parse;
    use serde_json::json;

    fn analysis() -> Analysis {
        let document = json!({
            "format_version": "1.2",
            "terraform_version": "1.9.5",
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
                    "change": {"actions": ["delete", "create"], "replace_paths": [["ami"]]}
                }
            ]
        });
        analyze(&parse(&document.to_string(), "plan.json").unwrap(), &[])
    }

    #[test]
    fn text_report_has_metadata_and_grouped_findings() {
        let text = render_text(
            &analysis(),
            TextOptions {
                color: false,
                fail_on: None,
                failing: false,
            },
        );
        assert!(text.starts_with("PlanGuard · "));
        assert!(text.contains("Plan      plan.json"));
        assert!(text.contains("Terraform 1.9.5"));
        assert!(text.contains("critical (1)"));
        assert!(text.contains("aws_db_instance.main"));
        assert!(text.contains("warning (1)"));
        assert!(text.contains("Result: report only"));
    }

    #[test]
    fn text_report_says_when_nothing_is_risky() {
        let document = json!({"format_version": "1.2", "resource_changes": []});
        let analysis = analyze(&parse(&document.to_string(), "plan.json").unwrap(), &[]);
        let text = render_text(
            &analysis,
            TextOptions {
                color: false,
                fail_on: None,
                failing: false,
            },
        );
        assert!(text.contains("No risky changes detected."));
        assert!(text.contains("no findings"));
    }

    #[test]
    fn markdown_report_is_a_paste_ready_table() {
        let markdown = render_markdown(&analysis());
        assert!(markdown.starts_with("# PlanGuard report"));
        assert!(markdown.contains("| Plan | `plan.json` |"));
        assert!(markdown.contains("## Critical (1)"));
        assert!(markdown.contains("| `aws_db_instance.main` | Destroy |"));
        assert!(markdown.contains("## Warning (1)"));
    }

    #[test]
    fn sarif_report_has_rules_levels_and_locations() {
        let value: Value = serde_json::from_str(&render_sarif(&analysis()).unwrap()).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "PlanGuard");
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "planguard/destroy");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "plan.json"
        );
        assert_eq!(results[1]["ruleId"], "planguard/replace");
        assert_eq!(results[1]["level"], "warning");
    }

    #[test]
    fn json_report_is_stable() {
        let value = report_value(&analysis()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["tool"]["name"], "planguard");
        assert_eq!(value["summary"]["total"], 2);
        assert_eq!(value["summary"]["critical"], 1);
        assert_eq!(value["summary"]["warning"], 1);
        assert_eq!(value["findings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn summary_grammar_handles_singular_and_plural() {
        let document = json!({"format_version": "1.2", "resource_changes": []});
        let analysis = analyze(&parse(&document.to_string(), "plan.json").unwrap(), &[]);
        assert!(format_summary(&analysis.summary).contains("no findings"));
        assert!(format_changes(&analysis.summary).contains("no changes"));
    }
}
