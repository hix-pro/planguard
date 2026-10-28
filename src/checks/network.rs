use std::collections::BTreeMap;

use serde_json::Value;

use crate::checks::{as_i64, is_open_source, scalar, str_at, strings};
use crate::model::{Action, Finding, FindingKind, Severity};
use crate::plan::Plan;

const SENSITIVE_PORTS: &[i64] = &[
    22, 1433, 1521, 2181, 2375, 2376, 3306, 3389, 5432, 5984, 6379, 6443, 9092, 9200, 9300, 10250,
    11211, 27017, 27018,
];

#[derive(Debug, Clone)]
struct Exposure {
    attribute: String,
    severity: Severity,
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

        let new = collect(change.type_name(), change.change.after());
        if new.is_empty() {
            continue;
        }
        let old: std::collections::BTreeSet<String> =
            collect(change.type_name(), change.change.before())
                .into_keys()
                .collect();

        for (fingerprint, exposure) in new {
            if old.contains(&fingerprint) {
                continue;
            }
            out.push(
                Finding::resource(
                    FindingKind::PublicIngress,
                    exposure.severity,
                    &change.address,
                    change.type_name(),
                    change.action(),
                    exposure.detail,
                )
                .attribute(exposure.attribute),
            );
        }
    }
}

fn collect(type_name: &str, value: Option<&Value>) -> BTreeMap<String, Exposure> {
    let Some(value) = value else {
        return BTreeMap::new();
    };
    match type_name {
        "aws_security_group" => aws_security_group(value),
        "aws_vpc_security_group_ingress_rule" => aws_vpc_security_group_rule(value),
        "aws_security_group_rule" => aws_security_group_rule(value),
        "azurerm_network_security_rule" => azure_network_security_rule(value),
        "google_compute_firewall" => google_compute_firewall(value),
        _ => BTreeMap::new(),
    }
}

fn aws_security_group(after: &Value) -> BTreeMap<String, Exposure> {
    let mut exposures = BTreeMap::new();
    let Some(ingress) = after.get("ingress").and_then(Value::as_array) else {
        return exposures;
    };

    for block in ingress {
        let protocol = block
            .get("protocol")
            .and_then(scalar)
            .unwrap_or_else(|| "tcp".to_owned());
        let port = port_range(as_i64(block.get("from_port")), as_i64(block.get("to_port")));
        let mut sources = strings(block.get("cidr_blocks"));
        sources.extend(strings(block.get("ipv6_cidr_blocks")));
        for source in sources.iter().filter(|source| is_open_source(source)) {
            add(&mut exposures, source, &protocol, &port, "ingress");
        }
    }
    exposures
}

fn aws_vpc_security_group_rule(after: &Value) -> BTreeMap<String, Exposure> {
    let mut exposures = BTreeMap::new();
    let protocol = after
        .get("ip_protocol")
        .and_then(scalar)
        .unwrap_or_else(|| "tcp".to_owned());
    let port = port_range(as_i64(after.get("from_port")), as_i64(after.get("to_port")));
    let mut sources = strings(after.get("cidr_ipv4"));
    sources.extend(strings(after.get("cidr_ipv6")));
    for source in sources.iter().filter(|source| is_open_source(source)) {
        add(&mut exposures, source, &protocol, &port, "cidr");
    }
    exposures
}

fn aws_security_group_rule(after: &Value) -> BTreeMap<String, Exposure> {
    let mut exposures = BTreeMap::new();
    if str_at(Some(after), "type").as_deref() != Some("ingress") {
        return exposures;
    }
    let protocol = after
        .get("protocol")
        .and_then(scalar)
        .unwrap_or_else(|| "tcp".to_owned());
    let port = port_range(as_i64(after.get("from_port")), as_i64(after.get("to_port")));
    let mut sources = strings(after.get("cidr_blocks"));
    sources.extend(strings(after.get("ipv6_cidr_blocks")));
    for source in sources.iter().filter(|source| is_open_source(source)) {
        add(&mut exposures, source, &protocol, &port, "cidr_blocks");
    }
    exposures
}

fn azure_network_security_rule(after: &Value) -> BTreeMap<String, Exposure> {
    let mut exposures = BTreeMap::new();
    let direction = str_at(Some(after), "direction").unwrap_or_default();
    let access = str_at(Some(after), "access").unwrap_or_default();
    if !direction.eq_ignore_ascii_case("inbound") || !access.eq_ignore_ascii_case("allow") {
        return exposures;
    }

    let protocol = str_at(Some(after), "protocol").unwrap_or_else(|| "*".to_owned());
    let mut ports = Vec::new();
    if let Some(port) = str_at(Some(after), "destination_port_range") {
        ports.push(port);
    }
    ports.extend(strings(after.get("destination_port_ranges")));
    if ports.is_empty() {
        ports.push("*".to_owned());
    }

    let mut sources = Vec::new();
    if let Some(source) = str_at(Some(after), "source_address_prefix") {
        sources.push(source);
    }
    sources.extend(strings(after.get("source_address_prefixes")));

    for source in sources.iter().filter(|source| is_open_source(source)) {
        for port in &ports {
            add(
                &mut exposures,
                source,
                &protocol,
                port,
                "source_address_prefix",
            );
        }
    }
    exposures
}

fn google_compute_firewall(after: &Value) -> BTreeMap<String, Exposure> {
    let mut exposures = BTreeMap::new();
    let direction = str_at(Some(after), "direction").unwrap_or_else(|| "INGRESS".to_owned());
    if !direction.eq_ignore_ascii_case("INGRESS") {
        return exposures;
    }
    if after.get("disabled").and_then(Value::as_bool) == Some(true) {
        return exposures;
    }

    let sources = strings(after.get("source_ranges"));
    let open: Vec<&String> = sources
        .iter()
        .filter(|source| is_open_source(source))
        .collect();
    if open.is_empty() {
        return exposures;
    }

    let Some(allows) = after.get("allow").and_then(Value::as_array) else {
        return exposures;
    };
    for allow in allows {
        let protocol = allow
            .get("protocol")
            .and_then(scalar)
            .unwrap_or_else(|| "tcp".to_owned());
        let ports = strings(allow.get("ports"));
        for source in &open {
            if ports.is_empty() {
                add(&mut exposures, source, &protocol, "*", "source_ranges");
            } else {
                for port in &ports {
                    add(&mut exposures, source, &protocol, port, "source_ranges");
                }
            }
        }
    }
    exposures
}

fn port_range(from: Option<i64>, to: Option<i64>) -> String {
    match (from, to) {
        (Some(from), Some(to)) if from == to => from.to_string(),
        (Some(from), Some(to)) => format!("{from}-{to}"),
        (Some(from), None) => from.to_string(),
        (None, Some(to)) => format!("0-{to}"),
        (None, None) => "all".to_owned(),
    }
}

fn add(
    exposures: &mut BTreeMap<String, Exposure>,
    source: &str,
    protocol: &str,
    port: &str,
    attribute: &str,
) {
    let (protocol, port, risk) = analyze_port(protocol, port);
    let fingerprint = format!("{protocol}|{port}|{source}");
    let severity = match risk {
        Risk::All | Risk::Sensitive => Severity::Critical,
        Risk::Standard => Severity::Error,
        Risk::OtherProtocol => Severity::Warning,
    };
    let traffic = if protocol == "all" {
        "all traffic".to_owned()
    } else {
        protocol.clone()
    };
    let detail = match risk {
        Risk::OtherProtocol => format!("{traffic} is open to {source}"),
        Risk::All => format!("{traffic} on all ports is open to {source}"),
        Risk::Standard | Risk::Sensitive => format!("{traffic}/{port} is open to {source}"),
    };
    exposures.entry(fingerprint).or_insert(Exposure {
        attribute: attribute.to_owned(),
        severity,
        detail,
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Risk {
    All,
    Sensitive,
    Standard,
    OtherProtocol,
}

fn analyze_port(protocol: &str, port: &str) -> (String, String, Risk) {
    let protocol = protocol.trim().to_ascii_lowercase();
    let protocol = match protocol.as_str() {
        "6" => "tcp".to_owned(),
        "17" => "udp".to_owned(),
        "1" => "icmp".to_owned(),
        "-1" | "all" | "*" | "any" => "all".to_owned(),
        "" => "tcp".to_owned(),
        other => other.to_owned(),
    };

    if protocol == "all" {
        return (protocol, "all".to_owned(), Risk::All);
    }

    if protocol != "tcp" && protocol != "udp" {
        return (protocol, "all".to_owned(), Risk::OtherProtocol);
    }

    let port = port.trim();
    if port.is_empty() || port == "*" || port == "all" || port == "-1" {
        return (protocol, "all".to_owned(), Risk::All);
    }

    if let Some((start, end)) = parse_range(port) {
        if start <= 0 && end >= 65535 {
            return (protocol, "all".to_owned(), Risk::All);
        }
        let label = if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        };
        let risk = if SENSITIVE_PORTS
            .iter()
            .any(|sensitive| *sensitive >= start && *sensitive <= end)
        {
            Risk::Sensitive
        } else {
            Risk::Standard
        };
        return (protocol, label, risk);
    }

    (protocol, port.to_owned(), Risk::Standard)
}

fn parse_range(port: &str) -> Option<(i64, i64)> {
    let mut parts = port.split('-');
    let start = parts.next()?.trim().parse::<i64>().ok()?;
    let end = match parts.next() {
        Some(end) => end.trim().parse::<i64>().ok()?,
        None => start,
    };
    if parts.next().is_some() || start > end {
        return None;
    }
    Some((start, end))
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

    fn network_findings(plan: &Plan) -> Vec<Finding> {
        let mut findings = Vec::new();
        check(plan, &mut findings);
        findings
    }

    #[test]
    fn newly_opened_ssh_port_is_critical() {
        let plan = plan_with(json!({
            "address": "aws_security_group.web",
            "mode": "managed",
            "type": "aws_security_group",
            "change": {
                "actions": ["update"],
                "before": {"ingress": [
                    {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
                ]},
                "after": {"ingress": [
                    {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
                    {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
                ]}
            }
        }));

        let findings = network_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].detail.contains("tcp/22"));
    }

    #[test]
    fn existing_exposure_is_not_reported_again() {
        let plan = plan_with(json!({
            "address": "aws_security_group.web",
            "mode": "managed",
            "type": "aws_security_group",
            "change": {
                "actions": ["update"],
                "before": {"ingress": [
                    {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
                ]},
                "after": {"ingress": [
                    {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"], "description": "ssh"}
                ]}
            }
        }));

        assert!(network_findings(&plan).is_empty());
    }

    #[test]
    fn private_ingress_is_ignored() {
        let plan = plan_with(json!({
            "address": "aws_security_group.web",
            "mode": "managed",
            "type": "aws_security_group",
            "change": {
                "actions": ["create"],
                "after": {"ingress": [
                    {"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}
                ]}
            }
        }));

        assert!(network_findings(&plan).is_empty());
    }

    #[test]
    fn non_sensitive_open_port_is_an_error() {
        let plan = plan_with(json!({
            "address": "aws_security_group.web",
            "mode": "managed",
            "type": "aws_security_group",
            "change": {
                "actions": ["create"],
                "after": {"ingress": [
                    {"from_port": 8080, "to_port": 8080, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
                ]}
            }
        }));

        let findings = network_findings(&plan);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn all_traffic_is_critical() {
        let plan = plan_with(json!({
            "address": "aws_security_group.web",
            "mode": "managed",
            "type": "aws_security_group",
            "change": {
                "actions": ["create"],
                "after": {"ingress": [
                    {"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}
                ]}
            }
        }));

        let findings = network_findings(&plan);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].detail.contains("all traffic on all ports"));
    }

    #[test]
    fn sensitive_range_is_critical() {
        let plan = plan_with(json!({
            "address": "aws_security_group.web",
            "mode": "managed",
            "type": "aws_security_group",
            "change": {
                "actions": ["create"],
                "after": {"ingress": [
                    {"from_port": 3300, "to_port": 3400, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
                ]}
            }
        }));

        let findings = network_findings(&plan);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].detail.contains("3300-3400"));
    }

    #[test]
    fn icmp_is_a_warning() {
        let plan = plan_with(json!({
            "address": "aws_security_group.web",
            "mode": "managed",
            "type": "aws_security_group",
            "change": {
                "actions": ["create"],
                "after": {"ingress": [
                    {"from_port": -1, "to_port": -1, "protocol": "icmp", "cidr_blocks": ["0.0.0.0/0"]}
                ]}
            }
        }));

        let findings = network_findings(&plan);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].detail.contains("icmp"));
    }

    #[test]
    fn azure_rdp_rule_is_critical() {
        let plan = plan_with(json!({
            "address": "azurerm_network_security_rule.rdp",
            "mode": "managed",
            "type": "azurerm_network_security_rule",
            "change": {
                "actions": ["create"],
                "after": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "destination_port_range": "3389",
                    "source_address_prefix": "*"
                }
            }
        }));

        let findings = network_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].detail.contains("tcp/3389"));
    }

    #[test]
    fn gcp_firewall_without_ports_is_all_ports() {
        let plan = plan_with(json!({
            "address": "google_compute_firewall.ssh",
            "mode": "managed",
            "type": "google_compute_firewall",
            "change": {
                "actions": ["create"],
                "after": {
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [{"protocol": "tcp"}]
                }
            }
        }));

        let findings = network_findings(&plan);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn egress_only_resources_are_ignored() {
        let plan = plan_with(json!({
            "address": "google_compute_firewall.egress",
            "mode": "managed",
            "type": "google_compute_firewall",
            "change": {
                "actions": ["create"],
                "after": {
                    "direction": "EGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [{"protocol": "tcp"}]
                }
            }
        }));

        assert!(network_findings(&plan).is_empty());
    }
}
