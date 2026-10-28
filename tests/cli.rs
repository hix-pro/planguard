use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_planguard"))
        .args(args)
        .env_remove("NO_COLOR")
        .output()
        .unwrap()
}

fn run_with_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_planguard"))
        .args(args)
        .env_remove("NO_COLOR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout(output),
            stderr(output)
        )
    })
}

const RISKY: &str = "examples/risky-plan.json";
const SAFE: &str = "examples/safe-plan.json";

#[test]
fn help_and_version_exit_zero() {
    let help = run(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let text = stdout(&help);
    assert!(text.contains("PlanGuard reads the JSON representation of a Terraform plan"));
    assert!(text.contains("Review a Terraform plan JSON document"));
    assert!(text.contains("Exit codes:"));
    assert!(text.contains("planguard review plan.json"));

    let review_help = run(&["review", "--help"]);
    assert_eq!(review_help.status.code(), Some(0));
    let text = stdout(&review_help);
    assert!(text.contains("--fail-on"));
    assert!(text.contains("--ignore"));
    assert!(text.contains("--sarif"));

    let version = run(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn text_report_groups_findings_and_stays_report_only() {
    let output = run(&["review", RISKY]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).is_empty());
    let text = stdout(&output);

    assert!(text.starts_with("PlanGuard · "));
    assert!(text.contains("Plan      examples/risky-plan.json"));
    assert!(text.contains("Terraform 1.9.5"));
    assert!(text.contains("format 1.2"));
    assert!(text.contains("Resources 10"));
    assert!(text.contains("critical (5)"));
    assert!(text.contains("error (2)"));
    assert!(text.contains("warning (4)"));
    assert!(text.contains("info (1)"));
    assert!(text.contains("aws_db_instance.main"));
    assert!(text.contains("tcp/22 is open to 0.0.0.0/0"));
    assert!(text.contains("Summary: 10 resources"));
    assert!(text.contains("Result: report only"));
}

#[test]
fn json_report_has_a_stable_schema_and_summary() {
    let output = run(&["review", RISKY, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).is_empty());

    let report = json(&output);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["tool"]["name"], "planguard");
    assert_eq!(report["plan"]["path"], RISKY);
    assert_eq!(report["plan"]["format_version"], "1.2");
    assert_eq!(report["plan"]["terraform_version"], "1.9.5");
    assert_eq!(report["plan"]["outputs_changed"], 1);
    assert_eq!(report["plan"]["variables"], 1);

    assert_eq!(report["summary"]["total"], 12);
    assert_eq!(report["summary"]["critical"], 5);
    assert_eq!(report["summary"]["error"], 2);
    assert_eq!(report["summary"]["warning"], 4);
    assert_eq!(report["summary"]["info"], 1);
    assert_eq!(report["summary"]["resources"], 10);
    assert_eq!(report["summary"]["changes"]["create"], 4);
    assert_eq!(report["summary"]["changes"]["update"], 2);
    assert_eq!(report["summary"]["changes"]["delete"], 1);
    assert_eq!(report["summary"]["changes"]["replace"], 2);
    assert_eq!(report["summary"]["changes"]["read"], 1);
    assert_eq!(report["summary"]["changes"]["no_op"], 1);
    assert_eq!(report["summary"]["drift"], 1);

    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 12);
    assert_eq!(findings[0]["kind"], "destroy");
    assert_eq!(findings[0]["severity"], "critical");
    assert_eq!(findings[0]["address"], "aws_db_instance.main");
    assert_eq!(findings[0]["action"], "delete");

    let secret = findings
        .iter()
        .find(|finding| finding["kind"] == "secret")
        .unwrap();
    assert_eq!(secret["severity"], "info");
    assert_eq!(secret["attribute"], "password");
    assert!(!secret["detail"].as_str().unwrap().contains("correct-horse"));
}

#[test]
fn safe_plan_has_no_findings() {
    let output = run(&["review", SAFE, "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let report = json(&output);
    assert_eq!(report["summary"]["total"], 0);
    assert_eq!(report["summary"]["resources"], 7);
    assert_eq!(report["summary"]["changes"]["create"], 5);
    assert_eq!(report["summary"]["changes"]["update"], 1);
    assert_eq!(report["findings"], serde_json::json!([]));

    let text = stdout(&run(&["review", SAFE]));
    assert!(text.contains("No risky changes detected."));
    assert!(text.contains("no findings"));
}

#[test]
fn fail_on_is_report_only_by_default_and_inclusive() {
    let report_only = run(&["review", RISKY]);
    assert_eq!(report_only.status.code(), Some(0));

    for threshold in ["critical", "error", "warning", "any"] {
        let output = run(&["review", RISKY, "--fail-on", threshold]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "--fail-on {threshold} should fail"
        );
        assert!(stdout(&output).contains(&format!("--fail-on {threshold} matched findings")));
    }

    let safe = run(&["review", SAFE, "--fail-on", "any"]);
    assert_eq!(safe.status.code(), Some(0));
    assert!(stdout(&safe).contains("Result: pass"));
}

#[test]
fn ignoring_every_finding_lets_the_threshold_pass() {
    let output = run(&[
        "review",
        RISKY,
        "--json",
        "--ignore",
        "aws_db_instance.main",
        "--ignore",
        "aws_security_group.web",
        "--ignore",
        "aws_iam_policy.deploy",
        "--ignore",
        "aws_s3_bucket_acl.assets",
        "--ignore",
        "aws_db_instance.analytics",
        "--ignore",
        "aws_ebs_volume.data",
        "--ignore",
        "secret",
        "--fail-on",
        "error",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = json(&output);
    assert_eq!(report["summary"]["critical"], 0);
    assert_eq!(report["summary"]["error"], 0);
    assert_eq!(report["summary"]["warning"], 4);
    assert_eq!(report["ignored"].as_array().unwrap().len(), 7);
}

#[test]
fn ignore_accepts_addresses_types_and_kinds() {
    let by_address = json(&run(&[
        "review",
        RISKY,
        "--json",
        "--ignore",
        "aws_db_instance.main",
    ]));
    assert!(
        by_address["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["address"] != "aws_db_instance.main")
    );
    assert_eq!(by_address["summary"]["critical"], 4);

    let by_type = json(&run(&[
        "review",
        RISKY,
        "--json",
        "--ignore",
        "aws_db_instance",
    ]));
    assert!(
        by_type["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["type"] != "aws_db_instance")
    );
    assert_eq!(by_type["summary"]["total"], 8);
    assert_eq!(by_type["summary"]["critical"], 3);
    assert_eq!(by_type["summary"]["error"], 1);
    assert_eq!(by_type["summary"]["info"], 0);

    let by_kind = json(&run(&[
        "review",
        RISKY,
        "--json",
        "--ignore",
        "deletion-protection",
    ]));
    assert!(
        by_kind["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["kind"] != "deletion_protection")
    );
    assert_eq!(by_kind["summary"]["warning"], 2);
}

#[test]
fn sarif_output_maps_severity_and_locations() {
    let output = run(&["review", RISKY, "--sarif"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report = json(&output);

    assert_eq!(report["version"], "2.1.0");
    assert_eq!(report["runs"][0]["tool"]["driver"]["name"], "PlanGuard");
    assert_eq!(
        report["runs"][0]["tool"]["driver"]["informationUri"],
        "https://github.com/hix-pro/planguard"
    );
    assert_eq!(
        report["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        9
    );

    let results = report["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 12);
    assert_eq!(results[0]["ruleId"], "planguard/destroy");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        RISKY
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
    assert_eq!(results[0]["properties"]["severity"], "critical");
    assert_eq!(results[0]["properties"]["address"], "aws_db_instance.main");
    assert_eq!(results[0]["properties"]["action"], "delete");

    let secret = results
        .iter()
        .find(|result| result["ruleId"] == "planguard/secret")
        .unwrap();
    assert_eq!(secret["level"], "note");

    let replace_error = results
        .iter()
        .find(|result| {
            result["ruleId"] == "planguard/replace"
                && result["properties"]["address"] == "aws_ebs_volume.data"
        })
        .unwrap();
    assert_eq!(replace_error["level"], "error");

    let replace_warning = results
        .iter()
        .find(|result| {
            result["ruleId"] == "planguard/replace"
                && result["properties"]["address"] == "aws_instance.web"
        })
        .unwrap();
    assert_eq!(replace_warning["level"], "warning");
}

#[test]
fn markdown_output_is_a_paste_ready_report() {
    let output = run(&["review", RISKY, "--markdown"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);

    assert!(text.starts_with("# PlanGuard report"));
    assert!(text.contains("| Plan | `examples/risky-plan.json` |"));
    assert!(text.contains("| Resources | 10 |"));
    assert!(text.contains("| Changes | 9 changes (4 create, 2 update, 1 delete, 2 replace) |"));
    assert!(text.contains("## Critical (5)"));
    assert!(text.contains("| `aws_db_instance.main` | Destroy |"));
    assert!(text.contains("## Info (1)"));
    assert!(text.contains("**Summary: 10 resources"));
}

#[test]
fn stdin_is_read_as_a_plan_and_mapped_to_a_sarif_uri() {
    let input = fs::read(RISKY).unwrap();

    let text = run_with_stdin(&["review", "-"], &input);
    assert_eq!(text.status.code(), Some(0), "{}", stderr(&text));
    assert!(stdout(&text).contains("Plan      stdin"));

    let sarif = run_with_stdin(&["review", "-", "--sarif"], &input);
    assert_eq!(sarif.status.code(), Some(0));
    let report = json(&sarif);
    assert_eq!(
        report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "terraform-plan.json"
    );
}

#[test]
fn absolute_plan_paths_use_the_basename_in_sarif() {
    let temp = TempDir::new().unwrap();
    let copied = temp.path().join("nightly.json");
    fs::copy(RISKY, &copied).unwrap();

    let output = run(&["review", copied.to_str().unwrap(), "--sarif"]);
    assert_eq!(output.status.code(), Some(0));
    let report = json(&output);
    assert_eq!(
        report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "nightly.json"
    );
}

#[test]
fn empty_plan_is_valid_and_has_no_findings() {
    let temp = TempDir::new().unwrap();
    let plan = temp.path().join("empty.json");
    fs::write(&plan, r#"{"format_version":"1.2","resource_changes":[]}"#).unwrap();

    let output = run(&[
        "review",
        plan.to_str().unwrap(),
        "--json",
        "--fail-on",
        "any",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let report = json(&output);
    assert_eq!(report["summary"]["total"], 0);
    assert_eq!(report["summary"]["resources"], 0);
    assert_eq!(report["summary"]["changes"]["create"], 0);
}

#[test]
fn invalid_state_and_future_plans_fail_with_guidance() {
    let temp = TempDir::new().unwrap();

    let malformed = temp.path().join("malformed.json");
    fs::write(&malformed, "{ not json").unwrap();
    let output = run(&["review", malformed.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not valid Terraform plan JSON"));

    let state = temp.path().join("state.json");
    fs::write(
        &state,
        r#"{"format_version":"1.0","terraform_version":"1.9.5","serial":4,"lineage":"abc","values":{"root_module":{}}}"#,
    )
    .unwrap();
    let output = run(&["review", state.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("Terraform state JSON"));
    assert!(stderr(&output).contains("terraform show -json tfplan"));

    let future = temp.path().join("future.json");
    fs::write(&future, r#"{"format_version":"2.0","resource_changes":[]}"#).unwrap();
    let output = run(&["review", future.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("unsupported plan format version 2.0"));

    let plain = temp.path().join("plain.json");
    fs::write(&plain, r#"{"hello":"world"}"#).unwrap();
    let output = run(&["review", plain.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not a Terraform plan JSON document"));
}

#[test]
fn missing_files_fail_with_a_terraform_hint() {
    let output = run(&["review", "/tmp/does-not-exist-planguard.json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("failed to read"));
    assert!(stderr(&output).contains("terraform show -json"));
}

#[test]
fn output_flags_are_mutually_exclusive() {
    let output = run(&["review", RISKY, "--json", "--sarif"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("cannot be used with"));
    assert!(stdout(&output).is_empty());
}

#[cfg(unix)]
#[test]
fn help_through_a_closed_pipe_exits_zero() {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("read -r _ || true; exec \"$0\" --help")
        .arg(env!("CARGO_BIN_EXE_planguard"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn examples_exist_and_are_files() {
    assert!(Path::new(RISKY).is_file());
    assert!(Path::new(SAFE).is_file());
}
