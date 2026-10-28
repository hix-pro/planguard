use std::io::Write;

use anyhow::{Context, Result};
use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::analyze;
use crate::model::Analysis;
use crate::plan;
use crate::report::{self, TextOptions};

#[derive(Debug, Parser)]
#[command(
    name = "planguard",
    version,
    about = "Review a Terraform plan before it is applied.",
    long_about = "PlanGuard reads the JSON representation of a Terraform plan and reports the changes \
                  worth a second look: destroyed or replaced stateful resources, public ingress, \
                  wildcard IAM policies, public storage, disabled encryption, weakened deletion \
                  protection, drift, and plaintext secrets in the plan file. It reads one file and \
                  never calls a cloud API. Report-only by default.",
    after_help = "Examples:\n  terraform show -json tfplan > plan.json\n  planguard review plan.json\n  planguard review plan.json --markdown\n  planguard review plan.json --fail-on warning\n  cat plan.json | planguard review -\n\nExit codes:\n  0  success, or report-only run with findings\n  1  usage, I/O, or parse error\n  2  findings matched --fail-on"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Review a Terraform plan JSON document.
    Review(ReviewArgs),
}

#[derive(Debug, Args)]
struct ReviewArgs {
    /// Terraform plan JSON, as written by `terraform show -json`. Use `-` for stdin.
    plan: String,

    /// Emit a stable JSON document.
    #[arg(long, conflicts_with_all = ["markdown", "sarif"])]
    json: bool,

    /// Emit a Markdown report.
    #[arg(long, conflicts_with_all = ["json", "sarif"])]
    markdown: bool,

    /// Emit a SARIF 2.1.0 report for GitHub code scanning.
    #[arg(long, conflicts_with_all = ["json", "markdown"])]
    sarif: bool,

    /// Ignore a resource address, resource type, or finding kind. Repeat as needed.
    #[arg(long = "ignore", short = 'i', value_name = "ADDRESS|TYPE|KIND")]
    ignore: Vec<String>,

    /// Exit with code 2 when findings at or above this severity are present.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Fail only on findings that can destroy data or expose it publicly.
    Critical,
    /// Fail on critical findings and errors such as weak encryption or IAM.
    Error,
    /// Fail on critical, error, and warning findings.
    Warning,
    /// Fail on any finding, including informational ones.
    Any,
}

impl FailOn {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Any => "any",
        }
    }
}

/// Parses arguments, reviews the plan, renders output, and returns the exit code.
pub fn run() -> Result<u8> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let display_only = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            if let Err(print_error) = error.print() {
                if is_early_reader_exit(&print_error) {
                    return Ok(0);
                }
                return Err(print_error).context("failed to print help");
            }
            return Ok(if display_only { 0 } else { 1 });
        }
    };

    let Command::Review(args) = cli.command;
    let plan = plan::load(&args.plan)?;
    let analysis = analyze::analyze(&plan, &args.ignore);
    let failing = args
        .fail_on
        .is_some_and(|threshold| threshold_met(&analysis, threshold));

    let output = if args.json {
        report::render_json(&analysis)?
    } else if args.markdown {
        report::render_markdown(&analysis)
    } else if args.sarif {
        report::render_sarif(&analysis)?
    } else {
        report::render_text(
            &analysis,
            TextOptions {
                color: report::color_enabled(),
                fail_on: args.fail_on.map(FailOn::as_str),
                failing,
            },
        )
    };

    write_stdout(&output)?;
    Ok(if failing { 2 } else { 0 })
}

pub fn threshold_met(analysis: &Analysis, threshold: FailOn) -> bool {
    match threshold {
        FailOn::Critical => analysis.summary.critical > 0,
        FailOn::Error => analysis.summary.critical + analysis.summary.error > 0,
        FailOn::Warning => {
            analysis.summary.critical + analysis.summary.error + analysis.summary.warning > 0
        }
        FailOn::Any => analysis.summary.total > 0,
    }
}

fn write_stdout(output: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout.write_all(output.as_bytes()) {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error).context("failed to write output");
    }
    stdout.flush().context("failed to flush output")?;
    Ok(())
}

fn is_early_reader_exit(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::Interrupted
    )
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
            "resource_changes": [{
                "address": "aws_db_instance.main",
                "mode": "managed",
                "type": "aws_db_instance",
                "change": {"actions": ["delete"], "before": {"id": "db-1"}}
            }]
        });
        analyze(&parse(&document.to_string(), "plan.json").unwrap(), &[])
    }

    #[test]
    fn thresholds_are_inclusive() {
        let analysis = analysis();
        assert!(threshold_met(&analysis, FailOn::Critical));
        assert!(threshold_met(&analysis, FailOn::Error));
        assert!(threshold_met(&analysis, FailOn::Warning));
        assert!(threshold_met(&analysis, FailOn::Any));
    }

    #[test]
    fn fail_on_labels_are_stable() {
        assert_eq!(FailOn::Critical.as_str(), "critical");
        assert_eq!(FailOn::Error.as_str(), "error");
        assert_eq!(FailOn::Warning.as_str(), "warning");
        assert_eq!(FailOn::Any.as_str(), "any");
    }
}
