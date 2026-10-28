# PlanGuard

**Review a Terraform plan before it is applied.**

[![CI](https://github.com/hix-pro/planguard/actions/workflows/ci.yml/badge.svg)](https://github.com/hix-pro/planguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hix-pro/planguard)](https://github.com/hix-pro/planguard/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

`terraform plan` tells you what will change. It does not tell you which changes
deserve a second look. PlanGuard reads the JSON plan and reports the findings
that matter: a database about to be deleted, SSH opened to the world, a wildcard
IAM policy, storage made public, encryption turned off, or a secret left in the
plan file.

One small binary. Reads one file. No cloud calls, account, or telemetry.
Report-only by default.

## Why

A plan is a diff against production, and a line diff treats every change equally.
A tag update and a database replacement scroll past at the same speed. PlanGuard
reads the structured plan and classifies changes by what they can break:

- **Stateful data** — destroys and replacements of databases, volumes, buckets,
  queues, and secrets are called out separately from routine resource churn.
- **Public exposure** — newly opened security-group and firewall rules, public
  bucket ACLs, public databases, and removed public-access blocks.
- **Identity** — wildcard actions, public principals, owner/editor grants, and
  broad policies that appear in the plan.
- **Encryption and safety rails** — disabled encryption and weakened deletion
  protection.
- **Plan health** — drift, incomplete plans, and plans that already report an
  error.
- **Secrets** — attribute paths whose values appear in plaintext in the plan.

PlanGuard reports attribute paths, never secret values.

## Install

Prebuilt binaries are attached to each
[release](https://github.com/hix-pro/planguard/releases/latest) for Linux x86_64,
macOS Apple Silicon, and Windows x86_64.

From source:

```sh
cargo install --git https://github.com/hix-pro/planguard
```

Requires Rust 1.85 or newer.

## Quick start

```sh
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
planguard review plan.json
```

```text
PlanGuard · 0.1.0
Plan      plan.json
Tooling   Terraform 1.9.5 · format 1.2
Resources 10
Changes   9 changes (4 create, 2 update, 1 delete, 2 replace)

critical (5)
  destroy             aws_db_instance.main
    deleting a stateful resource destroys data that this plan cannot recover (removed from configuration)
  public-ingress      aws_security_group.web (ingress)
    tcp/22 is open to 0.0.0.0/0
  iam-policy          aws_iam_policy.deploy (policy)
    policy allows Action "*" on every resource
  public-access       aws_db_instance.analytics (publicly_accessible)
    publicly_accessible is enabled; the database accepts connections from the internet
  public-access       aws_s3_bucket_acl.assets (acl)
    bucket ACL is public-read; anyone can read or write objects in the bucket

...

Summary: 10 resources · 9 changes (4 create, 2 update, 1 delete, 2 replace) · 12 findings (5 critical, 2 errors, 4 warnings, 1 info)
Result: report only (use --fail-on critical|error|warning|any to gate CI)
```

The [`examples/`](examples/) directory contains a
[risky plan](examples/risky-plan.json) and a
[safe plan](examples/safe-plan.json) you can run against immediately.

## What it checks

| Kind | Severity | Looks for |
| --- | --- | --- |
| `destroy` | critical / warning | A resource is deleted. Critical for stateful types, warning otherwise. |
| `replace` | error / warning | A resource is deleted and recreated. Error for stateful types, warning otherwise. |
| `drift` | warning | A managed resource changed outside Terraform before this plan. |
| `public-ingress` | critical / error / warning | A new internet-facing rule. Critical on sensitive ports or all traffic, error on other TCP/UDP ports, warning on other protocols. |
| `iam-policy` | critical / error / warning / info | Public principals, `Action: "*"`, service wildcards, and GCP owner/editor or public bindings. Conditions reduce severity. |
| `public-access` | critical / error / warning | Public bucket ACLs and containers, public databases, disabled public-access blocks, and public storage transitions. |
| `encryption` | error / warning | Encryption disabled on databases, volumes, file systems, caches, and clusters. |
| `deletion-protection` | warning | Deletion protection is turned off, or `force_destroy` is enabled on a bucket. |
| `secret` | info | A plaintext secret-looking value is present in the plan. Only the attribute path is reported. |
| `plan-errored` | critical | The plan reports an error. |
| `plan-incomplete` | warning | The plan is incomplete and needs another round. |

Stateful types include managed databases, DynamoDB tables, EBS/EFS volumes,
S3 and GCS buckets, Azure storage accounts and disks, SQS/SNS, KMS keys,
secrets, and persistent volumes. PlanGuard also treats `*_snapshot`, `*_volume`,
`*_filesystem`, and `*_secret_version` types as stateful.

The rules are deliberately conservative heuristics, not a compliance policy.
They are designed to surface the changes a reviewer would ask about, and to stay
quiet on routine churn.

## Usage

```sh
planguard review plan.json                 # text report
planguard review plan.json --json          # stable JSON
planguard review plan.json --markdown      # paste into a PR or ticket
planguard review plan.json --sarif         # GitHub code scanning
planguard review plan.json --fail-on error # gate CI
planguard review plan.json --ignore aws_db_instance.main
cat plan.json | planguard review -
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success. Report-only mode, or no findings matched `--fail-on`. |
| `1` | Usage, I/O, or plan JSON parse error. |
| `2` | Findings matched `--fail-on`. |

`--fail-on` is inclusive: `error` fails on critical and error findings;
`warning` also includes warnings; `any` includes informational findings.

## Ignoring findings

`--ignore` accepts an exact resource address, a resource type, or a finding kind.
Repeat the flag as needed:

```sh
planguard review plan.json \
  --ignore aws_db_instance.legacy \
  --ignore aws_s3_bucket \
  --ignore secret
```

Ignored patterns are listed in the report so the decision is visible. Ignores
filter findings; they do not remove resources from the plan or change the
change counts. Prefer the narrowest pattern that works: an exact address, then
a type, then a kind.

## GitHub Actions

Generate the JSON plan, then run the action. SARIF is uploaded to code scanning
by default, and the finding exit code is preserved.

```yaml
name: Terraform plan review

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: hashicorp/setup-terraform@v3

      - name: Terraform plan
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > plan.json

      - uses: hix-pro/planguard@v0.1.0
        with:
          plan: plan.json
          fail-on: error
```

The action needs cloud credentials to create the plan. PlanGuard itself only
reads `plan.json` on the runner.

Inputs:

| Input | Default | Description |
| --- | --- | --- |
| `plan` | required | Plan JSON, relative to the workspace or absolute. |
| `fail-on` | empty | `critical`, `error`, `warning`, or `any`. Empty keeps report-only mode. |
| `args` | empty | Extra arguments for `planguard review`. |
| `sarif` | `true` | Write and upload SARIF. Set to `false` for text output. |
| `category` | `planguard` | Code-scanning category for separate runs. |

## JSON output

JSON output is stable within a major version. `schema_version` is `1`.

```json
{
  "schema_version": 1,
  "tool": { "name": "planguard", "version": "0.1.0" },
  "plan": {
    "path": "plan.json",
    "format_version": "1.2",
    "terraform_version": "1.9.5",
    "applyable": true,
    "complete": true,
    "errored": false,
    "outputs_changed": 1,
    "variables": 1
  },
  "ignored": [],
  "summary": {
    "total": 12,
    "critical": 5,
    "error": 2,
    "warning": 4,
    "info": 1,
    "resources": 10,
    "changes": {
      "create": 4,
      "update": 2,
      "delete": 1,
      "replace": 2,
      "read": 1,
      "no_op": 1
    },
    "drift": 1
  },
  "findings": [
    {
      "kind": "destroy",
      "severity": "critical",
      "address": "aws_db_instance.main",
      "type": "aws_db_instance",
      "action": "delete",
      "detail": "deleting a stateful resource destroys data that this plan cannot recover"
    }
  ]
}
```

Findings are ordered by severity, then kind, then resource, then attribute, so
diffs between runs stay small.

## SARIF output

`--sarif` writes SARIF 2.1.0 for GitHub code scanning and other SARIF consumers.
Critical and error findings map to `error`, warnings to `warning`, and
informational findings to `note`. Each result points at the plan file. Stdin
input is reported as `terraform-plan.json`, and absolute plan paths use the
basename.

## Design principles

- **Local-first.** PlanGuard reads a file. It does not call cloud APIs, contact a
  registry, require an account, or collect telemetry.
- **Report-only by default.** A review tool should not fail a build until asked.
- **No secrets in reports.** Secret findings identify the attribute path and say
  the value is present, never the value itself.
- **Deterministic.** Same plan and flags produce the same bytes.
- **Small surface.** One command, one file, three output formats.

## Limitations

- PlanGuard supports Terraform plan JSON format 1.x. Binary plan files must be
  converted with `terraform show -json`.
- It analyzes the plan, not the configuration or the provider schema. Stateful
  detection and secret detection are name-based heuristics.
- Unknown values, variables, and provider defaults are whatever the plan
  contains. PlanGuard does not resolve them.
- It is a review aid, not a policy engine or a replacement for provider-specific
  security controls.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- review examples/risky-plan.json
```

The test suite covers the analyzer, each check family, all four output formats,
thresholds, ignores, stdin, and invalid input.

## License

MIT. See [LICENSE](LICENSE).
