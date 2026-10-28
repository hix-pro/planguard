# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-28

### Added
- `planguard review <plan.json>` reads `terraform show -json` output and reports destructive, public, and unencrypted changes.
- Checks for stateful destroys and replacements, drift, incomplete or errored plans, public ingress, IAM wildcards and public principals, public storage and databases, disabled encryption, weakened deletion protection, and plaintext secrets.
- Severity-aware rule engine with report-only default and `--fail-on critical|error|warning|any` gating.
- `--ignore <address|type|kind>` to filter findings while keeping the decision visible in the report.
- `--json`, `--markdown`, and `--sarif` output with deterministic ordering.
- Stdin support with `planguard review -`.
- Composite GitHub Action that downloads a prebuilt binary, uploads SARIF by default, and preserves the review exit code.
- Prebuilt release binaries for Linux x86_64, macOS Apple Silicon, and Windows x86_64.
