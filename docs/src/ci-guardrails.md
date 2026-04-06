# CI guardrails and policy linting

Dumpling ships with a built-in policy linter (`lint-policy`) and a reference
GitHub Actions workflow so you can catch anonymization policy regressions in
pull requests before they reach production.

---

## `dumpling lint-policy`

```bash
dumpling lint-policy                          # auto-discover config
dumpling lint-policy --config .dumplingconf   # explicit config path
dumpling lint-policy --allow-noop             # treat missing config as empty (no violations)
```

The command loads your configuration, runs a set of policy checks, prints any
violations to stderr, and exits:

| Exit code | Meaning |
|---|---|
| `0` | No violations found |
| `1` | One or more violations found |

### Checks performed

| Code | Severity | Description |
|---|---|---|
| `empty-rules-table` | warning | A `[rules]` entry has no column rules. Likely a stale or incomplete config section. |
| `empty-column-cases-table` | warning | A `[column_cases]` entry has no column cases. |
| `unsalted-hash` | warning | A `hash` strategy is used with no salt (neither per-column `salt` nor global `salt`). Unsalted hashes are reversible via precomputed lookup tables for low-entropy inputs (names, emails, common IDs). |
| `inconsistent-domain-strategy` | error | The same domain name is used with two or more different strategies. This breaks referential integrity: a domain shared between `email` and `name` would try to maintain a bidirectional map between incompatible pseudonym types. |
| `uncovered-sensitive-column` | error | A column listed in `[sensitive_columns]` has no matching anonymization rule or case. The column will pass through unmodified, making the sensitive declaration misleading. |

---

## Recommended CI setup

### Minimal (policy lint only)

```yaml
# .github/workflows/policy-lint.yml
name: Policy Lint

on:
  pull_request:
  push:
    branches: [main]

jobs:
  policy-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release --locked
      - run: ./target/release/dumpling lint-policy
```

This single job will block merges whenever a policy violation is introduced.

### Production-ready: lint + strict coverage + PII scan

Combine `lint-policy` with Dumpling's other CI gates for defence in depth:

```yaml
name: Anonymization CI

on:
  pull_request:
  push:
    branches: [main]

jobs:
  policy-lint:
    name: Policy lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release --locked
      - name: Lint anonymization policy
        run: ./target/release/dumpling lint-policy

  anonymize-and-scan:
    name: Anonymize + residual PII scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release --locked

      - name: Anonymize with strict coverage enforcement
        run: |
          ./target/release/dumpling \
            --strict-coverage \
            --scan-output \
            --fail-on-findings \
            --report report.json \
            -i dump.sql \
            -o sanitized.sql

      - name: Upload anonymization report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: anonymization-report
          path: report.json
```

### Gating on report diff against a baseline

To detect *increases* in risk findings across PRs, store a baseline report as a
CI artifact on your main branch and compare against it in PRs:

```yaml
- name: Download baseline report
  uses: dawidd6/action-download-artifact@v6
  with:
    workflow: ci.yml
    branch: main
    name: anonymization-report
    path: baseline/
  continue-on-error: true   # first run has no baseline yet

- name: Fail if findings increased
  run: |
    BASELINE=$(jq '.output_scan.total_findings // 0' baseline/report.json 2>/dev/null || echo 0)
    CURRENT=$(jq '.output_scan.total_findings' report.json)
    echo "Baseline findings: $BASELINE  Current findings: $CURRENT"
    if [ "$CURRENT" -gt "$BASELINE" ]; then
      echo "ERROR: residual PII findings increased from $BASELINE to $CURRENT"
      exit 1
    fi
```

---

## Tips

- Run `dumpling lint-policy` locally before opening a PR to catch violations
  early: `cargo run -- lint-policy`.
- Treat `error`-severity violations as mandatory fixes; `warning`-severity
  violations are advisory but should be reviewed.
- If you intentionally use `hash` without a salt (e.g. for non-sensitive
  low-cardinality fields), add a `salt = "${ENV_VAR}"` at the global level to
  suppress the `unsalted-hash` warning globally.
- In hardened security profile environments, a global `salt` is required anyway
  (`--security-profile hardened` will error without it), so `unsalted-hash`
  warnings become informational.
