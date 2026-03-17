# Configuration guide

## Dump format

Use `--format` to declare the SQL dialect of your input file:

| Value | Description |
|---|---|
| `postgres` (default) | PostgreSQL `pg_dump` plain-text format. Supports `COPY … FROM stdin` blocks, `"double-quoted"` identifiers, `''`-escaped strings. |
| `sqlite` | SQLite `.dump` format. Adds `INSERT OR REPLACE INTO` / `INSERT OR IGNORE INTO` support. No COPY blocks. |
| `mssql` | SQL Server / MSSQL plain SQL. Adds `[bracket]` identifier quoting, `N'…'` Unicode string literals, and `nvarchar(n)` / `nchar(n)` length extraction. No COPY blocks. |

Example:

```bash
dumpling --format sqlite -i data.db.sql -o anonymized.sql
dumpling --format mssql  -i backup.sql  -o anonymized.sql
```

---

## Configuration sources

Configuration can be loaded from:

1. `--config <path>` (highest precedence)
2. `.dumplingconf` in the current working directory
3. `[tool.dumpling]` in `pyproject.toml`

If no configuration is found, Dumpling fails closed by default and exits non-zero.
Error output includes every checked location. If you intentionally want a no-op
run, pass `--allow-noop`.

## Baseline config template

```toml
salt = "${DUMPLING_GLOBAL_SALT}"

[rules."public.users"]
email = { strategy = "hash", salt = "${env:DUMPLING_USERS_EMAIL_SALT}", as_string = true }
name = { strategy = "name" }

[sensitive_columns]
"public.users" = ["employee_number", "tax_id"]

[output_scan]
enabled_categories = ["email", "ssn", "pan", "token"]
default_threshold = 0
default_severity = "high"
fail_on_severity = "low"
sample_limit_per_category = 5

[output_scan.thresholds]
email = 0
ssn = 0
pan = 0
token = 0

[output_scan.severities]
email = "medium"
ssn = "high"
pan = "critical"
token = "high"
[row_filters."public.users"]
retain = [
  { column = "country", op = "eq", value = "US" },
  { column = "profile.plan", op = "eq", value = "gold" }
]
delete = [
  { column = "is_admin", op = "eq", value = "true" },
  { column = "devices__platform", op = "eq", value = "android" }
]
```

## Secret references

Dumpling supports env-backed secret substitution in string config fields:

- `${ENV_VAR}`
- `${env:ENV_VAR}`

Example:

```toml
salt = "${DUMPLING_GLOBAL_SALT}"

[rules."public.users"]
ssn = { strategy = "hash", salt = "${env:DUMPLING_USERS_SSN_SALT}" }
```

Behavior:

- Missing env references fail fast at startup with a non-zero exit and an actionable error including the config path.
- Plaintext `salt` values are accepted for backward compatibility, but Dumpling prints a warning because plaintext secrets are insecure.
- Unknown providers (anything except `env`) fail startup.

Secure setup snippets:

```bash
# local development
export DUMPLING_GLOBAL_SALT='local-dev-salt'
export DUMPLING_USERS_EMAIL_SALT='users-email-salt'
dumpling --input dump.sql --check

# CI environment (values injected from your secret manager)
export DUMPLING_GLOBAL_SALT="$CI_DUMPLING_GLOBAL_SALT"
export DUMPLING_USERS_EMAIL_SALT="$CI_DUMPLING_USERS_EMAIL_SALT"
dumpling --input dump.sql --check --strict-coverage --report coverage.json
```

Nested JSON targeting is supported in predicate `column` values via either:

- dot notation (`payload.profile.tier`)
- Django-style separators (`payload__profile__tier`)

When a JSON path traverses an array, Dumpling checks each element (useful for
list-of-dicts JSON structures).

## Safety recommendations

- Prefer deterministic runs in CI by passing `--seed` (or `DUMPLING_SEED`).
- Keep fail-closed behavior enabled in CI/CD; avoid `--allow-noop` unless a no-op
  run is explicitly intended.
- Treat new or changed anonymization rules as code changes and require review.
- Keep table/column names lowercase in config to avoid case-mismatch surprises.
- `table_options` are no longer supported; define explicit `rules` and optional
  conditional `column_cases` instead.
- Use `--strict-coverage --report <file> --check` in CI so uncovered sensitive columns fail the build.

## Strict sensitive coverage

`--strict-coverage` enforces explicit policy coverage for sensitive columns.

- Sensitive columns are detected by:
  1. built-in column-name patterns, and
  2. explicit per-table lists under `[sensitive_columns]`.
- A sensitive column is considered covered only if it has an explicit `rules` or `column_cases` entry.
- If uncovered sensitive columns are found, Dumpling exits non-zero.

When `--report` is enabled, coverage fields are added to JSON output:

- `sensitive_columns_detected`
- `sensitive_columns_covered`
- `sensitive_columns_uncovered`

Example CI gate:

```bash
dumpling --input dump.sql --check --strict-coverage --report coverage.json
```

## Residual output scanning

Enable output scanning with:

```bash
dumpling --input dump.sql --scan-output --report scan_report.json
```

Add fail gates with:

```bash
dumpling --input dump.sql --check --scan-output --fail-on-findings --report scan_report.json
```

Output scanning inspects transformed output for common sensitive categories:

- `email`
- `ssn`
- `pan` (Luhn-validated card-like numbers)
- `token` (common secret/token formats)

When `--report` is set, report JSON includes an `output_scan` object with per-category:

- `category`
- `count`
- `threshold`
- `severity`
- `sample_locations` (line + column + snippet where available)
