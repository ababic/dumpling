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

Dumpling supports secret substitution in string config fields using two providers:

| Syntax | Provider | Description |
|---|---|---|
| `${ENV_VAR}` | `env` (implicit) | Read from environment variable `ENV_VAR` |
| `${env:ENV_VAR}` | `env` (explicit) | Read from environment variable `ENV_VAR` |
| `${file:/path/to/secret}` | `file` | Read from a file (trailing newlines are stripped) |

Example using both providers:

```toml
salt = "${DUMPLING_GLOBAL_SALT}"

[rules."public.users"]
ssn   = { strategy = "hash", salt = "${env:DUMPLING_USERS_SSN_SALT}" }
email = { strategy = "hash", salt = "${file:/run/secrets/dumpling_email_salt}" }
```

Behavior:

- Missing env references fail fast at startup with a non-zero exit and an actionable error including the config path.
- Missing or empty file references fail fast with a non-zero exit and an actionable error.
- Plaintext `salt` values are accepted for backward compatibility, but Dumpling prints a warning because plaintext secrets are insecure.
- Unknown providers fail startup with a list of supported providers.

### Environment-variable secrets (CI / local dev)

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

### File-mounted secrets (Docker / Kubernetes)

The `file:` provider reads the secret value from a file on disk and trims trailing
newlines. This is the natural format for Docker Swarm secrets
(`/run/secrets/<name>`), Kubernetes mounted secrets, and HashiCorp Vault Agent
injected files.

**Docker Swarm** — declare a secret and mount it into the service:

```yaml
# docker-compose.yml
secrets:
  dumpling_hmac_key:
    external: true

services:
  anonymizer:
    image: your-image
    secrets:
      - dumpling_hmac_key
    environment:
      - DUMPLING_CONFIG=/app/.dumplingconf
```

```toml
# .dumplingconf
salt = "${file:/run/secrets/dumpling_hmac_key}"
```

**Kubernetes** — mount a `Secret` as a volume:

```yaml
# deployment.yaml (excerpt)
volumes:
  - name: dumpling-secrets
    secret:
      secretName: dumpling-keys
volumeMounts:
  - name: dumpling-secrets
    mountPath: /run/secrets
    readOnly: true
```

```toml
# .dumplingconf
salt = "${file:/run/secrets/hmac_key}"
```

**HashiCorp Vault Agent** — inject secrets as files using the `template` stanza:

```hcl
# vault-agent.hcl (excerpt)
template {
  contents     = "{{ with secret \"secret/dumpling\" }}{{ .Data.data.hmac_key }}{{ end }}"
  destination  = "/run/secrets/dumpling_hmac_key"
}
```

```toml
# .dumplingconf
salt = "${file:/run/secrets/dumpling_hmac_key}"
```

Nested JSON targeting is supported in predicate `column` values via either:

- dot notation (`payload.profile.tier`)
- Django-style separators (`payload__profile__tier`)

When a JSON path traverses an array, Dumpling checks each element (useful for
list-of-dicts JSON structures).

### JSON path rules (`json` / `jsonb` columns)

You can anonymise values **inside** a text column that holds JSON using the same path syntax as row-filter predicates, but on **`[rules]` keys**:

- Dot notation: `"payload.profile.email" = { strategy = "email", domain = "orders_email", as_string = true }`
- Django-style: `"payload__profile__email" = { strategy = "hash", salt = "${env:ORDER_SECRET_SALT}", as_string = true }`

The part before the first dot or `__` is the **SQL column name**; the rest is the path inside the parsed JSON document. Use **quoted** keys in TOML when the name contains dots. For a given table, you can use **either** path-level rules for a column **or** one whole-column rule for that column’s base name, not both (Dumpling rejects the conflict at startup). If a path is missing in a given row, that rule is skipped for that row. When only path rules apply (no whole-column rule), the rest of the JSON is left unchanged. Path rules are applied in **longest-path-first** order. `column_cases` still match the SQL column name only; use `when` predicates with nested `column` paths to branch on JSON content.

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
- A sensitive column is considered covered only if it has an explicit `rules` or `column_cases` entry (including JSON path rules whose base name is that column, e.g. `payload.x.y` covers `payload`).
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
