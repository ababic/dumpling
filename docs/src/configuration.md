# Configuration guide

## Dump format

Use `--format` to declare the SQL dialect of your input file:

| Value | Description |
|---|---|
| `postgres` (default) | PostgreSQL `pg_dump` plain-text format. Supports `COPY … FROM stdin` blocks, `"double-quoted"` identifiers, `''`-escaped strings. Custom-format (`-Fc`) or directory dumps can be decoded on the fly with `dumpling --dump-decode` (wraps `pg_restore -f -`; requires client tools). By default the archive is deleted after success; use `--dump-decode-keep-input` to retain it. |
| `sqlite` | SQLite `.dump` format. Adds `INSERT OR REPLACE INTO` / `INSERT OR IGNORE INTO` support. No COPY blocks. |
| `mssql` | SQL Server / MSSQL plain SQL. Adds `[bracket]` identifier quoting, `N'…'` Unicode string literals, and `nvarchar(n)` / `nchar(n)` length extraction. No COPY blocks. |

Example:

```bash
dumpling --format sqlite -i data.db.sql -o anonymized.sql
dumpling --format mssql  -i backup.sql  -o anonymized.sql
```

### PostgreSQL custom-format archives (`--dump-decode`)

Heroku PGBackups and many pipelines ship **`pg_dump` custom format** (`-Fc`) or **directory-format** dumps to save bandwidth. Dumpling’s SQL engine still expects **plain text**; use **`--dump-decode`** so Dumpling runs **`pg_restore -f -`** (script to stdout, no database) and pipes the result through the same anonymizer as a normal plain-SQL file.

**Requirements:** PostgreSQL client tools on `PATH` (`pg_restore`), or set **`--pg-restore-path`**. Use **`--dump-decode-arg`** (repeatable) for extra `pg_restore` flags, e.g. `--dump-decode-arg=--no-owner --dump-decode-arg=--no-acl`.

**Input deletion:** After a **fully successful** run, Dumpling **removes** the `--input` path (single file or directory-format folder) by default so only the anonymized output remains. Pass **`--dump-decode-keep-input`** to retain the archive.

**Check mode:** **`--check`** with **`--dump-decode`** requires **`--dump-decode-keep-input`**. Otherwise the default would delete the dump before you can iterate on config.

Example (e.g. after `heroku pg:backups:download`):

```bash
dumpling --dump-decode -i latest.dump -c .dumplingconf -o anonymized.sql
```

Dry run while keeping the downloaded file:

```bash
dumpling --dump-decode --dump-decode-keep-input --check -i latest.dump -c .dumplingconf
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

---

## Dump seal (always on)

Every successful run that writes output prefixes the stream with a single-line SQL comment:

`-- dumpling-seal: v=3 version=<semver> profile=<standard|hardened> sha256=<64 hex chars>`

The `sha256` is over canonical JSON that includes the Dumpling version, the active security profile, a stable encoding of the resolved policy (rules, row filters, column cases, sensitive columns, output scan, global salt), and **runtime options** that affect transforms: `--format` and the effective `--seed` / `DUMPLING_SEED` value in standard profile (`null` in hardened, where seeds are ignored).

If the **input** already begins with a seal line and it **matches** the current run, Dumpling copies the rest of the file through unchanged. If the line looks like a seal but does **not** match (stale policy, different flags, or older `v=`), that line is **dropped** and the dump is re-processed so you do not end up with two seal lines. `--strict-coverage` cannot be combined with a matching seal (table definitions are not scanned in passthrough mode). `--check` writes no output and therefore emits no seal line.

## Hardened security profile

For adversarial risk environments — where an internal or external actor may have partial auxiliary data — use `--security-profile hardened`:

```bash
dumpling --security-profile hardened -i dump.sql -o sanitized.sql
```

### What changes in hardened mode

| Aspect | Standard | Hardened |
|---|---|---|
| Random generation | xorshift64\* seeded from system time | OS CSPRNG (`getrandom`) — non-predictable |
| `hash` strategy | SHA-256(salt \|\| input) | HMAC-SHA-256(key=salt, data=input) |
| Deterministic domain byte stream | SHA-256 CTR-mode | HMAC-SHA-256 CTR-mode |
| Report `security_profile` field | `"standard"` | `"hardened"` |
| `--seed` / `DUMPLING_SEED` | Seeds the PRNG | Ignored (warning emitted) |

### Why this matters

- **Non-predictable output**: xorshift64\* is seeded from system time, which is guessable. The OS CSPRNG cannot be predicted from timing alone.
- **Proper keyed hashing**: `SHA-256(key || data)` is vulnerable to length-extension attacks and weak as a MAC. HMAC-SHA-256 uses the salt as a genuine cryptographic key, providing provable PRF security.
- **Domain separation**: HMAC construction ensures outputs from one salt/key cannot be confused with another.

### Key management guidance

Configure a per-environment secret via an env-backed reference to prevent key leakage:

```toml
# .dumplingconf
salt = "${DUMPLING_HMAC_KEY}"

[rules."public.users"]
ssn = { strategy = "hash", as_string = true }
email = { strategy = "email", domain = "users" }
```

```bash
export DUMPLING_HMAC_KEY="$(openssl rand -base64 32)"
dumpling --security-profile hardened -i dump.sql -o sanitized.sql
```

**Key rotation**: Changing `DUMPLING_HMAC_KEY` will produce entirely different pseudonyms for all salted/domain-mapped columns. If you rely on referential consistency across separately-processed dumps (e.g., snapshots over time), keep the same key or re-anonymize all related dumps together. Rotate keys when:

- A key may have been compromised.
- You intentionally want to break prior referential linkability.

### Report metadata

The JSON report always includes the active security profile:

```json
{
  "security_profile": "hardened",
  "total_rows_processed": 1000,
  ...
}
```

## Faker strategy and the `fake` crate

When you use `strategy = "faker"` with `faker = "module::Type"`, those names align with the Rust [**`fake`**](https://crates.io/crates/fake) crate’s [`faker`](https://docs.rs/fake/latest/fake/faker/index.html) modules (for example `name::FirstName` ↔ `fake::faker::name::raw::FirstName`). Use the upstream docs to discover available generators and options:

- [docs.rs — `fake` (crate overview)](https://docs.rs/fake/latest/fake/)
- [docs.rs — `fake::faker` (all faker submodules)](https://docs.rs/fake/latest/fake/faker/index.html)
- [GitHub — `cksac/fake-rs` (source + README)](https://github.com/cksac/fake-rs)

Dumpling only exposes a **subset** wired in `src/faker_dispatch.rs`; unsupported `module::Type` pairs fail at config load.

## Anonymization strategies

Strategy names and **per-strategy options** (`min`, `scale`, `as_string`, `faker`, …) are documented in the repository **README** under **Anonymization strategies** (each strategy lists only the keys it accepts, plus **Choosing a strategy** for when to prefer cheap vs realistic transforms, and **Cross-cutting options** for `domain`, `unique_within_domain`, and `as_string`). Row filters, JSON path rules, and conditional `column_cases` are also covered in the README before the full TOML example.

The sections below expand on **JSON path rules** (same semantics as the README) and **secret references** in more depth.

## Baseline config template

```toml
salt = "${DUMPLING_GLOBAL_SALT}"

[rules."public.users"]
email = { strategy = "hash", salt = "${env:DUMPLING_USERS_EMAIL_SALT}", as_string = true }
full_name = { strategy = "faker", faker = "name::Name" }

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
