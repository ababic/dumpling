<p align="center">
  <img src="assets/logo.svg" width="140" height="140" alt="Dumpling logo: a dumpling with steam" />
</p>

<h1 align="center">Dumpling</h1>

<p align="center">
  <strong>Sanitize SQL dumps before they go anywhere.</strong><br />
  Turn huge <code>pg_dump</code> / SQLite / SQL Server exports into shareable, test-friendly snapshots — no DB connection, no secrets left by accident.
</p>

<p align="center">
  <a href="https://pypi.org/project/dumpling-cli/"><img src="https://img.shields.io/pypi/v/dumpling-cli.svg" alt="PyPI version" /></a>
  <a href="https://pypi.org/project/dumpling-cli/"><img src="https://img.shields.io/pypi/pyversions/dumpling-cli.svg" alt="Python versions" /></a>
  <a href="https://pypi.org/project/dumpling-cli/"><img src="https://img.shields.io/pypi/l/dumpling-cli.svg" alt="PyPI license" /></a>
  <a href="https://github.com/ababic/dumpling/actions/workflows/tests.yml"><img src="https://github.com/ababic/dumpling/actions/workflows/tests.yml/badge.svg" alt="Tests" /></a>
  <a href="https://github.com/ababic/dumpling/actions/workflows/ci.yml"><img src="https://github.com/ababic/dumpling/actions/workflows/ci.yml/badge.svg" alt="Lint" /></a>
  <img src="https://img.shields.io/badge/rust-stable-orange?logo=rust" alt="Rust stable" />
</p>

<p align="center">
  <a href="https://ababic.github.io/dumpling/"><strong>Documentation</strong></a>
  &nbsp;·&nbsp;
  <a href="https://github.com/ababic/dumpling"><strong>GitHub</strong></a>
</p>

<p align="center">
  <sub><em>Disclaimer: This project is entirely vibe-coded, but with strong human guidance, review, and attention to quality and safety.</em></sub>
</p>

---

**Dumpling** reads plain-text SQL dumps (PostgreSQL `pg_dump`, SQLite `.dump`, SQL Server / MSSQL scripts) and rewrites sensitive columns using rules you define in TOML. Everything runs offline on files — ideal for CI, staging share-outs, and compliance-minded workflows.

## Why Dumpling?

- **Offline by design** — works on dump files only; nothing connects to your database.
- **Streams giant files** — line-by-line processing keeps multi‑GB dumps reasonable on modest hardware.
- **Fails loud, not silent** — missing config exits non‑zero and lists where Dumpling looked; use `--allow-noop` only when you mean it.
- **Stable pseudonyms** — optional domain mappings keep the same source value as the same fake value across tables (foreign keys stay consistent).
- **Pipeline-ready** — `--check`, strict coverage, JSON reports, and residual PII scans fit pre-merge gates and release automation.
- **Configure once** — `.dumplingconf` or `[tool.dumpling]` in `pyproject.toml`; install via **Rust** (`cargo`) or **`pip install dumpling-cli`**.

---

## Install

### Rust (from source)

```bash
cargo build --release
./target/release/dumpling --help
```

### Python / pip (`dumpling-cli`)

Dumpling is also published as a pip-installable CLI package:

```bash
pip install dumpling-cli
```

Or install from local source (requires [maturin](https://www.maturin.rs/) as PEP 517 backend):

```bash
pip install .
```

After install the CLI command is the same:

```bash
dumpling --help
```

---

## Usage

```bash
dumpling -i dump.sql -o sanitized.sql           # read from file, write to file
dumpling -i dump.sql --in-place                 # overwrite the input file (atomic swap)
cat dump.sql | dumpling > sanitized.sql         # stream from stdin to stdout
dumpling -i dump.sql -c .dumplingconf           # use explicit config path
dumpling --check -i dump.sql                    # exit 1 if changes would occur, no output
dumpling --stats -i dump.sql -o out.sql         # print summary to stderr
dumpling --report report.json -i dump.sql       # write detailed JSON report of changes/drops
dumpling --strict-coverage --report report.json -i dump.sql --check  # fail on uncovered sensitive columns
dumpling --scan-output --report report.json -i dump.sql               # scan transformed output for residual PII-like patterns
dumpling --scan-output --fail-on-findings --report report.json -i dump.sql --check  # fail if scan thresholds are exceeded
dumpling --include-table '^public\\.' -i dump.sql -o out.sql
dumpling --exclude-table '^audit\\.' -i dump.sql -o out.sql
dumpling --allow-ext dmp -i data.dmp            # restrict processing to specific extensions
dumpling --allow-noop -i dump.sql -o out.sql    # explicitly allow no-op when config is missing
dumpling --format sqlite -i data.db.sql -o out.sql  # process a SQLite .dump file
dumpling --format mssql  -i backup.sql -o out.sql   # process a SQL Server plain-SQL dump
dumpling --security-profile hardened -i dump.sql -o sanitized.sql  # hardened CSPRNG + HMAC mode
dumpling --emit-seal-line -i dump.sql -o sealed.sql                 # prefix output with policy/version fingerprint
dumpling --trust-sealed-dumps -i sealed.sql -o out.sql              # pass through when leading seal matches
dumpling lint-policy                          # lint the anonymization policy config
dumpling lint-policy --config .dumplingconf   # lint with explicit config path
```

Configuration is loaded in this order:

1. `--config <path>` if provided
2. `.dumplingconf` in the current directory
3. `pyproject.toml` `[tool.dumpling]` section

If no configuration is found, Dumpling fails closed by default and exits non-zero.
The error output lists every checked location. Use `--allow-noop` to explicitly
permit no-op behavior.

### Sealed dumps (`--emit-seal-line` / `--trust-sealed-dumps`)

`--emit-seal-line` writes a first-line SQL comment after any replayed input prefix:

`-- dumpling-seal: v=1 version=<semver> profile=<standard|hardened> sha256=<64 hex chars>`

The `sha256` value is over canonical JSON that includes the Dumpling version, the active security profile, and a stable encoding of the resolved policy (rules, row filters, column cases, sensitive columns, output scan, and global salt).

With `--trust-sealed-dumps`, if the input begins with a seal line that matches the current binary version, security profile, and policy fingerprint, Dumpling copies the remainder of the file through unchanged (no INSERT/COPY rewriting). This is opt-in and intended as a pipeline hint, not cryptographic proof. `--strict-coverage` cannot be combined with a matching trusted seal (table definitions are not scanned). `--emit-seal-line` is incompatible with `--check`.

---

## Configuration (TOML)

Both `.dumplingconf` and `[tool.dumpling]` inside `pyproject.toml` use the same schema:

```toml
# Optional global salt for strategies that support it (e.g. hash)
# Prefer env-backed secret references over plaintext.
salt = "${DUMPLING_GLOBAL_SALT}"

# Rules are keyed by either "table" or "schema.table"
[rules."public.users"]
email = { strategy = "email", domain = "customer_identity", unique_within_domain = true }
name  = { strategy = "name", locale = "de_de" }   # German-locale name
ssn   = { strategy = "hash", salt = "${env:DUMPLING_USERS_SSN_SALT}", as_string = true }   # SHA-256 of original (salted)
age   = { strategy = "int_range", min = 18, max = 90 }

[rules."orders"]
credit_card = { strategy = "redact", as_string = true }

# Optional explicit sensitive columns policy list (for strict coverage)
[sensitive_columns]
"public.users" = ["employee_number", "tax_id"]

[output_scan]
# optional allowlist; if omitted, all built-in categories are enabled
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
```

### Anonymization strategies

| Strategy | Description |
|---|---|
| `null` | Set field to SQL `NULL` |
| `redact` | Replace with `REDACTED` (string) |
| `uuid` | Random UUIDv4-like string |
| `hash` | SHA-256 hex of original value; supports per-column `salt` and global `salt` |
| `email` | Safe email address (same generator as `faker = "internet::SafeEmail"`); supports `locale` |
| `name` | Full name (same as `faker = "name::Name"`); supports `locale` |
| `first_name` | First name (same as `faker = "name::FirstName"`); supports `locale` |
| `last_name` | Last name (same as `faker = "name::LastName"`); supports `locale` |
| `phone` | Locale-aware fake phone number (configurable via `locale`); defaults to English format |
| `faker` | Values from the Rust [`fake`](https://crates.io/crates/fake) crate ([docs.rs](https://docs.rs/fake/latest/fake/), [`faker` modules](https://docs.rs/fake/latest/fake/faker/index.html)), chosen by a **string identifier** only (`faker = "module::Type"`, e.g. `internet::SafeEmail`). Config is **data only**: nothing from TOML is compiled or executed as Rust at runtime. Use `locale` for locale-aware generators; optional `min`/`max`, `length`, `format` as documented. Unsupported targets fail at config load. New generators require a **new Dumpling release** (or your own fork), not config-side code. |
| `int_range` | Random integer in `[min, max]` |
| `string` | Random alphanumeric string (`length = 12` by default) |
| `date_fuzz` | Shifts a date by a random number of days in `[min_days, max_days]` (defaults: `-30..30`) |
| `time_fuzz` | Shifts a time-of-day by a random number of seconds in `[min_seconds, max_seconds]` with 24h wraparound (defaults: `-300..300`) |
| `datetime_fuzz` | Shifts a timestamp/timestamptz by a random number of seconds in `[min_seconds, max_seconds]` (defaults: `-86400..86400`) |

**`faker` reference (upstream `fake` crate):** Dumpling’s `faker = "module::Type"` strings mirror the Rust [`fake`](https://crates.io/crates/fake) crate’s [`faker`](https://docs.rs/fake/latest/fake/faker/index.html) module layout. Use these when picking or extending generators:

- [docs.rs — `fake` crate root](https://docs.rs/fake/latest/fake/) (overview, `Fake` / `Dummy` traits, locales)
- [docs.rs — `fake::faker` module index](https://docs.rs/fake/latest/fake/faker/index.html) (per-domain submodules: `address`, `internet`, `name`, …)
- [GitHub — `cksac/fake-rs`](https://github.com/cksac/fake-rs) (source, README with the CLI’s generator name list)

### Secret references

Dumpling resolves secret references in string config fields so plaintext salts/keys
never need to be committed to version control.

| Syntax | Description |
|---|---|
| `${ENV_VAR}` | Value of environment variable `ENV_VAR` |
| `${env:ENV_VAR}` | Value of environment variable `ENV_VAR` (explicit provider prefix) |
| `${file:/path/to/secret}` | Contents of a file (trailing newlines stripped); works with Docker Swarm secrets, Kubernetes mounted secrets, and Vault Agent injected files |

- Missing env references and unreadable/empty files fail fast with a non-zero startup error that includes the config path.
- Plaintext `salt` values still work for backwards compatibility, but Dumpling prints a startup warning because plaintext secrets are insecure.

```toml
# .dumplingconf — keep salts out of source control
salt = "${DUMPLING_GLOBAL_SALT}"

[rules."public.users"]
ssn   = { strategy = "hash", salt = "${env:DUMPLING_USERS_SSN_SALT}" }
email = { strategy = "hash", salt = "${file:/run/secrets/dumpling_email_salt}" }
```

```bash
# Local dev
export DUMPLING_GLOBAL_SALT='local-dev-salt'
export DUMPLING_USERS_SSN_SALT='users-ssn-salt'
dumpling --input dump.sql --check

# CI (injected from your secret store)
export DUMPLING_GLOBAL_SALT="$CI_DUMPLING_GLOBAL_SALT"
export DUMPLING_USERS_SSN_SALT="$CI_DUMPLING_USERS_SSN_SALT"
dumpling --input dump.sql --check --strict-coverage --report coverage.json

# Docker / Kubernetes (file-mounted secrets)
# salt = "${file:/run/secrets/dumpling_hmac_key}" in .dumplingconf
# secret mounted at /run/secrets/dumpling_hmac_key by the orchestrator
dumpling --security-profile hardened --input dump.sql --check
```

### Common column options

- `as_string`: if true, forces the anonymized value to be rendered as a quoted SQL string literal. By default Dumpling preserves the original quoting where possible.
- `domain`: deterministic mapping domain. When set, the same source value always maps to the same pseudonym inside that domain (across tables/columns). **SQL `NULL` inputs are always preserved as `NULL`** — a null FK reference has no source value to map, so no pseudonym is fabricated.
- `unique_within_domain`: when true, different source values are assigned unique pseudonyms within the configured `domain`. NULL values are unaffected and always remain NULL.
- `min_days` / `max_days`: used by `date_fuzz`.
- `min_seconds` / `max_seconds`: used by `time_fuzz` and `datetime_fuzz`.
- `locale`: selects the language/regional format for `email`, `name`, `first_name`, `last_name`, `faker`, and `phone`. Supported values: `en`, `fr_fr`, `de_de`, `it_it`, `pt_br`, `pt_pt`, `ar_sa`, `zh_cn`, `zh_tw`, `ja_jp`, `cy_gb`. Defaults to `en` when not specified.
- `faker`: required when `strategy = "faker"`. A plain string `"module::Type"` (case-insensitive) that maps to a **built-in** generator compiled into Dumpling—not arbitrary Rust or expressions. Names follow [`fake::faker`](https://docs.rs/fake/latest/fake/faker/index.html) (e.g. `internet::SafeEmail` → `faker::internet::SafeEmail` in the crate).
- `format`: used with `faker = "number::NumberWithFormat"`; pattern uses `#` (0–9) and `^` (1–9) per the [`fake` crate docs](https://docs.rs/fake/latest/fake/).

> **Note:** `table_options` are no longer supported; use explicit `rules` and optional `column_cases`.

---

## Strict coverage

`--strict-coverage` enforces that all detected sensitive columns have an explicit anonymization rule.

Sensitive columns are detected via:
- Built-in column-name heuristics (the same patterns used by auto-detection).
- Explicit lists under `[sensitive_columns]`.

A column is considered **covered** only when it has an explicit `rules` entry or at least one `column_cases` entry. When strict coverage fails, Dumpling exits non-zero and reports the uncovered columns.

### Coverage reporting

When `--report <file>` is used, the JSON output includes:

- `sensitive_columns_detected`
- `sensitive_columns_covered`
- `sensitive_columns_uncovered`
- `deterministic_mapping_domains` (columns configured with deterministic domain mapping)
- `output_scan` (when `--scan-output` is enabled), including category counts and sample locations

### CI gate pattern

```bash
dumpling --input dump.sql --check --strict-coverage --report coverage.json
```

This command exits non-zero if:
- Data changes/drops are detected (`--check` semantics), or
- Strict coverage finds uncovered sensitive columns.

---

## Residual PII scan

```bash
dumpling \
  --input dump.sql \
  --check \
  --scan-output \
  --fail-on-findings \
  --report scan-report.json
```

`--scan-output` scans the transformed output for built-in detector categories:

- `email`: email-address-like strings
- `ssn`: U.S. SSN-like values
- `pan`: payment-card-like numbers (Luhn validated)
- `token`: common secret/token formats (JWT, AWS access key IDs, GitHub PAT prefixes, etc.)

When `--fail-on-findings` is set, Dumpling exits non-zero if any configured category exceeds its threshold and meets the configured severity gate.

---

## Input format

Dumpling processes plain-text SQL dump files from multiple sources. Use `--format` to select the dialect (default: `postgres`).

### PostgreSQL (`--format postgres`)

Produced by `pg_dump --format=plain`. Handles:

- `INSERT INTO schema.table (col1, col2, ...) VALUES (...), (...), ...;`
- `COPY schema.table (col1, col2, ...) FROM stdin; ... \.` (tab-delimited with `\N` as NULL)
- `"double-quoted"` identifiers
- `''`-escaped string literals

Binary, custom, and directory formats from `pg_dump` are not parsed directly — Dumpling’s SQL pipeline expects plain text. Use either:

- **`pg_dump --format=plain`** when you control capture, or
- **`dumpling --dump-decode`** with `--input` set to a **custom-format** (`.dump`) or **directory-format** folder: Dumpling runs `pg_restore -f -` and streams the resulting SQL (same as a manual `pg_restore` “script” output, no database required). Requires PostgreSQL client tools on `PATH` (`pg_restore`), or set `--pg-restore-path`. Use `--dump-decode-arg` to pass extra flags (e.g. `--no-owner --no-acl`). **By default** the archive is removed after a fully successful run; pass **`--dump-decode-keep-input`** to retain it. **`--check`** requires **`--dump-decode-keep-input`** so the archive still exists if changes would be detected.

Example (e.g. after `heroku pg:backups:download`):

```bash
dumpling --dump-decode -i latest.dump -c .dumplingconf -o anonymized.sql
```

### SQLite (`--format sqlite`)

Produced by the SQLite CLI `.dump` command or equivalent. Handles:

- Standard `INSERT INTO table (col1, ...) VALUES (...);`
- `INSERT OR REPLACE INTO table (...) VALUES (...);`
- `INSERT OR IGNORE INTO table (...) VALUES (...);`
- `"double-quoted"` identifiers
- `''`-escaped string literals

The `OR REPLACE` / `OR IGNORE` variant keyword is preserved verbatim in the output.

### SQL Server / MSSQL (`--format mssql`)

Produced by SSMS "Script Table as → INSERT To", `mssql-scripter`, or similar tools. Handles:

- `INSERT INTO [schema].[table] ([col1], [col2], ...) VALUES (...), ...;`
- `[bracket]`-quoted identifiers (stripped to unquoted names in output)
- `N'...'` Unicode string literals (the `N` prefix is transparently discarded; value is preserved)
- `nvarchar(n)` and `nchar(n)` column-length declarations (used to truncate generated values)
- `''`-escaped string literals

---

## Row filtering

You can retain or delete rows for specific tables using explicit predicate lists.

- If `retain` is non-empty, a row is kept only if it matches at least one predicate.
- Regardless of `retain`, a row is dropped if it matches any predicate in `delete`.

Supported predicate operators:

| Operator | Description |
|---|---|
| `eq` / `neq` | String compare (case-insensitive if `case_insensitive = true`) |
| `in` / `not_in` | List of values (string compare) |
| `like` / `ilike` | SQL-like patterns (`%` and `_`) |
| `regex` / `iregex` | Rust regex (`iregex` is case-insensitive) |
| `lt` / `lte` / `gt` / `gte` | Numeric compare (values parsed as numbers) |
| `is_null` / `not_null` | No value needed |

Predicates can target nested JSON values using dot notation (`payload.profile.tier`) or Django-style notation (`payload__profile__tier`). For JSON arrays, path segments are evaluated against each element, so list-of-dicts structures can be matched naturally.

### JSON path list targeting

JSON list/array traversal is automatic once a path segment resolves to an array.

- **All elements in an array**: use the next field name directly.
  - `payload.items.kind` or `payload__items__kind`
  - Matches/rewrites `kind` for every object in `items`.
- **Specific array index**: use a numeric segment.
  - `payload.items.0.kind` or `payload__items__0__kind`
  - Targets only the first element.
- **Nested arrays**: combine field and index segments as needed.
  - `payload.groups.members.email`
  - `payload.groups.1.members.0.email`

This path behavior is shared by both `row_filters` predicates and JSON-path anonymization rules in `[rules]`.

```toml
[row_filters."public.users"]
retain = [
  { column = "country", op = "eq",  value = "US" },
  { column = "email",   op = "ilike", value = "%@myco.com" },
  { column = "profile.flags.plan", op = "eq", value = "gold" }
]
delete = [
  { column = "is_admin", op = "eq", value = "true" },
  { column = "email",    op = "ilike", value = "%@example.com" },
  { column = "devices__platform", op = "eq", value = "android" }
]
```

Row filtering works for both `INSERT ... VALUES (...)` and `COPY ... FROM stdin` rows.

---

## Conditional per-column cases

Define default strategies in `rules."<table>"` and add ordered per-column cases in `column_cases."<table>"."<column>"`. For each row and column, Dumpling applies the first matching case; if none match, it falls back to the default from `rules`.

```toml
[rules."public.users"]
email = { strategy = "hash", as_string = true }   # default
name  = { strategy = "name" }

[[column_cases."public.users".email]]
when.any = [{ column = "is_admin", op = "eq", value = "true" }]
strategy = { strategy = "redact", as_string = true }

[[column_cases."public.users".email]]
when.any = [{ column = "country", op = "in", values = ["DE","FR","GB"] }]
strategy = { strategy = "hash", salt = "eu-salt", as_string = true }
```

- `when.any` is OR, `when.all` is AND; you can use either or both. If both are empty, the case matches unconditionally.
- First-match-wins per column; there is no merge or fallthrough.
- Row filtering (`row_filters`) is evaluated before cases; deleted rows are not transformed.

---

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

---

## Policy linting

The `lint-policy` subcommand statically analyses your configuration and flags common issues before they affect a production pipeline.

```bash
dumpling lint-policy                          # auto-discover config
dumpling lint-policy --config .dumplingconf   # explicit config path
```

| Check | Severity | Description |
|---|---|---|
| `empty-rules-table` | warning | A `[rules]` entry has no column rules |
| `empty-column-cases-table` | warning | A `[column_cases]` entry has no column cases |
| `unsalted-hash` | warning | `hash` strategy used without any salt — reversible for low-entropy inputs |
| `inconsistent-domain-strategy` | error | Same domain name used with different strategies — breaks referential integrity |
| `uncovered-sensitive-column` | error | A column in `[sensitive_columns]` has no matching rule or case |

Exits `0` if no violations are found, `1` if any violations exist. Plug it into CI as a pre-merge gate:

```yaml
- run: ./target/release/dumpling lint-policy
```

See the [CI guardrails documentation](docs/src/ci-guardrails.md) for full pipeline recipes including strict-coverage enforcement, residual PII scan gating, and report diffing.

---

## Notes

- This is a streaming transformer; memory usage stays small even for large dumps.
- For CI/CD and production-like workflows, prefer the default fail-closed mode and avoid `--allow-noop` unless a no-op run is intentional.
- For best results, configure strategies compatible with column data types. If you hash an integer column, Dumpling will render a string; most databases can coerce this, but explicit `as_string = false` may help in some cases.
- For length-restricted text columns (`varchar(n)`, `character varying(n)`, `char(n)`, `character(n)`), Dumpling reads `CREATE TABLE` definitions and truncates generated text values to fit within the declared limit.
- Deterministic anonymization for tests: pass `--seed <u64>` or set env `DUMPLING_SEED` to make fuzz strategies reproducible across runs. Note: `--seed` has no effect in `--security-profile hardened`.
- Domain mappings (`domain = "..."`) are deterministic by source value + domain (+ optional salt), so referential joins stay stable across tables within the same dump.

---

## Full documentation

Detailed docs, including the configuration reference and release process, are available at the project's [GitHub Pages site](https://ababic.github.io/dumpling/) (built from `docs/src/`).
