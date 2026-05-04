<p align="center">
  <img src="assets/logo.svg" width="140" height="140" alt="Dumpling logo: a dumpling with steam" />
</p>

<h1 align="center">Dumpling</h1>

<p align="center">
  <strong>Sanitize database dumps before they go anywhere.</strong><br />
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

- **Rich built-in strategies** — from fast clears (`null`, `redact`, `blank`, `empty_array` / `empty_object`) and bounded fakes (`int_range`, `decimal`, `string`) to realistic stand-ins (`email`, `name`, `payment_card`, `faker`, date/time fuzz), with optional **`domain`** so the same source value stays consistent across tables.
- **JSON inside columns** — target paths inside `json` / `jsonb` text with the same dot or `__` syntax you use elsewhere; pair with row filters on nested fields.
- **Row-level control** — **`retain`** and **`delete`** predicates (including nested JSON paths) drop or keep whole rows before transforms run.
- **Offline by design** — works on dump files only; nothing connects to your database.
- **Streams giant files** — line-by-line processing keeps multi‑GB dumps reasonable on modest hardware.
- **Fails loud, not silent** — missing config exits non‑zero and lists where Dumpling looked; use `--allow-noop` only when you mean it.
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

## Getting started

Follow these steps once; you will have a working path from “raw dump” to “first sanitized output,” then you can deepen coverage using the rest of this README and the [documentation site](https://ababic.github.io/dumpling/).

1. **Generate a draft policy (recommended)** — Run `dumpling scaffold-config -i dump.sql -o .dumplingconf` to emit a **beta** starter TOML with inferred `[rules]` from column names in `CREATE TABLE`, `INSERT`, and (PostgreSQL) `COPY` headers. Heuristics are **English-oriented**; treat the file as **draft only**—review every rule before production or compliance workflows. Add a global `salt` (for example `salt = "${DUMPLING_SALT}"`) and resolve `${…}` references before anonymizing. Optionally pass **`--infer-json-paths`** to sample up to **five rows per table** (reservoir) and suggest nested JSON keys as `column.path.to.leaf`; use **`--max-json-depth`** if you need a different walk depth (default 24). For PostgreSQL **custom-format** archives, add **`--dump-decode`** (requires **`--input`** and **`--format postgres`**). See `dumpling scaffold-config --help`.
2. **Or start from the example policy** — Copy [`.dumplingconf.example`](.dumplingconf.example) to `.dumplingconf` (or merge under `[tool.dumpling]` in `pyproject.toml`) and edit `[rules]` by hand. Set environment variables for `salt` and any `${…}` references so Dumpling can resolve secrets at startup.
3. **Align rules with your dump** — If you did not use `scaffold-config`, open the dump beside the config: `CREATE TABLE`, `COPY … (…)`, and `INSERT INTO … (…)` lines list identifiers for `[rules."table"]` or `[rules."schema.table"]` (see [Configuration (TOML)](#configuration-toml)). Trim rules to the tables you care about first, then extend columns and strategies as you go.
4. **Run Dumpling** — `dumpling -i dump.sql -o sanitized.sql` (add `-c path` if the config is not in the default search path). Use `dumpling --check -i dump.sql` when you only want to know whether anything would change.
5. **Tighten the policy** — Run `dumpling lint-policy` on your config. When you are ready for stricter gates, add `[sensitive_columns]` and use `--strict-coverage` / `--report` / `--scan-output` as described under [Usage](#usage).

The same flow is spelled out in the docs: [Getting started](https://ababic.github.io/dumpling/getting-started.html).

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
dumpling --allow-ext dmp -i data.dmp            # restrict processing to specific extensions
dumpling --allow-noop -i dump.sql -o out.sql    # explicitly allow no-op when config is missing
dumpling --format sqlite -i data.db.sql -o out.sql  # process a SQLite .dump file
dumpling --format mssql  -i backup.sql -o out.sql   # process a SQL Server plain-SQL dump
dumpling lint-policy                          # lint the anonymization policy config
dumpling lint-policy --config .dumplingconf   # lint with explicit config path
dumpling scaffold-config -i dump.sql -o .dumplingconf   # draft [rules] from column names (beta)
dumpling scaffold-config -i dump.sql -o draft.toml --infer-json-paths   # include JSON path hints (beta)
```

Configuration is loaded in this order:

1. `--config <path>` if provided
2. `.dumplingconf` in the current directory
3. `pyproject.toml` `[tool.dumpling]` section

If no configuration is found, Dumpling fails closed by default and exits non-zero.
The error output lists every checked location. Use `--allow-noop` to explicitly
permit no-op behavior.

The **dump seal** comment prefixed to successful output and **`--security-profile hardened`** are documented in the [configuration guide](https://ababic.github.io/dumpling/configuration.html) (see *Dump seal* and *Hardened security profile*).

---

## Anonymization strategies

Column rules live under `[rules."schema.table"]` (or `[rules."table"]`) as inline tables: `{ strategy = "<name>", ... }`. **Strategy-specific keys** are documented next to the strategy that accepts them. A few keys apply across many strategies; see [Cross-cutting options](#cross-cutting-options) below.

#### Choosing a strategy (cheaper vs more realistic)

Prefer **lightweight** strategies when nothing downstream requires lifelike values: **`null`**, **`redact`**, **`blank`**, **`empty_array`**, **`empty_object`**, **`string`**, **`int_range`**, and **`decimal`** are cheap to generate (simple constants, random digits/alnum, or bounded numeric shapes). Use **`blank`** for NOT NULL text where you must clear content without SQL NULL; use **`empty_array`** / **`empty_object`** on JSON path rules (or text columns holding JSON) when the document must keep `[]` / `{}` instead of `null` or `""`.

Reach for **richer** strategies when realism matters for restores, demos, or tests that exercise parsers and validators: **`email`**, **`name`**, **`first_name`**, **`last_name`**, **`phone`**, **`faker`**, **`uuid`**, **`hash`**, **`payment_card`**, and the **`date_fuzz` / `time_fuzz` / `datetime_fuzz`** family do more work (formatting, parsing, digest, or upstream generators). If a cheap strategy would break **CHECK constraints**, **NOT NULL**, **foreign-key shape**, or **import tooling** that validates formats, switch to a strategy that emits compatible values—or keep **`domain`** on the heavier strategy so referential consistency is preserved where you need it.

#### `null`

- **Behavior:** emit SQL `NULL` for the cell.
- **Options:** none. (`domain` is rejected.)

#### `redact`

- **Behavior:** replace with the literal `REDACTED`.
- **`as_string`:** if `true`, the replacement is always a single-quoted SQL string; if `false`, it is emitted without quotes (still valid as an identifier-like token in many dumps). When the **original** cell was already a quoted string, Dumpling quotes the output even when `as_string` is omitted—see [Cross-cutting options](#cross-cutting-options).

#### `blank`

- **Behavior:** replace with an **empty string** (`''` in SQL when quoted). If the source cell is SQL **`NULL`**, the cell stays **`NULL`** (same as `null` / `redact` semantics for missing values).
- **Options:** none. (`domain` is rejected.) **`as_string`** is ignored; output is always the empty string literal when non-NULL.

#### `empty_array` / `empty_object`

- **Behavior:** replace with the JSON tokens **`[]`** and **`{}`** as **unquoted** SQL/COPY tokens (so they parse as JSON when the column holds JSON). If the source cell is SQL **`NULL`**, the cell stays **`NULL`**.
- **JSON path rules:** use these on leaves that are JSON **arrays** or **objects** when you need a typed empty container instead of `null` or `""`.
- **Options:** none. (`domain` is rejected.)

#### `uuid`

- **Behavior:** random UUIDv4-like hyphenated hex string.
- **`as_string`:** same meaning as for `redact` / `hash` (force quoted literal vs. unquoted token).

#### `hash`

- **Behavior:** salted digest of the original cell value (SHA-256 by default; see [configuration guide — Hardened security profile](https://ababic.github.io/dumpling/configuration.html#hardened-security-profile) for HMAC mode).
- **`salt`:** optional per-column salt; otherwise the top-level `salt` or registry default applies.
- **`as_string`:** if `true`, force a quoted string literal; if `false`, unquoted hex. Quoted **source** cells are still written quoted when `as_string` is omitted.

#### `email`, `name`, `first_name`, `last_name`, `phone`

- **Behavior:** locale-aware fake values (same underlying generators as the matching `faker` targets).
- **`locale`:** optional; one of `en`, `fr_fr`, `de_de`, `it_it`, `pt_br`, `pt_pt`, `ar_sa`, `zh_cn`, `zh_tw`, `ja_jp`, `cy_gb` (default `en`).
- **Output:** always emitted as a quoted string replacement.

#### `int_range`

- **Behavior:** random integer in the inclusive range `[min, max]` (defaults `min = 0`, `max = 1_000_000`).
- **`min` / `max`:** inclusive bounds; `min` must be ≤ `max`.
- **Output:** always unquoted digits (suitable for integer / JSON number columns).

#### `decimal`

- **Behavior:** random decimal with integer part in `[min, max]` and fractional part of **`scale`** digits (defaults `min = 0`, `max = 1_000_000`, `scale = 2`). Use `scale = 0` for a plain integer string in the same range.
- **`min` / `max`:** inclusive integer-part bounds.
- **`scale`:** number of digits after `.` (0–38).
- **`as_string`:** same as `hash` / `redact` for quoting the full literal.

#### `payment_card`

- **Behavior:** random digit string of length **`length`** (default **16**) with a **valid Luhn check digit**, so `--scan-output` PAN detection treats synthetic values like test cards, not arbitrary digit runs.
- **`length`:** total digit count including check digit; must be 13–19 (PAN lengths).
- **Output:** always a quoted string of digits (no separators).

#### `string`

- **Behavior:** random alphanumeric string.
- **`length`:** character count (default 12); must be ≥ 1 when set.

#### `faker`

- **Behavior:** values from the Rust [`fake`](https://crates.io/crates/fake) crate ([`faker` modules](https://docs.rs/fake/latest/fake/faker/index.html)), selected only by the string **`faker = "module::Type"`** (e.g. `internet::SafeEmail`). Config is **data only**—nothing from TOML is compiled as Rust. Unsupported pairs fail at config load; new generators require a **new Dumpling release** (or a fork), not config-side code.
- **`faker`:** required; maps to a built-in allowlist in `src/faker_dispatch.rs`.
- **`locale`:** optional; same set as the built-in PII strategies when the upstream generator is locale-aware.
- **`min` / `max` / `length` / `format`:** only for/faker combinations that upstream supports (e.g. `number::NumberWithFormat` uses **`format`**: `#` = any digit, `^` = 1–9 per [`fake` docs](https://docs.rs/fake/latest/fake/)).

**Upstream reference:** [docs.rs — `fake`](https://docs.rs/fake/latest/fake/), [docs.rs — `fake::faker`](https://docs.rs/fake/latest/fake/faker/index.html), [GitHub — cksac/fake-rs](https://github.com/cksac/fake-rs).

#### `date_fuzz`, `time_fuzz`, `datetime_fuzz`

- **Behavior:** parse the existing value when possible and shift by a random offset; on parse failure the original string is kept.
- **`date_fuzz`:** **`min_days` / `max_days`** (defaults `-30` … `30`).
- **`time_fuzz` / `datetime_fuzz`:** **`min_seconds` / `max_seconds`** (`time_fuzz` defaults `-300` … `300`; `datetime_fuzz` defaults `-86400` … `86400`).
- **`as_string`:** force quoted literal vs. unquoted token for the emitted date/time/timestamp string.

### Cross-cutting options

These keys are valid on **multiple** strategies (unless validation says otherwise):

- **`domain`:** deterministic mapping bucket. The same non-NULL source value maps to the same pseudonym for that strategy inside the domain (across tables/columns). **SQL `NULL` is always preserved**—no fabricated FK targets.
- **`unique_within_domain`:** when `true` (requires `domain`), different source values are assigned distinct pseudonyms within the domain.
- **`as_string`:** when `true`, force the replacement to render as a **single-quoted SQL string literal**. When `false` or omitted, Dumpling still quotes the output if the **original** cell was quoted (`render_cell` uses `force_quoted || original.was_quoted`). Set `as_string = true` when the source may be unquoted (numeric-looking literals, some `COPY` shapes) but you need a string literal in the dump.

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

## JSON path rules inside columns

When a column stores JSON as text (`json` / `jsonb` dumped as a string), you can target **fields inside the document** with the same path syntax as row filters — but as **keys under `[rules."<table>"]`**. Use **quoted** TOML keys when the path contains dots.

- Dot notation: `"payload.profile.email" = { strategy = "email", domain = "orders_email", as_string = true }`
- Django-style: `"payload__profile__email" = { strategy = "hash", salt = "${env:ORDER_SECRET_SALT}", as_string = true }`

The segment before the first `.` or `__` is the **SQL column name**; the rest is the path inside the parsed JSON. You can use **either** path-level rules for a column **or** one whole-column rule for that column’s base name, not both (Dumpling rejects the conflict at startup). If a path is missing in a row, that rule is skipped for that row. When only path rules apply, the rest of the JSON is left unchanged. Path rules run in **longest-path-first** order. `column_cases` still match the SQL column name only; use `when` predicates with nested `column` paths to branch on JSON content.

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
credit_card = { strategy = "payment_card", length = 16, domain = "order_pan" }
amount = { strategy = "decimal", min = 0, max = 9999, scale = 2, domain = "order_amount" }

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
- Deterministic anonymization for tests: pass `--seed <u64>` or set env `DUMPLING_SEED` to make fuzz strategies reproducible across runs. In hardened security profile, seeds are ignored; see the [configuration guide](https://ababic.github.io/dumpling/configuration.html#hardened-security-profile).
- Domain mappings (`domain = "..."`) are deterministic by source value + domain (+ optional salt), so referential joins stay stable across tables within the same dump.

---

## Full documentation

Detailed docs, including the configuration reference and release process, are available at the project's [GitHub Pages site](https://ababic.github.io/dumpling/) (built from `docs/src/`).
