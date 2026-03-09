## Dumpling

Static anonymizer for Postgres plain SQL dumps produced by `pg_dump`. It scans `INSERT` and `COPY FROM stdin` statements and replaces sensitive row data based on configurable rules.

### Install / Build

```bash
cargo build --release
./target/release/dumpling --help
```

### Project automation

- **Lint:** `.github/workflows/ci.yml` runs `cargo fmt` and `cargo clippy` only (fast signal).
- **Test:** `.github/workflows/tests.yml` runs `cargo test --all-targets --all-features`.
- **Compatibility (special case):** `.github/workflows/build-smoke.yml` runs cross-platform release build smoke checks.
- **Docs:** `.github/workflows/docs.yml` builds this repo's mdBook docs and deploys them from `main` to GitHub Pages.
- **Release:** `.github/workflows/release.yml` publishes tagged releases (`v*.*.*`) with checksummed Linux artifacts.

### Docs

```bash
mdbook build
```

Primary docs live under `docs/src/`, including the [release process](docs/src/releasing.md).

### Usage

```bash
dumpling -i dump.sql -o sanitized.sql           # read from file, write to file
dumpling -i dump.sql --in-place                 # overwrite the input file (atomic swap)
cat dump.sql | dumpling > sanitized.sql         # stream from stdin to stdout
dumpling -i dump.sql -c .dumplingconf           # use explicit config path
dumpling --check -i dump.sql                    # exit 1 if changes would occur, no output
dumpling --stats -i dump.sql -o out.sql         # print summary to stderr
dumpling --report report.json -i dump.sql       # write detailed JSON report of changes/drops
dumpling --include-table '^public\\.' -i dump.sql -o out.sql
dumpling --exclude-table '^audit\\.' -i dump.sql -o out.sql
dumpling --allow-ext dmp -i data.dmp            # restrict processing to specific extensions
```

Configuration is loaded in this order:

1) `--config <path>` if provided
2) `.dumplingconf` in the current directory
3) `pyproject.toml` `[tool.dumpling]` section

If no configuration is found, Dumpling performs a no-op transformation.

### Configuration (TOML)

Both `.dumplingconf` and `[tool.dumpling]` inside `pyproject.toml` use the same schema:

```toml
# Optional global salt for strategies that support it (e.g. hash)
salt = "mysalt"

# Rules are keyed by either "table" or "schema.table"
[rules."public.users"]
email = { strategy = "email" }
name  = { strategy = "name" }
ssn   = { strategy = "hash", as_string = true }   # SHA-256 of original (salted)
age   = { strategy = "int_range", min = 18, max = 90 }

[rules."orders"]
credit_card = { strategy = "redact", as_string = true }
```

Supported strategies:

- `null`: set field to SQL NULL
- `redact`: replace with `REDACTED` (string)
- `uuid`: random UUIDv4-like string
- `hash`: SHA-256 hex of original value; supports per-column `salt` and global `salt`
- `email`: random-looking email at `example.com`
- `name`, `first_name`, `last_name`: simple placeholder names
- `phone`: simple US-like phone number `(xxx) xxx-xxxx`
- `int_range`: random integer in `[min, max]`
- `string`: random alphanumeric string, `length = 12` by default
- `date_fuzz`: shifts a date by a random number of days in `[min_days, max_days]` (defaults: `-30..30`)
- `time_fuzz`: shifts a time-of-day by a random number of seconds in `[min_seconds, max_seconds]` with 24h wraparound (defaults: `-300..300`)
- `datetime_fuzz`: shifts a timestamp/timestamptz by a random number of seconds in `[min_seconds, max_seconds]` (defaults: `-86400..86400`)

Common option:

- `as_string`: if true, forces the anonymized value to be rendered as a quoted SQL string literal. By default Dumpling preserves the original quoting where possible.
- `min_days`/`max_days`: used by `date_fuzz`
- `min_seconds`/`max_seconds`: used by `time_fuzz` and `datetime_fuzz`

### Input format

This tool targets the plain-text SQL format from `pg_dump`, handling:

- `INSERT INTO schema.table (col1, col2, ...) VALUES (...), (...), ...;`
- `COPY schema.table (col1, col2, ...) FROM stdin; ... \.` (tab-delimited with `\N` as NULL)

Other `pg_dump` formats (custom/binary/directory) are not supported.

### Row filtering (retain/delete)

You can retain or delete rows for specific tables using explicit predicate lists. Semantics:

- If `retain` is non-empty, a row is kept only if it matches at least one of its predicates.
- Regardless of `retain`, a row is dropped if it matches any predicate in `delete`.

Predicates support these operators on a column:

- `eq`, `neq` (string compare; case-insensitive if `case_insensitive = true`)
- `in`, `not_in` (list of values, string compare)
- `like`, `ilike` (SQL-like: `%` and `_`)
- `regex`, `iregex` (Rust regex; `iregex` is case-insensitive)
- `lt`, `lte`, `gt`, `gte` (numeric compare; values parsed as numbers)
- `is_null`, `not_null` (no value needed)

Example:

```toml
[row_filters."public.users"]
retain = [
  { column = "country", op = "eq",  value = "US" },
  { column = "email",   op = "ilike", value = "%@myco.com" }
]
delete = [
  { column = "is_admin", op = "eq", value = "true" },
  { column = "email",    op = "ilike", value = "%@example.com" }
]
```

Row filtering works for both `INSERT ... VALUES (...)` and `COPY ... FROM stdin` rows.

### Conditional per-column cases (first-match-wins)

Define default strategies in `rules."<table>"` and add ordered per-column cases in `column_cases."<table>"."<column>"`. For each row, for each column, Dumpling applies the first matching case; if none match, it uses the default from `rules`.

Example:

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

Notes:
- `when.any` is OR, `when.all` is AND; you can use either or both. If both are empty, the case matches unconditionally.
- First-match-wins per column; there is no merge/replace or fallthrough flag.
- Row filtering (`row_filters`) is evaluated before cases; deleted rows are not transformed.

### Notes

- This is a streaming transformer; memory usage stays small even for big dumps.
- For best results, configure strategies compatible with column data types. If you hash an integer column, Dumpling will render a string which Postgres can usually coerce, but explicit `as_string = false` may help in some cases.
- If you switch runtimes/branches frequently and see test DB migration issues in your project, remember you can run tests with `pytest --create-db` (project convention).
- Deterministic anonymization for tests: pass `--seed <u64>` or set env `DUMPLING_SEED` to make fuzz strategies reproducible across runs.

