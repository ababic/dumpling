# AGENTS.md

This file provides structured guidance for AI coding agents working on the **Dumpling** project. Read this before making any code changes.

---

## Project Overview

Dumpling is a streaming, static anonymizer for Postgres plain-SQL dumps produced by `pg_dump`. It reads dump files line by line, anonymizes sensitive column data according to TOML-based configuration rules, and writes sanitized output—without ever connecting to a live database.

Key design goals:
- **Fail-closed**: Missing config is a hard error by default (prevents accidental no-ops in pipelines)
- **Streaming**: Processes dumps line by line so even multi-gigabyte files use minimal memory
- **Deterministic**: Domain mappings ensure the same source value always produces the same pseudonym, preserving foreign-key consistency across tables
- **CI-ready**: `--check` mode, strict coverage enforcement, JSON reports, and a residual-PII scan gate plug into any pipeline

---

## Repository Layout

```
src/
  main.rs        — CLI entrypoint (clap), IO routing, program orchestration
  settings.rs    — Config loading, TOML parsing, secret resolution, validation, normalization
  transform.rs   — All anonymization strategies, PRNG, deterministic domain mapping
  sql.rs         — SQL stream processor: INSERT + COPY parsing, column strategy selection,
                   CREATE TABLE length extraction, sensitive coverage tracking
  filter.rs      — Row-filter predicate evaluation (eq/neq/like/regex/JSON-path/…)
  scan.rs        — Post-transform residual PII scanner (email/SSN/PAN/token regex)
  report.rs      — JSON report data structures and Reporter helper
  compressed_input.rs — gzip/ZIP wrappers; streaming vs temp materialization
  dump_input_resolve.rs — shared `--input` file resolution for anonymize + scaffold-config
  dump_input_detect.rs — PGDMP / directory dumps / MSSQL sniff helpers
docs/src/        — mdBook documentation source
.github/         — CI/CD GitHub Actions workflows
Cargo.toml       — Rust package manifest
pyproject.toml   — Python packaging (maturin) for pip-installable CLI
```

---

## Development Setup

### Prerequisites

- **Rust stable toolchain**: install via [rustup.rs](https://rustup.rs/). No database, Docker, or external services required.

### Build

```bash
cargo build                    # debug build
cargo build --release          # optimized release build
./target/debug/dumpling --help
```

### Run locally

```bash
# Anonymize a dump using a config found in CWD
dumpling -i dump.sql -o sanitized.sql

# Explicit config path
dumpling -i dump.sql -o sanitized.sql -c path/to/.dumplingconf

# Check mode: exit 1 if any changes would be made, write nothing
dumpling --check -i dump.sql

# Allow running with no config (explicitly opt into passthrough)
dumpling --allow-noop -i dump.sql -o out.sql
```

Config is discovered in order: `--config` path → `./.dumplingconf` → `./pyproject.toml [tool.dumpling]`.

---

## Testing

Run the full test suite:

```bash
cargo test --all-targets --all-features
```

All tests are inline `#[cfg(test)]` modules at the bottom of each source file. There are no separate test files.

### Test conventions

- Call `set_random_seed(N)` from `transform.rs` when a test exercises fuzz strategies (`date_fuzz`, `int_range`, etc.) to ensure reproducible, assertion-checkable output.
- Config-parsing tests use a `write_temp_config(contents)` helper that writes a TOML file to `std::env::temp_dir()`. Always clean up temp files after assertions with `let _ = fs::remove_file(path)`.
- Never hard-code absolute paths; always use `std::env::temp_dir()` or `std::env::current_dir()`.
- When testing with `ResolvedConfig` constructed directly (bypassing file loading), initialize all `HashMap` fields explicitly. Construct `OutputScanConfig::default()` for the `output_scan` field.
- Use `proc.process(&mut reader, &mut out)` and then `String::from_utf8(out).unwrap()` to get the full processed SQL output for assertion.

---

## CI Gates

**All three must pass.** Run these locally before pushing:

```bash
cargo fmt --all -- --check                  # formatting
cargo clippy --all-targets --all-features   # linting (zero warnings allowed)
cargo test --all-targets --all-features     # tests
```

Apply auto-formatting with `cargo fmt`. For clippy warnings, fix the code rather than adding `#[allow(...)]` attributes unless there is a specific, documented reason.

---

## Code Conventions

### Imports

Imports **must** be at the top of each module, grouped by standard library / external crates / internal crates. Never place `use` statements inside function bodies unless strictly necessary to resolve a circular import. This is a hard rule.

### Error handling

- Use `anyhow::Result<T>` for fallible public functions that propagate errors toward `main`.
- Attach context with `.with_context(|| format!("…"))` when propagating errors so callers see where the failure originated.
- Use `anyhow::bail!(…)` for early exits with a descriptive message.
- Define new typed errors with `thiserror` only when callers need to match on them (rare in this codebase).

### Naming and normalization

- All config table and column keys are normalized to **lowercase** during `resolve()` in `settings.rs`. The lookup helpers (`lookup_column_rule`, `lookup_column_cases`, `lookup_row_filters`, `lookup_sensitive_columns`) always compare lowercase keys. Pass lowercase when calling them.
- Follow standard Rust naming: `snake_case` for variables, functions, and modules; `PascalCase` for types and enum variants.

### SQL output quoting

The `Replacement` type in `transform.rs` carries a `force_quoted` flag that controls whether the value is wrapped in SQL single quotes on output.

- `Replacement::quoted(v)` — forces single-quoted output (use for strings, emails, names, etc.)
- `Replacement::unquoted(v)` — raw output (use for integers, hashes when not forced to string)
- `Replacement::null()` — renders as `NULL` / `\N` (COPY format)

`render_cell` in `sql.rs` applies: `force_quoted || original.was_quoted` → quoted output. New strategies should use `quoted` for text-like values and `unquoted` for numeric/raw values.

---

## Architecture Deep-Dive

### Config Resolution Flow (`settings.rs`)

1. Load raw TOML bytes from the selected source.
2. Walk the TOML value tree with `resolve_secrets_in_value`: replace `${ENV_VAR}` and `${env:ENV_VAR}` references with environment variable values. Emit stderr warnings for plaintext `salt` values.
3. Deserialize the resolved `toml::Value` into `RawConfig` via serde.
4. Call `validate_raw_config`: verify all `strategy` names are in `KNOWN_STRATEGIES`, check strategy-option compatibility (e.g., `salt` is only valid for `hash`), and validate numeric bounds.
5. Call `resolve()`: normalize all table/column keys to lowercase, producing `ResolvedConfig`.

**Lookup pattern** — all lookup helpers try `schema.table` first, then fall back to bare `table`:

```rust
lookup_column_rule(&cfg, Some("public"), "users", "email")
// tries "public.users" then "users"
```

### SQL Stream Processing (`sql.rs`)

`SqlStreamProcessor::process()` drives a state machine over lines:

| Mode | Trigger | Behavior |
|------|---------|----------|
| `Pass` | Default | Passthrough; detects INSERT/COPY/CREATE TABLE starts |
| `InInsert` | `INSERT INTO …` without trailing `;` | Accumulate until `statement_complete()` detects `;` outside quotes/parens |
| `InCopy` | `COPY … FROM stdin;` | Process tab-delimited rows until `\.` |
| `InCreateTable` | `CREATE TABLE …` | Accumulate until `;`; parse column length limits |

**Per-row pipeline (INSERT and COPY)**:
1. Parse cells (preserving quoting metadata into `Cell` structs).
2. Call `should_keep_row` (row filters) — skip row if filtered.
3. For each column, call `select_strategy_for_cell`:
   - Check `column_cases` for this table+column; iterate in declared order; **first matching `when` wins** (first-match-wins, no fallthrough).
   - Fall back to base `rules` entry for the table+column.
   - Return `None` → cell passes through unchanged.
4. Call `apply_anonymizer` → `Replacement`.
5. Render back to SQL with `render_cell`.

`CREATE TABLE` statements are parsed to extract `varchar(N)` / `character varying(N)` / `char(N)` / `character(N)` / `bpchar(N)` length limits. These are stored in `column_length_limits` and passed to `apply_anonymizer` so generated strings are truncated to fit the column constraint.

### Anonymization (`transform.rs`)

Two code paths:

- **Random path**: `apply_random_anonymizer` — uses a global xorshift64\* PRNG (seeded from system time, `--seed` flag, or `DUMPLING_SEED` env var). Used when `spec.domain` is absent.
- **Deterministic/domain path**: `apply_domain_anonymizer` → `apply_deterministic_anonymizer` — uses a `DeterministicByteStream` (SHA-256 CTR-mode) seeded from `(domain_key, original_value, strategy, salt, collision_index)`. Used when `spec.domain` is set. The `domain_mappings` cache ensures the same source value always maps to the same pseudonym within a domain across tables. When `unique_within_domain = true`, collision detection retries up to `MAX_DOMAIN_UNIQUENESS_ATTEMPTS` (4096) before giving up.

### Row Filtering (`filter.rs`)

`should_keep_row` evaluates `RowFilterSet`:
- `retain` (OR): if non-empty, a row is kept only if at least one predicate matches.
- `delete` (any-match): if any predicate matches, the row is dropped (evaluated after `retain`).

JSON path traversal is supported: `payload.profile.tier` (dot) and `payload__profile__tier` (Django double-underscore). Array elements are traversed by evaluating each item's fields, so list-of-dicts structures work naturally.

### Residual PII Scanning (`scan.rs`)

`ScanningWriter` wraps the output `Write` stream, intercepting bytes and passing them to `OutputScanner`. The scanner applies regex detectors line-by-line for:
- `email`: RFC-like email pattern
- `ssn`: US SSN-like `DDD-DD-DDDD` with invalid area/group/serial number rejection
- `pan`: Payment card numbers (13–19 digits, Luhn-validated)
- `token`: JWT, AWS access key IDs (`AKIA…`), GitHub PATs (`ghp_/gho_/…`), Slack tokens, labeled `key=value` patterns

Findings are aggregated per category and compared against configurable thresholds and severity gates.

---

## How to Add a New Anonymization Strategy

Follow these steps in order. Do not skip any step.

1. **`src/settings.rs` — `KNOWN_STRATEGIES`**: Add the strategy name string to the `KNOWN_STRATEGIES` const slice.

2. **`src/settings.rs` — `AnonymizerSpec`**: If the strategy needs new config fields (e.g., `min_length`, `charset`), add them as `pub field: Option<T>`. Keep them `Option` for backwards compatibility.

3. **`src/settings.rs` — `validate_anonymizer_spec`**: 
   - Add the new strategy-specific fields to the `unsupported` list for all *other* strategies (so using them with the wrong strategy produces a clear error).
   - Add bounds or range validation if applicable (see `int_range` and `string` examples).

4. **`src/transform.rs` — `apply_random_anonymizer`**: Add a `match` arm with the random implementation. Return an appropriate `Replacement` variant.

5. **`src/transform.rs` — `apply_deterministic_anonymizer`**: Add a matching `match` arm for domain-mapping support. Use the provided `DeterministicByteStream` for all randomness to ensure reproducibility.

6. **`src/transform.rs` — `should_enforce_max_len`**: If the strategy generates string values that should be truncated to fit `varchar(N)` columns, make sure it is **not** in the exclusion list. Currently excluded: `null` and `int_range`.

7. **Tests**: Add `#[test]` functions in `src/transform.rs` (unit-test strategy output values) and in `src/sql.rs` (end-to-end pipeline test). Use `set_random_seed(N)` for reproducibility.

8. **`README.md`**: Document the strategy under *Configuration → Anonymization strategies* (per-strategy subsection with accepted options), and mention any new spec fields in `AnonymizerSpec`’s doc comment in `settings.rs`.

**`faker` strategy:** Config only carries string identifiers; Dumpling never evaluates user Rust from config. To ship a new generator, add dispatch in `src/faker_dispatch.rs` and validation in `validate_anonymizer_spec` for the `faker` branch. Upstream reference: [`fake` on docs.rs](https://docs.rs/fake/latest/fake/), [`fake::faker` module index](https://docs.rs/fake/latest/fake/faker/index.html), [source on GitHub](https://github.com/cksac/fake-rs).

---

## How to Add a New Row Filter Predicate Operator

1. **`src/settings.rs` — `Predicate.op` doc comment**: Update the doc comment listing supported operator names.

2. **`src/filter.rs` — `predicate_matches`**: Add a match arm for the new operator string in the appropriate branch (`single-value` or `multi-value`).

3. **Tests**: Add `#[test]` functions in `src/filter.rs`.

4. **`README.md`**: Add a row to the predicate operators table.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Config/startup error, or `--check` mode found changes |
| `2`  | `--strict-coverage`: uncovered sensitive columns detected |
| `3`  | `--fail-on-findings`: output scan thresholds exceeded |

---

## Important Gotchas

- **Fail-closed by default**: If no config is found, Dumpling exits non-zero. Tests that exercise the CLI without providing a config must either supply one or pass `--allow-noop`. Never assume a missing config is safe.

- **`table_options` is intentionally removed**: The `[table_options]` key was deprecated and now deliberately fails with a targeted error pointing to `[rules]` and `[column_cases]`. Do not re-introduce it.

- **`null` and `redact` reject `domain`**: These strategies produce constant outputs regardless of input, so deterministic domain mapping is meaningless. The validator rejects `domain` with these strategies.

- **COPY NULL representation**: In COPY format, `\N` (backslash-N) means NULL. This is different from the string `"NULL"` used in INSERT VALUES format. Handle both correctly.

- **Multi-line INSERT statements**: A single logical INSERT may span many lines (pg_dump does this for large `VALUES` lists). The state machine accumulates lines until `statement_complete()` detects a semicolon that is outside all single-quote and parenthesis context.

- **Column key normalization is mandatory**: All config lookups compare lowercase keys. A table `Public.Users` in the dump matches config key `"public.users"`. Always normalize before lookup; the lookup helpers do this for you if you use them.

- **`AnonymizerSpec` construction in tests**: When building `AnonymizerSpec` directly in tests, you must set all fields explicitly (there is no `Default` impl). Set unused fields to `None`.

- **Clippy is zero-tolerance**: CI runs clippy with all targets and features. Any warning fails the build. Always run `cargo clippy --all-targets --all-features` locally before pushing.

- **Do not use `unsafe` beyond the existing PRNG seed**: The only `unsafe` in the codebase is in `transform.rs` for the global PRNG seed override (`RNG_SEED_OVERRIDE`). Do not add new `unsafe` blocks without a compelling reason and a code comment.

---

## Cursor Cloud specific instructions

This is a pure Rust CLI project with **no external services** (no database, Docker, or network dependencies). The Rust stable toolchain (rustc + cargo) is the only prerequisite.

### One-shot environment (agents and humans)

From the repository root:

```bash
./scripts/setup-dev.sh
```

This installs the **stable** toolchain with **rustfmt** and **clippy** (via `rustup` when available), runs **`cargo fetch`**, and installs a pinned **mdBook** binary under `.tools/` (same version as the Docs CI workflow) so you can run `mdbook build` without a global install. Add `.tools` to `PATH` for convenience, or invoke `.tools/mdbook build` directly.

The repo root **`rust-toolchain.toml`** pins **stable** and the **components** CI uses, so `cargo` automatically selects the right toolchain in fresh checkouts.

### Quick reference

| Task | Command |
|------|---------|
| Setup (toolchain + fetch + mdbook) | `./scripts/setup-dev.sh` |
| Build | `cargo build` |
| Test | `cargo test --all-targets --all-features` |
| Lint | `cargo clippy --all-targets --all-features` |
| Format check | `cargo fmt --all -- --check` |
| Auto-format | `cargo fmt` |
| Docs site (mdBook) | `mdbook build` or `.tools/mdbook build` after setup |
| Run CLI | `./target/debug/dumpling --help` |

### Running the CLI

Dumpling is fail-closed by default — it exits non-zero without a config file. To run a quick smoke test, either provide a `.dumplingconf` via `-c` or pass `--allow-noop`. Example:

```bash
./target/debug/dumpling --allow-noop -i /tmp/some_dump.sql -o /tmp/out.sql
```

### Notes

- All tests are inline `#[cfg(test)]` modules; there are no separate test files or fixtures to manage.
- The update script uses `cargo fetch` to pre-download crate dependencies. A full `cargo build` or `cargo test` will then compile from the local cache without network access.
- No environment variables or secrets are required for building, testing, or running the CLI locally.
