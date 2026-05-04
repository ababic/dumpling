# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-05-04

### Removed

- **`--include-table` / `--exclude-table`**: these CLI flags and the associated per-table skip logic in the SQL stream processor are removed. Anonymize the full dump, or split/filter dumps outside Dumpling if you need a smaller input.

### Changed

- **Dump seal runtime JSON:** `include_table` and `exclude_table` remain in the `v=2` payload as empty arrays; only `--format` and the PRNG seed (standard profile) vary among CLI options for the fingerprint.

## [0.6.0] - 2026-05-03

### Added

- **Dump seal** (leading `-- dumpling-seal:` SQL comment): records Dumpling version, security profile, a SHA-256 fingerprint of the resolved policy, and runtime CLI options that affect transforms (`--format` and the effective PRNG seed in standard profile; `null` in hardened, where seeds are ignored). When the input already begins with a **matching** seal, the remainder is copied through unchanged; stale or unknown seal lines are stripped and the dump is re-processed. See README for full semantics ([#58](https://github.com/ababic/dumpling/pull/58)).
- **`--stats`**: prints `wall_ms` plus `domain_cache_hits` and `domain_cache_misses` for quick profiling of large runs ([#59](https://github.com/ababic/dumpling/pull/59)).
- **`CONTRIBUTORS.md`** ([#59](https://github.com/ababic/dumpling/pull/59)).

### Changed

- **Domain-mapped replacement values** use shared `Arc<str>` storage so repeated lookups reuse the same allocation ([#59](https://github.com/ababic/dumpling/pull/59)).

## [0.5.0] - 2026-05-03

### Added

- **First-class strategies** `email`, `name`, `first_name`, `last_name`, and `phone` in config (same generators as `faker = "internet::SafeEmail"`, `name::Name`, `name::FirstName`, `name::LastName`, and locale-aware phone). Strategy names are normalized to lowercase at load.

### Changed

- **Random-path faker/phone/PII**: one reused `StdRng` on `AnonymizerRegistry` instead of re-seeding per cell.
- **`faker` locale resolution**: `resolved_locale_key` avoids allocating a `String` per faker call when locale is `en` or absent.

### Performance

- Larger default I/O buffers; fewer per-line and per-row allocations on the SQL stream path (INSERT/COPY parsing and row filters).

## [0.4.3] - 2026-05-03

### Fixed

- **COPY row integrity after anonymization**: Control characters in anonymized COPY text fields are escaped so tab/newline/etc. cannot break column alignment or row boundaries ([#53](https://github.com/ababic/dumpling/pull/53)).

## [0.4.2] - 2026-05-03

### Fixed

- **JSON path rules on non-JSON cells**: Path-based `[rules]` anonymization is skipped when the cell is not strict JSON, leaving the original value unchanged (consistent with row-filter JSON path behavior).
- **JSON scalar types in path-based anonymization**: Replacements at JSON paths preserve number and boolean leaf types where possible (numeric and boolean coercion from generated text).

## [0.4.1] - 2026-05-03

### Fixed

- **INSERT row parsing with JSON casts**: Values such as `'{"k":1}'::jsonb` are parsed so the cell’s unescaped payload is valid JSON for JSON path rules and anonymization; trailing casts like `::jsonb` / `::text` are preserved on output.

## [0.4.0] - 2026-05-02

### Added

- **`--dump-decode` CLI**: Decode PostgreSQL **custom-format** (`pg_dump -Fc`) or **directory-format** archives by running **`pg_restore -f -`** (plain SQL to stdout, no database), then anonymize—built for workflows such as **`heroku pg:backups:download`**. Requires PostgreSQL client tools (`pg_restore` on `PATH`, or **`--pg-restore-path`**).
- **`--dump-decode-arg`** (repeatable): Extra arguments forwarded to `pg_restore`.
- **`--dump-decode-keep-input`**: Keep the archive after a successful run. **By default** the `--input` path is **removed** after success so only anonymized output remains. **`--check`** with **`--dump-decode`** requires **`--dump-decode-keep-input`** (otherwise the dump would be deleted before config iteration).

### Changed

- README and mdBook documentation for PostgreSQL archive decoding and Heroku-style examples.

## [0.3.0] - 2026-05-02

### Added

- **`faker` anonymization strategy** backed by the Rust [`fake`](https://crates.io/crates/fake) crate: select generators with `faker = "module::Type"` (for example `internet::SafeEmail`, `name::Name`). Unsupported targets fail at config load with a clear error; extending the allowlist requires a Dumpling release (see `src/faker_dispatch.rs`).
- **JSON path rules in `[rules]`**: column keys such as `payload.profile.email` or `payload__profile__email` apply strategies to nested fields inside JSON text columns while preserving document structure. Conflicts between a whole-column rule and JSON path rules for the same base column are rejected at validation.
- **`format` on `AnonymizerSpec`** for pattern-based faker generators such as `number::NumberWithFormat`.

### Changed

- **Legacy strategy names** `email`, `name`, `first_name`, and `last_name` in config are normalized at load time to `strategy = "faker"` with the same defaults as before (`internet::SafeEmail`, `name::Name`, `name::FirstName`, `name::LastName`), so existing configs keep working.
- **`locale`** applies to both `faker` and `phone` strategies.

## [0.2.0] - 2026-05-02

### Added

- **Env-backed secret references for config salts** (resolves [#11](https://github.com/ababic/dumpling/issues/11)): Salt fields in `.dumplingconf` / `pyproject.toml` now support `${ENV_VAR}` and `${env:ENV_VAR}` substitutions. Referencing a missing environment variable causes a non-zero startup failure with an actionable error message including the config-path and the variable name. Plaintext salts still work for backwards compatibility but emit a startup warning so accidental secret commits are visible in CI output.
- **Hardened security profile** (`--security-profile hardened`): switches random generation from xorshift64\* to the OS CSPRNG (`getrandom`), replaces SHA-256 hashing with HMAC-SHA-256 (using the configured salt as a genuine key), and applies the HMAC construction to deterministic domain byte streams. Hardened mode requires a non-empty global salt and ignores `--seed` / `DUMPLING_SEED`. The active profile is recorded in JSON reports under the `security_profile` field.
- SQLite dump format support (`--format sqlite`): parses `INSERT OR REPLACE INTO` and `INSERT OR IGNORE INTO` variants; the keyword is preserved verbatim in the output. No COPY support (SQLite has none).
- SQL Server / MSSQL dump format support (`--format mssql`): `[bracket]`-quoted identifiers, `N'...'` Unicode string-literal prefix handling, and `nvarchar(n)` / `nchar(n)` column-length extraction for output truncation. No COPY support.
- `--format` CLI flag (`postgres` | `sqlite` | `mssql`, default `postgres`) to declare the input dump dialect.
- GitHub Actions lint workflow for formatting and clippy checks.
- GitHub Actions `Test` workflow for `cargo test --all-targets --all-features`.
- GitHub Actions `Platform compatibility (latest)` workflow for cross-platform builds on latest runner images.
- GitHub Actions `Platform compatibility (matrix)` workflow for manual compatibility runs on explicit platform versions.
- GitHub Actions docs workflow for mdBook build and GitHub Pages deployment.
- GitHub Actions release workflow for tag-based release artifact publishing.
- GitHub Actions `Publish` workflow for cross-platform wheel/sdist builds and PyPI/TestPyPI publishing via `maturin`.
- mdBook documentation structure and release process runbook.
- Python distribution metadata via `pyproject.toml` using `maturin` (`dumpling-cli`) for pip-compatible binary builds.
- Post-transform residual output scanning with detector categories for email, SSN, PAN-like values, and token-like values.
- New CLI flags: `--scan-output` and `--fail-on-findings`.
- Configurable output scan severities and per-category thresholds via `[output_scan]`.
- JSON report section for output scan findings including category, count, threshold, severity, and sample locations.

[0.6.0]: https://github.com/ababic/dumpling/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ababic/dumpling/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/ababic/dumpling/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/ababic/dumpling/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ababic/dumpling/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ababic/dumpling/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ababic/dumpling/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ababic/dumpling/compare/v0.1.0...v0.2.0
