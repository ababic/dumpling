# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[0.3.0]: https://github.com/ababic/dumpling/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ababic/dumpling/compare/v0.1.0...v0.2.0
