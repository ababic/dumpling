# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
