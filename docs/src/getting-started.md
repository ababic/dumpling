# Getting started

This page is the **shortest path** from zero to a first successful run. For strategy details, row filters, dump seals, and CI patterns, continue with the [configuration guide](configuration.md) and the repository `README.md`.

## Prerequisites

- Rust **stable** toolchain (`rustup` recommended). The repo includes `rust-toolchain.toml` (stable + `rustfmt` + `clippy`) so CI and local `cargo` stay aligned.
- `cargo` on your `PATH`

Optional: run **`./scripts/setup-dev.sh`** once from the repo root — it installs toolchain components, **`cargo fetch`**, and a pinned **mdBook** under `.tools/` for the same docs build CI uses.

## Build

```bash
cargo build --release
./target/release/dumpling --help
```

### Python / pip (`dumpling-cli`)

```bash
pip install dumpling-cli
dumpling --help
```

## First anonymization (four steps)

1. **Start from the example policy** — In the repository, copy [`.dumplingconf.example`](https://github.com/ababic/dumpling/blob/main/.dumplingconf.example) to `.dumplingconf` in your project root (or merge the same keys under `[tool.dumpling]` in `pyproject.toml`). Set environment variables for `salt` and any `${…}` references so Dumpling can resolve secrets at startup.
2. **Name your tables and columns** — Open your dump next to the config. `CREATE TABLE`, `COPY … (…)` and `INSERT INTO … (…)` lines list the identifiers you need for `[rules."table"]` or `[rules."schema.table"]`. Trim the example rules to the tables you care about first, then add columns and strategies as you go.
3. **Run Dumpling** — `dumpling -i dump.sql -o sanitized.sql` (add `-c path` if the config is not in the default search path). Use `dumpling --check -i dump.sql` when you only want to know whether anything would change.
4. **Tighten the policy** — Run `dumpling lint-policy` on your config. When you are ready for stricter gates, add `[sensitive_columns]` and use `--strict-coverage`, `--report`, and `--scan-output` as described in the [configuration guide](configuration.md) and the repository `README.md`.

**Draft policy generation (planned)** — A future command will stream a dump and emit a **draft** starter TOML (table/column names and basic DDL hints) so you spend less time spelunking large dumps by hand. Treat that output as **draft** only: review and edit before any production or compliance workflow.

## PostgreSQL custom-format archives

If your input is a PostgreSQL **custom-format** file (not plain SQL), decode and anonymize in one step with **`--dump-decode`** (needs `pg_restore` from PostgreSQL client tools). See [PostgreSQL custom-format archives](configuration.md#postgresql-custom-format-archives---dump-decode) in the configuration guide.

## Test locally (contributors)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo test --all-targets --all-features
```
