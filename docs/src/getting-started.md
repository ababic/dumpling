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

## First anonymization

1. **Generate a draft policy (recommended)** — From your project root (or anywhere you keep config):

   ```bash
   dumpling scaffold-config -i dump.sql -o .dumplingconf
   ```

   This **beta** subcommand streams the dump once and writes inferred `[rules]` from SQL column names (`CREATE TABLE`, `INSERT`, and PostgreSQL `COPY` column lists). Heuristics are **English-oriented**; output is **draft only**—review and edit every rule, add a top-level **`salt`** (for hashing) and any **`${…}`** secret placeholders before production use.

   Useful flags:

   - **`--infer-json-paths`** — Keep up to **five sampled rows per table** (reservoir) and suggest nested JSON rules as `column.path.leaf`.
   - **`--max-json-depth`** — Cap JSON walking depth when using `--infer-json-paths` (default 24).
   - **`--format`** — `postgres` (default), `sqlite`, or `mssql`.
   - **`--pg-restore-path`** / **`--pg-restore-arg`** — Optional **`pg_restore`** binary and extra arguments when **`--input`** is a PostgreSQL custom-format or directory-format archive (auto-detected with **`--format postgres`**); see [PostgreSQL archives and compressed inputs](configuration.md#postgresql-archives-and-compressed-inputs).

   Run `dumpling scaffold-config --help` for the full flag list.

2. **Or start from the example policy** — Copy [`.dumplingconf.example`](https://github.com/ababic/dumpling/blob/main/.dumplingconf.example) to `.dumplingconf` (or merge under `[tool.dumpling]` in `pyproject.toml`) and author `[rules]` by hand. Set environment variables for `salt` and any `${…}` references.

3. **Align rules with your dump (manual path only)** — If you skipped `scaffold-config`, use `CREATE TABLE`, `COPY … (…)`, and `INSERT INTO … (…)` lines to name `[rules."table"]` or `[rules."schema.table"]` keys. Trim to the tables you care about first.

4. **Run Dumpling** — `dumpling -i dump.sql -o sanitized.sql` (add `-c path` if the config is not in the default search path). Use `dumpling --check -i dump.sql` when you only want to know whether anything would change.

5. **Tighten the policy** — Run `dumpling lint-policy` on your config. When you are ready for stricter gates, add `[sensitive_columns]` and use `--strict-coverage`, `--report`, and `--scan-output` as described in the [configuration guide](configuration.md) and the repository `README.md`.

## PostgreSQL custom-format archives

If your input is a PostgreSQL **custom-format** file or **directory-format** folder (not plain SQL), use **`--format postgres`** (default): Dumpling **auto-detects** the archive and runs **`pg_restore -f -`** (needs `pg_restore` from PostgreSQL client tools). Gzip-wrapped plain SQL is streamed without a temp file; ZIP (or gzip wrapping `PGDMP`) uses a temp extract that is cleaned up afterward. See [PostgreSQL archives and compressed inputs](configuration.md#postgresql-archives-and-compressed-inputs) in the configuration guide.

## Test locally (contributors)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo test --all-targets --all-features
```
