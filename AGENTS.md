# Agents

## Cursor Cloud specific instructions

**Dumpling** is a standalone Rust CLI tool that anonymizes PostgreSQL plain-text SQL dumps. It has no runtime services, databases, or Docker dependencies.

### Build, lint, and test

Standard commands are documented in `docs/src/getting-started.md` and `README.md`:

- `cargo build --release` — build the release binary to `target/release/dumpling`
- `cargo fmt --all -- --check` — check formatting
- `cargo clippy --all-targets --all-features` — lint (warnings exist in the codebase; exit code 0 is passing)
- `cargo test --all-targets --all-features` — run all tests (4 inline tests; all self-contained, no external deps)

### Running the CLI

```bash
./target/release/dumpling -i datetime_sample.sql -o /tmp/out.sql --seed 42
```

Config is loaded from `--config <path>`, `.dumplingconf`, or `pyproject.toml` `[tool.dumpling]` section. Without config, it performs a no-op pass-through.

### Notes

- The Rust toolchain (stable, edition 2021) with `rustfmt` and `clippy` components is required.
- `cargo fetch` in the update script pre-downloads crate dependencies so builds are fast.
- There are existing compiler/clippy warnings in the codebase — these are not errors and do not block CI.
- Deterministic output for testing: use `--seed <u64>` or set env `DUMPLING_SEED`.
