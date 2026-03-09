# Agents

## Cursor Cloud specific instructions

**Dumpling** is a single-binary Rust CLI tool that anonymizes PostgreSQL plain SQL dumps. No external services, databases, Docker, or network access required.

### Quick reference

| Task | Command |
|------|---------|
| Build (dev) | `cargo build` |
| Build (release) | `cargo build --release` |
| Test | `cargo test` |
| Lint | `cargo clippy` |
| Run | `./target/release/dumpling -i <input.sql> -o <output.sql> -c <config.toml>` |

### Notes

- The Rust toolchain (1.83+) and clippy are pre-installed. No additional system dependencies are needed.
- There are existing compiler warnings (unused imports, unused variables, clippy suggestions) in the codebase — these are pre-existing and not introduced by setup.
- Use `--seed <u64>` (or env `DUMPLING_SEED`) to make fuzz strategies reproducible across runs — useful for testing.
- Sample input/output for datetime fuzzing: `datetime_sample.sql` / `datetime_out.sql` in the repo root.
- See `README.md` for full CLI usage, configuration schema, supported strategies, row filtering, and column cases documentation.
