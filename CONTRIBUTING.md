# Contributing to Dumpling

Thank you for your interest in contributing! This document covers how to get started, the development workflow, and the standards we hold contributions to.

For AI coding agents: also read `AGENTS.md`, which contains more detailed technical guidance.

---

## Getting Started

### Prerequisites

- **Rust stable toolchain** — install via [rustup.rs](https://rustup.rs/).
- No database, Docker, or external services are required. Dumpling is a pure CLI tool.

### Build and run

```bash
cargo build
./target/debug/dumpling --help

# Or release build
cargo build --release
./target/release/dumpling --help
```

---

## Development Workflow

### Run the tests

```bash
cargo test --all-targets --all-features
```

All tests live in inline `#[cfg(test)]` modules inside each source file. There are no separate test directories.

### Lint and format

```bash
cargo fmt                                   # apply formatting
cargo fmt --all -- --check                  # check formatting (what CI runs)
cargo clippy --all-targets --all-features   # lint (zero warnings required)
```

---

## CI Requirements

Every pull request must pass all three checks:

| Check | Command |
|-------|---------|
| Formatting | `cargo fmt --all -- --check` |
| Lint | `cargo clippy --all-targets --all-features` |
| Tests | `cargo test --all-targets --all-features` |

Run all three locally before opening a PR. Clippy warnings are treated as errors — fix the code rather than adding suppression attributes.

---

## Code Style

- **Imports at the top**: All `use` statements belong at the top of each module. Never place them inside function bodies (except to resolve circular imports).
- **Error handling**: Use `anyhow::Result` and `.with_context(|| …)` for propagated errors; `anyhow::bail!(…)` for early exits. Add descriptive context messages so failures are actionable.
- **Comments**: Only add comments that explain non-obvious intent, trade-offs, or constraints. Do not narrate what the code already says clearly.
- **Unsafe**: The only existing `unsafe` block is the PRNG seed in `transform.rs`. Do not add new `unsafe` code without strong justification.

---

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes with focused, well-described commits.
3. Ensure all three CI checks pass locally.
4. Open a pull request with a clear description of what changed and why.

For bug fixes, include a test that reproduces the bug before your fix and passes after it.

For new features (e.g., a new anonymization strategy or predicate operator), consult the step-by-step guides in `AGENTS.md` and include tests and `README.md` updates.

---

## Documentation

The project documentation is built with [mdBook](https://rust-lang.github.io/mdBook/) from sources in `docs/src/`. To build locally:

```bash
mdbook build
```

The `README.md` in the repository root is the primary reference for users. Keep it up to date when adding new strategies, CLI flags, or config options.

---

## Releasing

See [docs/src/releasing.md](docs/src/releasing.md) for the full release process runbook.
