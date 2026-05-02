# Getting started

## Prerequisites

- Rust **stable** toolchain (`rustup` recommended). The repo includes `rust-toolchain.toml` (stable + `rustfmt` + `clippy`) so CI and local `cargo` stay aligned.
- `cargo` on your `PATH`

Optional: run **`./scripts/setup-dev.sh`** once from the repo root — it installs toolchain components, **`cargo fetch`**, and a pinned **mdBook** under `.tools/` for the same docs build CI uses.

## Build

```bash
cargo build --release
./target/release/dumpling --help
```

## Test locally

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo test --all-targets --all-features
```

## Run against a dump

```bash
dumpling -i dump.sql -o sanitized.sql
```

For full command examples and strategy options, see the repository `README.md`.
