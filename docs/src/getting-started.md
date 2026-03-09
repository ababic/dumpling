# Getting started

## Prerequisites

- Rust stable toolchain (edition 2021 compatible)
- `cargo` on your `PATH`

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
