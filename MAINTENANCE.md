# Maintenance Guide

This document covers information for contributors and maintainers of the Dumpling project: CI/CD workflows, building docs, and development conventions.

---

## Project automation (CI/CD)

All workflows live under `.github/workflows/`.

| Workflow | File | Purpose |
|---|---|---|
| **Lint** | `ci.yml` | Runs `cargo fmt` and `cargo clippy` on every push/PR (fast signal). |
| **Test** | `tests.yml` | Runs `cargo test --all-targets --all-features`. |
| **Platform compat (latest)** | `platform-compat-latest.yml` | Cross-platform build checks on the latest runner images. |
| **Platform compat (matrix)** | `platform-compat-matrix.yml` | Manual, explicit-version matrix for legacy compatibility checks over time. |
| **Docs** | `docs.yml` | Builds the mdBook docs site and deploys from `main` to GitHub Pages. |
| **Publish** | `publish.yml` | Builds wheels/sdist via `maturin`, publishes to PyPI from tags, and supports manual TestPyPI publication. |
| **Release** | `release.yml` | Publishes tagged releases (`v*.*.*`) with checksummed Linux artifacts. |

---

## Building the docs locally

The project docs are built with [mdBook](https://rust-lang.github.io/mdBook/).

```bash
mdbook build
```

Source files live under `docs/src/`. The [release process runbook](docs/src/releasing.md) is also kept there.

---

## Building the Python package

Dumpling is distributed as a pip-installable CLI via [maturin](https://www.maturin.rs/).

```bash
# Build wheel/sdist locally
maturin build --release

# Install from local source
pip install .
```

See `publish.yml` for how this is automated on tag pushes.

---

## Running tests

```bash
cargo test --all-targets --all-features
```

If you switch branches frequently and see database migration issues in tests that depend on a test DB, run:

```bash
pytest --create-db
```

---

## Releasing

See [docs/src/releasing.md](docs/src/releasing.md) for the full release process runbook.
