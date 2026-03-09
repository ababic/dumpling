# Release process

This project uses **tag-driven releases**.

## Release policy

- Versioning follows Semantic Versioning (`MAJOR.MINOR.PATCH`).
- Every release is tied to an immutable git tag (`vX.Y.Z`).
- The release workflow runs quality checks before publishing artifacts.

## Maintainer checklist

1. Ensure `main` is green in CI.
2. Update `Cargo.toml` version and `CHANGELOG.md`.
3. Open and merge a release preparation PR.
4. Create and push a tag from `main`:

   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

5. Verify the `Release` GitHub Actions workflow passes.
6. Validate uploaded artifacts and checksums from the GitHub Release page.
7. Announce the release with upgrade notes and rollback guidance.

## Python package publishing (PyPI)

Dumpling is also configured for Python packaging via `maturin` (`pyproject.toml`).
The Python distribution name is `dumpling-cli`, while the installed CLI command
is still `dumpling`.

Recommended flow:

1. Install maturin (`pipx install maturin` recommended).
2. Build distributions:

   ```bash
   maturin build --release
   ```

3. Publish to TestPyPI first:

   ```bash
   maturin publish --release --repository testpypi
   ```

4. Validate install from TestPyPI in a clean virtualenv.
5. Publish to PyPI:

   ```bash
   maturin publish --release
   ```

## Rollback guidance

- If a release is faulty, create a new patch release (for example `v1.2.4`) that reverts or fixes the issue.
- Avoid deleting published tags; treat tags as immutable history.
