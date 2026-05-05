# Dumpling documentation

Dumpling is a streaming anonymizer for plain SQL dumps. It supports PostgreSQL (`pg_dump` plain format), SQLite (`.dump`), and SQL Server / MSSQL (SSMS / mssql-scripter plain SQL output). For PostgreSQL **custom-format** or **directory-format** archives (e.g. Heroku `pg:backups:download`), Dumpling **auto-detects** them when `--format postgres` (default) and invokes `pg_restore -f -`—see [PostgreSQL archives and compressed inputs](configuration.html#postgresql-archives-and-compressed-inputs) in the configuration guide.

**New here?** Start with [**Getting started**](getting-started.html): generate a **draft** policy with `scaffold-config`, review and add secrets, run Dumpling, then tighten with `lint-policy` and optional CI flags.

This documentation covers the operating model for day-to-day use:

- how to build and run Dumpling locally,
- how to configure transformation behavior safely,
- how CI validates quality before changes merge,
- and how maintainers produce tagged releases.

## Documentation quality gate

The mdBook site is built in CI as follows:

- **Pull requests:** the **Docs (PR)** workflow runs `mdbook build` when docs-related paths change (no deploy).
- **`main`:** the **Docs** workflow builds and deploys to GitHub Pages when docs-related paths change.

This keeps the docs in a continuously deployable state instead of drifting from the codebase.
