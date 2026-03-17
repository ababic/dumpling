# Dumpling documentation

Dumpling is a streaming anonymizer for plain SQL dumps. It supports PostgreSQL (`pg_dump` plain format), SQLite (`.dump`), and SQL Server / MSSQL (SSMS / mssql-scripter plain SQL output).

This documentation covers the operating model for day-to-day use:

- how to build and run Dumpling locally,
- how to configure transformation behavior safely,
- how CI validates quality before changes merge,
- and how maintainers produce tagged releases.

## Documentation quality gate

All documentation is built with `mdBook` in CI:

- pull requests must pass the docs build job,
- pushes to `main` automatically publish docs to GitHub Pages.

This keeps the docs in a continuously deployable state instead of drifting from the codebase.
