# Configuration guide

Configuration can be loaded from:

1. `--config <path>` (highest precedence)
2. `.dumplingconf` in the current working directory
3. `[tool.dumpling]` in `pyproject.toml`

If no configuration is found, Dumpling fails closed by default and exits non-zero.
Error output includes every checked location. If you intentionally want a no-op
run, pass `--allow-noop`.

## Baseline config template

```toml
salt = "replace-me"

[rules."public.users"]
email = { strategy = "hash", as_string = true }
name = { strategy = "name" }

[row_filters."public.users"]
retain = [
  { column = "country", op = "eq", value = "US" },
  { column = "profile.plan", op = "eq", value = "gold" }
]
delete = [
  { column = "is_admin", op = "eq", value = "true" },
  { column = "devices__platform", op = "eq", value = "android" }
]
```

Nested JSON targeting is supported in predicate `column` values via either:

- dot notation (`payload.profile.tier`)
- Django-style separators (`payload__profile__tier`)

When a JSON path traverses an array, Dumpling checks each element (useful for
list-of-dicts JSON structures).

## Safety recommendations

- Prefer deterministic runs in CI by passing `--seed` (or `DUMPLING_SEED`).
- Keep fail-closed behavior enabled in CI/CD; avoid `--allow-noop` unless a no-op
  run is explicitly intended.
- Treat new or changed anonymization rules as code changes and require review.
- Keep table/column names lowercase in config to avoid case-mismatch surprises.
- `table_options` are no longer supported; define explicit `rules` and optional
  conditional `column_cases` instead.

