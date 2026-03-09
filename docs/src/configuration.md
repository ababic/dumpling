# Configuration guide

Configuration can be loaded from:

1. `--config <path>` (highest precedence)
2. `.dumplingconf` in the current working directory
3. `[tool.dumpling]` in `pyproject.toml`

If no configuration is found, Dumpling runs as a no-op transformer.

## Baseline config template

```toml
salt = "replace-me"

[rules."public.users"]
email = { strategy = "hash", as_string = true }
name = { strategy = "name" }

[row_filters."public.users"]
retain = [
  { column = "country", op = "eq", value = "US" }
]
delete = [
  { column = "is_admin", op = "eq", value = "true" }
]
```

## Safety recommendations

- Prefer deterministic runs in CI by passing `--seed` (or `DUMPLING_SEED`).
- Treat new or changed anonymization rules as code changes and require review.
- Keep table/column names lowercase in config to avoid case-mismatch surprises.
