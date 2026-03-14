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

[table_options."public.users"]
auto = true

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
- Treat new or changed anonymization rules as code changes and require review.
- Keep table/column names lowercase in config to avoid case-mismatch surprises.

## Table auto-detection

You can enable per-table strategy inference when no explicit `rules` or `column_cases`
match:

```toml
[table_options."public.users"]
auto = true
```

When `auto = true`, Dumpling infers strategy from the column name (case-insensitive):

- `email*` -> `email`
- `first_name`/`given_name` -> `first_name`
- `last_name`/`surname` -> `last_name`
- `*name*` -> `name`
- `*phone*`/`*mobile*`/`*cell*` -> `phone`
- `*password*`/`*secret*`/`*token*`/`*api_key*`/`*ssn*`/`*credit_card*`/`*account_number*` -> `hash`
- `dob`/`date_of_birth`/`birth_date` -> `date_fuzz`
- `*datetime*`/`*timestamp*`/`*_at` -> `datetime_fuzz`
- `*time*` -> `time_fuzz`
- `*date*` -> `date_fuzz`
