# Design rationale

This page explains **why Dumpling is shaped the way it is**: the problems it optimizes for, the alternatives we considered, and the strengths that fall out of those choices. It is written for operators and contributors who want the “why,” not only the “how.”

If you want to run Dumpling today, start with [Getting started](getting-started.md). Configuration details live in the [configuration guide](configuration.md).

---

## The problem Dumpling solves

Teams need **realistic, shareable database snapshots** for staging, demos, support reproduction, and analytics sandboxes — without shipping production PII.

That requirement sounds simple until you add constraints common in real pipelines:

- dumps are often **multi-gigabyte** and must run on modest CI runners;
- foreign keys and “same person across tables” must stay **consistent** after rewrite;
- a missing or empty policy must be a **loud failure**, not a silent passthrough;
- compliance and security teams want **evidence** that a given file was processed under a known policy;
- the tool must fit **batch/CI workflows**, not only interactive DBA sessions.

Dumpling is a **streaming, file-based anonymizer** for plain SQL dumps. It never connects to a live database. That single constraint drives most of the design below.

---

## Design pillars (what “good” means here)

| Pillar | What it means in practice |
|---|---|
| **Fail closed** | No config → non-zero exit (lists where Dumpling looked). Opt into passthrough only with `--allow-noop`. |
| **Stream, don’t load** | Line-by-line processing of `INSERT` / `COPY` so multi‑GB dumps stay memory-light. |
| **Deterministic where it matters** | Optional `domain` mapping: same source value → same pseudonym across tables (FK-friendly). |
| **Policy as data** | TOML rules and allowlisted `faker` names — never evaluate user code from config. |
| **CI-native gates** | `--check`, `--strict-coverage`, `lint-policy`, residual `--scan-output`, JSON `--report`, dump seals. |
| **Offline by default** | Works on files (and archive→SQL via `pg_restore`); no production credentials required to sanitize. |

---

## Alternative approaches — and why Dumpling’s model wins

Other ways to “get a scrubbed database” exist. They solve overlapping problems under different trade-offs. Dumpling deliberately picks the **static dump** niche and pushes that model as far as it can go.

### 1. Live-database anonymization (connect and `UPDATE`)

**How it works:** Point a tool at Postgres/MySQL, scan tables, rewrite rows in place or into a clone.

**Strengths of that approach**

- Can use live schema introspection and database constraints.
- Feels familiar to DBAs who already operate against a running instance.

**Why Dumpling prefers files instead**

- **Blast radius:** a live connection needs credentials and network path to data. A dump file can be processed on an isolated runner with no DB access.
- **Repeatability:** the same dump + same policy + same seed/profile → reproducible output. Live `UPDATE` jobs are harder to pin as an artifact.
- **Pipeline fit:** CI already moves artifacts (backup downloads, `pg_dump` outputs). File in → file out matches that shape.
- **Blast-free rehearsal:** you can re-run anonymization until the policy is right without mutating a shared database.

Live anonymizers remain useful when you *must* scrub an already-restored environment. Dumpling is better when the unit of work is a **dump you will restore later**.

### 2. In-database views / dynamic masking

**How it works:** Keep production data; expose masked views or session-level masking policies to lower-privilege users.

**Strengths of that approach**

- No separate sanitized copy to store.
- Masking can follow RBAC and change with the live schema.

**Why Dumpling still exists beside masking**

- Masking does not produce a **portable snapshot** for contractors, demos, or offline analytics.
- Many “we need a DB” workflows require a **full restore** with fake-but-shaped data, not a live view into prod.
- Dumpling’s output is a normal SQL dump: restore anywhere, no vendor masking stack required.

Use dynamic masking for day-to-day least privilege. Use Dumpling when you need a **sanitized artifact**.

### 3. Ad-hoc scripts (Python/`sed`/one-off SQL)

**How it works:** Engineers write custom parsers or regex rewrites for each dump shape.

**Strengths of that approach**

- Maximum flexibility for one weird table.
- No new tool to learn for a tiny team.

**Why a purpose-built tool is better**

- **SQL dumps are hostile:** multi-line `INSERT`s, `COPY … FROM stdin`, quoting, `\N` NULLs, escaped quotes — regexes rot quickly.
- **Consistency bugs are silent:** mismatched email domains across FK-linked tables break restores and tests in confusing ways. Dumpling’s `domain` cache exists specifically to prevent that class of bug.
- **Safety defaults:** scripts default to “do nothing special”; Dumpling defaults to fail-closed, coverage gates, and residual PII scanning.
- **Shared policy:** TOML in-repo is reviewable in PRs; tribal scripts are not.

Scripts are fine for a one-time migration. They are a poor long-term anonymization *platform*.

### 4. “Anonymize after restore” in application code

**How it works:** Load prod dump into staging, then run app factories / Faker in the ORM to overwrite columns.

**Strengths of that approach**

- Reuses application domain knowledge and factories.
- Easy to keep formats that your app already validates.

**Why Dumpling prefers transform-before-restore**

- You still briefly hold **raw PII on disk and in the DB** during restore — often the compliance pain point.
- App factories rarely cover every table (audit logs, JSON blobs, legacy schemas).
- Dumpling runs **before** restore, so staging never sees original values for ruled columns.
- Domain mapping works across tables that may not share an ORM model graph.

Application-level faking remains useful for *generating* synthetic fixtures from scratch. Dumpling is better for *scrubbing an existing dump*.

### 5. Heavyweight commercial data platforms

**How it works:** Enterprise suites with discovery UI, connectors, and policy engines across warehouses and DBs.

**Strengths of that approach**

- Broad connector coverage and vendor support contracts.
- Often includes discovery/classification UIs for large orgs.

**Why Dumpling is often the better fit anyway**

- **Operational weight:** many teams only need “scrub this `pg_dump` in CI.”
- **Inspectable policy:** plain TOML + open-source Rust beats opaque rule UIs when auditors ask “what exactly ran?”
- **Cost and lock-in:** Dumpling is a single binary / `pip install dumpling-cli` with no control plane.
- **Determinism and seals:** dump seals and `--report` give artifact-level provenance without a SaaS sidecar.

If you already run an enterprise platform for cross-system discovery, Dumpling can still be the sharp tool for **SQL dump CI gates**.

### 6. Fully random replacement (no domains)

**How it works:** Every cell gets an independent random value.

**Why Dumpling supports this — but makes domains first-class**

Independent randomness is fine for isolated columns. It **breaks**:

- foreign keys (`users.id` ↔ `orders.user_id`);
- natural keys reused across tables (email, external IDs);
- human debugging (“why doesn’t this order belong to anyone?”).

Dumpling’s `domain` option keeps a deterministic map: same input → same output within a named bucket, optionally with `unique_within_domain`. That is the difference between “technically anonymized” and “still a usable relational database.”

### Summary: choosing an approach

| Need | Prefer |
|---|---|
| Scrub a dump in CI without DB credentials | **Dumpling** |
| Least-privilege access to live prod | Dynamic masking / RBAC |
| Mutate an already-restored staging DB | Live anonymizer |
| One-off weird transform | Script (then graduate to Dumpling if it repeats) |
| Org-wide discovery across many systems | Enterprise platform (± Dumpling for dumps) |

---

## Strengths of the Dumpling codebase (easy tour)

These are the concrete capabilities that make the pillars real.

### Offline and multi-format input

- PostgreSQL plain SQL, plus auto-detect of **custom/directory** archives via `pg_restore`.
- SQLite `.dump` and SQL Server plain scripts via `--format`.
- Gzip streamed in-process; ZIP / nested archives handled with careful temp materialization and cleanup.

You sanitize **artifacts**, not production sockets.

### Streaming SQL state machine

`SqlStreamProcessor` walks modes (`Pass`, `InInsert`, `InCopy`, `InCreateTable`) so huge `VALUES` lists and `COPY` bodies never require loading the whole dump. Quoting and parenthesis depth are tracked so statement boundaries stay correct.

### Rich, allowlisted strategies

From cheap clears (`null`, `redact`, `blank`, empty JSON containers) to realistic fakes (`email`, `name`, `payment_card`, `faker`, date/time fuzz), plus conditional **`keep`** under `column_cases` when some rows must retain the original value. Config only carries **string identifiers**; new generators ship in Dumpling releases (`faker_dispatch`), never as eval’d user code.

### Referential integrity via domains

Optional `domain` + in-memory mapping cache (and optional uniqueness retries) keeps related columns coherent after rewrite. SQL `NULL` stays `NULL` — no fabricated FK targets for missing values.

### Row filters and conditional cases

- `row_filters` retain/delete whole rows before transforms.
- Optional `[[row_filters."<parent>".cascade]]` links keep child rows only when their FK matches a retained parent PK (explicit, shallow, parent-before-child in the dump)—avoids orphan-trimmed graphs without live FK discovery.
- `column_cases` apply first-match-wins strategies per row (including `keep` for allowlist exceptions, or cases-only scrub with keep-by-omission).
- Predicate operators include positive and negating forms (`not_like` / `not_ilike` / `not_regex` / `not_iregex`); invalid Rust `regex` patterns fail closed at config load.
- JSON path rules (dot or Django-style `__`) reach into `json` / `jsonb` text, including list-of-object shapes.

### Schema-aware string lengths

`CREATE TABLE` parsing extracts `varchar(N)` / `char(N)` limits so generated strings truncate to fit — fewer restore failures from oversized fakes.

### Safety and evidence built in

- **Fail-closed** config discovery.
- **Dump seal** comment fingerprinting policy + transform options (skippable with `--no-seal` for pipes).
- **`--report`** JSON audit sidecar (hashes, flags, coverage, scan outcomes).
- **`--strict-coverage`** against `[sensitive_columns]`.
- **Residual PII scan** (`email` / SSN / PAN / token patterns) with fail thresholds.
- **`lint-policy`** for unsalted hashes, inconsistent domains, uncovered sensitive columns, empty rule tables, and invalid regex predicates.
- **`--security-profile hardened`**: OS CSPRNG + HMAC constructions when adversarial risk is in scope.

### Contributor-friendly engineering

- Single Rust crate, inline tests, clippy/fmt as CI gates.
- Clear module boundaries (`settings` → `sql` → `transform` / `filter` / `scan` / `report`).
- Docs as mdBook with PR build checks so the rationale stays next to the code.

---

## What we deliberately do *not* do

These omissions are intentional, not unfinished work:

| Non-goal | Why |
|---|---|
| Connect to a live database | Keeps the trust boundary at “files on disk”; no prod credentials for sanitize jobs. |
| Evaluate Rust/Python from config | Policy stays data; attackers and accidents cannot smuggle code through TOML. |
| Guarantee perfect PII discovery | Scaffolding and scans are aids; humans own the policy. Fail-closed + coverage gates reduce silent gaps. |
| Replace your backup system | Dumpling transforms dumps; it does not schedule or store backups. |
| Be a general SQL rewriter | Scope is anonymization / filtering of dump payloads, not arbitrary migrations. |

---

## How the pieces fit at runtime

```text
  dump file / archive / stdin
            │
            ▼
   resolve input (detect format, decompress, pg_restore if needed)
            │
            ▼
   load & validate TOML policy (secrets → env, fail closed if missing)
            │
            ▼
   stream lines → parse INSERT/COPY rows
            │
            ├─ row filters (retain / delete)
            ├─ column_cases (first match) else rules
            ├─ apply strategy (random or domain-deterministic)
            └─ render cells (respect quoting + varchar limits)
            │
            ▼
   optional residual scan on the write path
            │
            ▼
   dump seal + sanitized SQL out   and/or   --report JSON sidecar
```

Each stage exists because an alternative (load-all parsing, silent missing config, independent random FKs, “trust the rewrite with no scan”) failed real operational needs.

---

## Further reading

- [Getting started](getting-started.md) — shortest path to a first run
- [Configuration guide](configuration.md) — seals, hardened profile, reports, strategies
- [CI guardrails and policy linting](ci-guardrails.md) — gates and audit evidence
- Repository `README.md` — strategy catalog and usage cheat sheet
- `AGENTS.md` — architecture notes for contributors
