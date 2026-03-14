use anyhow::Context;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct RawConfig {
    /// Optional default salt used by certain anonymizers (e.g., hash)
    pub salt: Option<String>,
    /// Rules keyed by either `table` or `schema.table`
    #[serde(default)]
    pub rules: HashMap<String, HashMap<String, AnonymizerSpec>>,
    /// Row filters keyed by either `table` or `schema.table`
    #[serde(default)]
    pub row_filters: HashMap<String, RowFilterSet>,
    /// Per-column conditional cases keyed by table then column
    /// Example: [[column_cases."public.users".email]] { when.any=[...], strategy={...} }
    #[serde(default)]
    pub column_cases: HashMap<String, HashMap<String, Vec<ColumnCase>>>,
    /// Deprecated per-table options (kept only to emit a clear validation error).
    #[serde(default)]
    pub table_options: HashMap<String, TableOptions>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnonymizerSpec {
    /// Strategy name: redact|null|uuid|hash|email|name|first_name|last_name|phone|int_range|string
    pub strategy: String,
    /// if strategy=hash: optional per-column salt override; otherwise ignored
    pub salt: Option<String>,
    /// if strategy=int_range: inclusive min/max
    pub min: Option<i64>,
    pub max: Option<i64>,
    /// if strategy=string: length to generate
    pub length: Option<usize>,
    /// if strategy=date_fuzz: inclusive min/max day shift
    pub min_days: Option<i64>,
    pub max_days: Option<i64>,
    /// if strategy=time_fuzz or datetime_fuzz: inclusive min/max seconds shift
    pub min_seconds: Option<i64>,
    pub max_seconds: Option<i64>,
    /// Force the replacement to be rendered as a SQL string literal
    /// If unset, we attempt to preserve the original quoting style.
    pub as_string: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub salt: Option<String>,
    /// Normalized rule map: lowercase keys for table and column names
    pub rules: HashMap<String, HashMap<String, AnonymizerSpec>>,
    /// Normalized row filters per table
    pub row_filters: HashMap<String, RowFilterSet>,
    /// Normalized column cases per table and column
    pub column_cases: HashMap<String, HashMap<String, Vec<ColumnCase>>>,
    /// For debugging/trace
    pub source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TableOptions {
    /// Deprecated: retained for config parsing so we can fail with a targeted message.
    #[serde(default, rename = "auto")]
    pub _auto: bool,
}

pub fn load_config(
    explicit_path: Option<&PathBuf>,
    allow_noop: bool,
) -> anyhow::Result<ResolvedConfig> {
    // 1) If explicit path is provided, try it.
    if let Some(path) = explicit_path {
        return load_from_file(path).with_context(|| {
            format!(
                "failed loading config from explicit path {}",
                path.display()
            )
        });
    }
    // 2) Look for ./.dumplingconf
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let dot_conf = cwd.join(".dumplingconf");
    let mut checked_locations = vec![dot_conf.clone()];
    if dot_conf.exists() {
        return load_from_file(&dot_conf);
    }
    // 3) Look for ./pyproject.toml with [tool.dumpling]
    let pyproject = cwd.join("pyproject.toml");
    checked_locations.push(pyproject.clone());
    if pyproject.exists() {
        if let Some(resolved) = load_from_pyproject(&pyproject)? {
            return Ok(resolved);
        }
    }
    // 4) No discoverable config
    if allow_noop {
        return Ok(empty_config(None));
    }
    anyhow::bail!(
        "no Dumpling configuration found; searched locations:\n{}",
        format_checked_locations(&checked_locations)
    );
}

fn load_from_file(path: &Path) -> anyhow::Result<ResolvedConfig> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed reading config file {}", path.display()))?;
    let raw: RawConfig = toml::from_str(&content)
        .with_context(|| format!("failed parsing TOML in {}", path.display()))?;
    validate_raw_config(&raw).with_context(|| {
        format!(
            "config semantic validation failed in {}",
            path.to_string_lossy()
        )
    })?;
    Ok(resolve(raw, Some(path.to_path_buf())))
}

fn load_from_pyproject(path: &Path) -> anyhow::Result<Option<ResolvedConfig>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    #[derive(Deserialize)]
    struct PyProject {
        tool: Option<Tool>,
    }
    #[derive(Deserialize)]
    struct Tool {
        dumpling: Option<RawConfig>,
    }
    let pp: PyProject =
        toml::from_str(&content).with_context(|| "failed parsing pyproject.toml".to_string())?;
    if let Some(tool) = pp.tool {
        if let Some(raw) = tool.dumpling {
            validate_raw_config(&raw).with_context(|| {
                format!("config semantic validation failed in {}", path.display())
            })?;
            return Ok(Some(resolve(raw, Some(path.to_path_buf()))));
        }
    }
    Ok(None)
}

fn resolve(raw: RawConfig, source_path: Option<PathBuf>) -> ResolvedConfig {
    let mut normalized_rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
    for (table_key, cols) in raw.rules.into_iter() {
        let table_key_norm = table_key.to_lowercase();
        let mut col_map: HashMap<String, AnonymizerSpec> = HashMap::new();
        for (col, spec) in cols.into_iter() {
            col_map.insert(col.to_lowercase(), spec);
        }
        normalized_rules.insert(table_key_norm, col_map);
    }
    let mut normalized_filters: HashMap<String, RowFilterSet> = HashMap::new();
    for (table_key, set) in raw.row_filters.into_iter() {
        normalized_filters.insert(table_key.to_lowercase(), set);
    }
    let mut normalized_cases: HashMap<String, HashMap<String, Vec<ColumnCase>>> = HashMap::new();
    for (table_key, cols) in raw.column_cases.into_iter() {
        let table_key_norm = table_key.to_lowercase();
        let mut inner: HashMap<String, Vec<ColumnCase>> = HashMap::new();
        for (col, cases) in cols.into_iter() {
            inner.insert(col.to_lowercase(), cases);
        }
        normalized_cases.insert(table_key_norm, inner);
    }
    ResolvedConfig {
        salt: raw.salt,
        rules: normalized_rules,
        row_filters: normalized_filters,
        column_cases: normalized_cases,
        source_path,
    }
}

const KNOWN_STRATEGIES: &[&str] = &[
    "null",
    "redact",
    "uuid",
    "hash",
    "email",
    "name",
    "first_name",
    "last_name",
    "phone",
    "int_range",
    "string",
    "date_fuzz",
    "time_fuzz",
    "datetime_fuzz",
];

fn validate_raw_config(raw: &RawConfig) -> anyhow::Result<()> {
    if !raw.table_options.is_empty() {
        anyhow::bail!(
            "table_options has been removed; define explicit strategies under [rules] and optional conditional overrides under [column_cases]"
        );
    }

    for (table_key, cols) in &raw.rules {
        for (col, spec) in cols {
            let base_path = format!("rules.\"{}\".{}", table_key, col);
            validate_anonymizer_spec(spec, &base_path)?;
        }
    }

    for (table_key, cols) in &raw.column_cases {
        for (col, cases) in cols {
            for (idx, case_spec) in cases.iter().enumerate() {
                let base_path = format!("column_cases.\"{}\".{}[{}].strategy", table_key, col, idx);
                validate_anonymizer_spec(&case_spec.strategy, &base_path)?;
            }
        }
    }

    Ok(())
}

fn validate_anonymizer_spec(spec: &AnonymizerSpec, path: &str) -> anyhow::Result<()> {
    let strategy = spec.strategy.as_str();
    if !KNOWN_STRATEGIES.contains(&strategy) {
        anyhow::bail!(
            "{}.strategy has unknown strategy '{}'; expected one of {}",
            path,
            strategy,
            KNOWN_STRATEGIES.join(", ")
        );
    }

    let mut unsupported: Vec<&str> = Vec::new();
    if spec.salt.is_some() && strategy != "hash" {
        unsupported.push("salt");
    }
    if (spec.min.is_some() || spec.max.is_some()) && strategy != "int_range" {
        if spec.min.is_some() {
            unsupported.push("min");
        }
        if spec.max.is_some() {
            unsupported.push("max");
        }
    }
    if spec.length.is_some() && strategy != "string" {
        unsupported.push("length");
    }
    if (spec.min_days.is_some() || spec.max_days.is_some()) && strategy != "date_fuzz" {
        if spec.min_days.is_some() {
            unsupported.push("min_days");
        }
        if spec.max_days.is_some() {
            unsupported.push("max_days");
        }
    }
    if (spec.min_seconds.is_some() || spec.max_seconds.is_some())
        && !matches!(strategy, "time_fuzz" | "datetime_fuzz")
    {
        if spec.min_seconds.is_some() {
            unsupported.push("min_seconds");
        }
        if spec.max_seconds.is_some() {
            unsupported.push("max_seconds");
        }
    }

    if !unsupported.is_empty() {
        unsupported.sort_unstable();
        unsupported.dedup();
        anyhow::bail!(
            "{} has unsupported option(s) for strategy '{}': {}",
            path,
            strategy,
            unsupported.join(", ")
        );
    }

    match strategy {
        "int_range" => {
            let min = spec.min.unwrap_or(0);
            let max = spec.max.unwrap_or(1_000_000);
            if min > max {
                anyhow::bail!(
                    "{} has invalid bounds: min ({}) must be <= max ({})",
                    path,
                    min,
                    max
                );
            }
        }
        "string" => {
            if let Some(0) = spec.length {
                anyhow::bail!("{}.length must be >= 1", path);
            }
        }
        "date_fuzz" => {
            let min_days = spec.min_days.unwrap_or(-30);
            let max_days = spec.max_days.unwrap_or(30);
            if min_days > max_days {
                anyhow::bail!(
                    "{} has invalid day range: min_days ({}) must be <= max_days ({})",
                    path,
                    min_days,
                    max_days
                );
            }
        }
        "time_fuzz" => {
            let min_seconds = spec.min_seconds.unwrap_or(-300);
            let max_seconds = spec.max_seconds.unwrap_or(300);
            if min_seconds > max_seconds {
                anyhow::bail!(
                    "{} has invalid second range: min_seconds ({}) must be <= max_seconds ({})",
                    path,
                    min_seconds,
                    max_seconds
                );
            }
        }
        "datetime_fuzz" => {
            let min_seconds = spec.min_seconds.unwrap_or(-86_400);
            let max_seconds = spec.max_seconds.unwrap_or(86_400);
            if min_seconds > max_seconds {
                anyhow::bail!(
                    "{} has invalid second range: min_seconds ({}) must be <= max_seconds ({})",
                    path,
                    min_seconds,
                    max_seconds
                );
            }
        }
        _ => {}
    }

    Ok(())
}

/// Helper to lookup a column rule by table identifiers. Tries schema-qualified then unqualified.
pub fn lookup_column_rule<'a>(
    cfg: &'a ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    column: &str,
) -> Option<&'a AnonymizerSpec> {
    let column_norm = column.to_lowercase();
    // Try schema.table if schema provided
    if let Some(s) = schema {
        let key = format!("{}.{}", s.to_lowercase(), table.to_lowercase());
        if let Some(cols) = cfg.rules.get(&key) {
            if let Some(spec) = cols.get(&column_norm) {
                return Some(spec);
            }
        }
    }
    // Try unqualified table
    let key = table.to_lowercase();
    if let Some(cols) = cfg.rules.get(&key) {
        if let Some(spec) = cols.get(&column_norm) {
            return Some(spec);
        }
    }
    None
}

#[derive(Debug, Clone, Deserialize)]
pub struct RowFilterSet {
    /// Keep a row if at least one predicate matches (when non-empty)
    /// Preferred name: retain. Back-compat alias: include_any.
    #[serde(default, alias = "include_any")]
    pub retain: Vec<Predicate>,
    /// Drop a row if any predicate matches
    /// Preferred name: delete. Back-compat alias: exclude_any.
    #[serde(default, alias = "exclude_any")]
    pub delete: Vec<Predicate>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Predicate {
    /// Column name to check (case-insensitive, unquoted).
    /// Supports nested JSON path targeting via:
    /// - dot notation: "payload.profile.tier"
    /// - Django-style notation: "payload__profile__tier"
    pub column: String,
    /// One of: eq, neq, in, not_in, like, ilike, regex, iregex, lt, lte, gt, gte, is_null, not_null
    pub op: String,
    /// Single value for eq/neq/like/ilike/lt/lte/gt/gte
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    /// Multiple values for in/not_in
    #[serde(default)]
    pub values: Option<Vec<serde_json::Value>>,
    /// Case-insensitive match for eq/neq/contains/starts_with/ends_with/like (overridden by ilike)
    #[serde(default)]
    pub case_insensitive: Option<bool>,
}

/// Lookup row filter set by schema-qualified or unqualified table name
pub fn lookup_row_filters<'a>(
    cfg: &'a ResolvedConfig,
    schema: Option<&str>,
    table: &str,
) -> Option<&'a RowFilterSet> {
    if let Some(s) = schema {
        let key = format!("{}.{}", s.to_lowercase(), table.to_lowercase());
        if let Some(set) = cfg.row_filters.get(&key) {
            return Some(set);
        }
    }
    let key = table.to_lowercase();
    cfg.row_filters.get(&key)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ColumnCase {
    /// Conditions for this case
    #[serde(default)]
    pub when: When,
    /// Strategy to apply if conditions match
    pub strategy: AnonymizerSpec,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct When {
    /// Any-of predicates (OR)
    #[serde(default)]
    pub any: Vec<Predicate>,
    /// All-of predicates (AND)
    #[serde(default)]
    pub all: Vec<Predicate>,
}

/// Lookup column cases by schema-qualified or unqualified table and column name
pub fn lookup_column_cases<'a>(
    cfg: &'a ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    column: &str,
) -> Option<&'a Vec<ColumnCase>> {
    let col_norm = column.to_lowercase();
    if let Some(s) = schema {
        let key = format!("{}.{}", s.to_lowercase(), table.to_lowercase());
        if let Some(map) = cfg.column_cases.get(&key) {
            if let Some(cases) = map.get(&col_norm) {
                return Some(cases);
            }
        }
    }
    let key = table.to_lowercase();
    if let Some(map) = cfg.column_cases.get(&key) {
        if let Some(cases) = map.get(&col_norm) {
            return Some(cases);
        }
    }
    None
}

fn empty_config(source_path: Option<PathBuf>) -> ResolvedConfig {
    ResolvedConfig {
        salt: None,
        rules: HashMap::new(),
        row_filters: HashMap::new(),
        column_cases: HashMap::new(),
        source_path,
    }
}

fn format_checked_locations(paths: &[PathBuf]) -> String {
    let mut out = String::new();
    for p in paths {
        if p.exists() {
            if p.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
                out.push_str(&format!(
                    "- {} (found, but missing [tool.dumpling])\n",
                    p.display()
                ));
            } else {
                out.push_str(&format!("- {} (found)\n", p.display()));
            }
        } else {
            out.push_str(&format!("- {} (not found)\n", p.display()));
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::load_config;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct CurrentDirGuard {
        original: PathBuf,
    }

    impl CurrentDirGuard {
        fn change_to(path: &Path) -> Self {
            let original = std::env::current_dir().expect("failed to read current dir");
            std::env::set_current_dir(path).expect("failed to switch to temp dir");
            Self { original }
        }
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    fn make_temp_dir(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock error")
            .as_nanos();
        dir.push(format!(
            "dumpling-settings-test-{}-{}-{}",
            tag,
            std::process::id(),
            stamp
        ));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn write_temp_config(contents: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        path.push(format!("dumpling-settings-test-{}-{}.toml", pid, nanos));
        fs::write(&path, contents).expect("failed to write temp config");
        path
    }

    #[test]
    fn load_config_fails_closed_when_nothing_found() {
        let temp_dir = make_temp_dir("fail-closed");
        {
            let _cwd_guard = CurrentDirGuard::change_to(&temp_dir);
            let err = load_config(None, false).expect_err("expected missing config failure");
            let message = err.to_string();
            assert!(message.contains("no Dumpling configuration found"));
            assert!(message.contains(".dumplingconf"));
            assert!(message.contains("pyproject.toml"));
            assert!(message.contains("not found"));
        }
        fs::remove_dir_all(temp_dir).expect("failed to remove temp dir");
    }

    #[test]
    fn load_config_allow_noop_returns_empty_config() {
        let temp_dir = make_temp_dir("allow-noop");
        {
            let _cwd_guard = CurrentDirGuard::change_to(&temp_dir);
            let cfg = load_config(None, true).expect("allow_noop should permit missing config");
            assert!(cfg.rules.is_empty());
            assert!(cfg.row_filters.is_empty());
            assert!(cfg.column_cases.is_empty());
            assert!(cfg.source_path.is_none());
        }
        fs::remove_dir_all(temp_dir).expect("failed to remove temp dir");
    }

    #[test]
    fn load_config_reports_pyproject_without_tool_dumpling() {
        let temp_dir = make_temp_dir("pyproject-missing-tool");
        {
            let _cwd_guard = CurrentDirGuard::change_to(&temp_dir);
            fs::write(
                temp_dir.join("pyproject.toml"),
                "[tool.poetry]\nname = \"x\"\n",
            )
            .expect("failed writing pyproject");
            let err = load_config(None, false).expect_err("expected missing config failure");
            let message = err.to_string();
            assert!(message.contains("pyproject.toml"));
            assert!(message.contains("missing [tool.dumpling]"));
        }
        fs::remove_dir_all(temp_dir).expect("failed to remove temp dir");
    }

    #[test]
    fn unknown_strategy_fails_validation_with_key_path() {
        let path = write_temp_config(
            r#"
[rules."public.users"]
email = { strategy = "has" }
"#,
        );
        let err =
            load_config(Some(&path), false).expect_err("expected semantic validation failure");
        let msg = format!("{:#}", err);
        assert!(msg.contains("rules.\"public.users\".email.strategy"));
        assert!(msg.contains("unknown strategy 'has'"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn invalid_strategy_option_combination_fails_validation() {
        let path = write_temp_config(
            r#"
[rules."public.users"]
email = { strategy = "email", min = 1 }
"#,
        );
        let err =
            load_config(Some(&path), false).expect_err("expected semantic validation failure");
        let msg = format!("{:#}", err);
        assert!(msg.contains("rules.\"public.users\".email"));
        assert!(msg.contains("unsupported option(s)"));
        assert!(msg.contains("min"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn malformed_strategy_parameters_fail_validation() {
        let path = write_temp_config(
            r#"
[rules."public.users"]
age = { strategy = "int_range", min = 100, max = 10 }
"#,
        );
        let err =
            load_config(Some(&path), false).expect_err("expected semantic validation failure");
        let msg = format!("{:#}", err);
        assert!(msg.contains("rules.\"public.users\".age"));
        assert!(msg.contains("min (100) must be <= max (10)"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn table_options_are_rejected_with_targeted_error() {
        let path = write_temp_config(
            r#"
[table_options."public.users"]
auto = true
"#,
        );
        let err =
            load_config(Some(&path), false).expect_err("expected semantic validation failure");
        let msg = format!("{:#}", err);
        assert!(msg.contains("table_options has been removed"));
        assert!(msg.contains("[rules]"));
        assert!(msg.contains("[column_cases]"));
        let _ = fs::remove_file(path);
    }
}
