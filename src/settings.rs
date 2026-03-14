use anyhow::Context;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
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
    /// Explicit sensitive columns keyed by either `table` or `schema.table`
    /// Used by strict coverage checks to supplement name-pattern detection.
    #[serde(default)]
    pub sensitive_columns: HashMap<String, Vec<String>>,
    /// Post-transform output scanning config for residual sensitive patterns.
    #[serde(default)]
    pub output_scan: OutputScanConfig,
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
    /// Normalized explicit sensitive columns per table
    pub sensitive_columns: HashMap<String, HashSet<String>>,
    /// Resolved output scan config
    pub output_scan: OutputScanConfig,
    /// For debugging/trace
    pub source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputScanConfig {
    /// Optional category allowlist; default enables all built-ins.
    #[serde(default)]
    pub enabled_categories: Vec<String>,
    /// Per-category finding threshold (inclusive allowed count).
    #[serde(default)]
    pub thresholds: HashMap<String, u64>,
    /// Per-category severity level override.
    #[serde(default)]
    pub severities: HashMap<String, String>,
    /// Default threshold used when category-specific threshold is absent.
    #[serde(default)]
    pub default_threshold: u64,
    /// Default severity for categories not listed under `severities`.
    #[serde(default = "default_output_scan_severity")]
    pub default_severity: String,
    /// Minimum severity level that can trigger a failure.
    #[serde(default = "default_output_scan_fail_severity")]
    pub fail_on_severity: String,
    /// Max number of sample locations to store per category in report.
    #[serde(default = "default_output_scan_sample_limit")]
    pub sample_limit_per_category: usize,
}

impl Default for OutputScanConfig {
    fn default() -> Self {
        Self {
            enabled_categories: Vec::new(),
            thresholds: HashMap::new(),
            severities: HashMap::new(),
            default_threshold: 0,
            default_severity: default_output_scan_severity(),
            fail_on_severity: default_output_scan_fail_severity(),
            sample_limit_per_category: default_output_scan_sample_limit(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TableOptions {
    /// Deprecated: retained for config parsing so we can fail with a targeted message.
    #[serde(default, rename = "auto")]
    pub _auto: bool,
}

fn default_output_scan_severity() -> String {
    "high".to_string()
}

fn default_output_scan_fail_severity() -> String {
    "low".to_string()
}

fn default_output_scan_sample_limit() -> usize {
    5
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
    let RawConfig {
        salt,
        rules,
        row_filters,
        column_cases,
        table_options: _,
        sensitive_columns,
        output_scan,
    } = raw;
    let OutputScanConfig {
        enabled_categories,
        thresholds,
        severities,
        default_threshold,
        default_severity,
        fail_on_severity,
        sample_limit_per_category,
    } = output_scan;

    let mut normalized_rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
    for (table_key, cols) in rules.into_iter() {
        let table_key_norm = table_key.to_lowercase();
        let mut col_map: HashMap<String, AnonymizerSpec> = HashMap::new();
        for (col, spec) in cols.into_iter() {
            col_map.insert(col.to_lowercase(), spec);
        }
        normalized_rules.insert(table_key_norm, col_map);
    }
    let mut normalized_filters: HashMap<String, RowFilterSet> = HashMap::new();
    for (table_key, set) in row_filters.into_iter() {
        normalized_filters.insert(table_key.to_lowercase(), set);
    }
    let mut normalized_cases: HashMap<String, HashMap<String, Vec<ColumnCase>>> = HashMap::new();
    for (table_key, cols) in column_cases.into_iter() {
        let table_key_norm = table_key.to_lowercase();
        let mut inner: HashMap<String, Vec<ColumnCase>> = HashMap::new();
        for (col, cases) in cols.into_iter() {
            inner.insert(col.to_lowercase(), cases);
        }
        normalized_cases.insert(table_key_norm, inner);
    }
    let mut normalized_sensitive_columns: HashMap<String, HashSet<String>> = HashMap::new();
    for (table_key, columns) in sensitive_columns.into_iter() {
        let key = table_key.to_lowercase();
        let mut set = HashSet::new();
        for col in columns {
            let trimmed = col.trim();
            if !trimmed.is_empty() {
                set.insert(trimmed.to_lowercase());
            }
        }
        normalized_sensitive_columns.insert(key, set);
    }
    let mut normalized_thresholds: HashMap<String, u64> = HashMap::new();
    for (category, threshold) in thresholds.into_iter() {
        normalized_thresholds.insert(category.to_ascii_lowercase(), threshold);
    }
    let mut normalized_severities: HashMap<String, String> = HashMap::new();
    for (category, severity) in severities.into_iter() {
        normalized_severities.insert(category.to_ascii_lowercase(), severity.to_ascii_lowercase());
    }
    let normalized_enabled_categories = enabled_categories
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    ResolvedConfig {
        salt,
        rules: normalized_rules,
        row_filters: normalized_filters,
        column_cases: normalized_cases,
        sensitive_columns: normalized_sensitive_columns,
        output_scan: OutputScanConfig {
            enabled_categories: normalized_enabled_categories,
            thresholds: normalized_thresholds,
            severities: normalized_severities,
            default_threshold,
            default_severity: default_severity.to_ascii_lowercase(),
            fail_on_severity: fail_on_severity.to_ascii_lowercase(),
            sample_limit_per_category,
        },
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

    validate_output_scan_config(&raw.output_scan)?;

    Ok(())
}

fn validate_output_scan_config(cfg: &OutputScanConfig) -> anyhow::Result<()> {
    const KNOWN_CATEGORIES: &[&str] = &["email", "ssn", "pan", "token"];
    if cfg.sample_limit_per_category == 0 {
        anyhow::bail!("output_scan.sample_limit_per_category must be >= 1");
    }
    if !is_valid_severity(&cfg.default_severity) {
        anyhow::bail!(
            "output_scan.default_severity has invalid value '{}'; expected one of: low, medium, high, critical",
            cfg.default_severity
        );
    }
    if !is_valid_severity(&cfg.fail_on_severity) {
        anyhow::bail!(
            "output_scan.fail_on_severity has invalid value '{}'; expected one of: low, medium, high, critical",
            cfg.fail_on_severity
        );
    }
    for category in &cfg.enabled_categories {
        let normalized = category.trim().to_ascii_lowercase();
        if !KNOWN_CATEGORIES.contains(&normalized.as_str()) {
            anyhow::bail!(
                "output_scan.enabled_categories contains unknown category '{}'; expected one of: {}",
                category,
                KNOWN_CATEGORIES.join(", ")
            );
        }
    }
    for (category, severity) in &cfg.severities {
        let normalized = category.trim().to_ascii_lowercase();
        if !KNOWN_CATEGORIES.contains(&normalized.as_str()) {
            anyhow::bail!(
                "output_scan.severities contains unknown category '{}'; expected one of: {}",
                category,
                KNOWN_CATEGORIES.join(", ")
            );
        }
        if !is_valid_severity(severity) {
            anyhow::bail!(
                "output_scan.severities.{} has invalid value '{}'; expected one of: low, medium, high, critical",
                category,
                severity
            );
        }
    }
    for category in cfg.thresholds.keys() {
        let normalized = category.trim().to_ascii_lowercase();
        if !KNOWN_CATEGORIES.contains(&normalized.as_str()) {
            anyhow::bail!(
                "output_scan.thresholds contains unknown category '{}'; expected one of: {}",
                category,
                KNOWN_CATEGORIES.join(", ")
            );
        }
    }
    Ok(())
}

fn is_valid_severity(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "low" | "medium" | "high" | "critical"
    )
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
        sensitive_columns: HashMap::new(),
        output_scan: OutputScanConfig::default(),
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

    #[test]
    fn output_scan_config_is_loaded_and_normalized() {
        let path = write_temp_config(
            r#"
[output_scan]
enabled_categories = ["Email", "TOKEN"]
default_threshold = 2
default_severity = "Medium"
fail_on_severity = "High"
sample_limit_per_category = 7

[output_scan.thresholds]
EMAIL = 3

[output_scan.severities]
TOKEN = "Critical"
"#,
        );
        let cfg = load_config(Some(&path), false).expect("expected output_scan to load");
        assert_eq!(
            cfg.output_scan.enabled_categories,
            vec!["email".to_string(), "token".to_string()]
        );
        assert_eq!(cfg.output_scan.default_threshold, 2);
        assert_eq!(cfg.output_scan.default_severity, "medium");
        assert_eq!(cfg.output_scan.fail_on_severity, "high");
        assert_eq!(cfg.output_scan.sample_limit_per_category, 7);
        assert_eq!(cfg.output_scan.thresholds.get("email"), Some(&3));
        assert_eq!(
            cfg.output_scan.severities.get("token"),
            Some(&"critical".to_string())
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn output_scan_invalid_severity_fails_validation() {
        let path = write_temp_config(
            r#"
[output_scan]
default_severity = "urgent"
"#,
        );
        let err = load_config(Some(&path), false).expect_err("expected validation failure");
        let msg = format!("{:#}", err);
        assert!(msg.contains("output_scan.default_severity"));
        let _ = fs::remove_file(path);
    }
}

/// Lookup explicit sensitive columns by schema-qualified or unqualified table name.
pub fn lookup_sensitive_columns<'a>(
    cfg: &'a ResolvedConfig,
    schema: Option<&str>,
    table: &str,
) -> Option<&'a HashSet<String>> {
    if let Some(s) = schema {
        let key = format!("{}.{}", s.to_lowercase(), table.to_lowercase());
        if let Some(columns) = cfg.sensitive_columns.get(&key) {
            return Some(columns);
        }
    }
    let key = table.to_lowercase();
    cfg.sensitive_columns.get(&key)
}

/// Returns true when a column is explicitly listed as sensitive in config.
pub fn is_explicit_sensitive_column(
    cfg: &ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    column: &str,
) -> bool {
    let col_norm = column.to_lowercase();
    lookup_sensitive_columns(cfg, schema, table)
        .map(|columns| columns.contains(&col_norm))
        .unwrap_or(false)
}
