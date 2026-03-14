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
    /// Per-table options keyed by either `table` or `schema.table`
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
    /// Normalized table options
    pub table_options: HashMap<String, TableOptions>,
    /// For debugging/trace
    pub source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TableOptions {
    /// Enable strategy auto-detection from column names when no explicit rule/case matches
    #[serde(default)]
    pub auto: bool,
}

pub fn load_config(explicit_path: Option<&PathBuf>) -> anyhow::Result<ResolvedConfig> {
    // 1) If explicit path is provided, try it.
    if let Some(path) = explicit_path {
        return load_from_file(path);
    }
    // 2) Look for ./.dumplingconf
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let dot_conf = cwd.join(".dumplingconf");
    if dot_conf.exists() {
        return load_from_file(&dot_conf);
    }
    // 3) Look for ./pyproject.toml with [tool.dumpling]
    let pyproject = cwd.join("pyproject.toml");
    if pyproject.exists() {
        return load_from_pyproject(&pyproject);
    }
    // 4) No config found, return empty/default
    Ok(ResolvedConfig {
        salt: None,
        rules: HashMap::new(),
        row_filters: HashMap::new(),
        column_cases: HashMap::new(),
        table_options: HashMap::new(),
        source_path: None,
    })
}

fn load_from_file(path: &Path) -> anyhow::Result<ResolvedConfig> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed reading config file {}", path.display()))?;
    let raw: RawConfig = toml::from_str(&content)
        .with_context(|| format!("failed parsing TOML in {}", path.display()))?;
    Ok(resolve(raw, Some(path.to_path_buf())))
}

fn load_from_pyproject(path: &Path) -> anyhow::Result<ResolvedConfig> {
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
            return Ok(resolve(raw, Some(path.to_path_buf())));
        }
    }
    // pyproject exists but no tool.dumpling -> empty
    Ok(ResolvedConfig {
        salt: None,
        rules: HashMap::new(),
        row_filters: HashMap::new(),
        column_cases: HashMap::new(),
        table_options: HashMap::new(),
        source_path: Some(path.to_path_buf()),
    })
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
    let mut normalized_table_options: HashMap<String, TableOptions> = HashMap::new();
    for (table_key, options) in raw.table_options.into_iter() {
        normalized_table_options.insert(table_key.to_lowercase(), options);
    }
    ResolvedConfig {
        salt: raw.salt,
        rules: normalized_rules,
        row_filters: normalized_filters,
        column_cases: normalized_cases,
        table_options: normalized_table_options,
        source_path,
    }
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

/// Lookup table options by schema-qualified or unqualified table name
pub fn lookup_table_options<'a>(
    cfg: &'a ResolvedConfig,
    schema: Option<&str>,
    table: &str,
) -> Option<&'a TableOptions> {
    if let Some(s) = schema {
        let key = format!("{}.{}", s.to_lowercase(), table.to_lowercase());
        if let Some(options) = cfg.table_options.get(&key) {
            return Some(options);
        }
    }
    let key = table.to_lowercase();
    cfg.table_options.get(&key)
}
