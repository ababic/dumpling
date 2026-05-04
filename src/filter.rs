use crate::settings::{
    lookup_row_filters, parse_json_column_key, AnonymizerSpec, Predicate, ResolvedConfig, When,
};
use crate::transform::{apply_anonymizer, AnonymizerRegistry, Replacement};
use regex::RegexBuilder;
use std::collections::HashMap;
use std::sync::Mutex;

/// Decide whether to keep a row based on configured filters.
/// Returns true to keep, false to drop.
pub fn should_keep_row(
    cfg: &ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    columns: &[String],
    cells: &[Option<&str>], // unescaped strings; None for NULL
) -> bool {
    let set = match lookup_row_filters(cfg, schema, table) {
        Some(s) => s,
        None => return true,
    };
    // Build a map: column name (lowercase) -> Option<&str>
    // We will index by position for speed
    // Evaluate include_any: if non-empty, must match at least one
    if !set.retain.is_empty() {
        let mut matched = false;
        for pred in &set.retain {
            if predicate_matches(pred, columns, cells) {
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    // Evaluate exclude_any: if any match, drop
    for pred in &set.delete {
        if predicate_matches(pred, columns, cells) {
            return false;
        }
    }
    true
}

fn predicate_matches(pred: &Predicate, columns: &[String], cells: &[Option<&str>]) -> bool {
    let targets = match extract_predicate_targets(pred, columns, cells) {
        Some(values) => values,
        None => return false, // top-level column missing -> does not match
    };
    let op = pred.op.as_str();
    match op {
        "is_null" => return targets.iter().all(|v| v.is_none()),
        "not_null" => return targets.iter().any(|v| v.is_some()),
        _ => {}
    }
    let case_insensitive = pred.case_insensitive.unwrap_or(matches!(op, "ilike"));
    // Fetch value(s)
    match op {
        "eq" | "neq" | "like" | "ilike" | "lt" | "lte" | "gt" | "gte" | "regex" | "iregex" => {
            let v = match &pred.value {
                Some(v) => v,
                None => return false,
            };
            match op {
                "eq" => targets
                    .iter()
                    .any(|cell| cmp_eq(cell.as_deref(), v, case_insensitive)),
                "neq" => !targets
                    .iter()
                    .any(|cell| cmp_eq(cell.as_deref(), v, case_insensitive)),
                "like" | "ilike" => targets
                    .iter()
                    .any(|cell| cmp_like(cell.as_deref(), v, case_insensitive)),
                "regex" | "iregex" => targets
                    .iter()
                    .any(|cell| cmp_regex(cell.as_deref(), v, case_insensitive || op == "iregex")),
                "lt" => targets.iter().any(|cell| {
                    cmp_order(cell.as_deref(), v)
                        .map(|o| o < 0)
                        .unwrap_or(false)
                }),
                "lte" => targets.iter().any(|cell| {
                    cmp_order(cell.as_deref(), v)
                        .map(|o| o <= 0)
                        .unwrap_or(false)
                }),
                "gt" => targets.iter().any(|cell| {
                    cmp_order(cell.as_deref(), v)
                        .map(|o| o > 0)
                        .unwrap_or(false)
                }),
                "gte" => targets.iter().any(|cell| {
                    cmp_order(cell.as_deref(), v)
                        .map(|o| o >= 0)
                        .unwrap_or(false)
                }),
                _ => false,
            }
        }
        "in" | "not_in" => {
            let values = match &pred.values {
                Some(vs) => vs,
                None => return false,
            };
            let any = targets.iter().any(|cell| {
                values
                    .iter()
                    .any(|v| cmp_eq(cell.as_deref(), v, case_insensitive))
            });
            if op == "in" {
                any
            } else {
                !any
            }
        }
        _ => false,
    }
}

fn extract_predicate_targets(
    pred: &Predicate,
    columns: &[String],
    cells: &[Option<&str>],
) -> Option<Vec<Option<String>>> {
    if let Some(i) = columns
        .iter()
        .position(|c| c.eq_ignore_ascii_case(&pred.column))
    {
        let cell = cells.get(i).copied().flatten();
        return Some(vec![cell.map(|s| s.to_string())]);
    }

    let (base_column, path) = parse_json_column_key(&pred.column);
    if path.is_empty() {
        return None;
    }
    let base_idx = columns
        .iter()
        .position(|c| c.eq_ignore_ascii_case(&base_column))?;
    let base_cell = cells.get(base_idx).and_then(|c| c.as_deref());
    Some(extract_json_path_targets(base_cell, &path))
}

fn extract_json_path_targets(cell: Option<&str>, path: &[String]) -> Vec<Option<String>> {
    let raw = match cell {
        Some(v) => v,
        None => return vec![None],
    };
    if path.is_empty() {
        return vec![Some(raw.to_string())];
    }
    let parsed = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => v,
        Err(_) => return vec![None],
    };

    let mut current = vec![parsed];
    for segment in path {
        let mut next = Vec::new();
        for value in current.into_iter() {
            collect_segment_values(&value, segment, &mut next);
        }
        if next.is_empty() {
            return vec![None];
        }
        current = next;
    }

    current.into_iter().map(json_value_to_cell).collect()
}

fn collect_segment_values(
    value: &serde_json::Value,
    segment: &str,
    out: &mut Vec<serde_json::Value>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get(segment) {
                out.push(v.clone());
            }
        }
        serde_json::Value::Array(items) => {
            if let Ok(idx) = segment.parse::<usize>() {
                if let Some(v) = items.get(idx) {
                    out.push(v.clone());
                }
                return;
            }
            for item in items {
                match item {
                    serde_json::Value::Object(map) => {
                        if let Some(v) = map.get(segment) {
                            out.push(v.clone());
                        }
                    }
                    serde_json::Value::Array(_) => collect_segment_values(item, segment, out),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn json_value_to_cell(v: serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(if b { "true" } else { "false" }.to_string()),
        other => Some(other.to_string()),
    }
}

fn replacement_to_json_value(repl: &Replacement) -> serde_json::Value {
    if repl.is_null {
        return serde_json::Value::Null;
    }
    if repl.force_quoted {
        return serde_json::Value::String(repl.value.as_ref().to_string());
    }
    serde_json::from_str(repl.value.as_ref())
        .unwrap_or_else(|_| serde_json::Value::String(repl.value.as_ref().to_string()))
}

/// When rewriting JSON at a path, map `Replacement` back into [`serde_json::Value`] while keeping
/// the leaf's JSON type when the strategy still returns text (e.g. `Replacement::quoted` for
/// `string`, `hash`, etc.): numeric and boolean leaves stay JSON numbers/bools if the replacement
/// text parses as such.
fn coerce_json_path_replacement(
    original: &serde_json::Value,
    repl: &Replacement,
) -> serde_json::Value {
    if repl.is_null {
        return serde_json::Value::Null;
    }
    match original {
        serde_json::Value::Bool(_) => {
            if let Some(b) = parse_loose_json_bool(repl.value.as_ref()) {
                return serde_json::Value::Bool(b);
            }
            if !repl.force_quoted {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(repl.value.as_ref()) {
                    match v {
                        serde_json::Value::Bool(b) => return serde_json::Value::Bool(b),
                        serde_json::Value::Number(n) => {
                            if n.as_u64() == Some(0) || n.as_i64() == Some(0) {
                                return serde_json::Value::Bool(false);
                            }
                            if n.as_u64() == Some(1) || n.as_i64() == Some(1) {
                                return serde_json::Value::Bool(true);
                            }
                        }
                        _ => {}
                    }
                }
            }
            serde_json::Value::String(repl.value.as_ref().to_string())
        }
        serde_json::Value::Number(_) => {
            if let Some(n) = parse_loose_json_number(repl.value.as_ref()) {
                return serde_json::Value::Number(n);
            }
            if !repl.force_quoted {
                if let Ok(serde_json::Value::Number(n)) =
                    serde_json::from_str::<serde_json::Value>(repl.value.as_ref())
                {
                    return serde_json::Value::Number(n);
                }
            }
            serde_json::Value::String(repl.value.as_ref().to_string())
        }
        serde_json::Value::String(_) => {
            if repl.force_quoted {
                serde_json::Value::String(repl.value.as_ref().to_string())
            } else {
                serde_json::from_str(repl.value.as_ref())
                    .unwrap_or_else(|_| serde_json::Value::String(repl.value.as_ref().to_string()))
            }
        }
        serde_json::Value::Null => replacement_to_json_value(repl),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            replacement_to_json_value(repl)
        }
    }
}

fn parse_loose_json_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_loose_json_number(s: &str) -> Option<serde_json::Number> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(i) = t.parse::<i64>() {
        return Some(i.into());
    }
    if let Ok(u) = t.parse::<u64>() {
        return Some(u.into());
    }
    let f = t.parse::<f64>().ok()?;
    serde_json::Number::from_f64(f)
}

fn apply_leaf_replacement(target: &mut serde_json::Value, repl: &Replacement) {
    let original = target.clone();
    *target = coerce_json_path_replacement(&original, repl);
}

/// Mutate JSON document strings at configured paths using the same path semantics as predicates.
///
/// Returns [`None`] when `raw_json` is not valid strict JSON (same tolerance as row-filter JSON
/// path extraction): path rules are skipped for that cell and callers should passthrough the
/// original value unchanged.
pub fn rewrite_json_paths_with_rules(
    registry: &AnonymizerRegistry,
    column_max_len: Option<usize>,
    json_rules: &[(Vec<String>, AnonymizerSpec)],
    raw_json: &str,
) -> anyhow::Result<Option<String>> {
    let mut root = match serde_json::from_str::<serde_json::Value>(raw_json) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    for (path, spec) in json_rules {
        let mut apply = |original_cell: Option<String>| {
            apply_anonymizer(registry, spec, original_cell.as_deref(), column_max_len)
        };
        mutate_json_at_path(&mut root, path, &mut apply)?;
    }
    Ok(Some(root.to_string()))
}

fn mutate_json_at_path<F>(
    value: &mut serde_json::Value,
    segments: &[String],
    apply: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(Option<String>) -> Replacement,
{
    if segments.is_empty() {
        return Ok(());
    }
    let seg = segments[0].as_str();
    let rest = &segments[1..];

    if rest.is_empty() {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(leaf) = map.get_mut(seg) {
                    let original = json_value_to_cell(leaf.clone());
                    let repl = apply(original);
                    apply_leaf_replacement(leaf, &repl);
                }
            }
            serde_json::Value::Array(items) => {
                if let Ok(idx) = seg.parse::<usize>() {
                    if let Some(leaf) = items.get_mut(idx) {
                        let original = json_value_to_cell(leaf.clone());
                        let repl = apply(original);
                        apply_leaf_replacement(leaf, &repl);
                    }
                } else {
                    for item in items.iter_mut() {
                        match item {
                            serde_json::Value::Object(map) => {
                                if let Some(leaf) = map.get_mut(seg) {
                                    let original = json_value_to_cell(leaf.clone());
                                    let repl = apply(original);
                                    apply_leaf_replacement(leaf, &repl);
                                }
                            }
                            serde_json::Value::Array(_) => {
                                mutate_json_at_path(item, segments, apply)?;
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
        return Ok(());
    }

    match value {
        serde_json::Value::Object(map) => {
            if let Some(next) = map.get_mut(seg) {
                mutate_json_at_path(next, rest, apply)?;
            }
        }
        serde_json::Value::Array(items) => {
            if let Ok(idx) = seg.parse::<usize>() {
                if let Some(next) = items.get_mut(idx) {
                    mutate_json_at_path(next, rest, apply)?;
                }
            } else {
                for item in items.iter_mut() {
                    mutate_json_at_path(item, rest, apply)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn when_matches(when: &When, columns: &[String], cells: &[Option<&str>]) -> bool {
    // If any is non-empty, require at least one to match
    if !when.any.is_empty() {
        let mut matched_any = false;
        for p in &when.any {
            if predicate_matches(p, columns, cells) {
                matched_any = true;
                break;
            }
        }
        if !matched_any {
            return false;
        }
    }
    // If all is non-empty, require all to match
    if !when.all.is_empty() {
        for p in &when.all {
            if !predicate_matches(p, columns, cells) {
                return false;
            }
        }
    }
    // If both empty, treat as unconditional true
    true
}

fn cmp_regex(cell: Option<&str>, rhs: &serde_json::Value, case_insensitive: bool) -> bool {
    let pat = match value_to_string(rhs) {
        Some(s) => s,
        None => return false,
    };
    let re = get_cached_regex(&pat, case_insensitive);
    match cell {
        None => false,
        Some(lv) => re.is_match(lv),
    }
}

fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(if *b { "true" } else { "false" }.to_string()),
        _ => None,
    }
}

fn cmp_eq(cell: Option<&str>, rhs: &serde_json::Value, case_insensitive: bool) -> bool {
    let rv = match value_to_string(rhs) {
        Some(s) => s,
        None => return false,
    };
    match cell {
        None => false,
        Some(lv) => {
            if case_insensitive {
                lv.eq_ignore_ascii_case(&rv)
            } else {
                lv == rv
            }
        }
    }
}

fn cmp_like(cell: Option<&str>, rhs: &serde_json::Value, case_insensitive: bool) -> bool {
    let pat = match value_to_string(rhs) {
        Some(s) => s,
        None => return false,
    };
    let regex = like_to_regex(&pat);
    let re = get_cached_regex(&regex, case_insensitive);
    match cell {
        None => false,
        Some(lv) => re.is_match(lv),
    }
}

fn like_to_regex(pat: &str) -> String {
    // Convert SQL LIKE pattern to anchored regex: % -> .*, _ -> .
    let mut s = String::from("^");
    for ch in pat.chars() {
        match ch {
            '%' => s.push_str(".*"),
            '_' => s.push('.'),
            '.' | '+' | '(' | ')' | '|' | '{' | '}' | '[' | ']' | '^' | '$' | '*' | '?' | '\\' => {
                s.push('\\');
                s.push(ch);
            }
            _ => s.push(ch),
        }
    }
    s.push('$');
    s
}

fn parse_f64(s: &str) -> Option<f64> {
    // Accept commas? No, assume period decimal.
    s.parse::<f64>().ok()
}

fn cmp_order(cell: Option<&str>, rhs: &serde_json::Value) -> Option<i32> {
    let rv = match rhs {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => parse_f64(s),
        _ => None,
    }?;
    let lv = parse_f64(cell?)?;
    if (lv - rv).abs() < f64::EPSILON {
        Some(0)
    } else if lv < rv {
        Some(-1)
    } else {
        Some(1)
    }
}

// Simple global regex cache
lazy_static::lazy_static! {
    static ref REGEX_CACHE: Mutex<HashMap<(String, bool), regex::Regex>> = Mutex::new(HashMap::new());
}

fn get_cached_regex(pat: &str, case_insensitive: bool) -> regex::Regex {
    let key = (pat.to_string(), case_insensitive);
    if let Some(r) = REGEX_CACHE.lock().unwrap().get(&key) {
        return r.clone();
    }
    let mut builder = RegexBuilder::new(pat);
    builder.case_insensitive(case_insensitive);
    let re = builder
        .build()
        .unwrap_or_else(|_| RegexBuilder::new("$^").build().unwrap());
    REGEX_CACHE.lock().unwrap().insert(key, re.clone());
    re
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{AnonymizerSpec, ResolvedConfig, RowFilterSet};
    use crate::transform::AnonymizerRegistry;
    use std::collections::HashMap;

    #[test]
    fn regex_predicates_work() {
        let cfg = ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: {
                let mut m = HashMap::new();
                m.insert(
                    "public.users".to_string(),
                    RowFilterSet {
                        retain: vec![
                            Predicate {
                                column: "email".to_string(),
                                op: "regex".to_string(),
                                value: Some(serde_json::json!(".*@myco\\.com$")),
                                values: None,
                                case_insensitive: None,
                            },
                            Predicate {
                                column: "email".to_string(),
                                op: "iregex".to_string(),
                                value: Some(serde_json::json!(".*@myco\\.com$")),
                                values: None,
                                case_insensitive: None,
                            },
                        ],
                        delete: vec![Predicate {
                            column: "email".to_string(),
                            op: "regex".to_string(),
                            value: Some(serde_json::json!(".*@example\\.com$")),
                            values: None,
                            case_insensitive: None,
                        }],
                    },
                );
                m
            },
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let cols = vec!["id".to_string(), "email".to_string(), "country".to_string()];
        // Keep myco.com
        assert!(should_keep_row(
            &cfg,
            Some("public"),
            "users",
            &cols,
            &[Some("1"), Some("alice@myco.com"), Some("US")]
        ));
        // Case-insensitive keep (iregex)
        assert!(should_keep_row(
            &cfg,
            Some("public"),
            "users",
            &cols,
            &[Some("2"), Some("Carol@MYCO.COM"), Some("GB")]
        ));
        // Delete example.com
        assert!(!should_keep_row(
            &cfg,
            Some("public"),
            "users",
            &cols,
            &[Some("3"), Some("bob@example.com"), Some("US")]
        ));
    }

    #[test]
    fn nested_json_dict_path_predicate_matches() {
        let cfg = ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: {
                let mut m = HashMap::new();
                m.insert(
                    "public.events".to_string(),
                    RowFilterSet {
                        retain: vec![Predicate {
                            column: "payload.profile.tier".to_string(),
                            op: "eq".to_string(),
                            value: Some(serde_json::json!("gold")),
                            values: None,
                            case_insensitive: None,
                        }],
                        delete: vec![],
                    },
                );
                m
            },
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let cols = vec!["payload".to_string()];
        assert!(should_keep_row(
            &cfg,
            Some("public"),
            "events",
            &cols,
            &[Some(r#"{"profile":{"tier":"gold"}}"#)]
        ));
        assert!(!should_keep_row(
            &cfg,
            Some("public"),
            "events",
            &cols,
            &[Some(r#"{"profile":{"tier":"silver"}}"#)]
        ));
    }

    #[test]
    fn nested_json_array_of_dicts_path_predicate_matches() {
        let cfg = ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: {
                let mut m = HashMap::new();
                m.insert(
                    "public.events".to_string(),
                    RowFilterSet {
                        retain: vec![Predicate {
                            column: "payload__items__kind".to_string(),
                            op: "eq".to_string(),
                            value: Some(serde_json::json!("primary")),
                            values: None,
                            case_insensitive: None,
                        }],
                        delete: vec![],
                    },
                );
                m
            },
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let cols = vec!["payload".to_string()];
        assert!(should_keep_row(
            &cfg,
            Some("public"),
            "events",
            &cols,
            &[Some(
                r#"{"items":[{"kind":"secondary"},{"kind":"primary"}]}"#
            )]
        ));
        assert!(!should_keep_row(
            &cfg,
            Some("public"),
            "events",
            &cols,
            &[Some(r#"{"items":[{"kind":"secondary"}]}"#)]
        ));
    }

    #[test]
    fn rewrite_json_paths_skips_non_json_cells_like_row_filters() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let spec = AnonymizerSpec {
            strategy: "string".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: Some(4),
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: Some(true),
            locale: None,
            faker: None,
            format: None,
        };
        rules.insert("public.t".to_string(), HashMap::new());
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let registry = AnonymizerRegistry::from_config(&cfg);
        let json_rules: Vec<(Vec<String>, AnonymizerSpec)> = vec![(
            vec!["profile".to_string(), "secret".to_string()],
            spec.clone(),
        )];
        assert!(
            rewrite_json_paths_with_rules(&registry, None, &json_rules, "{not json")
                .unwrap()
                .is_none()
        );
        let out = rewrite_json_paths_with_rules(
            &registry,
            None,
            &json_rules,
            r#"{"profile":{"secret":"x"}}"#,
        )
        .unwrap()
        .expect("valid JSON should rewrite");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_ne!(v["profile"]["secret"], "x");
    }

    #[test]
    fn rewrite_json_paths_preserves_number_and_bool_leaf_types_for_quoted_replacements() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert("public.t".to_string(), HashMap::new());
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let registry = AnonymizerRegistry::from_config(&cfg);

        let int_spec = AnonymizerSpec {
            strategy: "int_range".to_string(),
            salt: None,
            min: Some(0),
            max: Some(9),
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("coerce_int_leaf".to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let out = rewrite_json_paths_with_rules(
            &registry,
            None,
            &[(vec!["n".to_string()], int_spec)],
            r#"{"n":1,"b":true,"s":"x"}"#,
        )
        .unwrap()
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            v["n"].is_number(),
            "int_range replacement should stay JSON number, got {:?}",
            v["n"]
        );
        assert_eq!(v["b"], true);
        assert_eq!(v["s"], "x");

        let string_spec = AnonymizerSpec {
            strategy: "int_range".to_string(),
            salt: None,
            min: Some(0),
            max: Some(0),
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("coerce_bool_leaf".to_string()),
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let out2 = rewrite_json_paths_with_rules(
            &registry,
            None,
            &[(vec!["b".to_string()], string_spec)],
            r#"{"b":false}"#,
        )
        .unwrap()
        .unwrap();
        let v2: serde_json::Value = serde_json::from_str(&out2).unwrap();
        assert!(
            v2["b"].is_boolean(),
            "unquoted 0 from int_range should coerce to bool at bool leaf, got {:?}",
            v2["b"]
        );
        assert_eq!(v2["b"], false);
    }

    #[test]
    fn rewrite_json_paths_empty_array_and_empty_object_strategies() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert("public.t".to_string(), HashMap::new());
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let registry = AnonymizerRegistry::from_config(&cfg);

        let arr_spec = AnonymizerSpec {
            strategy: "empty_array".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let out = rewrite_json_paths_with_rules(
            &registry,
            None,
            &[(vec!["items".to_string()], arr_spec)],
            r#"{"items":[1,2],"meta":{}}"#,
        )
        .unwrap()
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["items"].is_array());
        assert_eq!(v["items"], serde_json::json!([]));
        assert_eq!(v["meta"], serde_json::json!({}));

        let obj_spec = AnonymizerSpec {
            strategy: "empty_object".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: None,
            unique_within_domain: None,
            as_string: None,
            locale: None,
            faker: None,
            format: None,
        };
        let out2 = rewrite_json_paths_with_rules(
            &registry,
            None,
            &[(vec!["meta".to_string()], obj_spec)],
            r#"{"items":[],"meta":{"k":1}}"#,
        )
        .unwrap()
        .unwrap();
        let v2: serde_json::Value = serde_json::from_str(&out2).unwrap();
        assert!(v2["meta"].is_object());
        assert_eq!(v2["meta"], serde_json::json!({}));
        assert_eq!(v2["items"], serde_json::json!([]));
    }
}
