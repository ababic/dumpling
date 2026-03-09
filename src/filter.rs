use crate::settings::{lookup_row_filters, Predicate, ResolvedConfig, RowFilterSet, When};
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
    cells: &[Option<String>], // unescaped strings; None for NULL
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

fn predicate_matches(pred: &Predicate, columns: &[String], cells: &[Option<String>]) -> bool {
    let col_idx = match columns
        .iter()
        .position(|c| c.eq_ignore_ascii_case(&pred.column))
    {
        Some(i) => i,
        None => return false, // column missing -> does not match
    };
    let cell = cells.get(col_idx).and_then(|c| c.as_ref().map(|s| s.as_str()));
    let op = pred.op.as_str();
    match op {
        "is_null" => return cell.is_none(),
        "not_null" => return cell.is_some(),
        _ => {}
    }
    let case_insensitive = pred
        .case_insensitive
        .unwrap_or(matches!(op, "ilike"));
    // Fetch value(s)
    match op {
        "eq" | "neq" | "like" | "ilike" | "lt" | "lte" | "gt" | "gte" | "regex" | "iregex" => {
            let v = match &pred.value {
                Some(v) => v,
                None => return false,
            };
            return match op {
                "eq" => cmp_eq(cell, v, case_insensitive),
                "neq" => !cmp_eq(cell, v, case_insensitive),
                "like" | "ilike" => cmp_like(cell, v, case_insensitive),
                "regex" | "iregex" => cmp_regex(cell, v, case_insensitive || op == "iregex"),
                "lt" => cmp_order(cell, v).map(|o| o < 0).unwrap_or(false),
                "lte" => cmp_order(cell, v).map(|o| o <= 0).unwrap_or(false),
                "gt" => cmp_order(cell, v).map(|o| o > 0).unwrap_or(false),
                "gte" => cmp_order(cell, v).map(|o| o >= 0).unwrap_or(false),
                _ => false,
            };
        }
        "in" | "not_in" => {
            let values = match &pred.values {
                Some(vs) => vs,
                None => return false,
            };
            let any = values
                .iter()
                .any(|v| cmp_eq(cell, v, case_insensitive));
            return if op == "in" { any } else { !any };
        }
        _ => false,
    }
}

pub fn when_matches(when: &When, columns: &[String], cells: &[Option<String>]) -> bool {
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
    let re = builder.build().unwrap_or_else(|_| RegexBuilder::new("$^").build().unwrap());
    REGEX_CACHE.lock().unwrap().insert(key, re.clone());
    re
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{ResolvedConfig, RowFilterSet};
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
            source_path: None,
        };
        let cols = vec![
            "id".to_string(),
            "email".to_string(),
            "country".to_string(),
        ];
        // Keep myco.com
        assert!(should_keep_row(
            &cfg,
            Some("public"),
            "users",
            &cols,
            &[
                Some("1".to_string()),
                Some("alice@myco.com".to_string()),
                Some("US".to_string())
            ]
        ));
        // Case-insensitive keep (iregex)
        assert!(should_keep_row(
            &cfg,
            Some("public"),
            "users",
            &cols,
            &[
                Some("2".to_string()),
                Some("Carol@MYCO.COM".to_string()),
                Some("GB".to_string())
            ]
        ));
        // Delete example.com
        assert!(!should_keep_row(
            &cfg,
            Some("public"),
            "users",
            &cols,
            &[
                Some("3".to_string()),
                Some("bob@example.com".to_string()),
                Some("US".to_string())
            ]
        ));
    }
}
