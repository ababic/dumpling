//! Scan a SQL dump and emit a starter TOML policy (draft — always review before use).

use crate::scan::luhn_valid;
use crate::seal::SEAL_LINE_PREFIX;
use crate::settings::{AnonymizerSpec, RawConfig};
use crate::sql::{
    detect_insert_keyword, find_ignore_ascii_case, infer_column_strategy_from_name,
    parse_create_table_details, parse_parenthesized_ident_list, parse_table_and_rest,
    parse_table_ident, parse_values_rows, split_ident_list, starts_with_create_table,
    starts_with_insert, statement_complete, strip_trailing_semicolon, Cell, DumpFormat,
    ParsedCreateTable,
};
use anyhow::Context;
use lazy_static::lazy_static;
use rand::Rng;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, Write};

lazy_static! {
    static ref EMAIL_RE: Regex =
        Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b").unwrap();
    static ref SSN_RE: Regex = Regex::new(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b").unwrap();
    static ref PAN_CANDIDATE_RE: Regex = Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap();
    static ref JWT_RE: Regex =
        Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap();
    static ref AWS_ACCESS_KEY_RE: Regex = Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap();
    static ref GITHUB_PAT_RE: Regex = Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap();
    static ref SLACK_TOKEN_RE: Regex = Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap();
    static ref LABELED_TOKEN_RE: Regex = Regex::new(
        r#"(?i)\b(?:token|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9._\-]{16,}\b"#
    )
    .unwrap();
}

#[derive(Debug, Default)]
struct TableAccum {
    columns: Vec<String>,
    ddl_lengths: HashMap<String, usize>,
    null_any: HashMap<String, bool>,
    /// Reservoir: up to `cap` row snapshots (tab-split fields aligned to `columns`)
    reservoir_rows: Vec<Vec<Option<String>>>,
    rows_seen: u64,
    reservoir_cap: usize,
}

impl TableAccum {
    fn new(cap: usize) -> Self {
        Self {
            reservoir_cap: cap,
            ..Default::default()
        }
    }

    fn merge_ddl(&mut self, parsed: &ParsedCreateTable) {
        if self.columns.is_empty() {
            self.columns = parsed.columns.clone();
        }
        for (k, v) in &parsed.lengths {
            self.ddl_lengths.insert(k.clone(), *v);
        }
    }

    fn observe_row_fields(&mut self, fields: &[Option<&str>]) {
        let n = self.columns.len().min(fields.len());
        for (i, field) in fields.iter().enumerate().take(n) {
            let col_key = self.columns[i].to_lowercase();
            if field.is_none() {
                self.null_any.insert(col_key, true);
            }
        }
        self.observe_reservoir(fields);
    }

    fn observe_reservoir(&mut self, fields: &[Option<&str>]) {
        if self.reservoir_cap == 0 {
            return;
        }
        let row: Vec<Option<String>> = fields.iter().map(|f| f.map(|s| s.to_string())).collect();
        self.rows_seen = self.rows_seen.saturating_add(1);
        let k = self.reservoir_rows.len();
        if k < self.reservoir_cap {
            self.reservoir_rows.push(row);
            return;
        }
        let mut rng = rand::rng();
        let j = rng.random_range(0..self.rows_seen as usize);
        if j < self.reservoir_cap {
            self.reservoir_rows[j] = row;
        }
    }
}

fn table_key(schema: Option<&str>, table: &str) -> String {
    let t = table.to_lowercase();
    match schema {
        Some(s) => format!("{}.{}", s.to_lowercase(), t),
        None => t,
    }
}

fn infer_from_value_heuristic(text: &str) -> Option<AnonymizerSpec> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if EMAIL_RE.is_match(t) {
        return Some(draft_spec("email", Some(true), None));
    }
    if SSN_RE.is_match(t) {
        return Some(draft_spec(
            "hash",
            Some(true),
            Some("${DUMPLING_HASH_SALT}".to_string()),
        ));
    }
    for cap in PAN_CANDIDATE_RE.captures_iter(t) {
        let digits: String = cap[0].chars().filter(|c| c.is_ascii_digit()).collect();
        if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
            return Some(draft_spec("payment_card", Some(true), None));
        }
    }
    if JWT_RE.is_match(t)
        || AWS_ACCESS_KEY_RE.is_match(t)
        || GITHUB_PAT_RE.is_match(t)
        || SLACK_TOKEN_RE.is_match(t)
        || LABELED_TOKEN_RE.is_match(t)
    {
        return Some(draft_spec(
            "hash",
            Some(true),
            Some("${DUMPLING_HASH_SALT}".to_string()),
        ));
    }
    None
}

fn draft_spec(strategy: &str, as_string: Option<bool>, salt: Option<String>) -> AnonymizerSpec {
    AnonymizerSpec {
        strategy: strategy.to_string(),
        salt,
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
        as_string,
        locale: None,
        faker: None,
        format: None,
    }
}

fn merge_spec(preferred: AnonymizerSpec, other: AnonymizerSpec) -> AnonymizerSpec {
    if preferred.strategy == "hash" {
        return preferred;
    }
    if other.strategy == "hash" {
        return other;
    }
    if matches!(
        preferred.strategy.as_str(),
        "payment_card" | "email" | "phone"
    ) {
        return preferred;
    }
    if matches!(other.strategy.as_str(), "payment_card" | "email" | "phone") {
        return other;
    }
    preferred
}

fn finalize_rules(
    tables: HashMap<String, TableAccum>,
) -> HashMap<String, HashMap<String, AnonymizerSpec>> {
    let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
    for (tk, acc) in tables {
        if acc.columns.is_empty() {
            continue;
        }
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        for (idx, col_name) in acc.columns.iter().enumerate() {
            let col_key = col_name.to_lowercase();
            let mut spec = infer_column_strategy_from_name(col_name);
            for row in &acc.reservoir_rows {
                if let Some(cell) = row.get(idx) {
                    if let Some(s) = cell.as_deref() {
                        if let Some(vs) = infer_from_value_heuristic(s) {
                            spec = Some(match spec {
                                Some(existing) => merge_spec(existing, vs),
                                None => vs,
                            });
                        }
                    }
                }
            }
            if let Some(mut s) = spec {
                if s.strategy == "hash" && s.salt.is_none() {
                    s.salt = Some("${DUMPLING_HASH_SALT}".to_string());
                }
                if let Some(max_len) = acc.ddl_lengths.get(&col_key).copied() {
                    if matches!(
                        s.strategy.as_str(),
                        "string"
                            | "email"
                            | "name"
                            | "first_name"
                            | "last_name"
                            | "phone"
                            | "payment_card"
                    ) {
                        s.length = Some(max_len);
                    }
                }
                cols.insert(col_key, s);
            }
        }
        if !cols.is_empty() {
            rules.insert(tk, cols);
        }
    }
    rules
}

fn raw_config_to_toml(raw: &RawConfig) -> anyhow::Result<String> {
    let mut v = toml::Value::try_from(raw).context("serialize draft RawConfig to TOML value")?;
    prune_empty_top_level(&mut v);
    Ok(toml::to_string_pretty(&v)?)
}

/// Remove empty maps from the root table so the draft file is mostly `[rules]` + `salt`.
fn prune_empty_top_level(v: &mut toml::Value) {
    let toml::Value::Table(t) = v else {
        return;
    };
    t.retain(|_, child| match child {
        toml::Value::Table(inner) => !inner.is_empty(),
        toml::Value::Array(a) => !a.is_empty(),
        _ => true,
    });
}

/// Stream `reader` and write a draft TOML policy to `writer`.
pub fn generate_draft_config<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    format: DumpFormat,
    sample_rows: usize,
) -> anyhow::Result<()> {
    use std::io::{BufReader, Cursor, Read};

    let mut first_line = String::new();
    let had = reader.read_line(&mut first_line)? > 0;
    let prefix = if had && first_line.trim_start().starts_with(SEAL_LINE_PREFIX) {
        Vec::new()
    } else if had {
        first_line.into_bytes()
    } else {
        Vec::new()
    };
    let mut scan = BufReader::new(Cursor::new(prefix).chain(reader));

    let copy_re = if format == DumpFormat::Postgres {
        Some(
            Regex::new(r#"(?i)^\s*COPY\s+([^\s(]+)\s*\(([^)]*)\)\s+FROM\s+stdin;\s*$"#)
                .expect("COPY regex"),
        )
    } else {
        None
    };

    let mut tables: HashMap<String, TableAccum> = HashMap::new();
    let mut ddl_columns: HashMap<String, Vec<String>> = HashMap::new();

    let mut line = String::new();
    let mut mode = DraftMode::Pass;
    let mut insert_buf = String::new();
    let mut create_buf = String::new();
    let mut copy_columns: Vec<String> = Vec::new();
    let mut copy_table_key = String::new();

    loop {
        line.clear();
        if scan.read_line(&mut line)? == 0 {
            break;
        }
        match &mut mode {
            DraftMode::Pass => {
                if starts_with_insert(&line) {
                    insert_buf.clear();
                    insert_buf.push_str(&line);
                    if statement_complete(&insert_buf) {
                        if let Ok(parsed) = parse_insert_for_draft(&insert_buf) {
                            record_insert_draft(&mut tables, parsed, sample_rows);
                        }
                    } else {
                        mode = DraftMode::InInsert;
                    }
                } else if starts_with_create_table(&line) {
                    create_buf.clear();
                    create_buf.push_str(&line);
                    if statement_complete(&create_buf) {
                        if let Some(parsed) = parse_create_table_details(&create_buf) {
                            let tk = table_key(parsed.schema.as_deref(), &parsed.table);
                            ddl_columns.insert(tk.clone(), parsed.columns.clone());
                            tables
                                .entry(tk)
                                .or_insert_with(|| TableAccum::new(sample_rows))
                                .merge_ddl(&parsed);
                        }
                    } else {
                        mode = DraftMode::InCreateTable;
                    }
                } else if let Some(cap) = copy_re.as_ref().and_then(|re| re.captures(&line)) {
                    let (schema, table) = parse_table_ident(cap.get(1).unwrap().as_str());
                    copy_table_key = table_key(schema.as_deref(), &table);
                    copy_columns = split_ident_list(cap.get(2).unwrap().as_str());
                    let entry = tables
                        .entry(copy_table_key.clone())
                        .or_insert_with(|| TableAccum::new(sample_rows));
                    if entry.columns.is_empty() {
                        entry.columns = copy_columns.clone();
                    }
                    mode = DraftMode::InCopy;
                }
            }
            DraftMode::InInsert => {
                insert_buf.push_str(&line);
                if statement_complete(&insert_buf) {
                    if let Ok(parsed) = parse_insert_for_draft(&insert_buf) {
                        record_insert_draft(&mut tables, parsed, sample_rows);
                    }
                    mode = DraftMode::Pass;
                    insert_buf.clear();
                }
            }
            DraftMode::InCreateTable => {
                create_buf.push_str(&line);
                if statement_complete(&create_buf) {
                    if let Some(parsed) = parse_create_table_details(&create_buf) {
                        let tk = table_key(parsed.schema.as_deref(), &parsed.table);
                        ddl_columns.insert(tk.clone(), parsed.columns.clone());
                        tables
                            .entry(tk)
                            .or_insert_with(|| TableAccum::new(sample_rows))
                            .merge_ddl(&parsed);
                    }
                    mode = DraftMode::Pass;
                    create_buf.clear();
                }
            }
            DraftMode::InCopy => {
                if line.trim_end() == "\\." {
                    mode = DraftMode::Pass;
                    copy_columns.clear();
                    copy_table_key.clear();
                } else {
                    let body = line.trim_end_matches(['\r', '\n']);
                    let fields: Vec<&str> = body.split('\t').collect();
                    let unescaped: Vec<Option<&str>> = fields
                        .iter()
                        .map(|f| if *f == r"\N" { None } else { Some(*f) })
                        .collect();
                    if let Some(acc) = tables.get_mut(&copy_table_key) {
                        acc.observe_row_fields(&unescaped);
                    }
                }
            }
        }
    }

    // Tables seen only in DDL: ensure they exist so column list is present
    for (tk, cols) in ddl_columns {
        let e = tables
            .entry(tk)
            .or_insert_with(|| TableAccum::new(sample_rows));
        if e.columns.is_empty() {
            e.columns = cols;
        }
    }

    let rules = finalize_rules(tables);
    let raw = RawConfig {
        salt: Some("${DUMPLING_GLOBAL_SALT}".to_string()),
        rules,
        row_filters: HashMap::new(),
        column_cases: HashMap::new(),
        table_options: HashMap::new(),
        sensitive_columns: HashMap::new(),
        output_scan: crate::settings::OutputScanConfig::default(),
    };

    writeln!(
        writer,
        "# DRAFT Dumpling policy — generated by `dumpling generate-draft-config`."
    )?;
    writeln!(writer, "# Review and edit before use; add salts, domains, row_filters, sensitive_columns, and output_scan as needed.")?;
    writeln!(writer)?;
    writer.write_all(raw_config_to_toml(&raw)?.as_bytes())?;
    Ok(())
}

struct InsertDraft {
    schema: Option<String>,
    table: String,
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

fn parse_insert_for_draft(stmt: &str) -> anyhow::Result<InsertDraft> {
    let s = stmt.trim();
    if !s.ends_with(';') {
        anyhow::bail!("INSERT without trailing semicolon");
    }
    let (insert_kw, kw_len) = detect_insert_keyword(s);
    let idx =
        find_ignore_ascii_case(s, insert_kw).ok_or_else(|| anyhow::anyhow!("not an INSERT"))?;
    let after = &s[idx + kw_len..];
    let (schema, table, rest_after_table) = parse_table_and_rest(after)?;
    let (columns, rest_after_cols) = parse_parenthesized_ident_list(rest_after_table)?;
    let idx_values = find_ignore_ascii_case(rest_after_cols, "VALUES")
        .ok_or_else(|| anyhow::anyhow!("INSERT missing VALUES"))?;
    let after_values = &rest_after_cols[idx_values + "VALUES".len()..];
    let values_block = strip_trailing_semicolon(after_values.trim());
    let rows = parse_values_rows(values_block)?;
    Ok(InsertDraft {
        schema,
        table,
        columns,
        rows,
    })
}

fn record_insert_draft(
    tables: &mut HashMap<String, TableAccum>,
    ins: InsertDraft,
    sample_rows: usize,
) {
    let tk = table_key(ins.schema.as_deref(), &ins.table);
    let entry = tables
        .entry(tk)
        .or_insert_with(|| TableAccum::new(sample_rows));
    if entry.columns.is_empty() {
        entry.columns = ins.columns.clone();
    }
    for row in ins.rows {
        let mut fields: Vec<Option<&str>> = Vec::with_capacity(row.len());
        for (i, cell) in row.iter().enumerate() {
            let v = cell.original.as_deref();
            fields.push(v);
            let col_key = ins
                .columns
                .get(i)
                .map(|s| s.to_lowercase())
                .unwrap_or_else(|| format!("col_{i}"));
            if v.is_none() {
                entry.null_any.insert(col_key, true);
            }
        }
        entry.observe_reservoir(&fields);
    }
}

enum DraftMode {
    Pass,
    InInsert,
    InCreateTable,
    InCopy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn draft_config_email_column_and_sample() {
        let sql = r#"
CREATE TABLE public.users (id int, email varchar(255), name text);
INSERT INTO public.users (id, email, name) VALUES
  (1, 'a@example.com', 'Alice'),
  (2, 'b@example.com', 'Bob'),
  (3, NULL, 'Carol');
"#;
        let mut out = Vec::new();
        generate_draft_config(&mut Cursor::new(sql), &mut out, DumpFormat::Postgres, 5).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("[rules.\"public.users\""));
        assert!(s.contains("email"));
        assert!(s.contains("strategy = \"email\""));
        assert!(s.contains("length = 255") || s.contains("length=255"));
    }

    #[test]
    fn draft_config_skips_leading_seal_line() {
        let mut input = String::from(crate::seal::SEAL_LINE_PREFIX);
        input.push_str(" v=3 version=0.0.0 profile=standard sha256=0000000000000000000000000000000000000000000000000000000000000000\n");
        input.push_str("CREATE TABLE t (email text);\nINSERT INTO t (email) VALUES ('x@y.com');\n");

        let mut out = Vec::new();
        generate_draft_config(&mut Cursor::new(input), &mut out, DumpFormat::Postgres, 5).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("strategy = \"email\""));
    }
}
