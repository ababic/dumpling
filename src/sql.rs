use crate::filter::{rewrite_json_paths_with_rules, should_keep_row, when_matches};
use crate::report::Reporter;
use crate::settings::{
    is_explicit_sensitive_column, lookup_column_cases, lookup_column_rule,
    lookup_json_path_rules_for_column, AnonymizerSpec, ResolvedConfig,
};
use crate::transform::{apply_anonymizer, AnonymizerRegistry, Replacement};
use anyhow::Context;
use rand::Rng;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};

/// The SQL dump dialect to process.
///
/// Selecting a format controls which syntax features are enabled:
/// - `Postgres`: full support including `COPY … FROM stdin` blocks.
/// - `Sqlite`: same INSERT parsing plus `INSERT OR REPLACE` / `INSERT OR IGNORE` variants;
///   no COPY support.
/// - `MsSql`: `[bracket]`-quoted identifiers, `N'…'` Unicode string literals, `nvarchar`/`nchar`
///   length extraction; no COPY support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DumpFormat {
    #[default]
    Postgres,
    Sqlite,
    MsSql,
}

pub struct SqlStreamProcessor {
    anonymizers: AnonymizerRegistry,
    config: ResolvedConfig,
    column_length_limits: HashMap<String, HashMap<String, usize>>,
    reporter: Option<*mut Reporter>, // raw pointer to allow mutable borrow during process
    sensitive_columns_detected: HashSet<String>,
    sensitive_columns_covered: HashSet<String>,
    format: DumpFormat,
}

#[derive(Debug, Clone, Default)]
pub struct SensitiveCoverageSummary {
    pub detected: Vec<String>,
    pub covered: Vec<String>,
    pub uncovered: Vec<String>,
}

enum Mode {
    Pass,
    InInsert,
    InCreateTable,
    InCopy {
        schema: Option<String>,
        table: String,
        columns: Vec<String>,
    },
}

impl SqlStreamProcessor {
    pub fn new(
        anonymizers: AnonymizerRegistry,
        config: ResolvedConfig,
        reporter: Option<&mut Reporter>,
        format: DumpFormat,
    ) -> Self {
        Self {
            anonymizers,
            config,
            column_length_limits: HashMap::new(),
            reporter: reporter.map(|r| r as *mut Reporter),
            sensitive_columns_detected: HashSet::new(),
            sensitive_columns_covered: HashSet::new(),
            format,
        }
    }

    /// Borrow the resolved config for fingerprinting (e.g. sealed-dump checks) without cloning.
    pub fn config_snapshot(&self) -> &ResolvedConfig {
        &self.config
    }

    pub fn sensitive_coverage_summary(&self) -> SensitiveCoverageSummary {
        let mut detected = self
            .sensitive_columns_detected
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        detected.sort();
        let mut covered = self
            .sensitive_columns_covered
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        covered.sort();
        let mut uncovered = detected
            .iter()
            .filter(|col| !self.sensitive_columns_covered.contains(*col))
            .cloned()
            .collect::<Vec<_>>();
        uncovered.sort();
        SensitiveCoverageSummary {
            detected,
            covered,
            uncovered,
        }
    }

    pub fn anonymizers(&self) -> &AnonymizerRegistry {
        &self.anonymizers
    }

    pub fn process<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        let mut line = String::new();
        let mut mode = Mode::Pass;
        let mut insert_buf = String::new();
        let mut create_table_buf = String::new();
        // COPY blocks are PostgreSQL-specific; skip the regex entirely for other formats.
        let copy_re = if self.format == DumpFormat::Postgres {
            Some(
                Regex::new(r#"(?i)^\s*COPY\s+([^\s(]+)\s*\(([^)]*)\)\s+FROM\s+stdin;\s*$"#)
                    .unwrap(),
            )
        } else {
            None
        };

        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                // EOF
                break;
            }
            match &mut mode {
                Mode::Pass => {
                    if starts_with_insert(&line) {
                        insert_buf.clear();
                        insert_buf.push_str(&line);
                        if statement_complete(&insert_buf) {
                            let transformed = self
                                .process_insert_statement(&insert_buf)
                                .with_context(|| {
                                    format!(
                                        "failed processing INSERT statement starting with: {}",
                                        &insert_buf.lines().next().unwrap_or("").trim()
                                    )
                                })?;
                            if !transformed.is_empty() {
                                writer.write_all(transformed.as_bytes())?;
                            }
                            insert_buf.clear();
                        } else {
                            mode = Mode::InInsert;
                        }
                    } else if starts_with_create_table(&line) {
                        create_table_buf.clear();
                        create_table_buf.push_str(&line);
                        if statement_complete(&create_table_buf) {
                            if let Some(parsed) = parse_create_table_details(&create_table_buf) {
                                self.track_sensitive_coverage(
                                    parsed.schema.as_deref(),
                                    &parsed.table,
                                    &parsed.columns,
                                );
                                if !parsed.lengths.is_empty() {
                                    self.register_column_lengths(
                                        parsed.schema.as_deref(),
                                        &parsed.table,
                                        parsed.lengths,
                                    );
                                }
                            }
                            writer.write_all(create_table_buf.as_bytes())?;
                            create_table_buf.clear();
                        } else {
                            mode = Mode::InCreateTable;
                        }
                    } else if let Some(cap) = copy_re.as_ref().and_then(|re| re.captures(&line)) {
                        // Begin COPY mode
                        let (schema, table) = parse_table_ident(cap.get(1).unwrap().as_str());
                        let columns = split_ident_list(cap.get(2).unwrap().as_str());
                        self.track_sensitive_coverage(schema.as_deref(), &table, &columns);
                        // Emit the header intact
                        writer.write_all(line.as_bytes())?;
                        mode = Mode::InCopy {
                            schema,
                            table,
                            columns,
                        };
                    } else {
                        // passthrough
                        writer.write_all(line.as_bytes())?;
                    }
                }
                Mode::InInsert => {
                    insert_buf.push_str(&line);
                    if statement_complete(&insert_buf) {
                        let transformed =
                            self.process_insert_statement(&insert_buf)
                                .with_context(|| {
                                    format!(
                                        "failed processing INSERT statement starting with: {}",
                                        &insert_buf.lines().next().unwrap_or("").trim()
                                    )
                                })?;
                        if !transformed.is_empty() {
                            writer.write_all(transformed.as_bytes())?;
                        }
                        mode = Mode::Pass;
                        insert_buf.clear();
                    }
                }
                Mode::InCopy {
                    schema,
                    table,
                    columns,
                } => {
                    if line.trim_end() == "\\." {
                        // end of copy
                        writer.write_all(line.as_bytes())?;
                        mode = Mode::Pass;
                    } else {
                        // data row
                        let line_body = line.trim_end_matches(['\n', '\r']);
                        let fields: Vec<&str> = line_body.split('\t').collect();
                        // Evaluate row filters
                        let unescaped: Vec<Option<&str>> = fields
                            .iter()
                            .map(|f| if *f == r"\N" { None } else { Some(*f) })
                            .collect();
                        let keep = should_keep_row(
                            &self.config,
                            schema.as_deref(),
                            table,
                            columns,
                            &unescaped,
                        );
                        if !keep {
                            if let Some(rp) = self.reporter {
                                unsafe {
                                    (*rp).record_row_dropped(schema.as_deref(), table, None);
                                }
                            }
                            continue;
                        }
                        if let Some(rp) = self.reporter {
                            unsafe {
                                (*rp).record_row_processed(schema.as_deref(), table);
                            }
                        }
                        let mut new_fields: Vec<String> = Vec::with_capacity(fields.len());
                        for (idx, field) in fields.iter().enumerate() {
                            let col = columns.get(idx).map(|s| s.as_str()).unwrap_or_else(|| "");
                            let original = if *field == r"\N" { None } else { Some(*field) };
                            match self.apply_column_rules(
                                schema.as_deref(),
                                table,
                                columns,
                                &unescaped,
                                col,
                                original,
                            ) {
                                Ok(None) => {
                                    new_fields.push((*field).to_string());
                                }
                                Ok(Some((repl, specs))) => {
                                    for spec in &specs {
                                        if let Some(rp) = self.reporter.as_ref() {
                                            unsafe {
                                                (*(*rp)).record_cell_changed(
                                                    schema.as_deref(),
                                                    table,
                                                    col,
                                                    &spec.strategy,
                                                    original.is_none(),
                                                );
                                                if let Some(domain) = spec
                                                    .domain
                                                    .as_deref()
                                                    .map(str::trim)
                                                    .filter(|value| !value.is_empty())
                                                {
                                                    (*(*rp)).record_deterministic_mapping_domain(
                                                        schema.as_deref(),
                                                        table,
                                                        col,
                                                        domain,
                                                        spec.unique_within_domain.unwrap_or(false),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    if repl.is_null {
                                        new_fields.push(r"\N".to_string());
                                    } else {
                                        new_fields.push(escape_postgres_copy_text_field(
                                            repl.value.as_ref(),
                                        ));
                                    }
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        // Re-add trailing newline
                        writer.write_all(new_fields.join("\t").as_bytes())?;
                        writer.write_all(b"\n")?;
                    }
                }
                Mode::InCreateTable => {
                    create_table_buf.push_str(&line);
                    if statement_complete(&create_table_buf) {
                        if let Some(parsed) = parse_create_table_details(&create_table_buf) {
                            self.track_sensitive_coverage(
                                parsed.schema.as_deref(),
                                &parsed.table,
                                &parsed.columns,
                            );
                            if !parsed.lengths.is_empty() {
                                self.register_column_lengths(
                                    parsed.schema.as_deref(),
                                    &parsed.table,
                                    parsed.lengths,
                                );
                            }
                        }
                        writer.write_all(create_table_buf.as_bytes())?;
                        mode = Mode::Pass;
                        create_table_buf.clear();
                    }
                }
            }
        }
        // Flush any unterminated buffer (shouldn't happen for valid dumps)
        match mode {
            Mode::InInsert => {
                writer.write_all(insert_buf.as_bytes())?;
            }
            Mode::InCreateTable => {
                writer.write_all(create_table_buf.as_bytes())?;
            }
            _ => {}
        }
        Ok(())
    }

    fn process_insert_statement(&mut self, stmt: &str) -> anyhow::Result<String> {
        // Compact whitespace minimally for parsing while preserving output formatting by re-rendering.
        // Extract INSERT [OR REPLACE|OR IGNORE] INTO <table> (columns) VALUES <rows> ;
        let s = stmt.trim();
        // Ensure trailing semicolon present
        if !s.ends_with(';') {
            anyhow::bail!("INSERT without trailing semicolon");
        }
        // Detect the INSERT variant keyword (SQLite supports OR REPLACE / OR IGNORE)
        let (insert_keyword, keyword_len) = detect_insert_keyword(s);
        let idx_insert = find_ignore_ascii_case(s, insert_keyword)
            .ok_or_else(|| anyhow::anyhow!("not an INSERT"))?;
        let after = &s[idx_insert + keyword_len..];
        // Parse table ident then columns list
        let (schema, table, rest_after_table) = parse_table_and_rest(after)?;
        let (columns, rest_after_cols) = parse_parenthesized_ident_list(rest_after_table)?;
        self.track_sensitive_coverage(schema.as_deref(), &table, &columns);
        // Expect VALUES
        let idx_values = find_ignore_ascii_case(rest_after_cols, "VALUES")
            .ok_or_else(|| anyhow::anyhow!("INSERT missing VALUES"))?;
        let after_values = &rest_after_cols[idx_values + "VALUES".len()..];
        // Strip trailing semicolon
        let values_block = strip_trailing_semicolon(after_values.trim());
        let rows = parse_values_rows(values_block)?;
        // Transform and filter rows
        let mut out = String::with_capacity(stmt.len());
        out.push_str(insert_keyword);
        out.push(' ');
        out.push_str(&format_table_ident(schema.as_deref(), &table));
        out.push_str(" (");
        out.push_str(&columns.join(", "));
        out.push_str(") VALUES ");
        let mut first_row = true;
        for row in rows.into_iter() {
            // Row-level keep/drop
            let cell_values: Vec<Option<&str>> =
                row.iter().map(|cell| cell.original.as_deref()).collect();
            let keep = should_keep_row(
                &self.config,
                schema.as_deref(),
                &table,
                &columns,
                &cell_values,
            );
            if !keep {
                if let Some(rp) = self.reporter {
                    unsafe {
                        (*rp).record_row_dropped(schema.as_deref(), &table, None);
                    }
                }
                continue;
            }
            if let Some(rp) = self.reporter {
                unsafe {
                    (*rp).record_row_processed(schema.as_deref(), &table);
                }
            }
            if !first_row {
                out.push_str(", ");
            }
            first_row = false;
            let mut rendered_cells: Vec<String> = Vec::with_capacity(row.len());
            for (i, cell) in row.iter().enumerate() {
                let col = columns.get(i).map(|s| s.as_str()).unwrap_or("");
                match self.apply_column_rules(
                    schema.as_deref(),
                    &table,
                    &columns,
                    cell_values.as_slice(),
                    col,
                    cell.original.as_deref(),
                ) {
                    Ok(None) => {
                        rendered_cells.push(cell.render_original());
                    }
                    Ok(Some((replacement, specs))) => {
                        for spec in &specs {
                            if let Some(rp) = self.reporter {
                                unsafe {
                                    (*rp).record_cell_changed(
                                        schema.as_deref(),
                                        &table,
                                        col,
                                        &spec.strategy,
                                        cell.original.is_none(),
                                    );
                                    if let Some(domain) = spec
                                        .domain
                                        .as_deref()
                                        .map(str::trim)
                                        .filter(|value| !value.is_empty())
                                    {
                                        (*rp).record_deterministic_mapping_domain(
                                            schema.as_deref(),
                                            &table,
                                            col,
                                            domain,
                                            spec.unique_within_domain.unwrap_or(false),
                                        );
                                    }
                                }
                            }
                        }
                        rendered_cells.push(render_cell(&replacement, cell));
                    }
                    Err(e) => return Err(e),
                }
            }
            out.push('(');
            let mut sep = "";
            for part in &rendered_cells {
                out.push_str(sep);
                out.push_str(part);
                sep = ", ";
            }
            out.push(')');
        }
        out.push_str(";\n");
        Ok(out)
    }

    fn register_column_lengths(
        &mut self,
        schema: Option<&str>,
        table: &str,
        lengths: HashMap<String, usize>,
    ) {
        if lengths.is_empty() {
            return;
        }
        let table_key = table.to_lowercase();
        self.column_length_limits.insert(table_key, lengths.clone());
        if let Some(schema_name) = schema {
            let key = format!("{}.{}", schema_name.to_lowercase(), table.to_lowercase());
            self.column_length_limits.insert(key, lengths);
        }
    }

    fn lookup_column_max_length(
        &self,
        schema: Option<&str>,
        table: &str,
        column: &str,
    ) -> Option<usize> {
        let column_key = column.to_lowercase();
        if let Some(schema_name) = schema {
            let table_key = format!("{}.{}", schema_name.to_lowercase(), table.to_lowercase());
            if let Some(cols) = self.column_length_limits.get(&table_key) {
                if let Some(len) = cols.get(&column_key) {
                    return Some(*len);
                }
            }
        }
        let table_key = table.to_lowercase();
        self.column_length_limits
            .get(&table_key)
            .and_then(|cols| cols.get(&column_key).copied())
    }

    /// Applies whole-column and/or JSON path rules. Returns `None` to passthrough the original cell.
    fn apply_column_rules(
        &self,
        schema: Option<&str>,
        table: &str,
        columns: &[String],
        row_cells: &[Option<&str>],
        col: &str,
        cell_original: Option<&str>,
    ) -> anyhow::Result<Option<(Replacement, Vec<AnonymizerSpec>)>> {
        let selected =
            select_strategy_for_cell(&self.config, schema, table, columns, row_cells, col);
        let json_refs = lookup_json_path_rules_for_column(&self.config, schema, table, col);
        let json_owned: Vec<(Vec<String>, AnonymizerSpec)> =
            json_refs.into_iter().map(|(p, s)| (p, s.clone())).collect();

        if selected.is_none() && json_owned.is_empty() {
            return Ok(None);
        }

        let col_len = self.lookup_column_max_length(schema, table, col);

        if let Some(spec) = selected {
            let repl = apply_anonymizer(&self.anonymizers, &spec, cell_original, col_len);
            return Ok(Some((repl, vec![spec])));
        }

        let raw = match cell_original {
            Some(s) => s,
            None => return Ok(None),
        };
        let specs: Vec<AnonymizerSpec> = json_owned.iter().map(|(_, s)| s.clone()).collect();
        let Some(out) =
            rewrite_json_paths_with_rules(&self.anonymizers, col_len, &json_owned, raw)?
        else {
            return Ok(None);
        };
        let repl = Replacement::quoted(out);
        Ok(Some((repl, specs)))
    }

    fn track_sensitive_coverage(&mut self, schema: Option<&str>, table: &str, columns: &[String]) {
        for column in columns {
            if !is_sensitive_candidate(&self.config, schema, table, column) {
                continue;
            }
            let qualified = qualified_column_name(schema, table, column);
            self.sensitive_columns_detected.insert(qualified.clone());
            if is_explicitly_covered_column(&self.config, schema, table, column) {
                self.sensitive_columns_covered.insert(qualified);
            }
        }
    }
}

/// Table key as used in config TOML: `schema.table` when a schema is present, else `table` (lowercase).
fn scaffold_table_key(schema: Option<&str>, table: &str) -> String {
    let t = table.to_lowercase();
    match schema {
        Some(s) if !s.trim().is_empty() => format!("{}.{}", s.to_lowercase(), t),
        _ => t,
    }
}

fn scaffold_address_like_segment(normalized: &str) -> bool {
    if normalized.contains("ip_address") || normalized.contains("mac_address") {
        return false;
    }
    if normalized.contains("address") {
        return true;
    }
    if normalized.contains("street")
        || normalized.contains("postal")
        || normalized.contains("postcode")
    {
        return true;
    }
    if normalized.contains("zip") && (normalized.contains("code") || normalized.ends_with("_zip")) {
        return true;
    }
    normalized.contains("mailing")
        || normalized.contains("shipping")
        || normalized.contains("billing")
}

/// Heuristic strategy for starter config from a column name. These rules are **English-oriented**
/// substring matches; other languages or opaque names need manual review.
pub fn infer_scaffold_strategy(column: &str) -> Option<AnonymizerSpec> {
    infer_auto_strategy(column)
}

/// Options for [`discover_scaffold_rules`].
#[derive(Debug, Clone)]
pub struct ScaffoldDiscoverOptions {
    /// When true, sample up to [`SCAFFOLD_JSON_RESERVOIR_SIZE`] rows **per table** (reservoir)
    /// from INSERT/COPY data and infer nested JSON `[rules]` keys from cell values.
    pub infer_json_paths: bool,
    /// Maximum nesting depth when walking JSON objects and arrays (default 24).
    pub max_json_depth: usize,
}

/// Max rows kept per table for JSON path inference (reservoir sampling for a fair spread).
pub const SCAFFOLD_JSON_RESERVOIR_SIZE: usize = 5;

impl Default for ScaffoldDiscoverOptions {
    fn default() -> Self {
        Self {
            infer_json_paths: false,
            max_json_depth: 24,
        }
    }
}

fn scaffold_merge_rule(
    rules: &mut HashMap<String, HashMap<String, AnonymizerSpec>>,
    table_key: &str,
    col_key: &str,
    spec: AnonymizerSpec,
) {
    let cols = rules.entry(table_key.to_string()).or_default();
    let col_key = col_key.to_lowercase();
    match cols.get(&col_key) {
        None => {
            cols.insert(col_key, spec);
        }
        Some(existing) if existing.strategy == spec.strategy => {}
        Some(_) => {}
    }
}

/// Reservoir (Algorithm R) for up to `k` rows per table; stores full cell text per row.
struct TableRowReservoir {
    k: usize,
    columns: Option<Vec<String>>,
    rows: Vec<Vec<String>>,
    n_seen: u64,
}

impl TableRowReservoir {
    fn new(k: usize) -> Self {
        Self {
            k,
            columns: None,
            rows: Vec::with_capacity(k),
            n_seen: 0,
        }
    }

    fn set_columns(&mut self, columns: Vec<String>) {
        if self.columns.is_none() {
            self.columns = Some(columns);
        }
    }

    fn push_row<R: Rng + ?Sized>(&mut self, cells: Vec<String>, rng: &mut R) {
        if self.k == 0 {
            return;
        }
        self.n_seen = self.n_seen.saturating_add(1);
        let n = self.n_seen as usize;
        if self.rows.len() < self.k {
            self.rows.push(cells);
            return;
        }
        let j = rng.random_range(0..n);
        if j < self.k {
            self.rows[j] = cells;
        }
    }

    fn flush_into_rules(
        self,
        table_key: &str,
        max_json_depth: usize,
        rules: &mut HashMap<String, HashMap<String, AnonymizerSpec>>,
    ) {
        let Some(columns) = self.columns else {
            return;
        };
        for row in self.rows {
            for (i, raw) in row.iter().enumerate() {
                let col = columns.get(i).map(|s| s.as_str()).unwrap_or("");
                scaffold_consider_json_column_cell(table_key, col, raw, max_json_depth, rules);
            }
        }
    }
}

/// One streaming pass over a SQL dump: collect `[rules]` from column names and (optionally) sampled
/// row values. Conflicting rule keys keep the first strategy seen.
pub fn discover_scaffold_rules<R: BufRead + ?Sized>(
    reader: &mut R,
    format: DumpFormat,
    options: &ScaffoldDiscoverOptions,
) -> anyhow::Result<HashMap<String, HashMap<String, AnonymizerSpec>>> {
    let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
    let mut line = String::new();
    let mut mode = Mode::Pass;
    let mut insert_buf = String::new();
    let mut create_table_buf = String::new();
    let copy_re = if format == DumpFormat::Postgres {
        Some(Regex::new(r#"(?i)^\s*COPY\s+([^\s(]+)\s*\(([^)]*)\)\s+FROM\s+stdin;\s*$"#).unwrap())
    } else {
        None
    };

    let mut rng = rand::rng();
    let mut table_reservoirs: HashMap<String, TableRowReservoir> = HashMap::new();

    fn consider_scaffold_columns_for_names(
        rules: &mut HashMap<String, HashMap<String, AnonymizerSpec>>,
        schema: Option<&str>,
        table: &str,
        columns: &[String],
    ) {
        for column in columns {
            if let Some(spec) = infer_scaffold_strategy(column) {
                let table_key = scaffold_table_key(schema, table);
                scaffold_merge_rule(rules, &table_key, column, spec);
            }
        }
    }

    fn reservoir_for_table<'a>(
        map: &'a mut HashMap<String, TableRowReservoir>,
        table_key: &str,
    ) -> &'a mut TableRowReservoir {
        map.entry(table_key.to_string())
            .or_insert_with(|| TableRowReservoir::new(SCAFFOLD_JSON_RESERVOIR_SIZE))
    }

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        match &mut mode {
            Mode::Pass => {
                if starts_with_insert(&line) {
                    insert_buf.clear();
                    insert_buf.push_str(&line);
                    if statement_complete(&insert_buf) {
                        let s = insert_buf.trim();
                        if s.ends_with(';') {
                            if let Ok((schema, table, rest_after_table)) =
                                parse_table_and_rest_after_insert(s)
                            {
                                if let Ok((columns, rest_after_cols)) =
                                    parse_parenthesized_ident_list(rest_after_table)
                                {
                                    consider_scaffold_columns_for_names(
                                        &mut rules,
                                        schema.as_deref(),
                                        &table,
                                        &columns,
                                    );
                                    if options.infer_json_paths {
                                        let table_key =
                                            scaffold_table_key(schema.as_deref(), &table);
                                        let r =
                                            reservoir_for_table(&mut table_reservoirs, &table_key);
                                        r.set_columns(columns.clone());
                                        if let Some(idx) =
                                            find_ignore_ascii_case(rest_after_cols, "VALUES")
                                        {
                                            let after_values =
                                                &rest_after_cols[idx + "VALUES".len()..];
                                            let values_block =
                                                strip_trailing_semicolon(after_values.trim());
                                            if let Ok(rows) = parse_values_rows(values_block) {
                                                for row in rows {
                                                    let cells: Vec<String> = row
                                                        .iter()
                                                        .map(|c| {
                                                            c.original.clone().unwrap_or_default()
                                                        })
                                                        .collect();
                                                    r.push_row(cells, &mut rng);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        insert_buf.clear();
                    } else {
                        mode = Mode::InInsert;
                    }
                } else if starts_with_create_table(&line) {
                    create_table_buf.clear();
                    create_table_buf.push_str(&line);
                    if statement_complete(&create_table_buf) {
                        if let Some(parsed) = parse_create_table_details(&create_table_buf) {
                            consider_scaffold_columns_for_names(
                                &mut rules,
                                parsed.schema.as_deref(),
                                &parsed.table,
                                &parsed.columns,
                            );
                        }
                        create_table_buf.clear();
                    } else {
                        mode = Mode::InCreateTable;
                    }
                } else if let Some(cap) = copy_re.as_ref().and_then(|re| re.captures(&line)) {
                    let (schema, table) = parse_table_ident(cap.get(1).unwrap().as_str());
                    let columns = split_ident_list(cap.get(2).unwrap().as_str());
                    consider_scaffold_columns_for_names(
                        &mut rules,
                        schema.as_deref(),
                        &table,
                        &columns,
                    );
                    if options.infer_json_paths {
                        let table_key = scaffold_table_key(schema.as_deref(), &table);
                        let r = reservoir_for_table(&mut table_reservoirs, &table_key);
                        r.set_columns(columns.clone());
                    }
                    mode = Mode::InCopy {
                        schema,
                        table,
                        columns,
                    };
                }
            }
            Mode::InInsert => {
                insert_buf.push_str(&line);
                if statement_complete(&insert_buf) {
                    let s = insert_buf.trim();
                    if s.ends_with(';') {
                        if let Ok((schema, table, rest_after_table)) =
                            parse_table_and_rest_after_insert(s)
                        {
                            if let Ok((columns, rest_after_cols)) =
                                parse_parenthesized_ident_list(rest_after_table)
                            {
                                consider_scaffold_columns_for_names(
                                    &mut rules,
                                    schema.as_deref(),
                                    &table,
                                    &columns,
                                );
                                if options.infer_json_paths {
                                    let table_key = scaffold_table_key(schema.as_deref(), &table);
                                    let r = reservoir_for_table(&mut table_reservoirs, &table_key);
                                    r.set_columns(columns.clone());
                                    if let Some(idx) =
                                        find_ignore_ascii_case(rest_after_cols, "VALUES")
                                    {
                                        let after_values = &rest_after_cols[idx + "VALUES".len()..];
                                        let values_block =
                                            strip_trailing_semicolon(after_values.trim());
                                        if let Ok(rows) = parse_values_rows(values_block) {
                                            for row in rows {
                                                let cells: Vec<String> = row
                                                    .iter()
                                                    .map(|c| c.original.clone().unwrap_or_default())
                                                    .collect();
                                                r.push_row(cells, &mut rng);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    mode = Mode::Pass;
                    insert_buf.clear();
                }
            }
            Mode::InCopy {
                schema,
                table,
                columns: _,
            } => {
                if line.trim_end() == "\\." {
                    mode = Mode::Pass;
                } else if options.infer_json_paths {
                    let line_body = line.trim_end_matches(['\n', '\r']);
                    let fields: Vec<&str> = line_body.split('\t').collect();
                    let table_key = scaffold_table_key(schema.as_deref(), table);
                    let r = reservoir_for_table(&mut table_reservoirs, &table_key);
                    let mut cells: Vec<String> = Vec::with_capacity(fields.len());
                    for field in fields.iter() {
                        if *field == r"\N" {
                            cells.push(String::new());
                        } else {
                            cells.push(decode_postgres_copy_text_field(field));
                        }
                    }
                    r.push_row(cells, &mut rng);
                }
            }
            Mode::InCreateTable => {
                create_table_buf.push_str(&line);
                if statement_complete(&create_table_buf) {
                    if let Some(parsed) = parse_create_table_details(&create_table_buf) {
                        consider_scaffold_columns_for_names(
                            &mut rules,
                            parsed.schema.as_deref(),
                            &parsed.table,
                            &parsed.columns,
                        );
                    }
                    mode = Mode::Pass;
                    create_table_buf.clear();
                }
            }
        }
    }

    if options.infer_json_paths {
        for (table_key, reservoir) in table_reservoirs {
            reservoir.flush_into_rules(&table_key, options.max_json_depth, &mut rules);
        }
    }

    Ok(rules)
}

/// Same as [`discover_scaffold_rules`] with default options (name-based columns only, no row sampling).
pub fn discover_scaffold_column_rules<R: BufRead + ?Sized>(
    reader: &mut R,
    format: DumpFormat,
) -> anyhow::Result<HashMap<String, HashMap<String, AnonymizerSpec>>> {
    discover_scaffold_rules(reader, format, &ScaffoldDiscoverOptions::default())
}

fn decode_postgres_copy_text_field(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('b') => out.push('\x08'),
                Some('f') => out.push('\x0c'),
                Some('v') => out.push('\x0b'),
                Some('0') => out.push('\0'),
                Some(x) => out.push(x),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn scaffold_rule_key_for_json_path(base_column: &str, path: &[String]) -> String {
    let mut s = base_column.to_string();
    for p in path {
        s.push('.');
        s.push_str(p);
    }
    s
}

fn infer_scaffold_from_leaf_segment_and_sample(
    segment_name: &str,
    sample: &str,
) -> Option<AnonymizerSpec> {
    infer_scaffold_strategy(segment_name)
        .or_else(|| infer_scaffold_from_address_like_literal(sample))
        .or_else(|| infer_scaffold_from_literal_sample(sample))
}

lazy_static::lazy_static! {
    /// US ZIP / ZIP+4 — common postal indicator in free-text addresses.
    static ref SCAFFOLD_US_ZIP: Regex = Regex::new(r"\b\d{5}(?:-\d{4})?\b").expect("zip regex");
    /// Single-line street-style address (digit + … + suffix).
    static ref SCAFFOLD_STREET_LINE: Regex = Regex::new(
        r"(?i)^\s*\d+\s+\S.+\s+(st|street|ave|avenue|rd|road|blvd|boulevard|ln|lane|dr|drive|ct|court|pl|place|way)\.?\s*$"
    )
    .expect("street regex");
}

/// Short free-text that looks like a postal/street line (English-oriented; many false negatives).
fn infer_scaffold_from_address_like_literal(sample: &str) -> Option<AnonymizerSpec> {
    let t = sample.trim();
    if t.is_empty() || t.len() > 512 || t.contains('\n') {
        return None;
    }
    if SCAFFOLD_US_ZIP.is_match(t) || SCAFFOLD_STREET_LINE.is_match(t) {
        return Some(base_spec("redact", Some(true)));
    }
    None
}

/// RFC-like email shape only — avoids keying `hash` off arbitrary `@` tokens.
fn infer_scaffold_from_literal_sample(sample: &str) -> Option<AnonymizerSpec> {
    let t = sample.trim();
    if t.len() > 320 || t.contains('\n') {
        return None;
    }
    if let Some(at) = t.find('@') {
        let rest = &t[at + 1..];
        if rest.contains('.') && t[..at].chars().any(|c| !c.is_whitespace()) {
            return Some(base_spec("email", Some(true)));
        }
    }
    None
}

fn scaffold_strip_whole_column_for_json_paths(
    table_key: &str,
    base_column: &str,
    rules: &mut HashMap<String, HashMap<String, AnonymizerSpec>>,
) {
    let base_lower = base_column.to_lowercase();
    if let Some(cols) = rules.get_mut(table_key) {
        cols.remove(&base_lower);
    }
}

fn scaffold_consider_json_column_cell(
    table_key: &str,
    sql_column: &str,
    cell_text: &str,
    max_depth: usize,
    rules: &mut HashMap<String, HashMap<String, AnonymizerSpec>>,
) {
    let v = match serde_json::from_str::<serde_json::Value>(cell_text) {
        Ok(v) => v,
        Err(_) => {
            if let Some(spec) = infer_scaffold_from_address_like_literal(cell_text) {
                scaffold_merge_rule(rules, table_key, sql_column, spec);
            }
            return;
        }
    };
    let mut path = Vec::new();
    match &v {
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
            scaffold_walk_json_for_rules(&v, sql_column, &mut path, 0, max_depth, table_key, rules);
        }
        serde_json::Value::String(s) => {
            if let Some(spec) = infer_scaffold_from_leaf_segment_and_sample(sql_column, s.as_str())
            {
                scaffold_merge_rule(rules, table_key, sql_column, spec);
            }
        }
        serde_json::Value::Number(n) => {
            if let Some(spec) =
                infer_scaffold_from_leaf_segment_and_sample(sql_column, &n.to_string())
            {
                scaffold_merge_rule(rules, table_key, sql_column, spec);
            }
        }
        serde_json::Value::Bool(b) => {
            if let Some(spec) = infer_scaffold_from_leaf_segment_and_sample(
                sql_column,
                if *b { "true" } else { "false" },
            ) {
                scaffold_merge_rule(rules, table_key, sql_column, spec);
            }
        }
        serde_json::Value::Null => {}
    }
}

fn scaffold_walk_json_for_rules(
    value: &serde_json::Value,
    sql_column: &str,
    path: &mut Vec<String>,
    depth: usize,
    max_depth: usize,
    table_key: &str,
    rules: &mut HashMap<String, HashMap<String, AnonymizerSpec>>,
) {
    if depth > max_depth {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                scaffold_walk_json_for_rules(
                    v,
                    sql_column,
                    path,
                    depth + 1,
                    max_depth,
                    table_key,
                    rules,
                );
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                path.push(i.to_string());
                scaffold_walk_json_for_rules(
                    v,
                    sql_column,
                    path,
                    depth + 1,
                    max_depth,
                    table_key,
                    rules,
                );
                path.pop();
            }
        }
        serde_json::Value::String(s) => {
            if let Some(spec) = infer_scaffold_from_leaf_segment_and_sample(
                path.last().map_or(sql_column, |s| s.as_str()),
                s.as_str(),
            ) {
                let key = scaffold_rule_key_for_json_path(sql_column, path);
                scaffold_strip_whole_column_for_json_paths(table_key, sql_column, rules);
                scaffold_merge_rule(rules, table_key, &key, spec);
            }
        }
        serde_json::Value::Number(n) => {
            let seg = path.last().map_or(sql_column, |s| s.as_str());
            if let Some(spec) = infer_scaffold_from_leaf_segment_and_sample(seg, &n.to_string()) {
                let key = scaffold_rule_key_for_json_path(sql_column, path);
                scaffold_strip_whole_column_for_json_paths(table_key, sql_column, rules);
                scaffold_merge_rule(rules, table_key, &key, spec);
            }
        }
        serde_json::Value::Bool(b) => {
            let seg = path.last().map_or(sql_column, |s| s.as_str());
            if let Some(spec) =
                infer_scaffold_from_leaf_segment_and_sample(seg, if *b { "true" } else { "false" })
            {
                let key = scaffold_rule_key_for_json_path(sql_column, path);
                scaffold_strip_whole_column_for_json_paths(table_key, sql_column, rules);
                scaffold_merge_rule(rules, table_key, &key, spec);
            }
        }
        serde_json::Value::Null => {}
    }
}

/// After the INSERT keyword and whitespace, parse `"schema"."table" (...cols)"` / table (...cols).
fn parse_table_and_rest_after_insert(stmt: &str) -> anyhow::Result<(Option<String>, String, &str)> {
    let trimmed = stmt.trim_start();
    let (insert_keyword, keyword_len) = detect_insert_keyword(trimmed);
    let idx_insert = find_ignore_ascii_case(trimmed, insert_keyword)
        .ok_or_else(|| anyhow::anyhow!("not an INSERT"))?;
    let after = &trimmed[idx_insert + keyword_len..];
    parse_table_and_rest(after)
}

fn starts_with_insert(line: &str) -> bool {
    let trimmed = line.trim_start();
    starts_with_ci(trimmed, "INSERT INTO")
        || starts_with_ci(trimmed, "INSERT OR REPLACE INTO")
        || starts_with_ci(trimmed, "INSERT OR IGNORE INTO")
}

/// Returns the INSERT keyword variant (uppercase) and its byte length.
/// Handles standard INSERT INTO as well as SQLite's OR REPLACE / OR IGNORE forms.
fn detect_insert_keyword(stmt: &str) -> (&'static str, usize) {
    // Search from the start of the (trimmed) statement for the first keyword
    let trimmed = stmt.trim_start();
    if starts_with_ci(trimmed, "INSERT OR REPLACE INTO") {
        ("INSERT OR REPLACE INTO", "INSERT OR REPLACE INTO".len())
    } else if starts_with_ci(trimmed, "INSERT OR IGNORE INTO") {
        ("INSERT OR IGNORE INTO", "INSERT OR IGNORE INTO".len())
    } else {
        ("INSERT INTO", "INSERT INTO".len())
    }
}

fn starts_with_create_table(line: &str) -> bool {
    let trimmed = line.trim_start();
    starts_with_ci(trimmed, "CREATE TABLE") || starts_with_ci(trimmed, "CREATE UNLOGGED TABLE")
}

fn statement_complete(buf: &str) -> bool {
    // Detect a semicolon that's not inside quotes or parentheses
    let mut depth: i32 = 0;
    let mut in_single = false;
    let mut chars = buf.chars().peekable();
    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                // doubled single-quote escapes (standard SQL)
                if chars.peek() == Some(&'\'') {
                    let _ = chars.next();
                } else {
                    in_single = false;
                }
            }
        } else {
            match c {
                '\'' => in_single = true,
                '(' => depth += 1,
                ')' => depth -= 1,
                ';' if depth == 0 => return true,
                _ => {}
            }
        }
    }
    false
}

fn parse_table_ident(s: &str) -> (Option<String>, String) {
    // Handles schema.table or table; may include quoted identifiers
    let trimmed = s.trim();
    let (schema, table) = if let Some(dot) = split_ident_by_dot(trimmed) {
        (Some(dot.0), dot.1)
    } else {
        (None, unquote_ident(trimmed))
    };
    (schema, table)
}

fn format_table_ident(schema: Option<&str>, table: &str) -> String {
    match schema {
        Some(s) => format!("{}.{}", s, table),
        None => table.to_string(),
    }
}

fn split_ident_by_dot(input: &str) -> Option<(String, String)> {
    // parse possibly quoted ident parts separated by dot at top-level
    // supports "double-quotes" (SQL standard / PostgreSQL / SQLite),
    // [brackets] (SQL Server / MSSQL), and `backticks` (MySQL / SQLite)
    let mut in_double = false;
    let mut in_bracket = false;
    let mut in_backtick = false;
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    for c in input.chars() {
        match c {
            '"' if !in_bracket && !in_backtick => {
                in_double = !in_double;
                current.push(c);
            }
            '[' if !in_double && !in_backtick && !in_bracket => {
                in_bracket = true;
                current.push(c);
            }
            ']' if in_bracket => {
                in_bracket = false;
                current.push(c);
            }
            '`' if !in_double && !in_bracket => {
                in_backtick = !in_backtick;
                current.push(c);
            }
            '.' if !in_double && !in_bracket && !in_backtick => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    if parts.len() == 2 {
        Some((unquote_ident(&parts[0]), unquote_ident(&parts[1])))
    } else {
        None
    }
}

fn unquote_ident(s: &str) -> String {
    let t = s.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        // Standard SQL / PostgreSQL / SQLite double-quote identifier
        t[1..t.len() - 1].to_string()
    } else if t.starts_with('[') && t.ends_with(']') && t.len() >= 2 {
        // SQL Server / MSSQL bracket-quoted identifier
        t[1..t.len() - 1].to_string()
    } else if t.starts_with('`') && t.ends_with('`') && t.len() >= 2 {
        // MySQL / SQLite backtick-quoted identifier (handled for completeness)
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

fn split_ident_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| unquote_ident(p.trim()))
        .collect::<Vec<_>>()
}

fn parse_table_and_rest(after_insert_into: &str) -> anyhow::Result<(Option<String>, String, &str)> {
    // after: "<table_ident> ("
    // Handles "double-quotes" (SQL standard), [brackets] (MSSQL), and `backticks`
    let bytes = after_insert_into.as_bytes();
    let mut i = 0usize;
    // skip whitespace
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    // read until first '(' at top-level (respect any quoting style)
    let mut ident = String::new();
    let mut in_double = false;
    let mut in_bracket = false;
    let mut in_backtick = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' if !in_bracket && !in_backtick => {
                in_double = !in_double;
                ident.push(c);
                i += 1;
            }
            '[' if !in_double && !in_backtick && !in_bracket => {
                in_bracket = true;
                ident.push(c);
                i += 1;
            }
            ']' if in_bracket => {
                in_bracket = false;
                ident.push(c);
                i += 1;
            }
            '`' if !in_double && !in_bracket => {
                in_backtick = !in_backtick;
                ident.push(c);
                i += 1;
            }
            '(' if !in_double && !in_bracket && !in_backtick => break,
            _ => {
                ident.push(c);
                i += 1;
            }
        }
    }
    if i >= bytes.len() || bytes[i] as char != '(' {
        anyhow::bail!("expected '(' after table ident");
    }
    let rest = &after_insert_into[i..];
    let (schema, table) = parse_table_ident(ident.trim());
    Ok((schema, table, rest))
}

fn parse_parenthesized_ident_list(s: &str) -> anyhow::Result<(Vec<String>, &str)> {
    // s starts with '('
    // Handles "double-quotes", [brackets], and `backticks` in column names
    let bytes = s.as_bytes();
    let mut i = 0usize;
    if bytes.first().copied().map(|b| b as char) != Some('(') {
        anyhow::bail!("expected '(' after table ident");
    }
    i += 1; // consume '('
    let start = i;
    let mut depth = 1i32;
    let mut in_double = false;
    let mut in_bracket = false;
    let mut in_backtick = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' if !in_bracket && !in_backtick => {
                in_double = !in_double;
                i += 1;
            }
            '[' if !in_double && !in_backtick && !in_bracket => {
                in_bracket = true;
                i += 1;
            }
            ']' if in_bracket => {
                in_bracket = false;
                i += 1;
            }
            '`' if !in_double && !in_bracket => {
                in_backtick = !in_backtick;
                i += 1;
            }
            '(' if !in_double && !in_bracket && !in_backtick => {
                depth += 1;
                i += 1;
            }
            ')' if !in_double && !in_bracket && !in_backtick => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    let content = &s[start..i - 1];
                    let rest = &s[i..];
                    let idents = split_ident_list(content);
                    return Ok((idents, rest));
                }
            }
            _ => i += 1,
        }
    }
    anyhow::bail!("unterminated column list")
}

struct ParsedCreateTable {
    schema: Option<String>,
    table: String,
    columns: Vec<String>,
    lengths: HashMap<String, usize>,
}

fn parse_create_table_details(stmt: &str) -> Option<ParsedCreateTable> {
    let (schema, table, column_block) = parse_create_table_header(stmt)?;
    let (columns, lengths) = parse_column_definitions(column_block);
    Some(ParsedCreateTable {
        schema,
        table,
        columns,
        lengths,
    })
}

fn parse_create_table_header(stmt: &str) -> Option<(Option<String>, String, &str)> {
    let mut rest = stmt.trim_start();
    if starts_with_ci(rest, "CREATE UNLOGGED TABLE") {
        rest = &rest["CREATE UNLOGGED TABLE".len()..];
    } else if starts_with_ci(rest, "CREATE TABLE") {
        rest = &rest["CREATE TABLE".len()..];
    } else {
        return None;
    }
    rest = rest.trim_start();
    if starts_with_ci(rest, "IF NOT EXISTS") {
        rest = &rest["IF NOT EXISTS".len()..];
        rest = rest.trim_start();
    }
    if starts_with_ci(rest, "ONLY") {
        rest = &rest["ONLY".len()..];
        rest = rest.trim_start();
    }
    // Parse the table identifier, handling "double-quotes", [brackets], and `backticks`
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    let mut ident = String::new();
    let mut in_double = false;
    let mut in_bracket = false;
    let mut in_backtick = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' if !in_bracket && !in_backtick => {
                in_double = !in_double;
                ident.push(c);
                i += 1;
            }
            '[' if !in_double && !in_backtick && !in_bracket => {
                in_bracket = true;
                ident.push(c);
                i += 1;
            }
            ']' if in_bracket => {
                in_bracket = false;
                ident.push(c);
                i += 1;
            }
            '`' if !in_double && !in_bracket => {
                in_backtick = !in_backtick;
                ident.push(c);
                i += 1;
            }
            '(' if !in_double && !in_bracket && !in_backtick => break,
            _ => {
                ident.push(c);
                i += 1;
            }
        }
    }
    if i >= bytes.len() || bytes[i] as char != '(' {
        return None;
    }
    let open_idx = i;
    let close_idx = find_matching_paren(rest, open_idx)?;
    let (schema, table) = parse_table_ident(ident.trim());
    let block = &rest[open_idx + 1..close_idx];
    Some((schema, table, block))
}

fn parse_column_definitions(column_block: &str) -> (Vec<String>, HashMap<String, usize>) {
    let mut columns = Vec::new();
    let mut lengths = HashMap::new();
    for part in split_top_level_commas(column_block) {
        let def = part.trim();
        if def.is_empty() {
            continue;
        }
        if is_table_constraint(def) {
            continue;
        }
        if let Some((column, rest)) = parse_column_name_and_rest(def) {
            columns.push(column.clone());
            if let Some(max_len) = extract_type_length(rest) {
                lengths.insert(column.to_lowercase(), max_len);
            }
        }
    }
    (columns, lengths)
}

fn find_matching_paren(s: &str, open_idx: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = open_idx;
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_single {
            if c == '\'' {
                if i + 1 < bytes.len() && bytes[i + 1] as char == '\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                if i + 1 < bytes.len() && bytes[i + 1] as char == '"' {
                    i += 2;
                    continue;
                }
                in_double = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn split_top_level_commas(input: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_single {
            if c == '\'' {
                if i + 1 < bytes.len() && bytes[i + 1] as char == '\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                if i + 1 < bytes.len() && bytes[i + 1] as char == '"' {
                    i += 2;
                    continue;
                }
                in_double = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&input[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&input[start..]);
    out
}

fn is_table_constraint(def: &str) -> bool {
    starts_with_ci(def, "CONSTRAINT")
        || starts_with_ci(def, "PRIMARY KEY")
        || starts_with_ci(def, "UNIQUE")
        || starts_with_ci(def, "CHECK")
        || starts_with_ci(def, "FOREIGN KEY")
        || starts_with_ci(def, "EXCLUDE")
}

fn parse_column_name_and_rest(def: &str) -> Option<(String, &str)> {
    let trimmed = def.trim_start();
    if trimmed.starts_with('"') {
        // SQL standard / PostgreSQL / SQLite double-quoted identifier
        let bytes = trimmed.as_bytes();
        let mut i = 1usize;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '"' {
                if i + 1 < bytes.len() && bytes[i + 1] as char == '"' {
                    i += 2;
                    continue;
                }
                let name = trimmed[1..i].replace("\"\"", "\"");
                let rest = trimmed[i + 1..].trim_start();
                return Some((name, rest));
            }
            i += 1;
        }
        None
    } else if trimmed.starts_with('[') {
        // SQL Server / MSSQL bracket-quoted identifier: [column name]
        let bytes = trimmed.as_bytes();
        let mut i = 1usize;
        while i < bytes.len() {
            if bytes[i] as char == ']' {
                let name = trimmed[1..i].to_string();
                let rest = trimmed[i + 1..].trim_start();
                return Some((name, rest));
            }
            i += 1;
        }
        None
    } else if trimmed.starts_with('`') {
        // Backtick-quoted identifier (MySQL / SQLite)
        let bytes = trimmed.as_bytes();
        let mut i = 1usize;
        while i < bytes.len() {
            if bytes[i] as char == '`' {
                let name = trimmed[1..i].to_string();
                let rest = trimmed[i + 1..].trim_start();
                return Some((name, rest));
            }
            i += 1;
        }
        None
    } else {
        let mut split_at = None;
        for (idx, ch) in trimmed.char_indices() {
            if ch.is_whitespace() {
                split_at = Some(idx);
                break;
            }
        }
        let idx = split_at?;
        let name = trimmed[..idx].trim().to_string();
        let rest = trimmed[idx..].trim_start();
        Some((name, rest))
    }
}

fn extract_type_length(rest: &str) -> Option<usize> {
    let lower = rest.trim_start().to_ascii_lowercase();
    parse_len_after_type_prefix(&lower, "character varying")
        .or_else(|| parse_len_after_type_prefix(&lower, "nvarchar")) // MSSQL Unicode varchar
        .or_else(|| parse_len_after_type_prefix(&lower, "varchar"))
        .or_else(|| parse_len_after_type_prefix(&lower, "character"))
        .or_else(|| parse_len_after_type_prefix(&lower, "nchar")) // MSSQL Unicode char
        .or_else(|| parse_len_after_type_prefix(&lower, "char"))
        .or_else(|| parse_len_after_type_prefix(&lower, "bpchar"))
}

fn parse_len_after_type_prefix(type_decl_lower: &str, prefix: &str) -> Option<usize> {
    if !type_decl_lower.starts_with(prefix) {
        return None;
    }
    let mut tail = type_decl_lower[prefix.len()..].trim_start();
    if !tail.starts_with('(') {
        return None;
    }
    tail = &tail[1..];
    let mut i = 0usize;
    while i < tail.len() && tail.as_bytes()[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < tail.len() && tail.as_bytes()[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    tail[start..i].parse::<usize>().ok()
}

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .map(|p| p.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

/// Find `needle` in `haystack` using ASCII case-insensitive comparison (no full-string uppercase allocation).
fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let hay = haystack.as_bytes();
    let nd = needle.as_bytes();
    if nd.len() > hay.len() {
        return None;
    }
    'outer: for start in 0..=(hay.len() - nd.len()) {
        for j in 0..nd.len() {
            if !hay[start + j].eq_ignore_ascii_case(&nd[j]) {
                continue 'outer;
            }
        }
        return Some(start);
    }
    None
}

#[derive(Clone, Debug)]
struct Cell {
    original: Option<String>, // None for NULL
    was_quoted: bool,
    was_default: bool,
    trailing_expr: Option<String>,
}

impl Cell {
    fn render_original(&self) -> String {
        let trailing = self.trailing_expr.as_deref().unwrap_or("");
        if self.was_default {
            return format!("DEFAULT{trailing}");
        }
        match &self.original {
            None => format!("NULL{trailing}"),
            Some(s) => {
                if self.was_quoted {
                    format!("'{}'{trailing}", s.replace('\'', "''"))
                } else {
                    format!("{s}{trailing}")
                }
            }
        }
    }
}

/// Escapes a field value for PostgreSQL `COPY ... FROM stdin` **text** format so the output
/// line still has one physical TAB-separated field per logical column. Without this, a
/// replacement containing a literal TAB or newline would split the row on restore and surface
/// as PostgreSQL errors like `missing data for column "..."`.
fn escape_postgres_copy_text_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\u{000b}' => out.push_str("\\v"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn render_cell(repl: &Replacement, original: &Cell) -> String {
    let trailing = original.trailing_expr.as_deref().unwrap_or("");
    if repl.is_null {
        return format!("NULL{trailing}");
    }
    let should_quote = repl.force_quoted || original.was_quoted;
    if should_quote {
        format!("'{}'{trailing}", repl.value.as_ref().replace('\'', "''"))
    } else {
        format!("{}{trailing}", repl.value.as_ref())
    }
}

fn strip_trailing_semicolon(s: &str) -> &str {
    let t = s.trim_end();
    if let Some(pos) = t.rfind(';') {
        &t[..pos]
    } else {
        t
    }
}

fn parse_values_rows(values_block: &str) -> anyhow::Result<Vec<Vec<Cell>>> {
    // values_block is everything after VALUES and before trailing ';'
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    let bytes = values_block.as_bytes();
    let len = bytes.len();
    // Helper to skip whitespace
    let next_non_ws = |mut j: usize| -> usize {
        while j < len && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        j
    };
    let mut pos = next_non_ws(0);
    while pos < len {
        if bytes[pos] as char != '(' {
            anyhow::bail!("expected '(' starting row");
        }
        // parse one row until matching ')'
        let (cells, new_pos) = parse_parenthesized_values(&values_block[pos..])?;
        rows.push(cells);
        pos += new_pos;
        // skip comma and whitespace
        pos = next_non_ws(pos);
        if pos < len && bytes[pos] as char == ',' {
            pos = next_non_ws(pos + 1);
            continue;
        } else {
            break;
        }
    }
    Ok(rows)
}

fn parse_parenthesized_values(s: &str) -> anyhow::Result<(Vec<Cell>, usize)> {
    // s starts with '('
    // Handles standard SQL '' escape doubling as well as MSSQL N'...' Unicode string literals
    // (and analogous E'...', B'...', X'...' prefixes used by other dialects). The one-character
    // prefix is silently stripped; the string content is preserved as-is.
    let mut it = s.char_indices().peekable();
    let (_, first) = it.next().ok_or_else(|| anyhow::anyhow!("expected '('"))?;
    if first != '(' {
        anyhow::bail!("expected '('");
    }
    let mut cells: Vec<Cell> = Vec::new();
    let mut in_single = false;
    let mut buf = String::new();
    let mut trailing_expr = String::new();
    let mut was_quoted = false;
    let mut closed_quoted_literal = false;
    while let Some((_, c)) = it.peek().copied() {
        if in_single {
            if c == '\'' {
                let _ = it.next(); // consume this '\''
                if it.peek().map(|&(_, p)| p) == Some('\'') {
                    let _ = it.next();
                    buf.push('\'');
                } else {
                    in_single = false;
                    closed_quoted_literal = true;
                }
                continue;
            }
            let _ = it.next();
            buf.push(c);
            continue;
        }
        match c {
            '\'' => {
                // Strip a leading string-type prefix accumulated in buf when it is exactly
                // one character: N (MSSQL Unicode), E (PostgreSQL escape), B/X (bit/hex).
                if buf.len() == 1 {
                    let b0 = buf.as_bytes()[0];
                    if matches!(b0, b'N' | b'n' | b'E' | b'e' | b'B' | b'b' | b'X' | b'x') {
                        buf.clear();
                    }
                }
                let _ = it.next();
                in_single = true;
                was_quoted = true;
            }
            ')' => {
                let (end_byte, _) = it.next().unwrap();
                let cell = finalize_cell(&buf, was_quoted, &trailing_expr);
                cells.push(cell);
                return Ok((cells, end_byte + ')'.len_utf8()));
            }
            ',' => {
                let _ = it.next();
                let cell = finalize_cell(&buf, was_quoted, &trailing_expr);
                cells.push(cell);
                buf.clear();
                trailing_expr.clear();
                was_quoted = false;
                closed_quoted_literal = false;
                while let Some(&(_, w)) = it.peek() {
                    if !w.is_whitespace() {
                        break;
                    }
                    let _ = it.next();
                }
            }
            w if w.is_whitespace() => {
                let _ = it.next();
                if was_quoted && closed_quoted_literal {
                    trailing_expr.push(w);
                }
            }
            other => {
                let _ = it.next();
                if was_quoted && closed_quoted_literal {
                    trailing_expr.push(other);
                } else {
                    buf.push(other);
                }
            }
        }
    }
    anyhow::bail!("unterminated values row")
}

fn finalize_cell(buf: &str, was_quoted: bool, trailing_expr: &str) -> Cell {
    let trailing = {
        let t = trailing_expr.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    if was_quoted {
        Cell {
            original: Some(buf.to_string()),
            was_quoted: true,
            was_default: false,
            trailing_expr: trailing,
        }
    } else {
        let t = buf.trim();
        if t.eq_ignore_ascii_case("null") {
            Cell {
                original: None,
                was_quoted: false,
                was_default: false,
                trailing_expr: None,
            }
        } else if t.eq_ignore_ascii_case("default") {
            Cell {
                original: None,
                was_quoted: false,
                was_default: true,
                trailing_expr: None,
            }
        } else {
            Cell {
                original: Some(t.to_string()),
                was_quoted: false,
                was_default: false,
                trailing_expr: None,
            }
        }
    }
}

fn select_strategy_for_cell(
    cfg: &ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    columns: &[String],
    row_cells: &[Option<&str>],
    column: &str,
) -> Option<AnonymizerSpec> {
    // First-match-wins on column_cases
    if let Some(cases) = lookup_column_cases(cfg, schema, table, column) {
        for case in cases {
            if when_matches(&case.when, columns, row_cells) {
                return Some(case.strategy.clone());
            }
        }
    }
    // Fallback to base rules
    if let Some(spec) = lookup_column_rule(cfg, schema, table, column) {
        return Some(spec.clone());
    }
    None
}

fn is_sensitive_candidate(
    cfg: &ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    column: &str,
) -> bool {
    is_explicit_sensitive_column(cfg, schema, table, column)
        || infer_auto_strategy(column).is_some()
}

fn is_explicitly_covered_column(
    cfg: &ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    column: &str,
) -> bool {
    lookup_column_rule(cfg, schema, table, column).is_some()
        || lookup_column_cases(cfg, schema, table, column)
            .map(|cases| !cases.is_empty())
            .unwrap_or(false)
        || !lookup_json_path_rules_for_column(cfg, schema, table, column).is_empty()
}

fn qualified_column_name(schema: Option<&str>, table: &str, column: &str) -> String {
    let table_norm = table.to_lowercase();
    let column_norm = column.to_lowercase();
    match schema {
        Some(s) => format!("{}.{}.{}", s.to_lowercase(), table_norm, column_norm),
        None => format!("{}.{}", table_norm, column_norm),
    }
}

fn infer_auto_strategy(column: &str) -> Option<AnonymizerSpec> {
    let normalized = column.to_ascii_lowercase().replace('-', "_");
    let spec = if normalized.contains("email") {
        base_spec("email", Some(true))
    } else if normalized.contains("first_name")
        || normalized == "fname"
        || normalized.contains("given_name")
    {
        base_spec("first_name", Some(true))
    } else if normalized.contains("last_name")
        || normalized.contains("surname")
        || normalized == "lname"
        || normalized.contains("family_name")
    {
        base_spec("last_name", Some(true))
    } else if normalized.contains("name") {
        base_spec("name", Some(true))
    } else if normalized.contains("phone")
        || normalized.contains("mobile")
        || normalized.contains("cell")
    {
        base_spec("phone", Some(true))
    } else if scaffold_address_like_segment(&normalized) {
        base_spec("redact", Some(true))
    } else if normalized.contains("password")
        || normalized == "pass"
        || normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("ssn")
        || normalized.contains("credit_card")
        || normalized.contains("card_number")
        || normalized.contains("iban")
        || normalized.contains("routing")
        || normalized.contains("account_number")
    {
        base_spec("hash", Some(true))
    } else if normalized == "dob"
        || normalized.contains("date_of_birth")
        || normalized.contains("birth_date")
    {
        base_spec("date_fuzz", Some(true))
    } else if normalized.contains("datetime")
        || normalized.contains("timestamp")
        || normalized.ends_with("_at")
    {
        base_spec("datetime_fuzz", Some(true))
    } else if normalized.contains("time") {
        base_spec("time_fuzz", Some(true))
    } else if normalized.contains("date") {
        base_spec("date_fuzz", Some(true))
    } else {
        return None;
    };
    Some(spec)
}

fn base_spec(strategy: &str, as_string: Option<bool>) -> AnonymizerSpec {
    AnonymizerSpec {
        strategy: strategy.to_string(),
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
        as_string,
        locale: None,
        faker: None,
        format: None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::luhn_valid;
    use crate::settings::{AnonymizerSpec, ColumnCase, ResolvedConfig, RowFilterSet, When};
    use crate::transform::{set_random_seed, AnonymizerRegistry};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn pipeline_filters_rows_and_applies_fuzz_with_seed() {
        // Config: retain myco.com, delete example.com, fuzz date by [-1,1]
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut users_cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        users_cols.insert(
            "the_date".to_string(),
            AnonymizerSpec {
                strategy: "date_fuzz".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: None,
                min_days: Some(-1),
                max_days: Some(1),
                min_seconds: None,
                max_seconds: None,
                domain: None,
                unique_within_domain: None,
                as_string: Some(true),
                locale: None,
                faker: None,
                format: None,
            },
        );
        rules.insert("public.events".to_string(), users_cols);
        let mut row_filters = HashMap::new();
        row_filters.insert(
            "public.events".to_string(),
            RowFilterSet {
                retain: vec![crate::settings::Predicate {
                    column: "email".to_string(),
                    op: "regex".to_string(),
                    value: Some(serde_json::json!(".*@myco\\.com$")),
                    values: None,
                    case_insensitive: None,
                }],
                delete: vec![crate::settings::Predicate {
                    column: "email".to_string(),
                    op: "regex".to_string(),
                    value: Some(serde_json::json!(".*@example\\.com$")),
                    values: None,
                    case_insensitive: None,
                }],
            },
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters,
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        set_random_seed(42);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.events (id int, email text, the_date date);
INSERT INTO public.events (id, email, the_date) VALUES
  (1, 'alice@myco.com', '2024-11-15'),
  (2, 'bob@example.com', '2024-11-16');

COPY public.events (id, email, the_date) FROM stdin;
3	alice@myco.com	2024-11-17
4	eve@example.com	2024-11-17
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // Row 2 and COPY row 4 should be filtered out
        assert!(s.contains("alice@myco.com"));
        assert!(!s.contains("(2, 'bob@example.com'"));
        assert!(s.contains("\n3\talice@myco.com\t")); // keep
        assert!(!s.contains("\n4\teve@example.com\t")); // drop
    }

    #[test]
    fn column_cases_first_match_wins() {
        // Base: email -> hash
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut base_cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        base_cols.insert(
            "email".to_string(),
            AnonymizerSpec {
                strategy: "hash".to_string(),
                salt: Some("base".into()),
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
                as_string: Some(true),
                locale: None,
                faker: None,
                format: None,
            },
        );
        rules.insert("public.users".to_string(), base_cols);
        // Column cases for email: first match admins -> redact, second eu -> hash with salt
        let mut column_cases: HashMap<String, HashMap<String, Vec<ColumnCase>>> = HashMap::new();
        let email_cases: Vec<ColumnCase> = vec![
            ColumnCase {
                when: When {
                    any: vec![crate::settings::Predicate {
                        column: "is_admin".into(),
                        op: "eq".into(),
                        value: Some(serde_json::json!("true")),
                        values: None,
                        case_insensitive: None,
                    }],
                    all: vec![],
                },
                strategy: AnonymizerSpec {
                    strategy: "redact".into(),
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
                    as_string: Some(true),
                    locale: None,
                    faker: None,
                    format: None,
                },
            },
            ColumnCase {
                when: When {
                    any: vec![crate::settings::Predicate {
                        column: "country".into(),
                        op: "in".into(),
                        value: None,
                        values: Some(vec![
                            serde_json::json!("DE"),
                            serde_json::json!("FR"),
                            serde_json::json!("GB"),
                        ]),
                        case_insensitive: None,
                    }],
                    all: vec![],
                },
                strategy: AnonymizerSpec {
                    strategy: "hash".into(),
                    salt: Some("eu".into()),
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
                    as_string: Some(true),
                    locale: None,
                    faker: None,
                    format: None,
                },
            },
        ];
        let mut per_col: HashMap<String, Vec<ColumnCase>> = HashMap::new();
        per_col.insert("email".into(), email_cases);
        column_cases.insert("public.users".into(), per_col);

        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases,
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        set_random_seed(1);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.users (id int, email text, country text, is_admin bool);
INSERT INTO public.users (id, email, country, is_admin) VALUES
  (1, 'alice@myco.com', 'US', false),
  (2, 'bob@myco.com', 'DE', false),
  (3, 'root@myco.com', 'US', true);
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // Ensure original emails do not appear in output (all transformed)
        assert!(!s.contains("alice@myco.com"));
        assert!(!s.contains("bob@myco.com"));
        assert!(!s.contains("root@myco.com"));
        // Ensure we still have one INSERT statement for users
        assert!(s.contains("INSERT INTO public.users"));
    }

    #[test]
    fn deterministic_domain_mapping_is_consistent_across_tables() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let email_spec = AnonymizerSpec {
            strategy: "faker".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("customer_identity".to_string()),
            unique_within_domain: Some(false),
            as_string: Some(true),
            locale: None,
            faker: Some("internet::SafeEmail".to_string()),
            format: None,
        };
        rules.insert(
            "public.customers".to_string(),
            HashMap::from([("email".to_string(), email_spec.clone())]),
        );
        rules.insert(
            "public.orders".to_string(),
            HashMap::from([("customer_email".to_string(), email_spec)]),
        );
        let cfg = ResolvedConfig {
            salt: Some("global-domain-salt".to_string()),
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.customers (id int, email text);
CREATE TABLE public.orders (id int, customer_email text);
INSERT INTO public.customers (id, email) VALUES
  (1, 'alice@myco.com'),
  (2, 'bob@myco.com');
INSERT INTO public.orders (id, customer_email) VALUES
  (10, 'alice@myco.com'),
  (11, 'bob@myco.com');
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();
        assert!(!output.contains("alice@myco.com"));
        assert!(!output.contains("bob@myco.com"));

        let customers_start = output.find("INSERT INTO public.customers").unwrap();
        let customers_tail = &output[customers_start..];
        let customers_stmt_end = customers_tail.find(";\n").unwrap() + customers_start;
        let customers_stmt = &output[customers_start..=customers_stmt_end];
        let customers_values_idx = customers_stmt.to_uppercase().find("VALUES").unwrap();
        let customers_block = strip_trailing_semicolon(
            customers_stmt[customers_values_idx + "VALUES".len()..].trim(),
        );
        let customer_rows = parse_values_rows(customers_block).unwrap();

        let orders_start = output.find("INSERT INTO public.orders").unwrap();
        let orders_tail = &output[orders_start..];
        let orders_stmt_end = orders_tail.find(";\n").unwrap() + orders_start;
        let orders_stmt = &output[orders_start..=orders_stmt_end];
        let orders_values_idx = orders_stmt.to_uppercase().find("VALUES").unwrap();
        let orders_block =
            strip_trailing_semicolon(orders_stmt[orders_values_idx + "VALUES".len()..].trim());
        let order_rows = parse_values_rows(orders_block).unwrap();

        let customer_alice = customer_rows[0][1].original.as_ref().unwrap();
        let customer_bob = customer_rows[1][1].original.as_ref().unwrap();
        let order_alice = order_rows[0][1].original.as_ref().unwrap();
        let order_bob = order_rows[1][1].original.as_ref().unwrap();
        assert_eq!(customer_alice, order_alice);
        assert_eq!(customer_bob, order_bob);
        assert_ne!(customer_alice, customer_bob);
    }

    #[test]
    fn deterministic_domain_mapping_can_enforce_uniqueness() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "public.users".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "faker".to_string(),
                    salt: None,
                    min: None,
                    max: None,
                    scale: None,
                    length: None,
                    min_days: None,
                    max_days: None,
                    min_seconds: None,
                    max_seconds: None,
                    domain: Some("customer_identity".to_string()),
                    unique_within_domain: Some(true),
                    as_string: Some(true),
                    locale: None,
                    faker: Some("internet::SafeEmail".to_string()),
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.users (id int, email text);
INSERT INTO public.users (id, email) VALUES
  (1, 'alice@myco.com'),
  (2, 'bob@myco.com'),
  (3, 'alice@myco.com');
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();
        let users_start = output.find("INSERT INTO public.users").unwrap();
        let users_tail = &output[users_start..];
        let users_stmt_end = users_tail.find(";\n").unwrap() + users_start;
        let users_stmt = &output[users_start..=users_stmt_end];
        let values_idx = users_stmt.to_uppercase().find("VALUES").unwrap();
        let values_block =
            strip_trailing_semicolon(users_stmt[values_idx + "VALUES".len()..].trim());
        let rows = parse_values_rows(values_block).unwrap();

        let first = rows[0][1].original.as_ref().unwrap();
        let second = rows[1][1].original.as_ref().unwrap();
        let third = rows[2][1].original.as_ref().unwrap();
        assert_eq!(first, third);
        assert_ne!(first, second);
    }

    #[test]
    fn report_records_deterministic_mapping_domain_usage() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "public.users".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "faker".to_string(),
                    salt: None,
                    min: None,
                    max: None,
                    scale: None,
                    length: None,
                    min_days: None,
                    max_days: None,
                    min_seconds: None,
                    max_seconds: None,
                    domain: Some("customer_identity".to_string()),
                    unique_within_domain: Some(true),
                    as_string: Some(true),
                    locale: None,
                    faker: Some("internet::SafeEmail".to_string()),
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut reporter = crate::report::Reporter::new(false);
        {
            let mut proc =
                SqlStreamProcessor::new(reg, cfg, Some(&mut reporter), DumpFormat::Postgres);
            let input = r#"
CREATE TABLE public.users (id int, email text);
INSERT INTO public.users (id, email) VALUES (1, 'alice@myco.com');
"#;
            let mut reader = std::io::BufReader::new(input.as_bytes());
            let mut out = Vec::new();
            proc.process(&mut reader, &mut out).unwrap();
        }
        assert_eq!(reporter.report.deterministic_mapping_domains.len(), 1);
        let usage = &reporter.report.deterministic_mapping_domains[0];
        assert_eq!(usage.schema.as_deref(), Some("public"));
        assert_eq!(usage.table, "users");
        assert_eq!(usage.column, "email");
        assert_eq!(usage.domain, "customer_identity");
        assert!(usage.unique_within_domain);
    }

    #[test]
    fn domain_mapping_preserves_null_cells_in_insert() {
        // NULL cells in domain-mapped columns must remain NULL in the output,
        // not be replaced by a fabricated pseudonym.
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let email_spec = AnonymizerSpec {
            strategy: "faker".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("customer_identity".to_string()),
            unique_within_domain: Some(false),
            as_string: Some(true),
            locale: None,
            faker: Some("internet::SafeEmail".to_string()),
            format: None,
        };
        rules.insert(
            "public.users".to_string(),
            HashMap::from([("email".to_string(), email_spec)]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.users (id int, email text);
INSERT INTO public.users (id, email) VALUES
  (1, 'alice@myco.com'),
  (2, NULL),
  (3, 'alice@myco.com');
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();

        // Original emails must not appear in output
        assert!(!output.contains("alice@myco.com"), "email not anonymized");

        // Parse out the output rows
        let insert_start = output.find("INSERT INTO public.users").unwrap();
        let insert_tail = &output[insert_start..];
        let stmt_end = insert_tail.find(";\n").unwrap() + insert_start;
        let stmt = &output[insert_start..=stmt_end];
        let values_idx = stmt.to_uppercase().find("VALUES").unwrap();
        let values_block = strip_trailing_semicolon(stmt[values_idx + "VALUES".len()..].trim());
        let rows = parse_values_rows(values_block).unwrap();

        // Row 1 (alice) — should have a real pseudonym
        let alice_email = rows[0][1].original.as_ref();
        assert!(
            alice_email.is_some(),
            "row 1 email should have a real pseudonym, not NULL"
        );

        // Row 2 (NULL) — must remain NULL
        let null_email = rows[1][1].original.as_ref();
        assert!(
            null_email.is_none(),
            "row 2 email was NULL and must remain NULL after domain mapping, got {:?}",
            null_email
        );

        // Row 3 (alice again) — same pseudonym as row 1
        let alice_repeat_email = rows[2][1].original.as_ref().unwrap();
        assert_eq!(
            alice_email.unwrap(),
            alice_repeat_email,
            "same source email must map to same pseudonym across rows"
        );
    }

    #[test]
    fn domain_mapping_preserves_null_cells_in_copy() {
        // In COPY format, \N represents NULL. Domain-mapped columns with \N must
        // output \N (not a fabricated pseudonym).
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let email_spec = AnonymizerSpec {
            strategy: "faker".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("customer_identity".to_string()),
            unique_within_domain: Some(false),
            as_string: Some(true),
            locale: None,
            faker: Some("internet::SafeEmail".to_string()),
            format: None,
        };
        rules.insert(
            "public.users".to_string(),
            HashMap::from([("email".to_string(), email_spec)]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        // tab-separated COPY rows: id<TAB>email
        let input = "COPY public.users (id, email) FROM stdin;\n\
                     1\talice@myco.com\n\
                     2\t\\N\n\
                     3\talice@myco.com\n\
                     \\.\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();

        // Original emails must not appear
        assert!(!output.contains("alice@myco.com"), "email not anonymized");

        let lines: Vec<&str> = output.lines().collect();
        // Line 0: COPY header, Line 1: row1, Line 2: row2, Line 3: row3, Line 4: \.
        let row1_fields: Vec<&str> = lines[1].split('\t').collect();
        let row2_fields: Vec<&str> = lines[2].split('\t').collect();
        let row3_fields: Vec<&str> = lines[3].split('\t').collect();

        // Row 2 email must be \N (NULL preserved)
        assert_eq!(
            row2_fields[1], r"\N",
            "NULL email in COPY must remain \\N after domain mapping, got '{}'",
            row2_fields[1]
        );

        // Row 1 and row 3 (same source alice@myco.com) must have the same pseudonym
        assert_eq!(
            row1_fields[1], row3_fields[1],
            "same source email must map to same pseudonym across COPY rows"
        );

        // Row 1 must not be NULL
        assert_ne!(
            row1_fields[1], r"\N",
            "non-NULL email must not be turned into NULL"
        );
    }

    #[test]
    fn escape_postgres_copy_text_field_escapes_control_chars() {
        assert_eq!(
            escape_postgres_copy_text_field("a\tb\nc\\"),
            "a\\tb\\nc\\\\"
        );
        assert_eq!(escape_postgres_copy_text_field("\0\u{01}"), "\\0\\x01");
    }

    #[test]
    fn domain_mapping_null_and_non_null_cross_table_consistency() {
        // When the same domain spans two tables, NULL stays NULL in both, and
        // non-NULL source values map to the same pseudonym across both tables.
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let email_spec = AnonymizerSpec {
            strategy: "faker".to_string(),
            salt: None,
            min: None,
            max: None,
            scale: None,
            length: None,
            min_days: None,
            max_days: None,
            min_seconds: None,
            max_seconds: None,
            domain: Some("customer_identity".to_string()),
            unique_within_domain: Some(false),
            as_string: Some(true),
            locale: None,
            faker: Some("internet::SafeEmail".to_string()),
            format: None,
        };
        rules.insert(
            "public.customers".to_string(),
            HashMap::from([("email".to_string(), email_spec.clone())]),
        );
        rules.insert(
            "public.orders".to_string(),
            HashMap::from([("customer_email".to_string(), email_spec)]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.customers (id int, email text);
CREATE TABLE public.orders (id int, customer_email text);
INSERT INTO public.customers (id, email) VALUES
  (1, 'alice@myco.com'),
  (2, NULL);
INSERT INTO public.orders (id, customer_email) VALUES
  (10, 'alice@myco.com'),
  (11, NULL);
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();

        assert!(!output.contains("alice@myco.com"), "email not anonymized");

        // Parse customers rows
        let cust_start = output.find("INSERT INTO public.customers").unwrap();
        let cust_tail = &output[cust_start..];
        let cust_end = cust_tail.find(";\n").unwrap() + cust_start;
        let cust_stmt = &output[cust_start..=cust_end];
        let cust_vals_idx = cust_stmt.to_uppercase().find("VALUES").unwrap();
        let cust_block =
            strip_trailing_semicolon(cust_stmt[cust_vals_idx + "VALUES".len()..].trim());
        let cust_rows = parse_values_rows(cust_block).unwrap();

        // Parse orders rows
        let ord_start = output.find("INSERT INTO public.orders").unwrap();
        let ord_tail = &output[ord_start..];
        let ord_end = ord_tail.find(";\n").unwrap() + ord_start;
        let ord_stmt = &output[ord_start..=ord_end];
        let ord_vals_idx = ord_stmt.to_uppercase().find("VALUES").unwrap();
        let ord_block = strip_trailing_semicolon(ord_stmt[ord_vals_idx + "VALUES".len()..].trim());
        let ord_rows = parse_values_rows(ord_block).unwrap();

        // customers row 1 (alice) and orders row 1 (alice) must share the same pseudonym
        let cust_alice = cust_rows[0][1].original.as_ref().unwrap();
        let ord_alice = ord_rows[0][1].original.as_ref().unwrap();
        assert_eq!(
            cust_alice, ord_alice,
            "same source email must map to same pseudonym across tables"
        );

        // customers row 2 (NULL) must remain NULL
        assert!(
            cust_rows[1][1].original.is_none(),
            "NULL email in customers must remain NULL, got {:?}",
            cust_rows[1][1].original
        );

        // orders row 2 (NULL) must remain NULL
        assert!(
            ord_rows[1][1].original.is_none(),
            "NULL customer_email in orders must remain NULL, got {:?}",
            ord_rows[1][1].original
        );
    }

    #[test]
    fn unmatched_columns_without_explicit_rules_are_left_unchanged() {
        let cfg = ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        set_random_seed(7);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
INSERT INTO public.users (id, email, first_name, password, dob, notes) VALUES
  (1, 'alice@myco.com', 'Alice', 's3cr3t', '1990-01-02', 'left alone');
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // No explicit rules/cases means all cells are preserved.
        assert!(s.contains("(1, "));
        assert!(s.contains("'left alone'"));
        assert!(s.contains("'alice@myco.com'"));
        assert!(s.contains("'Alice'"));
        assert!(s.contains("'s3cr3t'"));
        assert!(s.contains("'1990-01-02'"));
    }

    #[test]
    fn pipeline_filters_nested_json_paths_for_insert_and_copy() {
        let mut row_filters = HashMap::new();
        row_filters.insert(
            "public.events".to_string(),
            RowFilterSet {
                retain: vec![crate::settings::Predicate {
                    column: "payload.profile.tier".to_string(),
                    op: "eq".to_string(),
                    value: Some(serde_json::json!("gold")),
                    values: None,
                    case_insensitive: None,
                }],
                delete: vec![crate::settings::Predicate {
                    column: "payload__events__kind".to_string(),
                    op: "eq".to_string(),
                    value: Some(serde_json::json!("drop")),
                    values: None,
                    case_insensitive: None,
                }],
            },
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters,
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.events (id int, payload jsonb);
INSERT INTO public.events (id, payload) VALUES
  (1, '{"profile":{"tier":"gold"},"events":[{"kind":"keep"}]}'),
  (2, '{"profile":{"tier":"gold"},"events":[{"kind":"drop"}]}'),
  (3, '{"profile":{"tier":"silver"},"events":[{"kind":"keep"}]}');

COPY public.events (id, payload) FROM stdin;
4	{"profile":{"tier":"gold"},"events":[{"kind":"keep"}]}
5	{"profile":{"tier":"gold"},"events":[{"kind":"drop"}]}
6	{"profile":{"tier":"silver"},"events":[{"kind":"keep"}]}
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("(1, '{\"profile\":{\"tier\":\"gold\"},\"events\":[{\"kind\":\"keep\"}]}'")
        );
        assert!(
            !s.contains("(2, '{\"profile\":{\"tier\":\"gold\"},\"events\":[{\"kind\":\"drop\"}]}'")
        );
        assert!(!s.contains(
            "(3, '{\"profile\":{\"tier\":\"silver\"},\"events\":[{\"kind\":\"keep\"}]}'"
        ));
        assert!(
            s.contains("\n4\t{\"profile\":{\"tier\":\"gold\"},\"events\":[{\"kind\":\"keep\"}]}\n")
        );
        assert!(!s
            .contains("\n5\t{\"profile\":{\"tier\":\"gold\"},\"events\":[{\"kind\":\"drop\"}]}\n"));
        assert!(!s.contains(
            "\n6\t{\"profile\":{\"tier\":\"silver\"},\"events\":[{\"kind\":\"keep\"}]}\n"
        ));
    }

    #[test]
    fn pipeline_anonymizes_nested_json_paths_for_insert_and_copy() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "payload.profile.secret".to_string(),
            AnonymizerSpec {
                strategy: "string".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: Some(8),
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                domain: Some("secrets".to_string()),
                unique_within_domain: None,
                as_string: Some(true),
                locale: None,
                faker: None,
                format: None,
            },
        );
        rules.insert("public.events".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.events (id int, payload jsonb);
INSERT INTO public.events (id, payload) VALUES
  (1, '{"profile":{"tier":"gold","secret":"alpha"}}');

COPY public.events (id, payload) FROM stdin;
2	{"profile":{"tier":"gold","secret":"alpha"}}
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("\"tier\":\"gold\""),
            "non-target JSON fields should be preserved, got:\n{s}"
        );
        assert!(
            !s.contains("alpha"),
            "nested secret should be anonymized, got:\n{s}"
        );
        let insert_pos = s.find("INSERT INTO public.events").unwrap();
        let insert_tail = &s[insert_pos..];
        let insert_end = insert_tail.find(";\n").unwrap() + insert_pos;
        let ins_stmt = &s[insert_pos..=insert_end];
        let vals_idx = ins_stmt.to_uppercase().find("VALUES").unwrap();
        let ins_block = strip_trailing_semicolon(ins_stmt[vals_idx + "VALUES".len()..].trim());
        let ins_rows = parse_values_rows(ins_block).unwrap();
        let copy_line = s
            .lines()
            .find(|l| l.starts_with("2\t{"))
            .expect("expected COPY data row");
        let copy_json = copy_line.split_once('\t').unwrap().1;
        let v_ins =
            serde_json::from_str::<serde_json::Value>(ins_rows[0][1].original.as_ref().unwrap())
                .unwrap();
        let v_copy = serde_json::from_str::<serde_json::Value>(copy_json).unwrap();
        assert_eq!(
            v_ins["profile"]["secret"], v_copy["profile"]["secret"],
            "INSERT and COPY must apply the same nested anonymization"
        );
    }

    #[test]
    fn pipeline_json_path_rules_passthrough_non_json_cells() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "payload.profile.secret".to_string(),
            AnonymizerSpec {
                strategy: "string".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: Some(8),
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                domain: Some("secrets".to_string()),
                unique_within_domain: None,
                as_string: Some(true),
                locale: None,
                faker: None,
                format: None,
            },
        );
        rules.insert("public.events".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.events (id int, payload jsonb);
INSERT INTO public.events (id, payload) VALUES
  (1, '{not strict json}'),
  (2, '{"profile":{"tier":"gold","secret":"alpha"}}');

COPY public.events (id, payload) FROM stdin;
3	{not strict json}
4	{"profile":{"tier":"gold","secret":"alpha"}}
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("(1, '{not strict json}')"),
            "non-JSON INSERT cell should passthrough unchanged, got:\n{s}"
        );
        assert!(
            !s.contains("alpha"),
            "valid JSON INSERT row should still anonymize nested paths, got:\n{s}"
        );
        assert!(
            s.contains("\n3\t{not strict json}\n"),
            "non-JSON COPY cell should passthrough unchanged, got:\n{s}"
        );
        assert!(
            !s.contains("\n4\t{\"profile\":{\"tier\":\"gold\",\"secret\":\"alpha\"}}\n"),
            "valid JSON COPY row should anonymize nested secret, got:\n{s}"
        );
    }

    #[test]
    fn pipeline_json_path_int_range_preserves_json_number_type() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "payload.score".to_string(),
            AnonymizerSpec {
                strategy: "int_range".to_string(),
                salt: None,
                min: Some(0),
                max: Some(100),
                scale: None,
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                domain: Some("pipeline_json_num".to_string()),
                unique_within_domain: None,
                as_string: None,
                locale: None,
                faker: None,
                format: None,
            },
        );
        rules.insert("public.events".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.events (id int, payload jsonb);
INSERT INTO public.events (id, payload) VALUES
  (1, '{"score":42,"label":"x"}');

COPY public.events (id, payload) FROM stdin;
2	{"score":42,"label":"x"}
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        let insert_pos = s.find("INSERT INTO public.events").unwrap();
        let insert_tail = &s[insert_pos..];
        let insert_end = insert_tail.find(";\n").unwrap() + insert_pos;
        let ins_stmt = &s[insert_pos..=insert_end];
        let vals_idx = ins_stmt.to_uppercase().find("VALUES").unwrap();
        let ins_block = strip_trailing_semicolon(ins_stmt[vals_idx + "VALUES".len()..].trim());
        let ins_rows = parse_values_rows(ins_block).unwrap();
        let copy_line = s
            .lines()
            .find(|l| l.starts_with("2\t{"))
            .expect("expected COPY data row");
        let copy_json = copy_line.split_once('\t').unwrap().1;
        let v_ins =
            serde_json::from_str::<serde_json::Value>(ins_rows[0][1].original.as_ref().unwrap())
                .unwrap();
        let v_copy = serde_json::from_str::<serde_json::Value>(copy_json).unwrap();
        assert!(
            v_ins["score"].is_number(),
            "INSERT payload.score should remain JSON number, got {:?}",
            v_ins["score"]
        );
        assert!(
            v_copy["score"].is_number(),
            "COPY payload.score should remain JSON number, got {:?}",
            v_copy["score"]
        );
        assert_eq!(v_ins["score"], v_copy["score"]);
        assert_eq!(v_ins["label"], "x");
    }

    #[test]
    fn pipeline_payment_card_column_rewrites_insert_and_copy() {
        set_random_seed(77_007);
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "pan".to_string(),
            AnonymizerSpec {
                strategy: "payment_card".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: Some(16),
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
            },
        );
        rules.insert("public.payments".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.payments (id int, pan text);
INSERT INTO public.payments (id, pan) VALUES (1, '4111111111111111');

COPY public.payments (id, pan) FROM stdin;
2	4111111111111111
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            !s.contains("4111111111111111"),
            "original PAN should not appear, got:\n{s}"
        );
        let insert_line = s
            .lines()
            .find(|l| l.contains("INSERT INTO public.payments"))
            .unwrap();
        let pan_ins = insert_line
            .split_once(", '")
            .unwrap()
            .1
            .split_once('\'')
            .unwrap()
            .0;
        assert_eq!(pan_ins.len(), 16);
        assert!(luhn_valid(pan_ins), "INSERT PAN must be Luhn-valid");
        let copy_line = s.lines().find(|l| l.starts_with("2\t")).unwrap();
        let pan_copy = copy_line.split_once('\t').unwrap().1;
        assert_eq!(pan_copy.len(), 16);
        assert!(luhn_valid(pan_copy));
    }

    #[test]
    fn parse_values_rows_tracks_trailing_cast_for_quoted_literals() {
        let rows =
            parse_values_rows("(1, '{\"profile\":{\"secret\":\"alpha\"}}'::jsonb, 'note'::text)")
                .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 3);
        assert_eq!(
            rows[0][1].original.as_deref(),
            Some("{\"profile\":{\"secret\":\"alpha\"}}")
        );
        assert_eq!(rows[0][1].trailing_expr.as_deref(), Some("::jsonb"));
        assert_eq!(rows[0][2].original.as_deref(), Some("note"));
        assert_eq!(rows[0][2].trailing_expr.as_deref(), Some("::text"));
    }

    #[test]
    fn pipeline_anonymizes_nested_json_paths_for_jsonb_cast_insert_rows() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "payload.profile.secret".to_string(),
            AnonymizerSpec {
                strategy: "string".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: Some(8),
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                domain: Some("secrets".to_string()),
                unique_within_domain: None,
                as_string: Some(true),
                locale: None,
                faker: None,
                format: None,
            },
        );
        rules.insert("public.events".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.events (id int, payload jsonb);
INSERT INTO public.events (id, payload) VALUES
  (1, '{"profile":{"tier":"gold","secret":"alpha"}}'::jsonb),
  (2, '{"profile":{"tier":"gold","secret":"alpha"}}'::jsonb);
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("alpha"), "nested secret should be anonymized");
        assert!(s.contains("::jsonb"), "jsonb cast should be preserved");

        let insert_pos = s.find("INSERT INTO public.events").unwrap();
        let insert_tail = &s[insert_pos..];
        let insert_end = insert_tail.find(";\n").unwrap() + insert_pos;
        let ins_stmt = &s[insert_pos..=insert_end];
        let vals_idx = ins_stmt.to_uppercase().find("VALUES").unwrap();
        let ins_block = strip_trailing_semicolon(ins_stmt[vals_idx + "VALUES".len()..].trim());
        let ins_rows = parse_values_rows(ins_block).unwrap();
        assert_eq!(ins_rows[0][1].trailing_expr.as_deref(), Some("::jsonb"));
        assert_eq!(ins_rows[1][1].trailing_expr.as_deref(), Some("::jsonb"));
        let v0 =
            serde_json::from_str::<serde_json::Value>(ins_rows[0][1].original.as_ref().unwrap())
                .unwrap();
        let v1 =
            serde_json::from_str::<serde_json::Value>(ins_rows[1][1].original.as_ref().unwrap())
                .unwrap();
        assert_eq!(v0["profile"]["secret"], v1["profile"]["secret"]);
    }

    #[test]
    fn generated_values_fit_length_restricted_columns_from_create_table() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "email".to_string(),
            AnonymizerSpec {
                strategy: "faker".to_string(),
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
                as_string: Some(true),
                locale: None,
                faker: Some("internet::SafeEmail".to_string()),
                format: None,
            },
        );
        cols.insert(
            "nick".to_string(),
            AnonymizerSpec {
                strategy: "string".to_string(),
                salt: None,
                min: None,
                max: None,
                scale: None,
                length: Some(24),
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
            },
        );
        cols.insert(
            "phone".to_string(),
            AnonymizerSpec {
                strategy: "phone".to_string(),
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
                as_string: Some(true),
                locale: None,
                faker: None,
                format: None,
            },
        );
        rules.insert("public.users".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        set_random_seed(7);
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.users (
  email varchar(12),
  nick character varying(5),
  phone char(4)
);
INSERT INTO public.users (email, nick, phone) VALUES ('old@example.com', 'verylongname', '(000) 000-0000');

COPY public.users (email, nick, phone) FROM stdin;
old@example.com	verylongname	(000) 000-0000
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let output = String::from_utf8(out).unwrap();

        let insert_start = output.find("INSERT INTO public.users").unwrap();
        let insert_stmt_end = output[insert_start..].find(";\n").unwrap() + insert_start + 1;
        let insert_stmt = &output[insert_start..=insert_stmt_end];
        let values_idx = insert_stmt.to_uppercase().find("VALUES").unwrap();
        let values_block =
            strip_trailing_semicolon(insert_stmt[values_idx + "VALUES".len()..].trim());
        let rows = parse_values_rows(values_block).unwrap();
        let insert_row = &rows[0];
        let insert_email = insert_row[0].original.as_ref().unwrap();
        let insert_nick = insert_row[1].original.as_ref().unwrap();
        let insert_phone = insert_row[2].original.as_ref().unwrap();
        assert!(insert_email.chars().count() <= 12);
        assert!(insert_nick.chars().count() <= 5);
        assert!(insert_phone.chars().count() <= 4);

        let copy_row = output
            .lines()
            .skip_while(|line| !line.starts_with("COPY public.users"))
            .nth(1)
            .unwrap();
        let copy_fields: Vec<&str> = copy_row.split('\t').collect();
        assert_eq!(copy_fields.len(), 3);
        assert!(copy_fields[0].chars().count() <= 12);
        assert!(copy_fields[1].chars().count() <= 5);
        assert!(copy_fields[2].chars().count() <= 4);
    }

    #[test]
    fn sensitive_coverage_tracks_detected_covered_and_uncovered() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut users_cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        users_cols.insert(
            "email".to_string(),
            AnonymizerSpec {
                strategy: "faker".to_string(),
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
                as_string: Some(true),
                locale: None,
                faker: Some("internet::SafeEmail".to_string()),
                format: None,
            },
        );
        rules.insert("public.users".to_string(), users_cols);
        let mut sensitive_columns = HashMap::new();
        sensitive_columns.insert(
            "public.users".to_string(),
            HashSet::from(["employee_number".to_string()]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns,
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = r#"
CREATE TABLE public.users (
  id int,
  email text,
  ssn text,
  employee_number text
);
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let summary = proc.sensitive_coverage_summary();
        assert_eq!(
            summary.detected,
            vec![
                "public.users.email".to_string(),
                "public.users.employee_number".to_string(),
                "public.users.ssn".to_string(),
            ]
        );
        assert_eq!(summary.covered, vec!["public.users.email".to_string(),]);
        assert_eq!(
            summary.uncovered,
            vec![
                "public.users.employee_number".to_string(),
                "public.users.ssn".to_string(),
            ]
        );
    }

    // ── SQLite format tests ────────────────────────────────────────────────────

    #[test]
    fn sqlite_insert_or_replace_is_preserved_in_output() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "users".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "faker".to_string(),
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
                    as_string: Some(true),
                    locale: None,
                    faker: Some("internet::SafeEmail".to_string()),
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        set_random_seed(1);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Sqlite);
        let input = r#"CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
INSERT OR REPLACE INTO users (id, email) VALUES (1, 'alice@example.com');
INSERT OR IGNORE INTO users (id, email) VALUES (2, 'bob@example.com');
INSERT INTO users (id, email) VALUES (3, 'carol@example.com');
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // Each INSERT variant should be preserved in the output
        assert!(
            s.contains("INSERT OR REPLACE INTO users"),
            "INSERT OR REPLACE INTO not preserved:\n{}",
            s
        );
        assert!(
            s.contains("INSERT OR IGNORE INTO users"),
            "INSERT OR IGNORE INTO not preserved:\n{}",
            s
        );
        assert!(
            s.contains("INSERT INTO users"),
            "INSERT INTO not present:\n{}",
            s
        );
        // Original emails must be replaced
        assert!(
            !s.contains("alice@example.com"),
            "email not anonymized:\n{}",
            s
        );
        assert!(
            !s.contains("bob@example.com"),
            "email not anonymized:\n{}",
            s
        );
        assert!(
            !s.contains("carol@example.com"),
            "email not anonymized:\n{}",
            s
        );
    }

    #[test]
    fn sqlite_double_quoted_identifiers_are_parsed_correctly() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "users".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "redact".to_string(),
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
                    as_string: Some(true),
                    locale: None,
                    faker: None,
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Sqlite);
        let input = "INSERT INTO \"users\" (\"id\", \"email\") VALUES (1, 'alice@example.com');\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("INSERT INTO users"),
            "identifier quoting not stripped:\n{}",
            s
        );
        assert!(
            !s.contains("alice@example.com"),
            "email not anonymized:\n{}",
            s
        );
        assert!(
            s.contains("REDACTED"),
            "redact strategy not applied:\n{}",
            s
        );
    }

    #[test]
    fn sqlite_copy_blocks_are_not_processed() {
        // SQLite format: COPY-like lines should pass through verbatim (no COPY support)
        let cfg = ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Sqlite);
        // A line that looks like a COPY header should just pass through
        let input = "COPY users (id, email) FROM stdin;\nalice@example.com\n\\.\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // Everything passed through unchanged since COPY is not recognised in SQLite mode
        assert_eq!(
            s, input,
            "SQLite mode should pass COPY-like lines through verbatim"
        );
    }

    // ── SQL Server / MSSQL format tests ───────────────────────────────────────

    #[test]
    fn mssql_bracket_quoted_identifiers_are_parsed_correctly() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "dbo.users".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "redact".to_string(),
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
                    as_string: Some(true),
                    locale: None,
                    faker: None,
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::MsSql);
        let input = "INSERT INTO [dbo].[users] ([id], [email]) VALUES (1, 'alice@example.com');\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("INSERT INTO dbo.users"),
            "bracket quoting not stripped:\n{}",
            s
        );
        assert!(
            !s.contains("alice@example.com"),
            "email not anonymized:\n{}",
            s
        );
        assert!(
            s.contains("REDACTED"),
            "redact strategy not applied:\n{}",
            s
        );
    }

    #[test]
    fn mssql_unicode_string_prefix_is_stripped_transparently() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "dbo.users".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "redact".to_string(),
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
                    as_string: Some(true),
                    locale: None,
                    faker: None,
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::MsSql);
        // N'...' is MSSQL Unicode notation; the N prefix should be transparently stripped
        let input = "INSERT INTO [dbo].[users] ([id], [email]) VALUES (1, N'alice@example.com');\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            !s.contains("alice@example.com"),
            "N'...' email not anonymized:\n{}",
            s
        );
        assert!(
            s.contains("REDACTED"),
            "redact strategy not applied:\n{}",
            s
        );
    }

    #[test]
    fn mssql_create_table_with_bracket_quoting_and_nvarchar_length() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "dbo.users".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "faker".to_string(),
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
                    as_string: Some(true),
                    locale: None,
                    faker: Some("internet::SafeEmail".to_string()),
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        set_random_seed(42);
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::MsSql);
        let input = r#"CREATE TABLE [dbo].[users] (
  [id] int NOT NULL,
  [email] nvarchar(20) NOT NULL
);
INSERT INTO [dbo].[users] ([id], [email]) VALUES (1, N'alice@example.com');
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            !s.contains("alice@example.com"),
            "email not anonymized:\n{}",
            s
        );
        // Extract the replaced email value and verify length enforcement
        let insert_start = s.find("INSERT INTO dbo.users").unwrap();
        let insert_tail = &s[insert_start..];
        let values_start = insert_tail.to_uppercase().find("VALUES").unwrap() + "VALUES".len();
        let values_str = insert_tail[values_start..].trim();
        let rows = parse_values_rows(strip_trailing_semicolon(values_str.trim_end())).unwrap();
        let email_val = rows[0][1].original.as_ref().unwrap();
        assert!(
            email_val.chars().count() <= 20,
            "email '{}' exceeds nvarchar(20) limit",
            email_val
        );
    }

    #[test]
    fn mssql_copy_blocks_are_not_processed() {
        // MsSql format: COPY-like lines should pass through verbatim
        let cfg = ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::MsSql);
        let input = "COPY users (id, email) FROM stdin;\nalice@example.com\n\\.\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(
            s, input,
            "MsSql mode should pass COPY-like lines through verbatim"
        );
    }

    #[test]
    fn mssql_multi_row_insert_with_bracket_quoting() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        rules.insert(
            "dbo.customers".to_string(),
            HashMap::from([(
                "email".to_string(),
                AnonymizerSpec {
                    strategy: "hash".to_string(),
                    salt: Some("test-salt".to_string()),
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
                    as_string: Some(true),
                    locale: None,
                    faker: None,
                    format: None,
                },
            )]),
        );
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::MsSql);
        let input = "INSERT INTO [dbo].[customers] ([id], [email]) VALUES (1, N'alice@corp.com'), (2, N'bob@corp.com');\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("INSERT INTO dbo.customers"),
            "output should use unquoted idents:\n{}",
            s
        );
        assert!(
            !s.contains("alice@corp.com"),
            "first email not anonymized:\n{}",
            s
        );
        assert!(
            !s.contains("bob@corp.com"),
            "second email not anonymized:\n{}",
            s
        );
        // Both rows should still be present
        let row_count = s.matches("VALUES").count() + s.matches("), (").count();
        assert!(row_count >= 1, "expected multi-row output:\n{}", s);
    }

    #[test]
    fn localized_name_and_phone_are_replaced_in_pipeline() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "full_name".to_string(),
            AnonymizerSpec {
                strategy: "faker".to_string(),
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
                locale: Some("de_de".to_string()),
                faker: Some("name::Name".to_string()),
                format: None,
            },
        );
        cols.insert(
            "phone".to_string(),
            AnonymizerSpec {
                strategy: "phone".to_string(),
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
                locale: Some("de_de".to_string()),
                faker: None,
                format: None,
            },
        );
        rules.insert("public.contacts".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: crate::settings::OutputScanConfig::default(),
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, None, DumpFormat::Postgres);
        let input = "INSERT INTO public.contacts (id, full_name, phone) VALUES (1, 'Alice Müller', '+49 30 12345678');\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        proc.process(&mut reader, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            !s.contains("Alice Müller"),
            "original name must be replaced:\n{}",
            s
        );
        assert!(
            !s.contains("+49 30 12345678"),
            "original phone must be replaced:\n{}",
            s
        );
        assert!(
            s.contains("public.contacts"),
            "table name must be preserved:\n{}",
            s
        );
    }

    #[test]
    fn discover_scaffold_column_rules_streams_dump() {
        let input = r#"
CREATE TABLE "public"."users" (id int, user_email text, notes text);
INSERT INTO public.users (id, user_email, notes) VALUES (1, 'a@b.c', 'x');
COPY public.users (id, user_email, notes) FROM stdin;
1	x@y.z	n
\.
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let rules = discover_scaffold_column_rules(&mut reader, DumpFormat::Postgres).unwrap();
        let t = rules.get("public.users").expect("public.users");
        let email = t.get("user_email").expect("user_email");
        assert_eq!(email.strategy, "email");
    }

    #[test]
    fn discover_scaffold_rules_infer_json_paths() {
        let input = r#"INSERT INTO app.events (id, payload) VALUES (1, '{"profile":{"contact_email":"x@y.z"},"meta":"y"}');
"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let opts = ScaffoldDiscoverOptions {
            infer_json_paths: true,
            max_json_depth: 24,
        };
        let rules = discover_scaffold_rules(&mut reader, DumpFormat::Postgres, &opts).unwrap();
        let t = rules.get("app.events").expect("app.events");
        assert!(
            t.contains_key("payload.profile.contact_email"),
            "expected nested JSON rule key, got {:?}",
            t.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            t.get("payload.profile.contact_email").unwrap().strategy,
            "email"
        );
        assert!(
            !t.contains_key("payload"),
            "whole-column rule on payload should be removed when path rules exist"
        );
    }

    #[test]
    fn discover_scaffold_address_column_redact() {
        let input = "INSERT INTO t (id, shipping_address) VALUES (1, '123 Main St');\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let rules = discover_scaffold_column_rules(&mut reader, DumpFormat::Postgres).unwrap();
        let col = rules.get("t").unwrap().get("shipping_address").unwrap();
        assert_eq!(col.strategy, "redact");
    }

    #[test]
    fn discover_scaffold_address_literal_zip_redact() {
        let input = r#"INSERT INTO t (id, note) VALUES (1, 'Ship to 90210');"#;
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let opts = ScaffoldDiscoverOptions {
            infer_json_paths: true,
            max_json_depth: 24,
        };
        let rules = discover_scaffold_rules(&mut reader, DumpFormat::Postgres, &opts).unwrap();
        let note = rules.get("t").unwrap().get("note").unwrap();
        assert_eq!(note.strategy, "redact");
    }
}
