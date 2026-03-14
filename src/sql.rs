use crate::filter::{should_keep_row, when_matches};
use crate::report::Reporter;
use crate::settings::{lookup_column_cases, lookup_column_rule, AnonymizerSpec, ResolvedConfig};
use crate::transform::{apply_anonymizer, AnonymizerRegistry, Replacement};
use anyhow::Context;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, Write};

pub struct SqlStreamProcessor {
    anonymizers: AnonymizerRegistry,
    config: ResolvedConfig,
    include_tables: Vec<Regex>,
    exclude_tables: Vec<Regex>,
    column_length_limits: HashMap<String, HashMap<String, usize>>,
    check_only: bool,
    reporter: Option<*mut Reporter>, // raw pointer to allow mutable borrow during process
}

impl SqlStreamProcessor {
    pub fn new(
        anonymizers: AnonymizerRegistry,
        config: ResolvedConfig,
        include_tables: Vec<Regex>,
        exclude_tables: Vec<Regex>,
        check_only: bool,
        reporter: Option<&mut Reporter>,
    ) -> Self {
        Self {
            anonymizers,
            config,
            include_tables,
            exclude_tables,
            column_length_limits: HashMap::new(),
            check_only,
            reporter: reporter.map(|r| r as *mut Reporter),
        }
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
        let copy_re =
            Regex::new(r#"(?i)^\s*COPY\s+([^\s(]+)\s*\(([^)]*)\)\s+FROM\s+stdin;\s*$"#).unwrap();

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
                            if let Some((schema, table, lengths)) =
                                parse_create_table_column_lengths(&create_table_buf)
                            {
                                if !lengths.is_empty() {
                                    self.register_column_lengths(
                                        schema.as_deref(),
                                        &table,
                                        lengths,
                                    );
                                }
                            }
                            writer.write_all(create_table_buf.as_bytes())?;
                            create_table_buf.clear();
                        } else {
                            mode = Mode::InCreateTable;
                        }
                    } else if let Some(cap) = copy_re.captures(&line) {
                        // Begin COPY mode
                        let (schema, table) = parse_table_ident(cap.get(1).unwrap().as_str());
                        let columns = split_ident_list(cap.get(2).unwrap().as_str());
                        let enabled = self.table_enabled(schema.as_deref(), &table);
                        // Emit the header intact
                        writer.write_all(line.as_bytes())?;
                        mode = Mode::InCopy {
                            schema,
                            table,
                            columns,
                            enabled,
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
                    enabled,
                } => {
                    if line.trim_end() == "\\." {
                        // end of copy
                        writer.write_all(line.as_bytes())?;
                        mode = Mode::Pass;
                    } else {
                        // data row
                        let fields: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
                        if !*enabled {
                            // passthrough unchanged
                            writer.write_all(line.as_bytes())?;
                            continue;
                        }
                        // Evaluate row filters
                        let unescaped: Vec<Option<String>> = fields
                            .iter()
                            .enumerate()
                            .map(|(_i, f)| {
                                if *f == r"\N" {
                                    None
                                } else {
                                    Some((*f).to_string())
                                }
                            })
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
                            let selected = select_strategy_for_cell(
                                &self.config,
                                schema.as_deref(),
                                table,
                                columns,
                                &unescaped,
                                col,
                            );
                            // \N is null
                            let original = if *field == r"\N" { None } else { Some(*field) };
                            if let Some(spec) = selected {
                                let col_len =
                                    self.lookup_column_max_length(schema.as_deref(), table, col);
                                let repl =
                                    apply_anonymizer(&self.anonymizers, &spec, original, col_len);
                                if let Some(rp) = self.reporter.as_ref() {
                                    unsafe {
                                        (*(*rp)).record_cell_changed(
                                            schema.as_deref(),
                                            table,
                                            col,
                                            &spec.strategy,
                                            original.is_none(),
                                        );
                                    }
                                }
                                if repl.is_null {
                                    new_fields.push(r"\N".to_string());
                                } else {
                                    // In COPY, write raw with tabs avoided; our anonymizers generate safe content.
                                    new_fields.push(repl.value);
                                }
                            } else {
                                new_fields.push((*field).to_string());
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
                        if let Some((schema, table, lengths)) =
                            parse_create_table_column_lengths(&create_table_buf)
                        {
                            if !lengths.is_empty() {
                                self.register_column_lengths(schema.as_deref(), &table, lengths);
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
        // Extract INSERT INTO <table> (columns) VALUES <rows> ;
        let mut s = stmt.trim().to_string();
        // Ensure trailing semicolon present
        if !s.ends_with(';') {
            anyhow::bail!("INSERT without trailing semicolon");
        }
        // Find "INSERT INTO"
        let up = s.to_uppercase();
        let idx_insert = up
            .find("INSERT INTO")
            .ok_or_else(|| anyhow::anyhow!("not an INSERT"))?;
        let after = &s[idx_insert + "INSERT INTO".len()..];
        // Parse table ident then columns list
        let (schema, table, rest_after_table) = parse_table_and_rest(after)?;
        // If table is disabled by include/exclude, return original unchanged
        if !self.table_enabled(schema.as_deref(), &table) {
            return Ok(stmt.to_string());
        }
        let (columns, rest_after_cols) = parse_parenthesized_ident_list(rest_after_table)?;
        // Expect VALUES
        let rest_upper = rest_after_cols.to_uppercase();
        let idx_values = rest_upper
            .find("VALUES")
            .ok_or_else(|| anyhow::anyhow!("INSERT missing VALUES"))?;
        let after_values = &rest_after_cols[idx_values + "VALUES".len()..];
        // Strip trailing semicolon
        let values_block = strip_trailing_semicolon(after_values.trim());
        let rows = parse_values_rows(values_block)?;
        // Transform and filter rows
        let mut out = String::new();
        out.push_str(&format!(
            "INSERT INTO {} ({}) VALUES ",
            format_table_ident(schema.as_deref(), &table),
            columns.join(", ")
        ));
        let mut first_row = true;
        for row in rows.into_iter() {
            // Row-level keep/drop
            let cell_values: Vec<Option<String>> =
                row.iter().map(|cell| cell.original.clone()).collect();
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
            for (i, cell) in row.into_iter().enumerate() {
                let col = columns.get(i).map(|s| s.as_str()).unwrap_or("");
                let selected = select_strategy_for_cell(
                    &self.config,
                    schema.as_deref(),
                    &table,
                    &columns,
                    &cell_values,
                    col,
                );
                if let Some(spec) = selected {
                    let col_len = self.lookup_column_max_length(schema.as_deref(), &table, col);
                    let replacement = apply_anonymizer(
                        &self.anonymizers,
                        &spec,
                        cell.original.as_deref(),
                        col_len,
                    );
                    if let Some(rp) = self.reporter {
                        unsafe {
                            (*rp).record_cell_changed(
                                schema.as_deref(),
                                &table,
                                col,
                                &spec.strategy,
                                cell.original.is_none(),
                            );
                        }
                    }
                    rendered_cells.push(render_cell(&replacement, &cell));
                } else {
                    rendered_cells.push(cell.render_original());
                }
            }
            out.push('(');
            out.push_str(&rendered_cells.join(", "));
            out.push(')');
        }
        out.push_str(";\n");
        Ok(out)
    }

    fn table_enabled(&self, schema: Option<&str>, table: &str) -> bool {
        let q = format_table_ident(schema, table);
        let include_ok = if self.include_tables.is_empty() {
            true
        } else {
            self.include_tables.iter().any(|re| re.is_match(&q))
        };
        if !include_ok {
            return false;
        }
        if self.exclude_tables.iter().any(|re| re.is_match(&q)) {
            return false;
        }
        true
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
}

enum Mode {
    Pass,
    InInsert,
    InCreateTable,
    InCopy {
        schema: Option<String>,
        table: String,
        columns: Vec<String>,
        enabled: bool,
    },
}

fn starts_with_insert(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.to_uppercase().starts_with("INSERT INTO")
}

fn starts_with_create_table(line: &str) -> bool {
    let trimmed = line.trim_start();
    let upper = trimmed.to_uppercase();
    upper.starts_with("CREATE TABLE") || upper.starts_with("CREATE UNLOGGED TABLE")
}

fn statement_complete(buf: &str) -> bool {
    // Detect a semicolon that's not inside quotes or parentheses
    let mut depth: i32 = 0;
    let mut in_single = false;
    let mut last_char: Option<char> = None;
    let mut i = 0;
    let chars: Vec<char> = buf.chars().collect();
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            if c == '\'' {
                // doubled single-quote escapes
                if i + 1 < chars.len() && chars[i + 1] == '\'' {
                    i += 1; // skip escape
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
        last_char = Some(c);
        i += 1;
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
    let mut in_quote = false;
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quote = !in_quote;
                current.push(c);
            }
            '.' if !in_quote => {
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
    let bytes = after_insert_into.as_bytes();
    let mut i = 0usize;
    // skip whitespace
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    // read until first '(' at top-level (respect quotes)
    let mut ident = String::new();
    let mut in_quote = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' => {
                in_quote = !in_quote;
                ident.push(c);
                i += 1;
            }
            '(' if !in_quote => break,
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
    let bytes = s.as_bytes();
    let mut i = 0usize;
    if bytes.get(0).copied().map(|b| b as char) != Some('(') {
        anyhow::bail!("expected '(' after table ident");
    }
    i += 1; // consume '('
    let start = i;
    let mut depth = 1i32;
    let mut in_quote = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' => {
                in_quote = !in_quote;
                i += 1;
            }
            '(' if !in_quote => {
                depth += 1;
                i += 1;
            }
            ')' if !in_quote => {
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

fn parse_create_table_column_lengths(
    stmt: &str,
) -> Option<(Option<String>, String, HashMap<String, usize>)> {
    let (schema, table, column_block) = parse_create_table_header(stmt)?;
    let lengths = parse_column_length_limits(column_block);
    Some((schema, table, lengths))
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
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    let mut ident = String::new();
    let mut in_quote = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' => {
                in_quote = !in_quote;
                ident.push(c);
                i += 1;
            }
            '(' if !in_quote => break,
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

fn parse_column_length_limits(column_block: &str) -> HashMap<String, usize> {
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
            if let Some(max_len) = extract_type_length(rest) {
                lengths.insert(column.to_lowercase(), max_len);
            }
        }
    }
    lengths
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
        .or_else(|| parse_len_after_type_prefix(&lower, "varchar"))
        .or_else(|| parse_len_after_type_prefix(&lower, "character"))
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

#[derive(Clone, Debug)]
struct Cell {
    original: Option<String>, // None for NULL
    was_quoted: bool,
    was_default: bool,
}

impl Cell {
    fn render_original(&self) -> String {
        if self.was_default {
            return "DEFAULT".to_string();
        }
        match &self.original {
            None => "NULL".to_string(),
            Some(s) => {
                if self.was_quoted {
                    format!("'{}'", s.replace('\'', "''"))
                } else {
                    s.clone()
                }
            }
        }
    }
}

fn render_cell(repl: &Replacement, original: &Cell) -> String {
    if repl.is_null {
        return "NULL".to_string();
    }
    let should_quote = repl.force_quoted || original.was_quoted;
    if should_quote {
        format!("'{}'", repl.value.replace('\'', "''"))
    } else {
        repl.value.clone()
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
    let mut i = 0;
    let bytes = values_block.as_bytes();
    let len = bytes.len();
    // Helper to skip whitespace
    let mut next_non_ws = |mut j: usize| -> usize {
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
    let mut i = 0usize;
    let chs: Vec<char> = s.chars().collect();
    if chs.get(0) != Some(&'(') {
        anyhow::bail!("expected '('");
    }
    i += 1; // skip '('
    let mut cells: Vec<Cell> = Vec::new();
    let mut in_single = false;
    let mut buf = String::new();
    let mut was_quoted = false;
    while i < chs.len() {
        let c = chs[i];
        if in_single {
            if c == '\'' {
                // doubled '' escape
                if i + 1 < chs.len() && chs[i + 1] == '\'' {
                    buf.push('\'');
                    i += 2;
                    continue;
                } else {
                    in_single = false;
                    i += 1;
                    continue;
                }
            } else {
                buf.push(c);
                i += 1;
                continue;
            }
        } else {
            match c {
                '\'' => {
                    in_single = true;
                    was_quoted = true;
                    i += 1;
                }
                ')' => {
                    // end cell, end row
                    // finalize last cell
                    let cell = finalize_cell(&buf, was_quoted);
                    cells.push(cell);
                    i += 1;
                    return Ok((cells, i));
                }
                ',' => {
                    // end cell
                    let cell = finalize_cell(&buf, was_quoted);
                    cells.push(cell);
                    buf.clear();
                    was_quoted = false;
                    i += 1;
                    // consume following spaces
                    while i < chs.len() && chs[i].is_whitespace() {
                        i += 1;
                    }
                }
                c if c.is_whitespace() => {
                    // skip insignificant whitespace between tokens when unquoted
                    i += 1;
                }
                other => {
                    buf.push(other);
                    i += 1;
                }
            }
        }
    }
    anyhow::bail!("unterminated values row")
}

fn finalize_cell(buf: &str, was_quoted: bool) -> Cell {
    if was_quoted {
        Cell {
            original: Some(buf.to_string()),
            was_quoted: true,
            was_default: false,
        }
    } else {
        let t = buf.trim();
        if t.eq_ignore_ascii_case("null") {
            Cell {
                original: None,
                was_quoted: false,
                was_default: false,
            }
        } else if t.eq_ignore_ascii_case("default") {
            Cell {
                original: None,
                was_quoted: false,
                was_default: true,
            }
        } else {
            Cell {
                original: Some(t.to_string()),
                was_quoted: false,
                was_default: false,
            }
        }
    }
}

fn select_strategy_for_cell(
    cfg: &ResolvedConfig,
    schema: Option<&str>,
    table: &str,
    columns: &[String],
    row_cells: &[Option<String>],
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
    lookup_column_rule(cfg, schema, table, column).cloned()
}

fn row_as_option_strings(row: &[Option<String>]) -> Vec<Option<String>> {
    row.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{AnonymizerSpec, ColumnCase, ResolvedConfig, RowFilterSet, When};
    use crate::transform::{set_random_seed, AnonymizerRegistry};
    use std::collections::HashMap;

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
                length: None,
                min_days: Some(-1),
                max_days: Some(1),
                min_seconds: None,
                max_seconds: None,
                as_string: Some(true),
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
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        set_random_seed(42);
        let mut proc = SqlStreamProcessor::new(reg, cfg, Vec::new(), Vec::new(), false, None);
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
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                as_string: Some(true),
            },
        );
        rules.insert("public.users".to_string(), base_cols);
        // Column cases for email: first match admins -> redact, second eu -> hash with salt
        let mut column_cases: HashMap<String, HashMap<String, Vec<ColumnCase>>> = HashMap::new();
        let mut email_cases: Vec<ColumnCase> = Vec::new();
        email_cases.push(ColumnCase {
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
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                as_string: Some(true),
            },
        });
        email_cases.push(ColumnCase {
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
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                as_string: Some(true),
            },
        });
        let mut per_col: HashMap<String, Vec<ColumnCase>> = HashMap::new();
        per_col.insert("email".into(), email_cases);
        column_cases.insert("public.users".into(), per_col);

        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases,
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        set_random_seed(1);
        let mut proc = SqlStreamProcessor::new(reg, cfg, Vec::new(), Vec::new(), false, None);
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
            source_path: None,
        };
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, Vec::new(), Vec::new(), false, None);
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
    fn generated_values_fit_length_restricted_columns_from_create_table() {
        let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
        let mut cols: HashMap<String, AnonymizerSpec> = HashMap::new();
        cols.insert(
            "email".to_string(),
            AnonymizerSpec {
                strategy: "email".to_string(),
                salt: None,
                min: None,
                max: None,
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                as_string: Some(true),
            },
        );
        cols.insert(
            "nick".to_string(),
            AnonymizerSpec {
                strategy: "string".to_string(),
                salt: None,
                min: None,
                max: None,
                length: Some(24),
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                as_string: Some(true),
            },
        );
        cols.insert(
            "phone".to_string(),
            AnonymizerSpec {
                strategy: "phone".to_string(),
                salt: None,
                min: None,
                max: None,
                length: None,
                min_days: None,
                max_days: None,
                min_seconds: None,
                max_seconds: None,
                as_string: Some(true),
            },
        );
        rules.insert("public.users".to_string(), cols);
        let cfg = ResolvedConfig {
            salt: None,
            rules,
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            source_path: None,
        };
        set_random_seed(7);
        let reg = AnonymizerRegistry::from_config(&cfg);
        let mut proc = SqlStreamProcessor::new(reg, cfg, Vec::new(), Vec::new(), false, None);
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
}
