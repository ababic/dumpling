use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Default, Serialize, Clone)]
pub struct Report {
    pub total_rows_processed: u64,
    pub total_rows_dropped: u64,
    pub total_cells_changed: u64,
    pub sensitive_columns_detected: Vec<String>,
    pub sensitive_columns_covered: Vec<String>,
    pub sensitive_columns_uncovered: Vec<String>,
    pub per_table: HashMap<String, TableStats>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_scan: Option<OutputScanReport>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct TableStats {
    pub rows_processed: u64,
    pub rows_dropped: u64,
    pub cells_changed: u64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "type")]
pub enum Event {
    RowDropped {
        schema: Option<String>,
        table: String,
        reason: Option<String>,
    },
    CellChanged {
        schema: Option<String>,
        table: String,
        column: String,
        strategy: String,
        original_was_null: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Reporter {
    pub detailed: bool,
    pub report: Report,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct OutputScanReport {
    pub total_findings: u64,
    pub fail_on_severity: String,
    pub failed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed_categories: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<OutputScanFinding>,
}

#[derive(Debug, Serialize, Clone)]
pub struct OutputScanFinding {
    pub category: String,
    pub severity: String,
    pub count: u64,
    pub threshold: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sample_locations: Vec<OutputScanSample>,
}

#[derive(Debug, Serialize, Clone)]
pub struct OutputScanSample {
    pub line: u64,
    pub start_col: usize,
    pub end_col: usize,
    pub snippet: String,
}

impl Reporter {
    pub fn new(detailed: bool) -> Self {
        Self {
            detailed,
            report: Report::default(),
        }
    }

    pub fn record_row_processed(&mut self, schema: Option<&str>, table: &str) {
        self.report.total_rows_processed += 1;
        let key = qualified(schema, table);
        let entry = self.report.per_table.entry(key).or_default();
        entry.rows_processed += 1;
    }

    pub fn record_row_dropped(&mut self, schema: Option<&str>, table: &str, reason: Option<&str>) {
        self.report.total_rows_dropped += 1;
        let key = qualified(schema, table);
        let entry = self.report.per_table.entry(key).or_default();
        entry.rows_dropped += 1;
        if self.detailed {
            self.report.events.push(Event::RowDropped {
                schema: schema.map(|s| s.to_string()),
                table: table.to_string(),
                reason: reason.map(|r| r.to_string()),
            });
        }
    }

    pub fn record_cell_changed(
        &mut self,
        schema: Option<&str>,
        table: &str,
        column: &str,
        strategy: &str,
        original_was_null: bool,
    ) {
        self.report.total_cells_changed += 1;
        let key = qualified(schema, table);
        let entry = self.report.per_table.entry(key).or_default();
        entry.cells_changed += 1;
        if self.detailed {
            self.report.events.push(Event::CellChanged {
                schema: schema.map(|s| s.to_string()),
                table: table.to_string(),
                column: column.to_string(),
                strategy: strategy.to_string(),
                original_was_null,
            });
        }
    }
}

fn qualified(schema: Option<&str>, table: &str) -> String {
    match schema {
        Some(s) => format!("{}.{}", s, table),
        None => table.to_string(),
    }
}
