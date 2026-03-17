use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize, Clone)]
pub struct Report {
    pub security_profile: String,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deterministic_mapping_domains: Vec<DeterministicMappingDomainUsage>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            security_profile: "standard".to_string(),
            total_rows_processed: 0,
            total_rows_dropped: 0,
            total_cells_changed: 0,
            sensitive_columns_detected: Vec::new(),
            sensitive_columns_covered: Vec::new(),
            sensitive_columns_uncovered: Vec::new(),
            per_table: HashMap::new(),
            events: Vec::new(),
            output_scan: None,
            deterministic_mapping_domains: Vec::new(),
        }
    }
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
    deterministic_usage_seen: HashSet<String>,
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

#[derive(Debug, Serialize, Clone)]
pub struct DeterministicMappingDomainUsage {
    pub schema: Option<String>,
    pub table: String,
    pub column: String,
    pub domain: String,
    pub unique_within_domain: bool,
}

impl Reporter {
    pub fn new(detailed: bool) -> Self {
        Self {
            detailed,
            report: Report::default(),
            deterministic_usage_seen: HashSet::new(),
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

    pub fn record_deterministic_mapping_domain(
        &mut self,
        schema: Option<&str>,
        table: &str,
        column: &str,
        domain: &str,
        unique_within_domain: bool,
    ) {
        let key = format!(
            "{}|{}|{}|{}|{}",
            schema.unwrap_or(""),
            table,
            column,
            domain,
            unique_within_domain
        );
        if !self.deterministic_usage_seen.insert(key) {
            return;
        }
        self.report
            .deterministic_mapping_domains
            .push(DeterministicMappingDomainUsage {
                schema: schema.map(|s| s.to_string()),
                table: table.to_string(),
                column: column.to_string(),
                domain: domain.to_string(),
                unique_within_domain,
            });
    }
}

fn qualified(schema: Option<&str>, table: &str) -> String {
    match schema {
        Some(s) => format!("{}.{}", s, table),
        None => table.to_string(),
    }
}
