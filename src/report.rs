use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Default, Serialize, Clone)]
pub struct Report {
    pub total_rows_processed: u64,
    pub total_rows_dropped: u64,
    pub total_cells_changed: u64,
    pub per_table: HashMap<String, TableStats>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
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

