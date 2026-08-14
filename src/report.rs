use anyhow::Context;
use chrono::SecondsFormat;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read, Write};
use std::path::Path;

use crate::seal::sha256_hex_32;

#[derive(Debug, Serialize, Clone)]
pub struct Report {
    /// Crate semver. Deterministic for a given Dumpling build.
    pub dumpling_version: String,
    /// Instance metadata: unique per invocation (will not match on re-runs).
    pub run_id: String,
    /// Instance metadata: RFC 3339 UTC timestamp when the run started (will not match on re-runs).
    pub started_at: String,
    pub security_profile: String,
    /// Path of the loaded config file (`None` when `--allow-noop` ran without a config).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_source: Option<String>,
    /// SHA-256 of the config file bytes as loaded (not the resolved/secret-substituted policy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    /// SHA-256 of the SQL byte stream Dumpling actually read (decoded/decompressed when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_sha256: Option<String>,
    /// SHA-256 of bytes written to the output stream (includes the dump-seal line when a seal is written). Omitted in `--check`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    /// Same SHA-256 hex as the dump-seal `sha256=` field (policy + version + profile + transform runtime).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_sha256: Option<String>,
    pub flags: RunFlags,
    pub outcomes: RunOutcomes,
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
            dumpling_version: env!("CARGO_PKG_VERSION").to_string(),
            run_id: String::new(),
            started_at: String::new(),
            security_profile: "standard".to_string(),
            config_source: None,
            config_sha256: None,
            input_sha256: None,
            output_sha256: None,
            seal_sha256: None,
            flags: RunFlags::default(),
            outcomes: RunOutcomes::default(),
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

/// Explicit CLI gate / run flags recorded in the audit sidecar.
#[derive(Debug, Serialize, Clone)]
pub struct RunFlags {
    pub check: bool,
    pub strict_coverage: bool,
    pub scan_output: bool,
    pub fail_on_findings: bool,
    pub allow_noop: bool,
    pub in_place: bool,
    pub no_seal: bool,
    pub format: String,
}

impl Default for RunFlags {
    fn default() -> Self {
        Self {
            check: false,
            strict_coverage: false,
            scan_output: false,
            fail_on_findings: false,
            allow_noop: false,
            in_place: false,
            no_seal: false,
            format: "postgres".to_string(),
        }
    }
}

/// Validation outcomes. Gate-specific fields are omitted when that gate was not enabled.
#[derive(Debug, Default, Serialize, Clone)]
pub struct RunOutcomes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict_coverage_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_scan_passed: Option<bool>,
    pub trusted_passthrough: bool,
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub(crate) fn generate_run_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        bytes = nanos.to_le_bytes();
        let pid = (std::process::id() as u64).to_le_bytes();
        for (i, b) in pid.iter().enumerate() {
            bytes[i] ^= b;
        }
    }
    hex_encode(&bytes)
}

pub(crate) fn run_timestamp_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    sha256_hex_32(&Sha256::digest(data).into())
}

pub(crate) fn sha256_hex_of_path(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed hashing config file {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Streaming SHA-256 over a `BufRead`, hashed on `consume` so `read_line` is counted once.
pub(crate) struct OptionalHashingBufRead<R: BufRead> {
    inner: R,
    hasher: Option<Sha256>,
}

impl<R: BufRead> OptionalHashingBufRead<R> {
    pub(crate) fn new(inner: R, enabled: bool) -> Self {
        Self {
            inner,
            hasher: enabled.then(Sha256::new),
        }
    }

    pub(crate) fn finalize(self) -> Option<[u8; 32]> {
        self.hasher.map(|h| h.finalize().into())
    }
}

impl<R: BufRead> Read for OptionalHashingBufRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl<R: BufRead> BufRead for OptionalHashingBufRead<R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        if let Some(hasher) = self.hasher.as_mut() {
            if amt > 0 {
                if let Ok(buf) = self.inner.fill_buf() {
                    let n = amt.min(buf.len());
                    hasher.update(&buf[..n]);
                }
            }
        }
        self.inner.consume(amt);
    }
}

pub(crate) struct OptionalHashingWriter<W: Write> {
    inner: W,
    hasher: Option<Sha256>,
}

impl<W: Write> OptionalHashingWriter<W> {
    pub(crate) fn new(inner: W, enabled: bool) -> Self {
        Self {
            inner,
            hasher: enabled.then(Sha256::new),
        }
    }

    pub(crate) fn finish(self) -> (W, Option<[u8; 32]>) {
        let digest = self.hasher.map(|h| h.finalize().into());
        (self.inner, digest)
    }
}

impl<W: Write> Write for OptionalHashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            if let Some(hasher) = self.hasher.as_mut() {
                hasher.update(&buf[..n]);
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn hashing_writer_matches_sha256_of_abc() {
        let mut sink = Vec::new();
        let mut w = OptionalHashingWriter::new(&mut sink, true);
        w.write_all(b"abc").unwrap();
        let (_, digest) = w.finish();
        assert_eq!(sha256_hex_32(&digest.unwrap()), SHA256_ABC);
        assert_eq!(sink, b"abc");
    }

    #[test]
    fn hashing_bufread_matches_sha256_of_abc() {
        let mut cursor = std::io::Cursor::new(b"abc".as_slice());
        let mut r = OptionalHashingBufRead::new(&mut cursor, true);
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "abc");
        let digest = r.finalize().unwrap();
        assert_eq!(sha256_hex_32(&digest), SHA256_ABC);
    }

    #[test]
    fn hashing_bufread_hashes_read_line_path() {
        let data = b"hello\nworld\n";
        let mut cursor = std::io::Cursor::new(data.as_slice());
        let mut r = OptionalHashingBufRead::new(&mut cursor, true);
        let mut line = String::new();
        assert!(r.read_line(&mut line).unwrap() > 0);
        line.clear();
        assert!(r.read_line(&mut line).unwrap() > 0);
        let digest = r.finalize().unwrap();
        assert_eq!(sha256_hex_32(&digest), sha256_hex(data));
    }

    #[test]
    fn hashing_disabled_returns_no_digest() {
        let mut sink = Vec::new();
        let mut w = OptionalHashingWriter::new(&mut sink, false);
        w.write_all(b"abc").unwrap();
        let (_, digest) = w.finish();
        assert!(digest.is_none());
        assert_eq!(sink, b"abc");
    }

    #[test]
    fn hashing_writer_empty_is_empty_digest() {
        let sink = Vec::new();
        let w = OptionalHashingWriter::new(sink, true);
        let (_, digest) = w.finish();
        assert_eq!(sha256_hex_32(&digest.unwrap()), SHA256_EMPTY);
    }

    #[test]
    fn report_serializes_audit_fields_and_omits_absent_checksums() {
        let mut report = Report {
            dumpling_version: "0.7.0".into(),
            run_id: "abc123".into(),
            started_at: "2026-08-14T00:00:00Z".into(),
            seal_sha256: Some("deadbeef".into()),
            flags: RunFlags {
                check: true,
                strict_coverage: true,
                scan_output: true,
                fail_on_findings: true,
                allow_noop: false,
                in_place: false,
                no_seal: true,
                format: "postgres".into(),
            },
            outcomes: RunOutcomes {
                strict_coverage_passed: Some(true),
                output_scan_passed: Some(true),
                trusted_passthrough: false,
            },
            ..Report::default()
        };
        report.security_profile = "hardened".into();
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["dumpling_version"], "0.7.0");
        assert_eq!(v["run_id"], "abc123");
        assert_eq!(v["started_at"], "2026-08-14T00:00:00Z");
        assert_eq!(v["security_profile"], "hardened");
        assert_eq!(v["seal_sha256"], "deadbeef");
        assert_eq!(v["flags"]["strict_coverage"], true);
        assert_eq!(v["outcomes"]["strict_coverage_passed"], true);
        assert!(v.get("config_source").is_none());
        assert!(v.get("config_sha256").is_none());
        assert!(v.get("input_sha256").is_none());
        assert!(v.get("output_sha256").is_none());
    }

    #[test]
    fn generate_run_id_is_32_hex_chars() {
        let id = generate_run_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
