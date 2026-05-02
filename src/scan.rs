use crate::report::{OutputScanFinding, OutputScanReport, OutputScanSample};
use crate::settings::OutputScanConfig;
use anyhow::Context;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::io::{Result as IoResult, Write};

pub const OUTPUT_SCAN_CATEGORIES: [&str; 4] = ["email", "ssn", "pan", "token"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

pub fn parse_severity(raw: &str) -> Option<Severity> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct CategoryState {
    category: String,
    severity: Severity,
    threshold: u64,
    count: u64,
    samples: Vec<OutputScanSample>,
}

impl CategoryState {
    fn new(category: &str, severity: Severity, threshold: u64) -> Self {
        Self {
            category: category.to_string(),
            severity,
            threshold,
            count: 0,
            samples: Vec::new(),
        }
    }
}

pub struct OutputScanner {
    categories: HashMap<String, CategoryState>,
    sample_limit_per_category: usize,
    fail_on_severity: Severity,
    line_number: u64,
    current_line: String,
}

impl OutputScanner {
    pub fn new(config: OutputScanConfig) -> anyhow::Result<Self> {
        let mut enabled = normalize_enabled_categories(&config.enabled_categories);
        if enabled.is_empty() {
            enabled = OUTPUT_SCAN_CATEGORIES
                .iter()
                .map(|c| (*c).to_string())
                .collect();
        }
        let default_severity = parse_severity(&config.default_severity).with_context(|| {
            format!(
                "invalid output_scan.default_severity '{}'",
                config.default_severity
            )
        })?;
        let fail_on_severity = parse_severity(&config.fail_on_severity).with_context(|| {
            format!(
                "invalid output_scan.fail_on_severity '{}'",
                config.fail_on_severity
            )
        })?;
        let mut categories = HashMap::new();
        for category in enabled {
            let severity = config
                .severities
                .get(&category)
                .and_then(|value| parse_severity(value))
                .unwrap_or(default_severity);
            let threshold = config
                .thresholds
                .get(&category)
                .copied()
                .unwrap_or(config.default_threshold);
            categories.insert(
                category.clone(),
                CategoryState::new(&category, severity, threshold),
            );
        }
        Ok(Self {
            categories,
            sample_limit_per_category: config.sample_limit_per_category,
            fail_on_severity,
            line_number: 1,
            current_line: String::new(),
        })
    }

    pub fn observe_bytes(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for chunk in text.split_inclusive('\n') {
            if let Some(prefix) = chunk.strip_suffix('\n') {
                self.current_line.push_str(prefix);
                let line = std::mem::take(&mut self.current_line);
                self.scan_line(self.line_number, &line);
                self.line_number += 1;
            } else {
                self.current_line.push_str(chunk);
            }
        }
    }

    pub fn finish(&mut self) {
        if !self.current_line.is_empty() {
            let line = std::mem::take(&mut self.current_line);
            self.scan_line(self.line_number, &line);
        }
    }

    pub fn build_report(&self) -> OutputScanReport {
        let mut findings: Vec<OutputScanFinding> = self
            .categories
            .values()
            .filter(|state| state.count > 0)
            .map(|state| OutputScanFinding {
                category: state.category.clone(),
                severity: state.severity.as_str().to_string(),
                count: state.count,
                threshold: state.threshold,
                sample_locations: state.samples.clone(),
            })
            .collect();
        findings.sort_by(|a, b| a.category.cmp(&b.category));
        let total_findings = findings.iter().map(|f| f.count).sum();
        let failed_categories: Vec<String> = findings
            .iter()
            .filter(|f| {
                f.count > f.threshold
                    && parse_severity(&f.severity)
                        .map(|s| s >= self.fail_on_severity)
                        .unwrap_or(false)
            })
            .map(|f| f.category.clone())
            .collect();
        OutputScanReport {
            total_findings,
            fail_on_severity: self.fail_on_severity.as_str().to_string(),
            failed: !failed_categories.is_empty(),
            failed_categories,
            findings,
        }
    }

    fn scan_line(&mut self, line_number: u64, line: &str) {
        if line.is_empty() {
            return;
        }
        if self.categories.contains_key("email") {
            for m in EMAIL_RE.find_iter(line) {
                self.record_match("email", line_number, line, m.start(), m.end());
            }
        }
        if self.categories.contains_key("ssn") {
            for m in SSN_RE.find_iter(line) {
                let candidate = &line[m.start()..m.end()];
                if valid_ssn(candidate) {
                    self.record_match("ssn", line_number, line, m.start(), m.end());
                }
            }
        }
        if self.categories.contains_key("pan") {
            for m in PAN_CANDIDATE_RE.find_iter(line) {
                let candidate = &line[m.start()..m.end()];
                let digits: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 13 && digits.len() <= 19 && luhn_valid(&digits) {
                    self.record_match("pan", line_number, line, m.start(), m.end());
                }
            }
        }
        if self.categories.contains_key("token") {
            let mut seen: Vec<(usize, usize)> = Vec::new();
            for re in [
                &*JWT_RE,
                &*AWS_ACCESS_KEY_RE,
                &*GITHUB_PAT_RE,
                &*SLACK_TOKEN_RE,
                &*LABELED_TOKEN_RE,
            ] {
                for m in re.find_iter(line) {
                    let span = (m.start(), m.end());
                    if seen.iter().any(|existing| ranges_overlap(*existing, span)) {
                        continue;
                    }
                    seen.push(span);
                    self.record_match("token", line_number, line, span.0, span.1);
                }
            }
        }
    }

    fn record_match(
        &mut self,
        category: &str,
        line_number: u64,
        line: &str,
        start: usize,
        end: usize,
    ) {
        let Some(state) = self.categories.get_mut(category) else {
            return;
        };
        state.count += 1;
        if state.samples.len() >= self.sample_limit_per_category {
            return;
        }
        let start_col = byte_to_col(line, start);
        let end_col = byte_to_col(line, end);
        let snippet = line[start..end].to_string();
        state.samples.push(OutputScanSample {
            line: line_number,
            start_col,
            end_col,
            snippet,
        });
    }
}

pub struct ScanningWriter<'a, W: Write> {
    inner: &'a mut W,
    scanner: &'a mut OutputScanner,
}

impl<'a, W: Write> ScanningWriter<'a, W> {
    pub fn new(inner: &'a mut W, scanner: &'a mut OutputScanner) -> Self {
        Self { inner, scanner }
    }
}

impl<W: Write> Write for ScanningWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.scanner.observe_bytes(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

fn normalize_enabled_categories(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for category in raw {
        let normalized = category.trim().to_ascii_lowercase();
        if OUTPUT_SCAN_CATEGORIES.contains(&normalized.as_str()) && seen.insert(normalized.clone())
        {
            out.push(normalized);
        }
    }
    out
}

fn byte_to_col(line: &str, byte_idx: usize) -> usize {
    line[..byte_idx].chars().count() + 1
}

fn ranges_overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

#[allow(unknown_lints, clippy::manual_is_multiple_of)]
fn luhn_valid(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for ch in input.chars().rev() {
        let Some(mut digit) = ch.to_digit(10) else {
            return false;
        };
        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        double = !double;
    }
    sum % 10 == 0
}

fn valid_ssn(input: &str) -> bool {
    let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];
    if area == "000" || area == "666" || area.starts_with('9') {
        return false;
    }
    if group == "00" || serial == "0000" {
        return false;
    }
    true
}

lazy_static::lazy_static! {
    static ref EMAIL_RE: Regex = Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b").unwrap();
    static ref SSN_RE: Regex = Regex::new(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b").unwrap();
    static ref PAN_CANDIDATE_RE: Regex = Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap();
    static ref JWT_RE: Regex = Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap();
    static ref AWS_ACCESS_KEY_RE: Regex = Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap();
    static ref GITHUB_PAT_RE: Regex = Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap();
    static ref SLACK_TOKEN_RE: Regex = Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap();
    static ref LABELED_TOKEN_RE: Regex = Regex::new(r#"(?i)\b(?:token|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9._\-]{16,}\b"#).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::OutputScanConfig;
    use std::collections::HashMap;

    #[test]
    fn scanner_detects_categories_and_locations() {
        let mut scanner = OutputScanner::new(OutputScanConfig::default()).unwrap();
        scanner.observe_bytes(
            b"email='alice@example.com' ssn='123-45-6789' cc='4111 1111 1111 1111' token='ghp_abcdefghijklmnopqrstuvwxyz012345'\n",
        );
        scanner.finish();
        let report = scanner.build_report();
        assert_eq!(report.total_findings, 4);
        assert_eq!(report.findings.len(), 4);
        let categories = report
            .findings
            .iter()
            .map(|f| f.category.clone())
            .collect::<Vec<_>>();
        assert!(categories.contains(&"email".to_string()));
        assert!(categories.contains(&"ssn".to_string()));
        assert!(categories.contains(&"pan".to_string()));
        assert!(categories.contains(&"token".to_string()));
        assert!(report
            .findings
            .iter()
            .all(|f| !f.sample_locations.is_empty()));
    }

    #[test]
    fn scanner_applies_thresholds_and_severity_fail_gate() {
        let mut thresholds = HashMap::new();
        thresholds.insert("email".to_string(), 2u64);
        let mut severities = HashMap::new();
        severities.insert("email".to_string(), "low".to_string());
        let config = OutputScanConfig {
            enabled_categories: vec!["email".to_string()],
            thresholds,
            severities,
            default_threshold: 0,
            default_severity: "high".to_string(),
            fail_on_severity: "medium".to_string(),
            sample_limit_per_category: 3,
        };
        let mut scanner = OutputScanner::new(config).unwrap();
        scanner.observe_bytes(b"one=a@example.com two=b@example.com three=c@example.com\n");
        scanner.finish();
        let report = scanner.build_report();
        assert_eq!(report.total_findings, 3);
        assert!(!report.failed);
        assert!(report.failed_categories.is_empty());
    }
}
