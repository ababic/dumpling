//! Optional dump seal: a leading SQL comment records the Dumpling version, security profile,
//! and a SHA-256 fingerprint of the resolved policy. With `--trust-sealed-dumps`, a matching
//! seal causes the rest of the dump to pass through unchanged.

use crate::settings::{AnonymizerSpec, ColumnCase, RawConfig, ResolvedConfig, RowFilterSet};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Read};

pub const SEAL_LINE_PREFIX: &str = "-- dumpling-seal:";

/// JSON object key order is stabilized recursively so the fingerprint is deterministic.
#[derive(Debug, Serialize)]
struct SealFingerprintPayload {
    format_version: u32,
    dumpling_version: &'static str,
    security_profile: String,
    policy: RawConfig,
}

/// Hex-encode a 32-byte digest (lowercase, no `0x` prefix).
pub fn sha256_hex_32(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk.get(1).copied().unwrap_or(0))?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

fn resolved_to_raw_for_fingerprint(cfg: &ResolvedConfig) -> RawConfig {
    let mut rules: HashMap<String, HashMap<String, AnonymizerSpec>> = HashMap::new();
    let mut table_keys: Vec<String> = cfg.rules.keys().cloned().collect();
    table_keys.sort();
    for tk in table_keys {
        let col_map = cfg.rules.get(&tk).unwrap();
        let mut col_keys: Vec<String> = col_map.keys().cloned().collect();
        col_keys.sort();
        let mut inner = HashMap::new();
        for ck in col_keys {
            inner.insert(ck.clone(), col_map.get(&ck).unwrap().clone());
        }
        rules.insert(tk, inner);
    }

    let mut row_filters: HashMap<String, RowFilterSet> = HashMap::new();
    let mut rf_keys: Vec<String> = cfg.row_filters.keys().cloned().collect();
    rf_keys.sort();
    for k in rf_keys {
        row_filters.insert(k.clone(), cfg.row_filters.get(&k).unwrap().clone());
    }

    let mut column_cases: HashMap<String, HashMap<String, Vec<ColumnCase>>> = HashMap::new();
    let mut case_table_keys: Vec<String> = cfg.column_cases.keys().cloned().collect();
    case_table_keys.sort();
    for tk in case_table_keys {
        let col_map = cfg.column_cases.get(&tk).unwrap();
        let mut col_keys: Vec<String> = col_map.keys().cloned().collect();
        col_keys.sort();
        let mut inner: HashMap<String, Vec<ColumnCase>> = HashMap::new();
        for ck in col_keys {
            inner.insert(ck.clone(), col_map.get(&ck).unwrap().clone());
        }
        column_cases.insert(tk, inner);
    }

    let mut sensitive_columns: HashMap<String, Vec<String>> = HashMap::new();
    let mut sens_keys: Vec<String> = cfg.sensitive_columns.keys().cloned().collect();
    sens_keys.sort();
    for tk in sens_keys {
        let set = cfg.sensitive_columns.get(&tk).unwrap();
        let mut cols: Vec<String> = set.iter().cloned().collect();
        cols.sort();
        sensitive_columns.insert(tk, cols);
    }

    RawConfig {
        salt: cfg.salt.clone(),
        rules,
        row_filters,
        column_cases,
        table_options: HashMap::new(),
        sensitive_columns,
        output_scan: cfg.output_scan.clone(),
    }
}

fn sort_json_value(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for k in keys {
                if let Some(mut child) = map.remove(&k) {
                    sort_json_value(&mut child);
                    sorted.insert(k, child);
                }
            }
            *map = sorted.into_iter().collect();
        }
        Value::Array(arr) => {
            for item in arr {
                sort_json_value(item);
            }
        }
        _ => {}
    }
}

/// SHA-256 of stable JSON for the policy plus format version, crate version, and security profile.
pub fn compute_policy_sha256(
    cfg: &ResolvedConfig,
    security_profile: &str,
) -> anyhow::Result<[u8; 32]> {
    let payload = SealFingerprintPayload {
        format_version: 1,
        dumpling_version: env!("CARGO_PKG_VERSION"),
        security_profile: security_profile.to_string(),
        policy: resolved_to_raw_for_fingerprint(cfg),
    };
    let mut val = serde_json::to_value(&payload)?;
    sort_json_value(&mut val);
    let bytes = serde_json::to_vec(&val)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSeal {
    pub format_version: u32,
    pub dumpling_version: String,
    pub security_profile: String,
    pub sha256: [u8; 32],
}

/// Parse a single-line SQL comment body after `-- dumpling-seal:` (caller passes full line).
pub fn parse_seal_line(line: &str) -> Option<ParsedSeal> {
    let trimmed = line.trim_end_matches(['\r', '\n', ' ']);
    let rest = trimmed.strip_prefix(SEAL_LINE_PREFIX)?.trim_start();
    let mut format_version: Option<u32> = None;
    let mut dumpling_version: Option<String> = None;
    let mut security_profile: Option<String> = None;
    let mut sha256: Option<[u8; 32]> = None;

    for token in rest.split_whitespace() {
        let (k, v) = token.split_once('=')?;
        match k {
            "v" => {
                format_version = Some(v.parse().ok()?);
            }
            "version" => {
                dumpling_version = Some(v.to_string());
            }
            "profile" => {
                security_profile = Some(v.to_ascii_lowercase());
            }
            "sha256" => {
                sha256 = parse_hex_32(v);
            }
            _ => {}
        }
    }

    Some(ParsedSeal {
        format_version: format_version?,
        dumpling_version: dumpling_version?,
        security_profile: security_profile?,
        sha256: sha256?,
    })
}

pub fn format_seal_line(security_profile: &str, digest: &[u8; 32]) -> String {
    format!(
        "{} v=1 version={} profile={} sha256={}\n",
        SEAL_LINE_PREFIX,
        env!("CARGO_PKG_VERSION"),
        security_profile.to_ascii_lowercase(),
        sha256_hex_32(digest)
    )
}

pub fn seal_matches_current(
    parsed: &ParsedSeal,
    cfg: &ResolvedConfig,
    security_profile: &str,
) -> anyhow::Result<bool> {
    if parsed.format_version != 1 {
        return Ok(false);
    }
    if parsed.dumpling_version != env!("CARGO_PKG_VERSION") {
        return Ok(false);
    }
    if parsed.security_profile != security_profile.to_ascii_lowercase() {
        return Ok(false);
    }
    let expected = compute_policy_sha256(cfg, security_profile)?;
    Ok(parsed.sha256 == expected)
}

/// Wraps a `BufRead` and optionally replays the first line (bytes) before delegating.
pub struct FirstLineReplayBufRead<'a> {
    inner: &'a mut dyn BufRead,
    replay: Option<Vec<u8>>,
    pos: usize,
}

impl<'a> FirstLineReplayBufRead<'a> {
    pub fn new(inner: &'a mut dyn BufRead, replay: Option<Vec<u8>>) -> Self {
        Self {
            inner,
            replay,
            pos: 0,
        }
    }
}

impl Read for FirstLineReplayBufRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(ref r) = self.replay {
            if self.pos < r.len() {
                let n = (r.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&r[self.pos..self.pos + n]);
                self.pos += n;
                if self.pos >= r.len() {
                    self.replay = None;
                    self.pos = 0;
                }
                return Ok(n);
            }
        }
        self.inner.read(buf)
    }
}

impl BufRead for FirstLineReplayBufRead<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if let Some(ref r) = self.replay {
            if self.pos < r.len() {
                return Ok(&r[self.pos..]);
            }
        }
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        if let Some(ref r) = self.replay {
            if self.pos < r.len() {
                self.pos += amt;
                if self.pos >= r.len() {
                    self.replay = None;
                    self.pos = 0;
                }
                return;
            }
        }
        self.inner.consume(amt);
    }
}

/// Read the first line from `reader` and return `(first_line, skip_first_line)`.
/// If `skip_first_line` is true, the first line matched a trusted seal and must not be replayed.
pub fn read_first_line_for_seal(
    reader: &mut dyn BufRead,
    cfg: &ResolvedConfig,
    security_profile: &str,
    trust_sealed: bool,
) -> anyhow::Result<(String, bool)> {
    let mut first = String::new();
    let n = reader.read_line(&mut first)?;
    if n == 0 {
        return Ok((String::new(), false));
    }

    let skip_first = if trust_sealed && first.trim_start().starts_with(SEAL_LINE_PREFIX) {
        match parse_seal_line(&first) {
            Some(p) => seal_matches_current(&p, cfg, security_profile)?,
            None => false,
        }
    } else {
        false
    };

    if skip_first {
        eprintln!("dumpling: sealed dump header matches current version, profile, and policy; passing through unchanged");
    }

    Ok((first, skip_first))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::OutputScanConfig;

    fn minimal_cfg() -> ResolvedConfig {
        ResolvedConfig {
            salt: None,
            rules: HashMap::new(),
            row_filters: HashMap::new(),
            column_cases: HashMap::new(),
            sensitive_columns: HashMap::new(),
            output_scan: OutputScanConfig::default(),
            source_path: None,
        }
    }

    #[test]
    fn seal_line_round_trip() {
        let cfg = minimal_cfg();
        let digest = compute_policy_sha256(&cfg, "standard").unwrap();
        let line = format_seal_line("standard", &digest);
        let parsed = parse_seal_line(&line).expect("parse");
        assert!(seal_matches_current(&parsed, &cfg, "standard").unwrap());
    }

    #[test]
    fn wrong_version_does_not_match() {
        let cfg = minimal_cfg();
        let digest = compute_policy_sha256(&cfg, "standard").unwrap();
        let mut line = format_seal_line("standard", &digest);
        line = line.replace(
            &format!("version={}", env!("CARGO_PKG_VERSION")),
            "version=0.0.0-wrong",
        );
        let parsed = parse_seal_line(&line).expect("parse");
        assert!(!seal_matches_current(&parsed, &cfg, "standard").unwrap());
    }

    #[test]
    fn fingerprint_stable_across_map_insert_order() {
        let mut cfg1 = minimal_cfg();
        let mut cfg2 = minimal_cfg();
        let mut r1 = HashMap::new();
        r1.insert(
            "email".into(),
            AnonymizerSpec {
                strategy: "email".into(),
                salt: None,
                min: None,
                max: None,
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
            },
        );
        cfg1.rules.insert("users".into(), r1.clone());
        let mut r2 = HashMap::new();
        r2.insert(
            "email".into(),
            AnonymizerSpec {
                strategy: "email".into(),
                salt: None,
                min: None,
                max: None,
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
            },
        );
        cfg2.rules.insert("users".into(), r2);
        let h1 = compute_policy_sha256(&cfg1, "standard").unwrap();
        let h2 = compute_policy_sha256(&cfg2, "standard").unwrap();
        assert_eq!(h1, h2);
    }
}
