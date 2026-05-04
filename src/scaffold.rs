//! Draft `[rules]` generation from column names in a SQL dump (starter / beta).

use crate::settings::{validate_raw_config, RawConfig};
use crate::sql::{discover_scaffold_column_rules, DumpFormat};
use anyhow::Context;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::IO_BUF_CAPACITY;

/// CLI-backed options for [`run_scaffold_config`].
pub struct ScaffoldConfigOptions<'a> {
    pub input: Option<&'a PathBuf>,
    pub output: Option<&'a PathBuf>,
    pub dump_format: DumpFormat,
    pub allow_ext: &'a [String],
    pub dump_decode: bool,
    pub dump_decode_keep_input: bool,
    pub pg_restore_path: &'a PathBuf,
    pub dump_decode_arg: &'a [String],
}

/// Emit header comments, stderr notice, and TOML body for a starter config.
pub fn run_scaffold_config(opts: ScaffoldConfigOptions<'_>) -> anyhow::Result<()> {
    let ScaffoldConfigOptions {
        input,
        output,
        dump_format,
        allow_ext,
        dump_decode,
        dump_decode_keep_input,
        pg_restore_path,
        dump_decode_arg,
    } = opts;

    eprintln!(
        "dumpling scaffold-config: beta — draft rules from column names only; review before use. \
         Heuristics are English-oriented and miss opaque or non-English names."
    );

    let mut pg_restore_child = None;
    let (mut reader, _input_path): (Box<dyn BufRead>, Option<PathBuf>) = if dump_decode {
        let archive_path = input.ok_or_else(|| {
            anyhow::anyhow!(
                "--dump-decode requires --input pointing at a pg_dump custom-format file or directory-format directory"
            )
        })?;
        if !allow_ext.is_empty() && !crate::has_allowed_extension(archive_path, allow_ext) {
            anyhow::bail!("input file extension is not in allowed set {:?}", allow_ext);
        }
        if !archive_path.exists() {
            anyhow::bail!(
                "--dump-decode input path does not exist: {}",
                archive_path.display()
            );
        }
        eprintln!(
            "dumpling: decoding PostgreSQL archive via {} -f - {}",
            pg_restore_path.display(),
            archive_path.display()
        );
        let mut cmd = Command::new(pg_restore_path);
        for a in dump_decode_arg {
            cmd.arg(a);
        }
        cmd.arg("-f")
            .arg("-")
            .arg(archive_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "failed to spawn `{}`; install PostgreSQL client tools or set --pg-restore-path",
                pg_restore_path.display()
            )
        })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("pg_restore stdout missing"))?;
        pg_restore_child = Some((child, archive_path.clone()));
        (
            Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, stdout)),
            Some(archive_path.clone()),
        )
    } else {
        match input {
            Some(path) => {
                if !allow_ext.is_empty() && !crate::has_allowed_extension(path, allow_ext) {
                    anyhow::bail!("input file extension is not in allowed set {:?}", allow_ext);
                }
                let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
                (
                    Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, f)),
                    Some(path.clone()),
                )
            }
            None => {
                if !allow_ext.is_empty() {
                    eprintln!(
                        "dumpling: --allow-ext provided but no --input file; extension check is ignored for stdin"
                    );
                }
                (
                    Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, std::io::stdin())),
                    None,
                )
            }
        }
    };

    let rules = discover_scaffold_column_rules(&mut *reader, dump_format)
        .context("scanning dump for column names")?;

    if rules.is_empty() {
        eprintln!(
            "dumpling scaffold-config: warning: no columns matched name heuristics; emitted file contains header only"
        );
    }

    let raw = RawConfig {
        salt: None,
        rules,
        row_filters: HashMap::new(),
        column_cases: HashMap::new(),
        table_options: HashMap::new(),
        sensitive_columns: HashMap::new(),
        output_scan: crate::settings::OutputScanConfig::default(),
    };
    validate_raw_config(&raw).context("internal error: scaffold rules failed validation")?;

    let body = raw_config_to_toml(&raw)?;
    let mut text = SCAFFOLD_HEADER.to_string();
    text.push_str(&body);

    if let Some(path) = output {
        std::fs::write(path, &text).with_context(|| format!("write {}", path.display()))?;
        eprintln!("dumpling scaffold-config: wrote {}", path.display());
    } else {
        std::io::stdout().write_all(text.as_bytes())?;
    }

    if let Some((mut child, archive_path)) = pg_restore_child {
        let status = child
            .wait()
            .with_context(|| format!("waiting for `{}`", pg_restore_path.display()))?;
        if !status.success() {
            anyhow::bail!(
                "`{}` exited with status {}",
                pg_restore_path.display(),
                status
            );
        }
        if dump_decode && !dump_decode_keep_input {
            match crate::remove_pg_archive(&archive_path) {
                Ok(()) => eprintln!("dumpling: removed input archive {}", archive_path.display()),
                Err(e) => eprintln!(
                    "dumpling: warning: could not remove input archive {}: {}",
                    archive_path.display(),
                    e
                ),
            }
        }
    }

    Ok(())
}

const SCAFFOLD_HEADER: &str = r#"# Dumpling starter config (beta) — generated by `dumpling scaffold-config`.
#
# This file contains ONLY inferred [rules] from SQL column names (CREATE TABLE, INSERT, COPY).
# It does NOT inspect cell values. Heuristic keywords are English-oriented; review every rule.
# Add salt (e.g. salt = "${DUMPLING_SALT}") for hash strategies, tune strategies, row_filters,
# column_cases, sensitive_columns, and output_scan as needed before production use.
#

"#;

fn raw_config_to_toml(raw: &RawConfig) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut table_keys: Vec<&String> = raw.rules.keys().collect();
    table_keys.sort();
    for tk in table_keys {
        out.push_str(&format!("[rules.\"{}\"]\n", escape_toml_basic_string(tk)));
        let cols = &raw.rules[tk];
        let mut col_keys: Vec<&String> = cols.keys().collect();
        col_keys.sort();
        for ck in col_keys {
            let spec = &cols[ck];
            let inline = anonymizer_spec_inline_toml(spec)?;
            out.push_str(&format!("{} = {}\n", toml_key(ck), inline));
        }
        out.push('\n');
    }
    Ok(out)
}

fn escape_toml_basic_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Double-quoted TOML key when the name is not a bare identifier.
fn toml_key(name: &str) -> String {
    let bare = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare && !name.is_empty() && name.chars().next().unwrap().is_ascii_digit() {
        return format!("\"{}\"", escape_toml_basic_string(name));
    }
    if bare {
        name.to_string()
    } else {
        format!("\"{}\"", escape_toml_basic_string(name))
    }
}

fn anonymizer_spec_inline_toml(spec: &crate::settings::AnonymizerSpec) -> anyhow::Result<String> {
    let j = serde_json::to_value(spec).context("serialize anonymizer spec")?;
    let obj = j
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("expected JSON object"))?;
    let mut pairs = Vec::new();
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    for k in keys {
        let v = &obj[k];
        if v.is_null() {
            continue;
        }
        pairs.push(format!("{} = {}", k, json_to_toml_scalar_or_string(v)?));
    }
    Ok(format!("{{{}}}", pairs.join(", ")))
}

fn json_to_toml_scalar_or_string(v: &JsonValue) -> anyhow::Result<String> {
    match v {
        JsonValue::Null => anyhow::bail!("unexpected null"),
        JsonValue::Bool(b) => Ok(if *b { "true".into() } else { "false".into() }),
        JsonValue::Number(n) => Ok(n.to_string()),
        JsonValue::String(s) => Ok(format!(
            "\"{}\"",
            s.replace('\\', "\\\\").replace('"', "\\\"")
        )),
        JsonValue::Array(_) | JsonValue::Object(_) => {
            anyhow::bail!("unexpected nested value in anonymizer spec")
        }
    }
}
