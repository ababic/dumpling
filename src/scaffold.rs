//! Draft `[rules]` generation from column names in a SQL dump (starter / beta).

use crate::compressed_input::CompressionCleanup;
use crate::dump_input_resolve::{resolve_dump_input_from_path, ResolveDumpInputParams};
use crate::log_sanitize::path_basename_for_log;
use crate::pg_restore_decode;
use crate::settings::{validate_raw_config, RawConfig};
use crate::sql::{
    discover_scaffold_column_rules, discover_scaffold_rules, DumpFormat, ScaffoldDiscoverOptions,
};
use anyhow::Context;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::IO_BUF_CAPACITY;

/// CLI-backed options for [`run_scaffold_config`].
pub struct ScaffoldConfigOptions {
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub dump_format: DumpFormat,
    pub allow_ext: Vec<String>,
    pub keep_original: bool,
    pub pg_restore_path: PathBuf,
    pub pg_restore_arg: Vec<String>,
    pub infer_json_paths: bool,
    pub max_json_depth: usize,
}

/// Emit header comments, stderr notice, and TOML body for a starter config.
pub fn run_scaffold_config(opts: ScaffoldConfigOptions) -> anyhow::Result<()> {
    let mut compression_cleanup = CompressionCleanup::default();
    let ScaffoldConfigOptions {
        input,
        output,
        dump_format,
        allow_ext,
        keep_original,
        pg_restore_path,
        pg_restore_arg,
        infer_json_paths,
        max_json_depth,
    } = opts;

    eprintln!(
        "dumpling scaffold-config: beta — draft rules from column names{}; review before use. \
         Heuristics are English-oriented and miss opaque or non-English names.",
        if infer_json_paths {
            ", reservoir-sampled JSON paths (~5 rows/table)"
        } else {
            " only"
        }
    );

    let mut pg_restore_child: Option<pg_restore_decode::PgRestoreDecodeProcess> = None;
    let mut path_to_remove_pg_archive: Option<PathBuf> = None;
    let (mut reader, _input_path): (Box<dyn BufRead>, Option<PathBuf>) = match input {
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
        Some(path) => {
            if !allow_ext.is_empty() && !crate::has_allowed_extension(&path, &allow_ext) {
                anyhow::bail!("input file extension is not in allowed set {:?}", allow_ext);
            }
            let resolved = resolve_dump_input_from_path(ResolveDumpInputParams {
                user_input_path: &path,
                dump_format,
                compression_cleanup: &mut compression_cleanup,
                pg_restore_path: &pg_restore_path,
                pg_restore_arg: &pg_restore_arg,
                keep_original,
                in_place: false,
            })?;
            pg_restore_child = resolved.pg_restore_child;
            path_to_remove_pg_archive = resolved.path_to_remove_pg_archive;
            (resolved.reader, Some(path))
        }
    };

    let discovery_res = (|| -> anyhow::Result<()> {
        let rules = if !infer_json_paths {
            discover_scaffold_column_rules(&mut *reader, dump_format)
                .context("scanning dump for scaffold rules")?
        } else {
            let discover_opts = ScaffoldDiscoverOptions {
                infer_json_paths: true,
                max_json_depth,
            };
            discover_scaffold_rules(&mut *reader, dump_format, &discover_opts)
                .context("scanning dump for scaffold rules")?
        };

        if rules.is_empty() {
            eprintln!(
                "dumpling scaffold-config: warning: no rules inferred; emitted file contains header only"
            );
        } else if infer_json_paths {
            eprintln!(
                "dumpling scaffold-config: reservoir sample ({} rows max per table) for JSON path hints",
                crate::sql::SCAFFOLD_JSON_RESERVOIR_SIZE
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
            keep_original: None,
            pg_restore: crate::settings::PgRestoreRawConfig::default(),
        };
        validate_raw_config(&raw).context("internal error: scaffold rules failed validation")?;

        let body = raw_config_to_toml(&raw)?;
        let mut text = SCAFFOLD_HEADER.to_string();
        text.push_str(&body);

        if let Some(ref path) = output {
            std::fs::write(path, &text).with_context(|| format!("write {}", path.display()))?;
            eprintln!(
                "dumpling scaffold-config: wrote {}",
                path_basename_for_log(path.as_path())
            );
        } else {
            std::io::stdout().write_all(text.as_bytes())?;
        }
        Ok(())
    })();

    let pipeline_ok = discovery_res.is_ok();
    if let Some(pg_child) = pg_restore_child {
        pg_child.finish(pipeline_ok).with_context(|| {
            format!(
                "`{}` failed while decoding the PostgreSQL archive",
                path_basename_for_log(pg_restore_path.as_path())
            )
        })?;
    }
    if pipeline_ok {
        if let Some(ref p) = path_to_remove_pg_archive {
            match crate::remove_pg_archive(p) {
                Ok(()) => eprintln!(
                    "dumpling: removed input archive {}",
                    path_basename_for_log(p.as_path())
                ),
                Err(e) => eprintln!(
                    "dumpling: warning: could not remove input archive {}: {}",
                    path_basename_for_log(p.as_path()),
                    e
                ),
            }
        }
    }

    let out = discovery_res;
    drop(compression_cleanup);
    out
}

const SCAFFOLD_HEADER: &str = r#"# Dumpling starter config (beta) — generated by `dumpling scaffold-config`.
#
# Inferred [rules]: SQL column names (CREATE TABLE, INSERT, COPY) plus optional nested JSON paths
# when generated with `--infer-json-paths` (dot-separated keys: `payload.profile.email`).
# Name heuristics are English-oriented; JSON leaf inference uses segment names and light literals.
# Review every rule; add salt for hash strategies and extend row_filters / column_cases as needed.
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
