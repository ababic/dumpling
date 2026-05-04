//! Draft `[rules]` generation from column names in a SQL dump (starter / beta).

use crate::compressed_input::{resolve_compressed_wrappers, CompressionCleanup};
use crate::dump_input_detect::{
    classify_mssql_dump_file, postgres_input_needs_pg_restore, MssqlFileKind, MSSQL_BACPAC_HINT,
    MSSQL_BINARY_HINT, MSSQL_UTF16_HINT, MSSQL_WRONG_POSTGRES_ARCHIVE,
};
use crate::pg_restore_decode;
use crate::settings::{validate_raw_config, RawConfig};
use crate::sql::{
    discover_scaffold_column_rules, discover_scaffold_rules, DumpFormat, ScaffoldDiscoverOptions,
};
use anyhow::Context;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

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
    pub infer_json_paths: bool,
    pub max_json_depth: usize,
}

/// Emit header comments, stderr notice, and TOML body for a starter config.
pub fn run_scaffold_config(opts: ScaffoldConfigOptions<'_>) -> anyhow::Result<()> {
    let mut compression_cleanup = CompressionCleanup::default();
    let ScaffoldConfigOptions {
        input,
        output,
        dump_format,
        allow_ext,
        dump_decode,
        dump_decode_keep_input,
        pg_restore_path,
        dump_decode_arg,
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
            if dump_decode {
                anyhow::bail!(
                    "--dump-decode requires --input pointing at a pg_dump custom-format file or directory-format directory"
                );
            }
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
            if !allow_ext.is_empty() && !crate::has_allowed_extension(path, allow_ext) {
                anyhow::bail!("input file extension is not in allowed set {:?}", allow_ext);
            }
            if !path.exists() {
                anyhow::bail!("input path does not exist: {}", path.display());
            }

            let (inner_path, _had_wrap) = if path.is_dir() {
                (path.clone(), false)
            } else {
                let r = resolve_compressed_wrappers(path, &mut compression_cleanup)?;
                (r.path, r.had_compression_wrapper)
            };

            if inner_path.is_dir() && dump_format != crate::sql::DumpFormat::Postgres {
                anyhow::bail!(
                    "input `{}` is a directory; this dialect expects a single SQL file. \
                     For PostgreSQL directory-format dumps (folder containing `toc.dat`), use `--format postgres`.",
                    inner_path.display()
                );
            }

            if dump_format == crate::sql::DumpFormat::Sqlite
                && postgres_input_needs_pg_restore(&inner_path).map_err(|e| {
                    anyhow::anyhow!("could not inspect input `{}`: {}", inner_path.display(), e)
                })?
            {
                anyhow::bail!(
                    "input `{}` looks like a PostgreSQL custom-format or directory-format archive, not a SQLite `.dump`. \
                     Use `--format postgres` (default) so Dumpling can decode it with pg_restore.",
                    inner_path.display()
                );
            }

            if dump_format == crate::sql::DumpFormat::MsSql && inner_path.is_file() {
                match classify_mssql_dump_file(&inner_path) {
                    Ok(MssqlFileKind::PlainSqlText) => {}
                    Ok(MssqlFileKind::PostgresCustomArchiveWrongDialect) => {
                        anyhow::bail!(
                            "input `{}` is not plain SQL Server text.\n\n{}",
                            inner_path.display(),
                            MSSQL_WRONG_POSTGRES_ARCHIVE
                        );
                    }
                    Ok(MssqlFileKind::ZipArchive) => {
                        anyhow::bail!(
                            "input `{}` is not plain UTF-8 SQL text.\n\n{}",
                            inner_path.display(),
                            MSSQL_BACPAC_HINT
                        );
                    }
                    Ok(MssqlFileKind::Utf16EncodedSql) => {
                        anyhow::bail!(
                            "input `{}` is not UTF-8 plain SQL.\n\n{}",
                            inner_path.display(),
                            MSSQL_UTF16_HINT
                        );
                    }
                    Ok(MssqlFileKind::LikelyBinaryBackup) => {
                        anyhow::bail!(
                            "input `{}` does not look like UTF-8 plain SQL.\n\n{}",
                            inner_path.display(),
                            MSSQL_BINARY_HINT
                        );
                    }
                    Err(e) => {
                        anyhow::bail!("read `{}`: {}", inner_path.display(), e);
                    }
                }
            }

            let auto_pg_restore = dump_format == crate::sql::DumpFormat::Postgres
                && postgres_input_needs_pg_restore(&inner_path).map_err(|e| {
                    anyhow::anyhow!("could not inspect input `{}`: {}", inner_path.display(), e)
                })?;
            let use_pg_restore = dump_decode || auto_pg_restore;

            if use_pg_restore {
                if dump_format != crate::sql::DumpFormat::Postgres {
                    anyhow::bail!(
                        "PostgreSQL archive decoding only applies when --format postgres (default)"
                    );
                }
                if auto_pg_restore {
                    eprintln!(
                        "dumpling: detected PostgreSQL custom or directory-format archive; decoding via {} -f - {}",
                        pg_restore_path.display(),
                        inner_path.display()
                    );
                } else {
                    eprintln!(
                        "dumpling: decoding PostgreSQL archive via {} -f - {}",
                        pg_restore_path.display(),
                        inner_path.display()
                    );
                }
                let (stdout, pg) = pg_restore_decode::spawn_pg_restore_decode(
                    pg_restore_path,
                    dump_decode_arg,
                    &inner_path,
                )?;
                pg_restore_child = Some(pg);
                if !dump_decode_keep_input {
                    let tmp_root = std::env::temp_dir();
                    if !inner_path.starts_with(&tmp_root) {
                        path_to_remove_pg_archive = Some(inner_path.clone());
                    }
                }
                (
                    Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, stdout)),
                    Some(inner_path.clone()),
                )
            } else {
                let f = File::open(&inner_path)
                    .with_context(|| format!("open {}", inner_path.display()))?;
                (
                    Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, f)),
                    Some(inner_path.clone()),
                )
            }
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
        Ok(())
    })();

    let pipeline_ok = discovery_res.is_ok();
    if let Some(pg_child) = pg_restore_child {
        pg_child.finish(pipeline_ok).with_context(|| {
            format!(
                "`{}` failed while decoding the PostgreSQL archive",
                pg_restore_path.display()
            )
        })?;
    }
    if pipeline_ok {
        if let Some(ref p) = path_to_remove_pg_archive {
            match crate::remove_pg_archive(p) {
                Ok(()) => eprintln!("dumpling: removed input archive {}", p.display()),
                Err(e) => eprintln!(
                    "dumpling: warning: could not remove input archive {}: {}",
                    p.display(),
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
