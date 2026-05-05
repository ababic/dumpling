//! Shared `--input` file resolution for `run_anonymize` and `scaffold-config`.
//!
//! Keeps gzip/ZIP handling, format checks, `pg_restore`, and archive cleanup aligned between commands.

use crate::compressed_input::{resolve_compressed_wrappers, CompressionCleanup, ResolvedInput};
use crate::dump_input_detect::{
    classify_mssql_dump_file, classify_mssql_prefix, postgres_input_needs_pg_restore,
    MssqlFileKind, MSSQL_BACPAC_HINT, MSSQL_BINARY_HINT, MSSQL_UTF16_HINT,
    MSSQL_WRONG_POSTGRES_ARCHIVE,
};
use crate::log_sanitize::path_basename_for_log;
use crate::pg_restore_decode;
use crate::sql::DumpFormat;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::IO_BUF_CAPACITY;

pub(crate) struct ResolveDumpInputParams<'a> {
    pub user_input_path: &'a Path,
    pub dump_format: DumpFormat,
    pub compression_cleanup: &'a mut CompressionCleanup,
    pub pg_restore_path: &'a Path,
    pub pg_restore_arg: &'a [String],
    pub keep_original: bool,
    pub in_place: bool,
}

pub(crate) struct ResolvedDumpInput {
    pub reader: Box<dyn BufRead>,
    /// User's `--input` path (preserved for `--in-place` and logging).
    pub original_input_path: PathBuf,
    pub pg_restore_child: Option<pg_restore_decode::PgRestoreDecodeProcess>,
    pub path_to_remove_pg_archive: Option<PathBuf>,
}

pub(crate) fn resolve_dump_input_from_path(
    p: ResolveDumpInputParams<'_>,
) -> anyhow::Result<ResolvedDumpInput> {
    let ResolveDumpInputParams {
        user_input_path: path,
        dump_format,
        compression_cleanup,
        pg_restore_path,
        pg_restore_arg,
        keep_original,
        in_place,
    } = p;

    if !path.exists() {
        anyhow::bail!("input path does not exist: {}", path.display());
    }

    let resolved_input = if path.is_dir() {
        ResolvedInput::Path {
            path: path.to_path_buf(),
            had_compression_wrapper: false,
            materialized_temp_file: false,
        }
    } else {
        resolve_compressed_wrappers(path, compression_cleanup)?
    };

    let (
        inner_reader_opt,
        inner_path,
        had_compression_wrapper,
        materialized_compression_temp,
        mssql_sniff_prefix,
    ) = match resolved_input {
        ResolvedInput::Path {
            path: ip,
            had_compression_wrapper,
            materialized_temp_file,
        } => (
            None,
            ip,
            had_compression_wrapper,
            materialized_temp_file,
            None::<Vec<u8>>,
        ),
        ResolvedInput::PlainSqlStream {
            reader,
            had_compression_wrapper,
            sniff_prefix,
            ..
        } => (
            Some(reader),
            path.to_path_buf(),
            had_compression_wrapper,
            false,
            Some(sniff_prefix),
        ),
    };

    if inner_path.is_dir() && dump_format != DumpFormat::Postgres {
        anyhow::bail!(
            "input `{}` is a directory; Dumpling expects a single plain-SQL file for this `--format`. \
             For PostgreSQL directory-format dumps (folder containing `toc.dat`), use `--format postgres`.",
            inner_path.display()
        );
    }

    if dump_format == DumpFormat::Sqlite && postgres_input_needs_pg_restore(&inner_path)? {
        anyhow::bail!(
            "input `{}` looks like a PostgreSQL custom-format or directory-format archive, not a SQLite `.dump`. \
             Use `--format postgres` (default) so Dumpling can decode it with pg_restore.",
            inner_path.display()
        );
    }

    if dump_format == DumpFormat::MsSql {
        let kind = if let Some(ref pref) = mssql_sniff_prefix {
            classify_mssql_prefix(pref)
        } else if inner_path.is_file() {
            classify_mssql_dump_file(&inner_path)?
        } else {
            MssqlFileKind::PlainSqlText
        };
        match kind {
            MssqlFileKind::PlainSqlText => {}
            MssqlFileKind::PostgresCustomArchiveWrongDialect => {
                anyhow::bail!(
                    "input `{}` is not plain SQL Server text.\n\n{}",
                    inner_path.display(),
                    MSSQL_WRONG_POSTGRES_ARCHIVE
                );
            }
            MssqlFileKind::ZipArchive => {
                anyhow::bail!(
                    "input `{}` is not plain UTF-8 SQL text.\n\n{}",
                    inner_path.display(),
                    MSSQL_BACPAC_HINT
                );
            }
            MssqlFileKind::Utf16EncodedSql => {
                anyhow::bail!(
                    "input `{}` is not UTF-8 plain SQL.\n\n{}",
                    inner_path.display(),
                    MSSQL_UTF16_HINT
                );
            }
            MssqlFileKind::LikelyBinaryBackup => {
                anyhow::bail!(
                    "input `{}` does not look like UTF-8 plain SQL.\n\n{}",
                    inner_path.display(),
                    MSSQL_BINARY_HINT
                );
            }
        }
    }

    if had_compression_wrapper && in_place && materialized_compression_temp {
        anyhow::bail!(
            "this input was gzip- and/or ZIP-wrapped and Dumpling wrote a temporary decompressed file; \
             --in-place cannot safely replace the original path with anonymized SQL. Use --output (or stdout) instead"
        );
    }

    let auto_pg_restore = dump_format == DumpFormat::Postgres
        && postgres_input_needs_pg_restore(&inner_path).map_err(|e| {
            anyhow::anyhow!("could not inspect input `{}`: {}", inner_path.display(), e)
        })?;

    if auto_pg_restore && in_place {
        anyhow::bail!(
            "this input is a PostgreSQL custom-format or directory-format archive (decoded via pg_restore). \
             --in-place cannot replace the archive with plain SQL while atomically preserving the path; \
             write to --output (or stdout) instead, or decode manually with pg_restore -f -"
        );
    }

    let use_pg_restore = auto_pg_restore;

    let mut pg_restore_child = None;
    let mut path_to_remove_pg_archive = None;

    let reader: Box<dyn BufRead> = if use_pg_restore {
        if dump_format != DumpFormat::Postgres {
            anyhow::bail!(
                "PostgreSQL archive decoding only applies when --format postgres (default)"
            );
        }
        if auto_pg_restore {
            eprintln!(
                "dumpling: detected PostgreSQL custom or directory-format archive; decoding via {} -f - {} (input file)",
                path_basename_for_log(pg_restore_path),
                path_basename_for_log(&inner_path)
            );
        } else {
            eprintln!(
                "dumpling: decoding PostgreSQL archive via {} -f - {} (input file)",
                path_basename_for_log(pg_restore_path),
                path_basename_for_log(&inner_path)
            );
        }
        let (stdout, pg) = pg_restore_decode::spawn_pg_restore_decode(
            pg_restore_path,
            pg_restore_arg,
            &inner_path,
        )?;
        pg_restore_child = Some(pg);
        if !keep_original {
            let tmp_root = std::env::temp_dir();
            if !inner_path.starts_with(&tmp_root) {
                path_to_remove_pg_archive = Some(inner_path.clone());
            }
        }
        Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, stdout))
    } else if let Some(r) = inner_reader_opt {
        r
    } else {
        let f = File::open(&inner_path)?;
        Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, f))
    };

    Ok(ResolvedDumpInput {
        reader,
        original_input_path: path.to_path_buf(),
        pg_restore_child,
        path_to_remove_pg_archive,
    })
}
