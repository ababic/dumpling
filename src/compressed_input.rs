//! Transparent gzip / ZIP resolution for `--input` file paths.
//!
//! When the payload is **plain SQL text**, gzip is decompressed **in-process** (streamed) so no
//! temporary file is created. When the inner payload must be **materialized** (PostgreSQL `PGDMP`
//! for `pg_restore`, nested ZIP after gzip, or any ZIP inner file — the `zip` crate needs random
//! access to the central directory), we write to the temp dir and register paths on
//! [`CompressionCleanup`] so they are always removed on drop.

use crate::dump_input_detect::{read_file_prefix, PG_CUSTOM_FORMAT_MAGIC};
use anyhow::Context;
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Cursor, Read};
use std::path::{Path, PathBuf};

use crate::log_sanitize::path_basename_for_log;
use crate::IO_BUF_CAPACITY;

/// Prefix size for gzip/ZIP sniffing (matches MSSQL sample size in `dump_input_detect`).
const SNIFF_PREFIX_LEN: usize = 4096;

/// Paths and directories created while resolving compressed inputs; remove after a successful run.
#[derive(Default)]
pub(crate) struct CompressionCleanup {
    paths: Vec<PathBuf>,
}

impl Drop for CompressionCleanup {
    fn drop(&mut self) {
        for p in self.paths.drain(..) {
            let _ = if p.is_dir() {
                fs::remove_dir_all(p)
            } else {
                fs::remove_file(p)
            };
        }
    }
}

fn is_gzip_prefix(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[0] == 0x1f && buf[1] == 0x8b
}

fn is_zip_prefix(buf: &[u8]) -> bool {
    buf.len() >= 4 && &buf[0..4] == b"PK\x03\x04"
}

fn unique_temp_file(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "dumpling_{}_{}_{}",
        label,
        std::process::id(),
        nanos
    ))
}

/// Decompress gzip fully to a temp file (`pg_restore`, nested ZIP, or chained wrappers).
fn decompress_gzip_file(src: &Path, cleanup: &mut CompressionCleanup) -> anyhow::Result<PathBuf> {
    let out = unique_temp_file("ungz");
    let mut inp = File::open(src).with_context(|| format!("open {}", src.display()))?;
    let mut dec = GzDecoder::new(&mut inp);
    let mut tmp = File::create(&out).with_context(|| format!("create {}", out.display()))?;
    std::io::copy(&mut dec, &mut tmp).with_context(|| format!("decompress {}", src.display()))?;
    cleanup.paths.push(out.clone());
    Ok(out)
}

/// Extract the sole file, or a single `.sql` when multiple entries exist, to a temp path.
fn extract_zip_inner_file(src: &Path, cleanup: &mut CompressionCleanup) -> anyhow::Result<PathBuf> {
    let file = File::open(src).with_context(|| format!("open {}", src.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).with_context(|| format!("read ZIP {}", src.display()))?;
    let mut file_indices: Vec<usize> = Vec::new();
    let mut sql_indices: Vec<usize> = Vec::new();
    for i in 0..archive.len() {
        let ent = archive.by_index(i)?;
        let name = ent.name();
        if name.ends_with('/') || name.ends_with('\\') {
            continue;
        }
        file_indices.push(i);
        if Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("sql"))
            .unwrap_or(false)
        {
            sql_indices.push(i);
        }
    }
    let idx = if file_indices.len() == 1 {
        file_indices[0]
    } else if sql_indices.len() == 1 {
        sql_indices[0]
    } else if sql_indices.len() > 1 {
        let names: Vec<String> = sql_indices
            .iter()
            .map(|&i| archive.by_index(i).map(|e| e.name().to_string()))
            .collect::<Result<_, _>>()?;
        anyhow::bail!(
            "ZIP `{}` contains multiple `.sql` files; Dumpling needs exactly one dump file. Found: {}",
            src.display(),
            names.join(", ")
        );
    } else {
        anyhow::bail!(
            "ZIP `{}` contains {} file(s); Dumpling needs exactly one file (or exactly one `.sql`). \
             Repack or extract manually.",
            src.display(),
            file_indices.len()
        );
    };

    let mut ent = archive.by_index(idx).with_context(|| "ZIP entry")?;
    let inner = Path::new(ent.name());
    let ext = inner.extension().and_then(|e| e.to_str()).unwrap_or("sql");
    let mut out = unique_temp_file("unzip");
    out.set_extension(ext);
    let mut tmp = File::create(&out).with_context(|| format!("create {}", out.display()))?;
    std::io::copy(&mut ent, &mut tmp).with_context(|| format!("extract {}", ent.name()))?;
    cleanup.paths.push(out.clone());
    Ok(out)
}

/// Result of walking gzip/ZIP wrappers on a file path.
pub(crate) enum ResolvedInput {
    /// A filesystem path to open (plain file, directory dump, or materialized inner file).
    Path {
        path: PathBuf,
        had_compression_wrapper: bool,
        /// True when Dumpling wrote this path under the temp directory (gunzip / unzip extract).
        materialized_temp_file: bool,
    },
    /// Gzip was applied and the inner payload is plain SQL: decompress in memory without a temp file.
    PlainSqlStream {
        reader: Box<dyn BufRead + Send>,
        had_compression_wrapper: bool,
        /// First bytes after gzip (used for `--format mssql` classification).
        sniff_prefix: Vec<u8>,
    },
}

const MAX_WRAP_DEPTH: u32 = 16;

/// Follow gzip and/or ZIP wrappers so downstream logic can open a path or use a stream.
///
/// Temporary paths are registered on `cleanup` and deleted when `cleanup` is dropped.
pub(crate) fn resolve_compressed_wrappers(
    original: &Path,
    cleanup: &mut CompressionCleanup,
) -> anyhow::Result<ResolvedInput> {
    resolve_compressed_wrappers_inner(original, cleanup, 0, false, false)
}

fn resolve_compressed_wrappers_inner(
    original: &Path,
    cleanup: &mut CompressionCleanup,
    depth: u32,
    materialized_temp_file: bool,
    compressed_so_far: bool,
) -> anyhow::Result<ResolvedInput> {
    if depth > MAX_WRAP_DEPTH {
        anyhow::bail!(
            "nested gzip/ZIP wrappers exceed maximum depth ({MAX_WRAP_DEPTH}); simplify the archive chain"
        );
    }

    if !original.is_file() {
        return Ok(ResolvedInput::Path {
            path: original.to_path_buf(),
            had_compression_wrapper: compressed_so_far,
            materialized_temp_file: false,
        });
    }

    let mut current = original.to_path_buf();

    let prefix = read_file_prefix(&current, 4)
        .map_err(|e| anyhow::anyhow!("read {}: {}", current.display(), e))?;

    if is_gzip_prefix(&prefix) {
        eprintln!(
            "dumpling: decompressing gzip input {} in-process (streamed when inner is plain SQL)",
            path_basename_for_log(&current)
        );
        let inp = File::open(&current).with_context(|| format!("open {}", current.display()))?;
        let mut dec = GzDecoder::new(inp);
        let mut sniff = vec![0u8; SNIFF_PREFIX_LEN];
        let n = dec
            .read(&mut sniff)
            .with_context(|| format!("read gzip stream {}", current.display()))?;
        sniff.truncate(n);

        if sniff.starts_with(PG_CUSTOM_FORMAT_MAGIC) {
            // pg_restore needs a path; materialize full decompress.
            let temp = decompress_gzip_file(&current, cleanup)?;
            return resolve_compressed_wrappers_inner(&temp, cleanup, depth + 1, true, true);
        }
        if is_zip_prefix(&sniff) {
            // Inner ZIP: materialize gunzip result then recurse (ZIP uses central directory).
            let temp = decompress_gzip_file(&current, cleanup)?;
            return resolve_compressed_wrappers_inner(&temp, cleanup, depth + 1, true, true);
        }

        // Plain SQL (or other format we read as UTF-8 bytes): chain prefix + remainder, no temp file.
        let sniff_prefix = sniff.clone();
        let chained: Box<dyn Read + Send> = Box::new(Cursor::new(sniff).chain(dec));
        let reader = Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, chained));
        return Ok(ResolvedInput::PlainSqlStream {
            reader,
            had_compression_wrapper: true,
            sniff_prefix,
        });
    }

    let prefix = read_file_prefix(&current, 4)
        .map_err(|e| anyhow::anyhow!("read {}: {}", current.display(), e))?;
    if is_zip_prefix(&prefix) {
        eprintln!(
            "dumpling: extracting inner file from ZIP {} (materialized for zip directory access)",
            path_basename_for_log(&current)
        );
        current = extract_zip_inner_file(&current, cleanup)?;
        return resolve_compressed_wrappers_inner(&current, cleanup, depth + 1, true, true);
    }

    Ok(ResolvedInput::Path {
        path: current,
        had_compression_wrapper: compressed_so_far,
        materialized_temp_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    #[test]
    fn gzip_plain_sql_streams_without_materializing_path_branch() {
        let dir = std::env::temp_dir();
        let plain = dir.join(format!("dumpling_plain_{}.sql", std::process::id()));
        fs::write(&plain, b"SELECT 1;\n").unwrap();

        let gz_path = dir.join(format!("dumpling_test_{}.sql.gz", std::process::id()));
        let raw = fs::read(&plain).unwrap();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let compressed = enc.finish().unwrap();
        fs::write(&gz_path, &compressed).unwrap();

        let mut cleanup = CompressionCleanup::default();
        let resolved = resolve_compressed_wrappers(&gz_path, &mut cleanup).unwrap();
        match resolved {
            ResolvedInput::PlainSqlStream { mut reader, .. } => {
                let mut s = String::new();
                reader.read_to_string(&mut s).unwrap();
                assert_eq!(s, "SELECT 1;\n");
            }
            ResolvedInput::Path { .. } => panic!("expected PlainSqlStream"),
        }
        assert!(cleanup.paths.is_empty());

        drop(cleanup);
        let _ = fs::remove_file(&plain);
        let _ = fs::remove_file(&gz_path);
    }

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn gzip_nested_zip_materializes_then_cleans() {
        let dir = std::env::temp_dir();
        let zip_path = dir.join(format!("dumpling_inner_{}.zip", std::process::id()));
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("dump.sql", opts).unwrap();
        zip.write_all(b"INSERT INTO t VALUES (1);\n").unwrap();
        zip.finish().unwrap();

        let gz_path = dir.join(format!("dumpling_nested_{}.gz", std::process::id()));
        let gz_inner = fs::read(&zip_path).unwrap();
        fs::write(&gz_path, gzip_bytes(&gz_inner)).unwrap();

        let mut cleanup = CompressionCleanup::default();
        let resolved = resolve_compressed_wrappers(&gz_path, &mut cleanup).unwrap();
        match resolved {
            ResolvedInput::Path { path, .. } => {
                let text = fs::read_to_string(&path).unwrap();
                assert!(text.contains("INSERT INTO"));
            }
            ResolvedInput::PlainSqlStream { .. } => panic!("expected Path after nested zip"),
        }
        assert!(
            !cleanup.paths.is_empty(),
            "nested gzip->zip should register temp paths"
        );

        drop(cleanup);
        let _ = fs::remove_file(&zip_path);
        let _ = fs::remove_file(&gz_path);
    }

    #[test]
    fn zip_single_sql_extracts() {
        let dir = std::env::temp_dir();
        let zip_path = dir.join(format!("dumpling_zipt_{}.zip", std::process::id()));
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("dump.sql", opts).unwrap();
        zip.write_all(b"INSERT INTO t VALUES (1);\n").unwrap();
        zip.finish().unwrap();

        let mut cleanup = CompressionCleanup::default();
        let resolved = resolve_compressed_wrappers(&zip_path, &mut cleanup).unwrap();
        match resolved {
            ResolvedInput::Path { path, .. } => {
                let text = fs::read_to_string(&path).unwrap();
                assert!(text.contains("INSERT INTO"));
            }
            ResolvedInput::PlainSqlStream { .. } => panic!("expected Path for zip"),
        }

        drop(cleanup);
        let _ = fs::remove_file(&zip_path);
    }
}
