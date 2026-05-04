//! Transparent gzip / ZIP resolution for `--input` file paths.

use crate::dump_input_detect::read_file_prefix;
use anyhow::Context;
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// Paths and directories created while resolving compressed inputs; remove after a successful run.
#[derive(Default)]
pub(crate) struct CompressionCleanup {
    paths: Vec<PathBuf>,
}

impl Drop for CompressionCleanup {
    fn drop(&mut self) {
        for p in self.paths.drain(..) {
            let _ = if p.is_dir() {
                fs::remove_dir_all(&p)
            } else {
                fs::remove_file(&p)
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

/// Decompress gzip fully to a temp file (needed so `pg_restore` can read PGDMP or we can re-sniff).
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

pub(crate) struct ResolvedInput {
    pub path: PathBuf,
    /// True if the input was gzip and/or ZIP (temporary files may exist until `cleanup` drops).
    pub had_compression_wrapper: bool,
}

/// Follow gzip and/or ZIP wrappers so downstream logic sees a concrete file or directory path.
///
/// Any temporary paths are registered on `cleanup` and deleted when `cleanup` is dropped.
pub(crate) fn resolve_compressed_wrappers(
    original: &Path,
    cleanup: &mut CompressionCleanup,
) -> anyhow::Result<ResolvedInput> {
    if !original.is_file() {
        return Ok(ResolvedInput {
            path: original.to_path_buf(),
            had_compression_wrapper: false,
        });
    }

    let mut current = original.to_path_buf();
    let mut had_wrap = false;
    let prefix = read_file_prefix(&current, 4)
        .map_err(|e| anyhow::anyhow!("read {}: {}", current.display(), e))?;

    if is_gzip_prefix(&prefix) {
        had_wrap = true;
        eprintln!(
            "dumpling: decompressing gzip input {} to a temporary file",
            original.display()
        );
        current = decompress_gzip_file(&current, cleanup)?;
    }

    let prefix = read_file_prefix(&current, 4)
        .map_err(|e| anyhow::anyhow!("read {}: {}", current.display(), e))?;
    if is_zip_prefix(&prefix) {
        had_wrap = true;
        eprintln!(
            "dumpling: extracting inner file from ZIP {} (from {})",
            current.display(),
            original.display()
        );
        current = extract_zip_inner_file(&current, cleanup)?;
    }

    Ok(ResolvedInput {
        path: current,
        had_compression_wrapper: had_wrap,
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
    fn gzip_then_plain_roundtrip_path() {
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
        let text = fs::read_to_string(&resolved.path).unwrap();
        assert_eq!(text, "SELECT 1;\n");

        drop(cleanup);
        let _ = fs::remove_file(&plain);
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
        let text = fs::read_to_string(&resolved.path).unwrap();
        assert!(text.contains("INSERT INTO"));

        drop(cleanup);
        let _ = fs::remove_file(&zip_path);
    }
}
