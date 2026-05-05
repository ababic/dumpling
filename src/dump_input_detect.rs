//! Heuristic detection of non-plain-SQL dump inputs (archives, native backups).

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// `pg_dump -Fc` custom format files begin with this magic (see PostgreSQL `pg_backup_archiver`).
pub(crate) const PG_CUSTOM_FORMAT_MAGIC: &[u8] = b"PGDMP";

pub(crate) fn read_file_prefix(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; max];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub(crate) fn is_pg_custom_format_file(path: &Path) -> io::Result<bool> {
    let buf = read_file_prefix(path, PG_CUSTOM_FORMAT_MAGIC.len())?;
    Ok(buf.starts_with(PG_CUSTOM_FORMAT_MAGIC))
}

/// Directory-format dumps include a `toc.dat` table-of-contents file at the root.
pub(crate) fn is_pg_directory_format_dump(path: &Path) -> bool {
    path.is_dir() && path.join("toc.dat").is_file()
}

/// Custom-format file (`PGDMP` prefix) or directory dump (`toc.dat`).
pub(crate) fn postgres_input_needs_pg_restore(path: &Path) -> io::Result<bool> {
    if is_pg_directory_format_dump(path) {
        return Ok(true);
    }
    if path.is_file() {
        return is_pg_custom_format_file(path);
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MssqlFileKind {
    PlainSqlText,
    PostgresCustomArchiveWrongDialect,
    ZipArchive,
    Utf16EncodedSql,
    LikelyBinaryBackup,
}

pub(crate) fn classify_mssql_dump_file(path: &Path) -> io::Result<MssqlFileKind> {
    const SAMPLE: usize = 4096;
    let buf = read_file_prefix(path, SAMPLE)?;
    Ok(classify_mssql_prefix(&buf))
}

/// Classify the start of a UTF-8 SQL script for `--format mssql` without reading from a path.
pub(crate) fn classify_mssql_prefix(buf: &[u8]) -> MssqlFileKind {
    if buf.starts_with(PG_CUSTOM_FORMAT_MAGIC) {
        return MssqlFileKind::PostgresCustomArchiveWrongDialect;
    }
    // BACPAC / DACPAC / generic zip package
    if buf.len() >= 4 && &buf[0..4] == b"PK\x03\x04" {
        return MssqlFileKind::ZipArchive;
    }
    // UTF-16 BOM — Dumpling expects UTF-8 plain SQL.
    if buf.starts_with(&[0xFF, 0xFE]) || buf.starts_with(&[0xFE, 0xFF]) {
        return MssqlFileKind::Utf16EncodedSql;
    }
    if buf.is_empty() {
        return MssqlFileKind::PlainSqlText;
    }
    let mut nul = 0usize;
    let mut control = 0usize;
    for &b in buf {
        if b == 0 {
            nul += 1;
        }
        if b < 0x09 || (b > 0x0d && b < 0x20) {
            control += 1;
        }
    }
    let sample = buf.len();
    if nul > 0
        || (sample >= 64 && (nul * 100 / sample) >= 1)
        || (sample >= 64 && (control * 100 / sample) > 15)
    {
        return MssqlFileKind::LikelyBinaryBackup;
    }
    MssqlFileKind::PlainSqlText
}

pub(crate) const MSSQL_BACPAC_HINT: &str = "This looks like a ZIP package (for example a BACPAC/DACPAC). \
Dumpling only processes plain UTF-8 SQL text. Export scripts from SSMS, use sqlpackage to produce SQL where applicable, \
or use a tool that emits `.sql` text before running dumpling.";

pub(crate) const MSSQL_BINARY_HINT: &str = "This file does not look like UTF-8 plain SQL (many binary or NUL bytes). \
If this is a native SQL Server backup (`.bak`), a detached database (`.mdf`), or another binary format, Dumpling cannot read it. \
Restore or script the database to plain SQL (for example via SSMS Generate Scripts, sqlpackage, or mssql-scripter), then pass that `.sql` file.";

pub(crate) const MSSQL_UTF16_HINT: &str =
    "The file begins with a UTF-16 byte order mark. Dumpling expects UTF-8 plain SQL; \
re-export or convert the script to UTF-8 without BOM.";

pub(crate) const MSSQL_WRONG_POSTGRES_ARCHIVE: &str = "This file is a PostgreSQL custom-format archive (`pg_dump -Fc`), not SQL Server text. \
Use `--format postgres` (or omit `--format` — postgres is the default); Dumpling auto-detects custom-format (`PGDMP`) and directory dumps (`toc.dat`).";

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn pg_custom_magic_detected() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "dumpling_pg_magic_{}_{}.dump",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut f = File::create(&path).unwrap();
        f.write_all(PG_CUSTOM_FORMAT_MAGIC).unwrap();
        f.write_all(&[1, 2, 3]).unwrap();
        drop(f);
        assert!(is_pg_custom_format_file(&path).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mssql_classifies_zip_prefix() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "dumpling_zip_{}_{}.bacpac",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut f = File::create(&path).unwrap();
        f.write_all(b"PK\x03\x04").unwrap();
        f.write_all(b"fake zip content").unwrap();
        drop(f);
        assert_eq!(
            classify_mssql_dump_file(&path).unwrap(),
            MssqlFileKind::ZipArchive
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mssql_classifies_pg_archive_under_mssql() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "dumpling_wrong_{}_{}.dump",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut f = File::create(&path).unwrap();
        f.write_all(PG_CUSTOM_FORMAT_MAGIC).unwrap();
        drop(f);
        assert_eq!(
            classify_mssql_dump_file(&path).unwrap(),
            MssqlFileKind::PostgresCustomArchiveWrongDialect
        );
        let _ = std::fs::remove_file(&path);
    }
}
