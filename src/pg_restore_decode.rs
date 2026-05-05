//! Helpers for PostgreSQL custom/directory archives decoded via `pg_restore`.

use anyhow::Context;
use std::io::Write;
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread::JoinHandle;

/// Shown when `pg_restore` cannot be run or fails without stderr output.
pub(crate) const PG_RESTORE_MISSING_HINT: &str = "\
PostgreSQL client tools are required when Dumpling decodes a custom or directory-format archive. Install them (for example the \
`postgresql-client` package on Debian/Ubuntu, `postgresql` via Homebrew on macOS, or the \
official PostgreSQL installer on Windows), ensure `pg_restore` is on your PATH, or pass \
`--pg-restore-path` pointing at the `pg_restore` executable.";

/// When `--pg-restore-path` is a concrete filesystem path, verify it exists and can be executed
/// before starting a long anonymize run. A bare `pg_restore` relies on the system PATH at spawn
/// time (the same install hint is used if `spawn` fails).
pub(crate) fn ensure_pg_restore_available(pg_restore_path: &Path) -> anyhow::Result<()> {
    if pg_restore_path.as_os_str().is_empty() {
        anyhow::bail!("--pg-restore-path is empty");
    }
    if pg_restore_path == Path::new("pg_restore") {
        return Ok(());
    }
    if !pg_restore_path.exists() {
        anyhow::bail!(
            "pg_restore not found at `{}`\n\n{}",
            pg_restore_path.display(),
            PG_RESTORE_MISSING_HINT
        );
    }
    check_executable_file(pg_restore_path)?;
    Ok(())
}

#[cfg(unix)]
fn check_executable_file(path: &Path) -> anyhow::Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let meta = fs::metadata(path).with_context(|| format!("stat `{}`", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!(
            "`{}` is not a regular file\n\n{}",
            path.display(),
            PG_RESTORE_MISSING_HINT
        );
    }
    let mode = meta.permissions().mode();
    if mode & 0o111 == 0 {
        anyhow::bail!(
            "`{}` is not executable\n\n{}",
            path.display(),
            PG_RESTORE_MISSING_HINT
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_executable_file(path: &Path) -> anyhow::Result<()> {
    use std::fs;

    let meta = fs::metadata(path).with_context(|| format!("stat `{}`", path.display()))?;
    if !meta.is_file() {
        anyhow::bail!(
            "`{}` is not a file\n\n{}",
            path.display(),
            PG_RESTORE_MISSING_HINT
        );
    }
    Ok(())
}

pub(crate) struct PgRestoreDecodeProcess {
    child: Child,
    stderr_join: JoinHandle<std::io::Result<Vec<u8>>>,
    program: std::path::PathBuf,
}

/// Spawn `pg_restore -f - <archive>` with stdout/stderr piped. Stderr is collected so we can
/// attach it to failure messages; join it in [`PgRestoreDecodeProcess::finish`].
///
/// Returns stdout for piping into the anonymizer; wait with [`PgRestoreDecodeProcess::finish`].
pub(crate) fn spawn_pg_restore_decode(
    pg_restore_path: &Path,
    pg_restore_arg: &[String],
    archive_path: &Path,
) -> anyhow::Result<(ChildStdout, PgRestoreDecodeProcess)> {
    ensure_pg_restore_available(pg_restore_path)?;

    let mut cmd = Command::new(pg_restore_path);
    for a in pg_restore_arg {
        cmd.arg(a);
    }
    cmd.arg("-f")
        .arg("-")
        .arg(archive_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let program = pg_restore_path.to_path_buf();
    let mut child = cmd
        .spawn()
        .with_context(|| spawn_failed_context(&program))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("pg_restore stdout missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("pg_restore stderr missing"))?;

    let stderr_join = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let mut captured = Vec::new();
        let mut reader = BufReader::new(stderr);
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line)?;
            if n == 0 {
                break;
            }
            captured.extend_from_slice(&line);
            // Mirror pg_restore diagnostics to the user's terminal while buffering for errors.
            std::io::stderr().write_all(&line)?;
        }
        Ok(captured)
    });

    Ok((
        stdout,
        PgRestoreDecodeProcess {
            child,
            stderr_join,
            program,
        },
    ))
}

fn spawn_failed_context(program: &Path) -> String {
    format!(
        "failed to run `{}`\n\n{}",
        program.display(),
        PG_RESTORE_MISSING_HINT
    )
}

impl PgRestoreDecodeProcess {
    /// Wait for `pg_restore` after the pipeline has finished reading its stdout. If the pipeline
    /// failed, the child is killed before waiting.
    pub(crate) fn finish(mut self, pipeline_ok: bool) -> anyhow::Result<()> {
        if !pipeline_ok {
            let _ = self.child.kill();
        }
        let status = self
            .child
            .wait()
            .with_context(|| format!("waiting for `{}`", self.program.display()))?;

        let stderr_bytes = match self.stderr_join.join() {
            Ok(Ok(buf)) => buf,
            Ok(Err(e)) => {
                return Err(e).context(format!("reading `{}` stderr", self.program.display()));
            }
            Err(_) => anyhow::bail!(
                "internal error: stderr reader for `{}` panicked",
                self.program.display()
            ),
        };
        let stderr_text = String::from_utf8_lossy(&stderr_bytes);
        let stderr_trimmed = stderr_text.trim();

        if pipeline_ok && !status.success() {
            let mut msg = format!(
                "`{}` failed (exit status: {})",
                self.program.display(),
                status
            );
            if !stderr_trimmed.is_empty() {
                msg.push_str("\n\n");
                msg.push_str(stderr_trimmed);
            } else {
                msg.push_str("\n\n");
                msg.push_str(PG_RESTORE_MISSING_HINT);
            }
            anyhow::bail!(msg);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_rejects_missing_explicit_path() {
        let p = Path::new("/this/path/does/not/exist/pg_restore_dumpling_test");
        let err = ensure_pg_restore_available(p).unwrap_err();
        let s = format!("{:#}", err);
        assert!(
            s.contains("not found") || s.contains("pg_restore"),
            "unexpected message: {}",
            s
        );
        assert!(
            s.contains("PostgreSQL client") || s.contains("PATH"),
            "missing install hint: {}",
            s
        );
    }

    #[test]
    fn ensure_accepts_bare_pg_restore() {
        ensure_pg_restore_available(Path::new("pg_restore")).unwrap();
    }
}
