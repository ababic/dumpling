use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use std::thread::JoinHandle;
use std::time::Instant;

use clap::{ArgAction, Parser, Subcommand};

mod faker_dispatch;
mod filter;
mod lint;
mod report;
mod scaffold;
mod scan;
mod seal;
mod settings;
mod sql;
mod transform;

/// Larger than default 8 KiB to reduce syscall overhead on big dumps.
pub(crate) const IO_BUF_CAPACITY: usize = 256 * 1024;

/// Bytes queued between the transform thread and the file writer thread before backpressure applies.
const OUTPUT_PIPE_CHUNK: usize = IO_BUF_CAPACITY;
/// Number of full chunks allowed in flight (transform can run ahead of disk this far).
const OUTPUT_PIPE_DEPTH: usize = 8;

use anyhow::Context;
use report::Reporter;
use scan::{OutputScanner, ScanningWriter};
use seal::{
    compute_seal_digest, format_seal_line, read_first_line_for_seal, FirstLineReplayBufRead,
    SealFirstLine, SealRuntimeParams,
};
use settings::ResolvedConfig;
use sql::{DumpFormat, SqlStreamProcessor};
use transform::{
    prng_seed_override_for_fingerprint, set_hardened_profile, set_random_seed, AnonymizerRegistry,
    SecurityProfile,
};

#[derive(Parser, Debug)]
#[command(
    name = "dumpling",
    author,
    version,
    about = "Static anonymizer for SQL dumps. Supports PostgreSQL (pg_dump plain format), SQLite (.dump), and SQL Server (SSMS / mssql-scripter plain SQL)."
)]
struct Cli {
    /// Input SQL file path (default: stdin)
    #[arg(short = 'i', long = "input")]
    input: Option<PathBuf>,

    /// Output SQL file path (default: stdout). Use --in-place to overwrite input.
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    /// Path to configuration file (TOML). If absent, searches .dumplingconf then pyproject.toml.
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Permit running with no discoverable config (otherwise missing config is a hard error).
    #[arg(long = "allow-noop", action = ArgAction::SetTrue)]
    allow_noop: bool,

    /// Overwrite the input file in-place (mutually exclusive with --output)
    #[arg(long = "in-place", action = ArgAction::SetTrue)]
    in_place: bool,

    /// Optional deterministic seed for anonymization fuzzing (overrides env DUMPLING_SEED)
    #[arg(long = "seed")]
    seed: Option<u64>,

    /// Only check if changes would occur; do not write output. Exit code 1 if changes found.
    #[arg(long = "check", action = ArgAction::SetTrue)]
    check: bool,

    /// Print a stats summary to stderr when done.
    #[arg(long = "stats", action = ArgAction::SetTrue)]
    stats: bool,

    /// Write a detailed JSON report of changes and drops to this file.
    #[arg(long = "report")]
    report: Option<PathBuf>,

    /// Enforce explicit coverage for sensitive columns; exits non-zero when uncovered columns exist.
    #[arg(long = "strict-coverage", action = ArgAction::SetTrue)]
    strict_coverage: bool,

    /// Scan transformed output for residual PII-like patterns.
    #[arg(long = "scan-output", action = ArgAction::SetTrue)]
    scan_output: bool,

    /// Exit non-zero when output scan findings exceed configured thresholds.
    #[arg(long = "fail-on-findings", action = ArgAction::SetTrue)]
    fail_on_findings: bool,

    /// Only process input files with these extensions (repeatable), e.g. --allow-ext sql --allow-ext dmp
    /// Case-insensitive; leading dot optional. Ignored when reading from stdin.
    #[arg(long = "allow-ext")]
    allow_ext: Vec<String>,

    /// SQL dump dialect to process: postgres, sqlite, or mssql (default: postgres).
    ///
    /// - postgres: full support including COPY … FROM stdin blocks (pg_dump plain format).
    /// - sqlite: INSERT OR REPLACE / INSERT OR IGNORE variants; no COPY support.
    /// - mssql: [bracket]-quoted identifiers, N'…' Unicode literals, nvarchar/nchar lengths; no COPY support.
    #[arg(long = "format", default_value = "postgres")]
    format: String,

    /// Security profile to apply: standard (default) or hardened.
    ///
    /// - standard: xorshift64* PRNG for random strategies; SHA-256 for deterministic hashing.
    /// - hardened: OS CSPRNG for random strategies; HMAC-SHA-256 keyed by configured salt for
    ///   deterministic hashing. Recommended for adversarial risk environments.
    #[arg(long = "security-profile", default_value = "standard")]
    security_profile: String,

    /// Decode PostgreSQL custom-format or directory-format dumps via `pg_restore -f -` before anonymizing.
    /// Requires `--input` pointing at the archive file or directory and `--format postgres`. Requires a
    /// PostgreSQL client install (`pg_restore` on PATH unless overridden by `--pg-restore-path`).
    #[arg(long = "dump-decode", action = ArgAction::SetTrue)]
    dump_decode: bool,

    /// Keep the input archive after `--dump-decode` (default: delete file or directory after a fully
    /// successful run). Cannot retain the archive with `--check` (would delete before verifying changes).
    #[arg(long = "dump-decode-keep-input", action = ArgAction::SetTrue)]
    dump_decode_keep_input: bool,

    /// `pg_restore` executable to use with `--dump-decode` (default: `pg_restore` on PATH).
    #[arg(long = "pg-restore-path", default_value = "pg_restore")]
    pg_restore_path: PathBuf,

    /// Extra arguments forwarded to `pg_restore` before the archive path (repeatable). Example:
    /// `--dump-decode-arg=--no-owner` `--dump-decode-arg=--no-acl`
    #[arg(long = "dump-decode-arg")]
    dump_decode_arg: Vec<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Lint the anonymization policy config for common issues and misconfigurations.
    ///
    /// Checks performed:
    ///   empty-rules-table            — a [rules] entry has no column rules
    ///   empty-column-cases-table     — a [column_cases] entry has no column cases
    ///   unsalted-hash                — hash strategy used without any salt (reversible for low-entropy data)
    ///   inconsistent-domain-strategy — same domain used with different strategies (breaks referential integrity)
    ///   uncovered-sensitive-column   — sensitive_columns entry with no matching rule or case
    ///
    /// Exits 0 if no violations found, 1 if any violations exist.
    LintPolicy {
        /// Path to configuration file (TOML). If absent, searches .dumplingconf then pyproject.toml.
        #[arg(short = 'c', long = "config")]
        config: Option<PathBuf>,

        /// Permit running with no discoverable config (otherwise missing config is a hard error).
        #[arg(long = "allow-noop", action = ArgAction::SetTrue)]
        allow_noop: bool,
    },
    /// Emit a **draft** starter config from column names in a dump (beta). Does not read cell values;
    /// heuristics are English keyword substrings only — review and extend before use.
    ScaffoldConfig {
        /// Input SQL file path (default: stdin)
        #[arg(short = 'i', long = "input")]
        input: Option<PathBuf>,

        /// Write TOML to this file (default: stdout)
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,

        /// SQL dump dialect: postgres, sqlite, or mssql (default: postgres). COPY column lists are only read for postgres.
        #[arg(long = "format", default_value = "postgres")]
        format: String,

        /// Only read input files with these extensions (repeatable). Ignored for stdin.
        #[arg(long = "allow-ext")]
        allow_ext: Vec<String>,

        /// Decode a PostgreSQL custom- or directory-format dump via `pg_restore -f -` before scanning. Requires `--input` and `--format postgres`.
        #[arg(long = "dump-decode", action = ArgAction::SetTrue)]
        dump_decode: bool,

        /// Keep the input archive after `--dump-decode` (default: delete on success).
        #[arg(long = "dump-decode-keep-input", action = ArgAction::SetTrue)]
        dump_decode_keep_input: bool,

        /// `pg_restore` for `--dump-decode` (default: `pg_restore` on PATH).
        #[arg(long = "pg-restore-path", default_value = "pg_restore")]
        pg_restore_path: PathBuf,

        /// Extra args for `pg_restore` before the archive path (repeatable).
        #[arg(long = "dump-decode-arg")]
        dump_decode_arg: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::LintPolicy { config, allow_noop }) = cli.command {
        return run_lint_policy(config.as_ref(), allow_noop);
    }
    if let Some(Commands::ScaffoldConfig {
        input,
        output,
        format,
        allow_ext,
        dump_decode,
        dump_decode_keep_input,
        pg_restore_path,
        dump_decode_arg,
    }) = &cli.command
    {
        let dump_format = match format.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => DumpFormat::Postgres,
            "sqlite" => DumpFormat::Sqlite,
            "mssql" | "sqlserver" | "sql-server" | "tsql" => DumpFormat::MsSql,
            other => anyhow::bail!(
                "unknown --format value '{}'; expected one of: postgres, sqlite, mssql",
                other
            ),
        };
        if *dump_decode && dump_format != DumpFormat::Postgres {
            anyhow::bail!(
                "--dump-decode only applies to PostgreSQL dumps; use --format postgres (default)"
            );
        }
        return scaffold::run_scaffold_config(scaffold::ScaffoldConfigOptions {
            input: input.as_ref(),
            output: output.as_ref(),
            dump_format,
            allow_ext,
            dump_decode: *dump_decode,
            dump_decode_keep_input: *dump_decode_keep_input,
            pg_restore_path,
            dump_decode_arg,
        });
    }

    run_anonymize(cli)
}

fn run_lint_policy(config: Option<&PathBuf>, allow_noop: bool) -> anyhow::Result<()> {
    let resolved_config: ResolvedConfig = settings::load_config(config, allow_noop)?;
    if let Some(path) = resolved_config.source_path.as_ref() {
        eprintln!("dumpling: using config source {}", path.display());
    } else if allow_noop {
        eprintln!("dumpling: no config discovered; continuing because --allow-noop was set");
    }

    let violations = lint::lint_policy(&resolved_config);
    let has_errors = lint::report_violations(&violations);

    if violations.is_empty() {
        eprintln!("dumpling lint-policy: no violations found");
    } else {
        eprintln!(
            "dumpling lint-policy: {} violation(s) found ({} error(s), {} warning(s))",
            violations.len(),
            violations
                .iter()
                .filter(|v| v.severity == lint::Severity::Error)
                .count(),
            violations
                .iter()
                .filter(|v| v.severity == lint::Severity::Warning)
                .count(),
        );
    }

    if has_errors || !violations.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

/// Bounded handoff to a background thread so slow disk writes do not block dump parsing.
struct PipedFileWriter {
    sender: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    writer_thread: Option<JoinHandle<std::io::Result<()>>>,
    chunk: Vec<u8>,
}

impl PipedFileWriter {
    fn spawn(dest: File) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<Vec<u8>>(OUTPUT_PIPE_DEPTH);
        let writer_thread = std::thread::spawn(move || {
            let mut w = BufWriter::with_capacity(IO_BUF_CAPACITY, dest);
            while let Ok(buf) = rx.recv() {
                if buf.is_empty() {
                    break;
                }
                w.write_all(&buf)?;
            }
            w.flush()
        });
        Ok(Self {
            sender: Some(tx),
            writer_thread: Some(writer_thread),
            chunk: Vec::with_capacity(OUTPUT_PIPE_CHUNK),
        })
    }

    fn send_chunk(&mut self) -> std::io::Result<()> {
        if self.chunk.is_empty() {
            return Ok(());
        }
        let mut next = Vec::with_capacity(OUTPUT_PIPE_CHUNK);
        std::mem::swap(&mut self.chunk, &mut next);
        let Some(tx) = self.sender.as_ref() else {
            return Err(std::io::Error::other("output writer already finished"));
        };
        tx.send(next).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "output writer closed")
        })?;
        Ok(())
    }

    /// Flush the destination file and join the writer thread.
    fn finish(mut self) -> std::io::Result<()> {
        self.send_chunk()?;
        if let Some(tx) = self.sender.take() {
            let _ = tx.send(Vec::new());
        }
        let Some(th) = self.writer_thread.take() else {
            return Err(std::io::Error::other("output writer thread already joined"));
        };
        match th.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::other("output writer thread panicked")),
        }
    }
}

impl Write for PipedFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut off = 0;
        while off < buf.len() {
            let space = OUTPUT_PIPE_CHUNK.saturating_sub(self.chunk.len());
            if space == 0 {
                self.send_chunk()?;
                continue;
            }
            let take = (buf.len() - off).min(space);
            self.chunk.extend_from_slice(&buf[off..off + take]);
            off += take;
            if self.chunk.len() >= OUTPUT_PIPE_CHUNK {
                self.send_chunk()?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send_chunk()
    }
}

enum AnonWriter {
    Piped(PipedFileWriter),
    Stream(Box<dyn Write>),
}

impl Write for AnonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Piped(p) => p.write(buf),
            Self::Stream(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Piped(p) => p.flush(),
            Self::Stream(s) => s.flush(),
        }
    }
}

fn run_anonymize(cli: Cli) -> anyhow::Result<()> {
    if cli.in_place && cli.output.is_some() {
        anyhow::bail!("--in-place cannot be used together with --output");
    }
    if cli.check && (cli.in_place || cli.output.is_some()) {
        anyhow::bail!("--check cannot be used together with --output or --in-place");
    }
    if cli.dump_decode && !cli.dump_decode_keep_input && cli.check {
        anyhow::bail!(
            "--dump-decode removes the input archive on success by default; use --dump-decode-keep-input with --check"
        );
    }
    if cli.dump_decode && cli.in_place {
        anyhow::bail!("--dump-decode cannot be used with --in-place");
    }

    // Resolve config from provided path or discover in CWD
    let resolved_config: ResolvedConfig =
        settings::load_config(cli.config.as_ref(), cli.allow_noop)?;
    if let Some(path) = resolved_config.source_path.as_ref() {
        eprintln!("dumpling: using config source {}", path.display());
    } else if cli.allow_noop {
        eprintln!("dumpling: no config discovered; continuing because --allow-noop was set");
    }

    // Resolve and activate the security profile.
    let security_profile_name = match cli.security_profile.to_ascii_lowercase().as_str() {
        "standard" => "standard",
        "hardened" => "hardened",
        other => anyhow::bail!(
            "unknown --security-profile value '{}'; expected one of: standard, hardened",
            other
        ),
    };
    if security_profile_name == "hardened" {
        // Hardened mode requires a non-empty HMAC key (the global salt).
        // An absent or empty salt would silently degrade HMAC to a keyless construction,
        // letting anyone who knows the input values recompute the pseudonyms.
        let salt_is_empty = resolved_config
            .salt
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if salt_is_empty {
            anyhow::bail!(
                "hardened security profile requires a non-empty global salt (HMAC key); \
                 add 'salt = \"${{ENV_VAR}}\"' to your config file and set the corresponding \
                 environment variable to a strong random secret"
            );
        }
        set_hardened_profile(true);
        eprintln!("dumpling: security profile: hardened (CSPRNG + HMAC-SHA-256)");
        if cli.seed.is_some() || std::env::var("DUMPLING_SEED").ok().is_some() {
            eprintln!(
                "dumpling: warning: --seed / DUMPLING_SEED is ignored in hardened security profile"
            );
        }
    }

    // Initialize deterministic seed if provided via CLI or env
    if let Some(seed) = cli.seed.or_else(|| {
        std::env::var("DUMPLING_SEED")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
    }) {
        set_random_seed(seed);
    }

    // Parse the dump format flag
    let dump_format = match cli.format.to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" | "pg" => DumpFormat::Postgres,
        "sqlite" => DumpFormat::Sqlite,
        "mssql" | "sqlserver" | "sql-server" | "tsql" => DumpFormat::MsSql,
        other => anyhow::bail!(
            "unknown --format value '{}'; expected one of: postgres, sqlite, mssql",
            other
        ),
    };
    if cli.dump_decode && dump_format != DumpFormat::Postgres {
        anyhow::bail!(
            "--dump-decode only applies to PostgreSQL dumps; use --format postgres (default)"
        );
    }

    let seal_runtime = SealRuntimeParams::new(dump_format, prng_seed_override_for_fingerprint());

    // Determine IO (optional pg_restore child when --dump-decode)
    let mut pg_restore_child: Option<std::process::Child> = None;
    let (mut reader, input_path_for_inplace): (Box<dyn BufRead>, Option<PathBuf>) = if cli
        .dump_decode
    {
        let archive_path = cli
                .input
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "--dump-decode requires --input pointing at a pg_dump custom-format file or directory-format directory"
                    )
                })?;
        if !cli.allow_ext.is_empty() && !has_allowed_extension(archive_path, &cli.allow_ext) {
            let actual = archive_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("<none>")
                .to_string();
            anyhow::bail!(
                "input file extension '{}' is not in allowed set {:?}",
                actual,
                cli.allow_ext
            );
        }
        if !archive_path.exists() {
            anyhow::bail!(
                "--dump-decode input path does not exist: {}",
                archive_path.display()
            );
        }
        eprintln!(
            "dumpling: decoding PostgreSQL archive via {} -f - {}",
            cli.pg_restore_path.display(),
            archive_path.display()
        );
        let mut cmd = Command::new(&cli.pg_restore_path);
        for a in &cli.dump_decode_arg {
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
                cli.pg_restore_path.display()
            )
        })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("pg_restore stdout missing"))?;
        pg_restore_child = Some(child);
        (
            Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, stdout)),
            Some(archive_path.clone()),
        )
    } else {
        match &cli.input {
            Some(path) => {
                if !cli.allow_ext.is_empty() && !has_allowed_extension(path, &cli.allow_ext) {
                    let actual = path
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("<none>")
                        .to_string();
                    anyhow::bail!(
                        "input file extension '{}' is not in allowed set {:?}",
                        actual,
                        cli.allow_ext
                    );
                }
                let f = File::open(path)?;
                (
                    Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, f)),
                    Some(path.clone()),
                )
            }
            None => {
                if !cli.allow_ext.is_empty() {
                    eprintln!("dumpling: --allow-ext provided but no --input file; extension check is ignored for stdin");
                }
                (
                    Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, io::stdin())),
                    None,
                )
            }
        }
    };

    let (anon_writer, in_place_tmp_path): (AnonWriter, Option<PathBuf>) = if cli.check {
        (AnonWriter::Stream(Box::new(io::sink())), None)
    } else if cli.in_place {
        let input_path = input_path_for_inplace
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--in-place requires an --input path"))?;
        let mut tmp = input_path.clone();
        tmp.set_extension("sql.dumpling.tmp");
        let f = File::create(&tmp)?;
        (AnonWriter::Piped(PipedFileWriter::spawn(f)?), Some(tmp))
    } else if let Some(path) = &cli.output {
        let f = File::create(path)?;
        (AnonWriter::Piped(PipedFileWriter::spawn(f)?), None)
    } else {
        (
            AnonWriter::Stream(Box::new(BufWriter::new(io::stdout()))),
            None,
        )
    };

    // Build anonymizer registry from config
    let mut anonymizers = AnonymizerRegistry::from_config(&resolved_config);
    if security_profile_name == "hardened" {
        anonymizers.security_profile = SecurityProfile::Hardened;
    }

    let scan_requested = cli.scan_output || cli.fail_on_findings;
    if cli.fail_on_findings && !cli.scan_output {
        eprintln!("dumpling: --fail-on-findings implies output scanning; enabling scan");
    }
    let mut output_scanner = if scan_requested {
        Some(OutputScanner::new(resolved_config.output_scan.clone())?)
    } else {
        None
    };

    // Prepare reporter if requested
    let mut reporter = cli
        .report
        .as_ref()
        .map(|_| Reporter::new(true))
        .unwrap_or_else(|| Reporter::new(false));
    reporter.report.security_profile = security_profile_name.to_string();

    let mut processor = SqlStreamProcessor::new(
        anonymizers,
        resolved_config,
        Some(&mut reporter),
        dump_format,
    );

    let seal_digest = if cli.check {
        None
    } else {
        Some(compute_seal_digest(
            processor.config_snapshot(),
            security_profile_name,
            &seal_runtime,
        )?)
    };

    let mut writer = anon_writer;

    let seal_first = read_first_line_for_seal(
        reader.as_mut(),
        processor.config_snapshot(),
        security_profile_name,
        &seal_runtime,
    )?;

    if matches!(seal_first, SealFirstLine::TrustedPassthrough) && cli.strict_coverage {
        anyhow::bail!(
            "--strict-coverage cannot be used when the input begins with a matching seal; \
             the dump is passed through without parsing table definitions"
        );
    }

    let replay_first = match &seal_first {
        SealFirstLine::TrustedPassthrough | SealFirstLine::StaleSealStripped => None,
        SealFirstLine::Replay(v) if v.is_empty() => None,
        SealFirstLine::Replay(v) => Some(v.clone()),
    };
    let mut adapted_reader = FirstLineReplayBufRead::new(reader.as_mut(), replay_first);

    let run_started = Instant::now();
    let proc_res: anyhow::Result<()> = if matches!(seal_first, SealFirstLine::TrustedPassthrough) {
        if let Some(ref digest) = seal_digest {
            writer.write_all(format_seal_line(security_profile_name, digest).as_bytes())?;
        }
        if let Some(scanner) = output_scanner.as_mut() {
            let mut scanning_writer = ScanningWriter::new(&mut writer, scanner);
            std::io::copy(&mut adapted_reader, &mut scanning_writer)
                .map(|_| ())
                .map_err(anyhow::Error::from)
        } else {
            std::io::copy(&mut adapted_reader, &mut writer)
                .map(|_| ())
                .map_err(anyhow::Error::from)
        }
    } else {
        if let Some(ref digest) = seal_digest {
            writer.write_all(format_seal_line(security_profile_name, digest).as_bytes())?;
        }
        if let Some(scanner) = output_scanner.as_mut() {
            let mut scanning_writer = ScanningWriter::new(&mut writer, scanner);
            processor.process(&mut adapted_reader, &mut scanning_writer)
        } else {
            processor.process(&mut adapted_reader, &mut writer)
        }
    };

    if let Some(mut child) = pg_restore_child {
        if proc_res.is_err() {
            let _ = child.kill();
        }
        let status = child
            .wait()
            .with_context(|| format!("waiting for `{}`", cli.pg_restore_path.display()))?;
        if proc_res.is_ok() && !status.success() {
            anyhow::bail!(
                "`{}` exited with status {}",
                cli.pg_restore_path.display(),
                status
            );
        }
    }

    proc_res?;
    let coverage = processor.sensitive_coverage_summary();
    reporter.report.sensitive_columns_detected = coverage.detected.clone();
    reporter.report.sensitive_columns_covered = coverage.covered.clone();
    reporter.report.sensitive_columns_uncovered = coverage.uncovered.clone();
    let strict_coverage_failed = cli.strict_coverage && !coverage.uncovered.is_empty();
    let mut scan_failed = false;
    if let Some(scanner) = output_scanner.as_mut() {
        scanner.finish();
        let scan_report = scanner.build_report();
        if cli.fail_on_findings && scan_report.failed {
            scan_failed = true;
            eprintln!(
                "dumpling: output scan thresholds exceeded in categories: {}",
                scan_report.failed_categories.join(", ")
            );
        }
        reporter.report.output_scan = Some(scan_report);
    }
    if strict_coverage_failed {
        eprintln!(
            "dumpling: strict coverage failed; uncovered sensitive columns: {}",
            coverage.uncovered.join(", ")
        );
    }

    // Close the output stream (piped file writer joins its thread here).
    match writer {
        AnonWriter::Piped(p) => p.finish()?,
        AnonWriter::Stream(mut s) => {
            s.flush()?;
        }
    }

    if cli.in_place {
        let input_path = input_path_for_inplace
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--in-place requires an --input path"))?
            .clone();
        let tmp = in_place_tmp_path
            .ok_or_else(|| anyhow::anyhow!("internal error: missing in-place temp path"))?;
        if strict_coverage_failed || scan_failed {
            let _ = std::fs::remove_file(&tmp);
        } else {
            std::fs::rename(&tmp, &input_path)?;
        }
    }

    // Emit stats or report if requested
    if cli.stats {
        let elapsed_ms = run_started.elapsed().as_millis();
        let domain_hits = processor
            .anonymizers()
            .domain_cache_hits
            .load(Ordering::Relaxed);
        let domain_misses = processor
            .anonymizers()
            .domain_cache_misses
            .load(Ordering::Relaxed);
        eprintln!(
            "dumpling: rows processed={}, rows dropped={}, cells changed={}, wall_ms={}, domain_cache_hits={}, domain_cache_misses={}",
            reporter.report.total_rows_processed,
            reporter.report.total_rows_dropped,
            reporter.report.total_cells_changed,
            elapsed_ms,
            domain_hits,
            domain_misses
        );
    }
    if let Some(path) = cli.report.as_ref() {
        let json = serde_json::to_string_pretty(&reporter.report)?;
        std::fs::write(path, json)?;
    }

    if strict_coverage_failed {
        std::process::exit(2);
    }
    if scan_failed {
        std::process::exit(3);
    }

    // In check mode, exit with code 1 if any change/drop occurred
    if cli.check
        && (reporter.report.total_cells_changed > 0 || reporter.report.total_rows_dropped > 0)
    {
        std::process::exit(1);
    }

    if cli.dump_decode && !cli.dump_decode_keep_input {
        if let Some(ref p) = input_path_for_inplace {
            match remove_pg_archive(p) {
                Ok(()) => eprintln!("dumpling: removed input archive {}", p.display()),
                Err(e) => eprintln!(
                    "dumpling: warning: could not remove input archive {}: {}",
                    p.display(),
                    e
                ),
            }
        }
    }

    Ok(())
}

pub(crate) fn remove_pg_archive(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

pub(crate) fn has_allowed_extension(path: &Path, allow_exts: &[String]) -> bool {
    if allow_exts.is_empty() {
        return true;
    }
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return false,
    };
    for raw in allow_exts {
        let mut norm = raw.trim().to_ascii_lowercase();
        if let Some(stripped) = norm.strip_prefix('.') {
            norm = stripped.to_string();
        }
        if ext == norm {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests_main {
    use super::{has_allowed_extension, Cli, Commands};
    use clap::Parser;
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    fn seal_emit_then_trust_roundtrip() {
        let exe = match option_env!("CARGO_BIN_EXE_dumpling") {
            Some(p) => PathBuf::from(p),
            None => return,
        };
        let base =
            std::env::temp_dir().join(format!("dumpling_seal_integration_{}", std::process::id()));
        let conf = base.with_extension("toml");
        let pass1_in = base.with_extension("p1.sql");
        let pass1_out = base.with_extension("p2.sql");
        let pass2_out = base.with_extension("p3.sql");

        fs::write(
            &conf,
            r#"
[rules."public.users"]
email = { strategy = "email" }
"#,
        )
        .unwrap();
        fs::write(
            &pass1_in,
            "INSERT INTO public.users (email) VALUES ('alice@example.com');\n",
        )
        .unwrap();

        let s1 = Command::new(&exe)
            .args([
                "-c",
                conf.to_str().unwrap(),
                "-i",
                pass1_in.to_str().unwrap(),
                "-o",
                pass1_out.to_str().unwrap(),
                "--seed",
                "42",
            ])
            .output()
            .unwrap();
        assert!(
            s1.status.success(),
            "pass1 stderr={}",
            String::from_utf8_lossy(&s1.stderr)
        );

        let mut sealed = String::new();
        fs::File::open(&pass1_out)
            .unwrap()
            .read_to_string(&mut sealed)
            .unwrap();
        let first = sealed.lines().next().unwrap_or("");
        assert!(
            first.starts_with("-- dumpling-seal:"),
            "expected seal prefix, got: {first:?}"
        );
        assert!(
            !sealed.contains("alice@example.com"),
            "expected anonymization in pass1"
        );

        let s2 = Command::new(&exe)
            .args([
                "-c",
                conf.to_str().unwrap(),
                "-i",
                pass1_out.to_str().unwrap(),
                "-o",
                pass2_out.to_str().unwrap(),
                "--seed",
                "42",
            ])
            .output()
            .unwrap();
        assert!(
            s2.status.success(),
            "pass2 stderr={}",
            String::from_utf8_lossy(&s2.stderr)
        );

        let mut final_out = String::new();
        fs::File::open(&pass2_out)
            .unwrap()
            .read_to_string(&mut final_out)
            .unwrap();
        let rest_mid: String = sealed.lines().skip(1).collect::<Vec<_>>().join("\n");
        let rest_out: String = final_out.lines().skip(1).collect::<Vec<_>>().join("\n");
        assert_eq!(
            rest_mid, rest_out,
            "trusted pass-through should preserve dump body after seal line"
        );

        let _ = fs::remove_file(&conf);
        let _ = fs::remove_file(&pass1_in);
        let _ = fs::remove_file(&pass1_out);
        let _ = fs::remove_file(&pass2_out);
    }

    #[test]
    fn test_allowed_extensions() {
        let p = PathBuf::from("/tmp/foo.dmp");
        assert!(has_allowed_extension(&p, &["dmp".into()]));
        assert!(has_allowed_extension(&p, &[".dmp".into()]));
        assert!(has_allowed_extension(&p, &["SQL".into(), "DMP".into()]));
        assert!(!has_allowed_extension(&p, &["sql".into()]));
        assert!(has_allowed_extension(&p, &Vec::<String>::new()));
    }

    #[test]
    fn test_allow_noop_flag_parses() {
        let cli = Cli::parse_from(["dumpling", "--allow-noop"]);
        assert!(cli.allow_noop);
    }

    #[test]
    fn test_scan_flags_parse() {
        let cli = Cli::parse_from(["dumpling", "--scan-output", "--fail-on-findings"]);
        assert!(cli.scan_output);
        assert!(cli.fail_on_findings);
    }

    #[test]
    fn test_security_profile_default_is_standard() {
        let cli = Cli::parse_from(["dumpling"]);
        assert_eq!(cli.security_profile, "standard");
    }

    #[test]
    fn test_security_profile_hardened_parses() {
        let cli = Cli::parse_from(["dumpling", "--security-profile", "hardened"]);
        assert_eq!(cli.security_profile, "hardened");
    }

    #[test]
    fn test_lint_policy_subcommand_parses() {
        let cli = Cli::parse_from(["dumpling", "lint-policy"]);
        assert!(matches!(cli.command, Some(Commands::LintPolicy { .. })));
    }

    #[test]
    fn test_lint_policy_with_config_flag() {
        let cli = Cli::parse_from(["dumpling", "lint-policy", "--config", "/tmp/conf.toml"]);
        match cli.command {
            Some(Commands::LintPolicy { config, .. }) => {
                assert_eq!(config.unwrap(), PathBuf::from("/tmp/conf.toml"));
            }
            _ => panic!("expected LintPolicy subcommand"),
        }
    }

    #[test]
    fn test_dump_decode_flags_parse() {
        let cli = Cli::parse_from([
            "dumpling",
            "--dump-decode",
            "--dump-decode-keep-input",
            "--pg-restore-path",
            "/usr/bin/pg_restore",
            "--dump-decode-arg=--no-owner",
            "-i",
            "/tmp/latest.dump",
        ]);
        assert!(cli.dump_decode);
        assert!(cli.dump_decode_keep_input);
        assert_eq!(cli.pg_restore_path, PathBuf::from("/usr/bin/pg_restore"));
        assert_eq!(cli.dump_decode_arg, vec!["--no-owner"]);
    }

    #[test]
    fn test_scaffold_config_subcommand_parses() {
        let cli = Cli::parse_from([
            "dumpling",
            "scaffold-config",
            "-i",
            "/tmp/dump.sql",
            "-o",
            "/tmp/out.toml",
            "--format",
            "sqlite",
        ]);
        match cli.command {
            Some(Commands::ScaffoldConfig {
                input,
                output,
                format,
                ..
            }) => {
                assert_eq!(input.unwrap(), PathBuf::from("/tmp/dump.sql"));
                assert_eq!(output.unwrap(), PathBuf::from("/tmp/out.toml"));
                assert_eq!(format, "sqlite");
            }
            _ => panic!("expected ScaffoldConfig subcommand"),
        }
    }

    #[test]
    fn test_lint_policy_allow_noop_flag() {
        let cli = Cli::parse_from(["dumpling", "lint-policy", "--allow-noop"]);
        match cli.command {
            Some(Commands::LintPolicy { allow_noop, .. }) => {
                assert!(allow_noop);
            }
            _ => panic!("expected LintPolicy subcommand"),
        }
    }
}
