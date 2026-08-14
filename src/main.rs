use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use std::thread::JoinHandle;
use std::time::Instant;

use anyhow::Context;
use clap::{ArgAction, Parser, Subcommand};

mod compressed_input;
mod dump_input_detect;
mod dump_input_resolve;
mod faker_dispatch;
mod filter;
mod lint;
mod log_sanitize;
mod pg_restore_decode;
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

use compressed_input::CompressionCleanup;
use dump_input_resolve::{resolve_dump_input_from_path, ResolveDumpInputParams};
use log_sanitize::path_basename_for_log;
use report::{
    generate_run_id, run_timestamp_rfc3339, sha256_hex_of_path, OptionalHashingBufRead,
    OptionalHashingWriter, Reporter, RunFlags, RunOutcomes,
};
use scan::{OutputScanner, ScanningWriter};
use seal::{
    compute_seal_digest, format_seal_line, read_first_line_for_seal, sha256_hex_32,
    FirstLineReplayBufRead, SealFirstLine, SealRuntimeParams,
};
use settings::{merge_keep_original, ResolvedConfig};
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
    about = "Static anonymizer for SQL dumps. Supports PostgreSQL (pg_dump plain format), SQLite (.dump), and SQL Server (SSMS / mssql-scripter plain SQL).",
    after_help = "\
Examples:
  dumpling -i dump.sql -o sanitized.sql
  dumpling --report report.json -i dump.sql -o sanitized.sql
  cat dump.sql | dumpling --no-seal --report report.json > sanitized.sql
  dumpling --check --strict-coverage --report coverage.json -i dump.sql
"
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

    /// Write a JSON audit sidecar to this file (provenance, checksums, coverage, change events).
    ///
    /// Always includes Dumpling version, run id/timestamp, config path + SHA-256, streaming
    /// input/output SHA-256, `seal_sha256` (same digest as a dump-seal `sha256=` field), gate
    /// flags, and coverage/scan outcomes. `output_sha256` is omitted in `--check`. Pair with
    /// `--no-seal` when the SQL stream should not carry a dump-seal comment.
    ///
    /// Example: `dumpling --report report.json -i dump.sql -o sanitized.sql`
    #[arg(long = "report")]
    report: Option<PathBuf>,

    /// Do not prefix output with a dump-seal SQL comment.
    ///
    /// Incoming seal lines are still recognized (a matching seal passes the body through; a stale
    /// seal is stripped and the dump is re-processed). `--report` still records `seal_sha256`.
    ///
    /// Example: `cat dump.sql | dumpling --no-seal --report report.json > sanitized.sql`
    #[arg(long = "no-seal", action = ArgAction::SetTrue)]
    no_seal: bool,

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

    /// Keep original PostgreSQL archive inputs after decode (ignored with `--check`; incompatible with `--in-place`).
    /// Also set `keep_original = true` in `.dumplingconf`.
    #[arg(long = "keep-original", action = ArgAction::SetTrue)]
    keep_original: bool,

    /// `pg_restore` executable (optional; default: `pg_restore` on PATH or `[pg_restore] path` in config).
    #[arg(long = "pg-restore-path")]
    pg_restore_path: Option<PathBuf>,

    /// Extra arguments forwarded to `pg_restore` before the archive path (repeatable). Example:
    /// `--pg-restore-arg=--no-owner` `--pg-restore-arg=--no-acl`
    #[arg(long = "pg-restore-arg")]
    pg_restore_arg: Vec<String>,

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
    /// Emit a **draft** starter config from a dump (beta). Infers `[rules]` from column names; optional
    /// `--sample-rows` reads data rows to suggest nested JSON path rules. English-oriented heuristics.
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

        /// Keep original inputs (see main `dumpling --keep-original`).
        #[arg(long = "keep-original", action = ArgAction::SetTrue)]
        keep_original: bool,

        /// `pg_restore` for custom- or directory-format archives (optional; see main `dumpling` help).
        #[arg(long = "pg-restore-path")]
        pg_restore_path: Option<PathBuf>,

        /// Extra args for `pg_restore` before the archive path (repeatable).
        #[arg(long = "pg-restore-arg")]
        pg_restore_arg: Vec<String>,

        /// Sample JSON path hints: keep 5 rows per table (reservoir) from INSERT/COPY and infer nested `column.path` rules.
        #[arg(long = "infer-json-paths", action = ArgAction::SetTrue)]
        infer_json_paths: bool,

        /// Max JSON nesting depth when using `--infer-json-paths`.
        #[arg(long = "max-json-depth", default_value_t = 24)]
        max_json_depth: usize,
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
        keep_original,
        pg_restore_path,
        pg_restore_arg,
        infer_json_paths,
        max_json_depth,
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
        let resolved_for_pg = settings::load_config(cli.config.as_ref(), true).with_context(|| {
            "loading config for scaffold-config (pg_restore / keep-original merge only; use -c if an explicit file fails to load)"
        })?;
        if cli.config.is_none() && resolved_for_pg.source_path.is_none() {
            eprintln!(
                "dumpling scaffold-config: note: no Dumpling config found in the current directory; \
                 using defaults for pg_restore and keep-original hints"
            );
        }
        let (pg_restore_path_eff, pg_restore_arg_eff) = settings::merge_pg_restore_cli(
            &resolved_for_pg.pg_restore,
            pg_restore_path.clone(),
            pg_restore_arg.as_slice(),
        );
        let keep_original_eff = merge_keep_original(*keep_original, resolved_for_pg.keep_original);
        return scaffold::run_scaffold_config(scaffold::ScaffoldConfigOptions {
            input: input.clone(),
            output: output.clone(),
            dump_format,
            allow_ext: allow_ext.clone(),
            keep_original: keep_original_eff,
            pg_restore_path: pg_restore_path_eff,
            pg_restore_arg: pg_restore_arg_eff,
            infer_json_paths: *infer_json_paths,
            max_json_depth: *max_json_depth,
        });
    }

    run_anonymize(cli)
}

fn run_lint_policy(config: Option<&PathBuf>, allow_noop: bool) -> anyhow::Result<()> {
    let resolved_config: ResolvedConfig = settings::load_config(config, allow_noop)?;
    if let Some(path) = resolved_config.source_path.as_ref() {
        eprintln!(
            "dumpling: using config source {}",
            path_basename_for_log(path.as_path())
        );
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
    let mut compression_cleanup = CompressionCleanup::default();
    if cli.in_place && cli.output.is_some() {
        anyhow::bail!("--in-place cannot be used together with --output");
    }
    if cli.check && (cli.in_place || cli.output.is_some()) {
        anyhow::bail!("--check cannot be used together with --output or --in-place");
    }

    // Resolve config from provided path or discover in CWD
    let resolved_config: ResolvedConfig =
        settings::load_config(cli.config.as_ref(), cli.allow_noop)?;
    if let Some(path) = resolved_config.source_path.as_ref() {
        eprintln!(
            "dumpling: using config source {}",
            path_basename_for_log(path.as_path())
        );
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

    let seal_runtime = SealRuntimeParams::new(dump_format, prng_seed_override_for_fingerprint());

    let (pg_restore_path_eff, pg_restore_arg_eff) = settings::merge_pg_restore_cli(
        &resolved_config.pg_restore,
        cli.pg_restore_path.clone(),
        &cli.pg_restore_arg,
    );
    let keep_original_eff = merge_keep_original(cli.keep_original, resolved_config.keep_original);

    if cli.in_place && keep_original_eff {
        anyhow::bail!(
            "`--keep-original` (or `keep_original = true` in config) cannot be used with `--in-place`; \
             keeping the original path while overwriting it in place is ambiguous. Use `--output` (or stdout) instead, \
             or omit `--keep-original` for in-place overwrite."
        );
    }

    if !keep_original_eff && cli.check {
        anyhow::bail!(
            "PostgreSQL archive decoding removes the `--input` archive on success by default; use `--keep-original` or `keep_original = true` in config with --check"
        );
    }

    // Determine IO (optional pg_restore child for PostgreSQL custom/directory archives)
    let mut pg_restore_child: Option<pg_restore_decode::PgRestoreDecodeProcess> = None;
    let mut path_to_remove_pg_archive: Option<PathBuf> = None;
    let (reader, input_path_for_inplace): (Box<dyn BufRead>, Option<PathBuf>) = match &cli.input {
        None => {
            if !cli.allow_ext.is_empty() {
                eprintln!("dumpling: --allow-ext provided but no --input file; extension check is ignored for stdin");
            }
            (
                Box::new(BufReader::with_capacity(IO_BUF_CAPACITY, io::stdin())),
                None,
            )
        }
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
            let resolved = resolve_dump_input_from_path(ResolveDumpInputParams {
                user_input_path: path,
                dump_format,
                compression_cleanup: &mut compression_cleanup,
                pg_restore_path: &pg_restore_path_eff,
                pg_restore_arg: &pg_restore_arg_eff,
                keep_original: keep_original_eff,
                in_place: cli.in_place,
            })?;
            pg_restore_child = resolved.pg_restore_child;
            path_to_remove_pg_archive = resolved.path_to_remove_pg_archive;
            (resolved.reader, Some(resolved.original_input_path))
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
    let report_requested = cli.report.is_some();
    let (config_source, config_sha256) = if report_requested {
        match resolved_config.source_path.as_ref() {
            Some(p) => (
                Some(p.to_string_lossy().into_owned()),
                Some(sha256_hex_of_path(p)?),
            ),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    let mut reporter = if report_requested {
        Reporter::new(true)
    } else {
        Reporter::new(false)
    };
    reporter.report.security_profile = security_profile_name.to_string();
    if report_requested {
        reporter.report.dumpling_version = env!("CARGO_PKG_VERSION").to_string();
        reporter.report.run_id = generate_run_id();
        reporter.report.started_at = run_timestamp_rfc3339();
        reporter.report.config_source = config_source;
        reporter.report.config_sha256 = config_sha256;
        reporter.report.flags = RunFlags {
            check: cli.check,
            strict_coverage: cli.strict_coverage,
            scan_output: scan_requested,
            fail_on_findings: cli.fail_on_findings,
            allow_noop: cli.allow_noop,
            in_place: cli.in_place,
            no_seal: cli.no_seal,
            format: match dump_format {
                DumpFormat::Postgres => "postgres",
                DumpFormat::Sqlite => "sqlite",
                DumpFormat::MsSql => "mssql",
            }
            .to_string(),
        };
    }

    let mut processor = SqlStreamProcessor::new(
        anonymizers,
        resolved_config,
        Some(&mut reporter),
        dump_format,
    );

    let seal_digest_bytes = compute_seal_digest(
        processor.config_snapshot(),
        security_profile_name,
        &seal_runtime,
    )?;
    if report_requested {
        reporter.report.seal_sha256 = Some(sha256_hex_32(&seal_digest_bytes));
    }
    let write_seal = !cli.check && !cli.no_seal;

    let mut hashing_reader = OptionalHashingBufRead::new(reader, report_requested);
    let mut hashing_writer =
        OptionalHashingWriter::new(anon_writer, report_requested && !cli.check);

    let seal_first = read_first_line_for_seal(
        &mut hashing_reader,
        processor.config_snapshot(),
        security_profile_name,
        &seal_runtime,
    )?;
    let trusted_passthrough = matches!(seal_first, SealFirstLine::TrustedPassthrough);

    if trusted_passthrough && cli.strict_coverage {
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

    let run_started = Instant::now();
    let proc_res: anyhow::Result<()> = {
        let mut adapted_reader = FirstLineReplayBufRead::new(&mut hashing_reader, replay_first);
        if write_seal {
            hashing_writer.write_all(
                format_seal_line(security_profile_name, &seal_digest_bytes).as_bytes(),
            )?;
        }
        if trusted_passthrough {
            if let Some(scanner) = output_scanner.as_mut() {
                let mut scanning_writer = ScanningWriter::new(&mut hashing_writer, scanner);
                std::io::copy(&mut adapted_reader, &mut scanning_writer)
                    .map(|_| ())
                    .map_err(anyhow::Error::from)
            } else {
                std::io::copy(&mut adapted_reader, &mut hashing_writer)
                    .map(|_| ())
                    .map_err(anyhow::Error::from)
            }
        } else if let Some(scanner) = output_scanner.as_mut() {
            let mut scanning_writer = ScanningWriter::new(&mut hashing_writer, scanner);
            processor.process(&mut adapted_reader, &mut scanning_writer)
        } else {
            processor.process(&mut adapted_reader, &mut hashing_writer)
        }
    };

    if let Some(pg_child) = pg_restore_child {
        pg_child.finish(proc_res.is_ok())?;
    }

    proc_res?;
    if let Some(digest) = hashing_reader.finalize() {
        reporter.report.input_sha256 = Some(sha256_hex_32(&digest));
    }
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
    if report_requested {
        reporter.report.outcomes = RunOutcomes {
            strict_coverage_passed: cli.strict_coverage.then_some(!strict_coverage_failed),
            output_scan_passed: reporter
                .report
                .output_scan
                .as_ref()
                .map(|scan| !scan.failed),
            trusted_passthrough,
        };
    }
    if strict_coverage_failed {
        eprintln!(
            "dumpling: strict coverage failed; uncovered sensitive columns: {}",
            coverage.uncovered.join(", ")
        );
    }

    let (writer, output_digest) = hashing_writer.finish();
    if report_requested && !cli.check {
        if let Some(digest) = output_digest {
            reporter.report.output_sha256 = Some(sha256_hex_32(&digest));
        }
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
        drop(compression_cleanup);
        std::process::exit(2);
    }
    if scan_failed {
        drop(compression_cleanup);
        std::process::exit(3);
    }

    // In check mode, exit with code 1 if any change/drop occurred
    if cli.check
        && (reporter.report.total_cells_changed > 0 || reporter.report.total_rows_dropped > 0)
    {
        drop(compression_cleanup);
        std::process::exit(1);
    }

    if let Some(ref p) = path_to_remove_pg_archive {
        match remove_pg_archive(p) {
            Ok(()) => eprintln!(
                "dumpling: removed input archive {}",
                path_basename_for_log(p)
            ),
            Err(e) => eprintln!(
                "dumpling: warning: could not remove input archive {}: {}",
                path_basename_for_log(p),
                e
            ),
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
    use clap::{CommandFactory, Parser};
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

    fn sha256_file(path: &std::path::Path) -> String {
        crate::report::sha256_hex(&fs::read(path).unwrap())
    }

    #[test]
    fn report_audit_sidecar_checksums_and_seal_cross_link() {
        let exe = match option_env!("CARGO_BIN_EXE_dumpling") {
            Some(p) => PathBuf::from(p),
            None => return,
        };
        let base =
            std::env::temp_dir().join(format!("dumpling_audit_report_{}", std::process::id()));
        let conf = base.with_extension("toml");
        let input = base.with_extension("in.sql");
        let out1 = base.with_extension("out1.sql");
        let out2 = base.with_extension("out2.sql");
        let report1 = base.with_extension("r1.json");
        let report2 = base.with_extension("r2.json");
        let check_report = base.with_extension("check.json");

        let conf_body = r#"
[rules."public.users"]
email = { strategy = "email" }

[sensitive_columns]
"public.users" = ["email"]
"#;
        fs::write(&conf, conf_body).unwrap();
        fs::write(
            &input,
            "INSERT INTO public.users (email) VALUES ('alice@example.com');\n",
        )
        .unwrap();

        let run = |output: &std::path::Path, report: &std::path::Path| {
            Command::new(&exe)
                .args([
                    "-c",
                    conf.to_str().unwrap(),
                    "-i",
                    input.to_str().unwrap(),
                    "-o",
                    output.to_str().unwrap(),
                    "--report",
                    report.to_str().unwrap(),
                    "--strict-coverage",
                    "--seed",
                    "42",
                ])
                .output()
                .unwrap()
        };

        let s1 = run(&out1, &report1);
        assert!(
            s1.status.success(),
            "run1 stderr={}",
            String::from_utf8_lossy(&s1.stderr)
        );
        let s2 = run(&out2, &report2);
        assert!(
            s2.status.success(),
            "run2 stderr={}",
            String::from_utf8_lossy(&s2.stderr)
        );

        let v1: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&report1).unwrap()).unwrap();
        let v2: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&report2).unwrap()).unwrap();

        assert_eq!(v1["dumpling_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v1["security_profile"], "standard");
        assert_eq!(v1["flags"]["check"], false);
        assert_eq!(v1["flags"]["strict_coverage"], true);
        assert_eq!(v1["flags"]["scan_output"], false);
        assert_eq!(v1["flags"]["no_seal"], false);
        assert_eq!(v1["flags"]["format"], "postgres");
        assert_eq!(v1["outcomes"]["strict_coverage_passed"], true);
        assert_eq!(v1["outcomes"]["trusted_passthrough"], false);
        assert!(v1["outcomes"].get("output_scan_passed").is_none());

        let config_source = v1["config_source"].as_str().unwrap();
        assert!(
            config_source.ends_with(conf.file_name().unwrap().to_str().unwrap()),
            "config_source={config_source}"
        );
        assert_eq!(v1["config_sha256"], sha256_file(&conf));
        assert_eq!(v1["input_sha256"], sha256_file(&input));
        assert_eq!(v1["output_sha256"], sha256_file(&out1));

        let mut sealed = String::new();
        fs::File::open(&out1)
            .unwrap()
            .read_to_string(&mut sealed)
            .unwrap();
        let seal_hex = sealed
            .lines()
            .next()
            .unwrap()
            .split("sha256=")
            .nth(1)
            .unwrap()
            .trim();
        assert_eq!(v1["seal_sha256"], seal_hex);

        assert_eq!(v1["seal_sha256"], v2["seal_sha256"]);
        assert_eq!(v1["config_sha256"], v2["config_sha256"]);
        assert_eq!(v1["input_sha256"], v2["input_sha256"]);
        assert_eq!(v1["output_sha256"], v2["output_sha256"]);
        assert_eq!(v1["dumpling_version"], v2["dumpling_version"]);
        assert_ne!(v1["run_id"], v2["run_id"]);
        assert!(!v1["run_id"].as_str().unwrap().is_empty());
        assert!(v1["started_at"].as_str().unwrap().ends_with('Z'));

        let check = Command::new(&exe)
            .args([
                "-c",
                conf.to_str().unwrap(),
                "-i",
                input.to_str().unwrap(),
                "--check",
                "--keep-original",
                "--report",
                check_report.to_str().unwrap(),
                "--seed",
                "42",
            ])
            .output()
            .unwrap();
        // --check exits 1 when cells change
        assert_eq!(
            check.status.code(),
            Some(1),
            "check stderr={}",
            String::from_utf8_lossy(&check.stderr)
        );
        let vc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&check_report).unwrap()).unwrap();
        assert_eq!(vc["flags"]["check"], true);
        assert!(vc.get("output_sha256").is_none());
        assert_eq!(vc["seal_sha256"], v1["seal_sha256"]);
        assert_eq!(vc["input_sha256"], v1["input_sha256"]);

        let _ = fs::remove_file(&conf);
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&out1);
        let _ = fs::remove_file(&out2);
        let _ = fs::remove_file(&report1);
        let _ = fs::remove_file(&report2);
        let _ = fs::remove_file(&check_report);
    }

    #[test]
    fn no_seal_omits_dump_seal_comment_but_report_keeps_digest() {
        let exe = match option_env!("CARGO_BIN_EXE_dumpling") {
            Some(p) => PathBuf::from(p),
            None => return,
        };
        let base = std::env::temp_dir().join(format!("dumpling_no_seal_{}", std::process::id()));
        let conf = base.with_extension("toml");
        let input = base.with_extension("in.sql");
        let output = base.with_extension("out.sql");
        let report = base.with_extension("json");

        fs::write(
            &conf,
            r#"
[rules."public.users"]
email = { strategy = "email" }
"#,
        )
        .unwrap();
        fs::write(
            &input,
            "INSERT INTO public.users (email) VALUES ('alice@example.com');\n",
        )
        .unwrap();

        let run = Command::new(&exe)
            .args([
                "-c",
                conf.to_str().unwrap(),
                "-i",
                input.to_str().unwrap(),
                "-o",
                output.to_str().unwrap(),
                "--report",
                report.to_str().unwrap(),
                "--no-seal",
                "--seed",
                "42",
            ])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&run.stderr)
        );

        let out = fs::read_to_string(&output).unwrap();
        assert!(
            !out.contains("-- dumpling-seal:"),
            "expected no seal comment, got: {out:?}"
        );
        assert!(
            !out.contains("alice@example.com"),
            "expected anonymization without a seal prefix"
        );
        assert!(
            out.contains("INSERT INTO public.users"),
            "expected transformed SQL body"
        );

        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
        assert_eq!(v["flags"]["no_seal"], true);
        let digest = v["seal_sha256"].as_str().expect("seal_sha256");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(v["output_sha256"], sha256_file(&output));

        let _ = fs::remove_file(&conf);
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&report);
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
    fn test_no_seal_flag_parses() {
        let cli = Cli::parse_from(["dumpling", "--no-seal"]);
        assert!(cli.no_seal);
        let default = Cli::parse_from(["dumpling"]);
        assert!(!default.no_seal);
    }

    #[test]
    fn test_help_documents_report_no_seal_and_examples() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf).unwrap();
        let help = String::from_utf8(buf).unwrap();
        assert!(
            help.contains("Examples:"),
            "expected Examples section in --help"
        );
        assert!(help.contains("--no-seal"), "expected --no-seal in --help");
        assert!(
            help.contains("audit sidecar") || help.contains("--report"),
            "expected --report documented in --help"
        );
        assert!(
            help.contains("cat dump.sql | dumpling --no-seal"),
            "expected streaming --no-seal example in --help"
        );
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
    fn test_pg_restore_flags_parse() {
        let cli = Cli::parse_from([
            "dumpling",
            "--keep-original",
            "--pg-restore-path",
            "/usr/bin/pg_restore",
            "--pg-restore-arg=--no-owner",
            "-i",
            "/tmp/latest.dump",
        ]);
        assert!(cli.keep_original);
        assert_eq!(
            cli.pg_restore_path,
            Some(PathBuf::from("/usr/bin/pg_restore"))
        );
        assert_eq!(cli.pg_restore_arg, vec!["--no-owner"]);
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
    fn test_scaffold_config_infer_json_paths_parses() {
        let cli = Cli::parse_from([
            "dumpling",
            "scaffold-config",
            "--infer-json-paths",
            "--max-json-depth",
            "16",
        ]);
        match cli.command {
            Some(Commands::ScaffoldConfig {
                infer_json_paths,
                max_json_depth,
                ..
            }) => {
                assert!(infer_json_paths);
                assert_eq!(max_json_depth, 16);
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
