use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};

/// Larger than default 8 KiB to reduce syscall overhead on big dumps.
const IO_BUF_CAPACITY: usize = 256 * 1024;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{ArgAction, Parser, Subcommand};

mod faker_dispatch;
mod filter;
mod lint;
mod report;
mod scan;
mod settings;
mod sql;
mod transform;

use anyhow::Context;
use regex::Regex;
use report::Reporter;
use scan::{OutputScanner, ScanningWriter};
use settings::ResolvedConfig;
use sql::{DumpFormat, SqlStreamProcessor};
use transform::{set_hardened_profile, set_random_seed, AnonymizerRegistry, SecurityProfile};

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

    /// Include only tables matching these regex patterns (repeatable). If none provided, include all.
    #[arg(long = "include-table")]
    include_table: Vec<String>,

    /// Exclude tables matching these regex patterns (repeatable).
    #[arg(long = "exclude-table")]
    exclude_table: Vec<String>,

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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::LintPolicy { config, allow_noop }) = cli.command {
        return run_lint_policy(config.as_ref(), allow_noop);
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

    // Compile table include/exclude regex patterns
    let include_res = compile_patterns(&cli.include_table)?;
    let exclude_res = compile_patterns(&cli.exclude_table)?;

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

    let output: Box<dyn Write> = if cli.check {
        Box::new(io::sink())
    } else if cli.in_place {
        // Write to a temp file first; after success, replace the input file
        let input_path = input_path_for_inplace
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--in-place requires an --input path"))?;
        let mut tmp = input_path.clone();
        tmp.set_extension("sql.dumpling.tmp");
        Box::new(BufWriter::with_capacity(
            IO_BUF_CAPACITY,
            File::create(&tmp)?,
        ))
    } else if let Some(path) = &cli.output {
        Box::new(BufWriter::with_capacity(
            IO_BUF_CAPACITY,
            File::create(path)?,
        ))
    } else {
        Box::new(BufWriter::new(io::stdout()))
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

    // Process SQL stream
    let mut processor = SqlStreamProcessor::new(
        anonymizers,
        resolved_config,
        include_res,
        exclude_res,
        Some(&mut reporter),
        dump_format,
    );
    let mut writer = output;
    let proc_res = if let Some(scanner) = output_scanner.as_mut() {
        let mut scanning_writer = ScanningWriter::new(&mut writer, scanner);
        processor.process(&mut reader, &mut scanning_writer)
    } else {
        processor.process(&mut reader, &mut writer)
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

    // If in-place, do the swap now
    if cli.in_place {
        let input_path = input_path_for_inplace
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--in-place requires an --input path"))?
            .clone();
        let mut tmp = input_path.clone();
        tmp.set_extension("sql.dumpling.tmp");
        writer.flush()?;
        drop(writer); // close file before rename
        if strict_coverage_failed || scan_failed {
            let _ = std::fs::remove_file(&tmp);
        } else {
            std::fs::rename(&tmp, &input_path)?;
        }
    } else {
        writer.flush()?;
    }

    // Emit stats or report if requested
    if cli.stats {
        eprintln!(
            "dumpling: rows processed={}, rows dropped={}, cells changed={}",
            reporter.report.total_rows_processed,
            reporter.report.total_rows_dropped,
            reporter.report.total_cells_changed
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

fn remove_pg_archive(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

fn compile_patterns(patterns: &[String]) -> anyhow::Result<Vec<Regex>> {
    let mut out = Vec::new();
    for p in patterns {
        out.push(Regex::new(p)?);
    }
    Ok(out)
}

fn has_allowed_extension(path: &Path, allow_exts: &[String]) -> bool {
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
    use std::path::PathBuf;

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
