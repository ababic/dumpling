use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use clap::{ArgAction, Parser};

mod filter;
mod report;
mod settings;
mod sql;
mod transform;

use regex::Regex;
use report::Reporter;
use settings::ResolvedConfig;
use sql::SqlStreamProcessor;
use transform::{set_random_seed, AnonymizerRegistry};

#[derive(Parser, Debug)]
#[command(
    name = "dumpling",
    author,
    version,
    about = "Static anonymizer for Postgres SQL dumps produced by pg_dump (plain format)."
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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
        eprintln!("dumpling: using config source {}", path.display());
    } else if cli.allow_noop {
        eprintln!("dumpling: no config discovered; continuing because --allow-noop was set");
    }

    // Initialize deterministic seed if provided via CLI or env
    if let Some(seed) = cli.seed.or_else(|| {
        std::env::var("DUMPLING_SEED")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
    }) {
        set_random_seed(seed);
    }

    // Compile table include/exclude regex patterns
    let include_res = compile_patterns(&cli.include_table)?;
    let exclude_res = compile_patterns(&cli.exclude_table)?;

    // Determine IO
    let (mut reader, input_path_for_inplace): (Box<dyn BufRead>, Option<PathBuf>) = match &cli.input
    {
        Some(path) => {
            // Enforce extension allowlist if provided
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
            (Box::new(BufReader::new(f)), Some(path.clone()))
        }
        None => {
            if !cli.allow_ext.is_empty() {
                eprintln!("dumpling: --allow-ext provided but no --input file; extension check is ignored for stdin");
            }
            (Box::new(BufReader::new(io::stdin())), None)
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
        Box::new(BufWriter::new(File::create(&tmp)?))
    } else if let Some(path) = &cli.output {
        Box::new(BufWriter::new(File::create(path)?))
    } else {
        Box::new(BufWriter::new(io::stdout()))
    };

    // Build anonymizer registry from config
    let anonymizers = AnonymizerRegistry::from_config(&resolved_config);

    // Prepare reporter if requested
    let mut reporter = cli
        .report
        .as_ref()
        .map(|_| Reporter::new(true))
        .unwrap_or_else(|| Reporter::new(false));

    // Process SQL stream
    let mut processor = SqlStreamProcessor::new(
        anonymizers,
        resolved_config,
        include_res,
        exclude_res,
        cli.check,
        Some(&mut reporter),
    );
    let mut writer = output;
    processor.process(&mut reader, &mut writer)?;

    // If in-place, do the swap now
    if cli.in_place {
        let input_path = input_path_for_inplace.unwrap();
        let mut tmp = input_path.clone();
        tmp.set_extension("sql.dumpling.tmp");
        writer.flush()?;
        drop(writer); // close file before rename
        std::fs::rename(&tmp, &input_path)?;
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

    // In check mode, exit with code 1 if any change/drop occurred
    if cli.check {
        if reporter.report.total_cells_changed > 0 || reporter.report.total_rows_dropped > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn compile_patterns(patterns: &[String]) -> anyhow::Result<Vec<Regex>> {
    let mut out = Vec::new();
    for p in patterns {
        out.push(Regex::new(p)?);
    }
    Ok(out)
}

fn has_allowed_extension(path: &PathBuf, allow_exts: &[String]) -> bool {
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
    use super::{has_allowed_extension, Cli};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn test_allowed_extensions() {
        let p = PathBuf::from("/tmp/foo.dmp");
        assert!(has_allowed_extension(&p, &vec!["dmp".into()]));
        assert!(has_allowed_extension(&p, &vec![".dmp".into()]));
        assert!(has_allowed_extension(&p, &vec!["SQL".into(), "DMP".into()]));
        assert!(!has_allowed_extension(&p, &vec!["sql".into()]));
        assert!(has_allowed_extension(&p, &Vec::<String>::new()));
    }

    #[test]
    fn test_allow_noop_flag_parses() {
        let cli = Cli::parse_from(["dumpling", "--allow-noop"]);
        assert!(cli.allow_noop);
    }
}
