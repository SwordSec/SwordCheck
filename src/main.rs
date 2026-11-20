//! SwordCheck
//!
//! A read-only security check-up: audits local macOS security settings,
//! scores them and reports the result, and scans for known vulnerabilities,
//! malicious npm packages and stray API keys.
//!
//! Modules:
//! - `checks`  : the `Check` trait and all checks
//! - `runner`  : the layer that runs external commands (tests use a fake one)
//! - `config`  : the `audit.toml` configuration
//! - `score`   : score and grade calculation
//! - `history` : comparison with previous runs
//! - `report`  : text / JSON / Markdown / HTML output
//! - `npm`     : malicious npm package scan (`--npm`)
//! - `vulns`   : vulnerability scan of dependencies, macOS and apps (`--vulns`)
//! - `lockfiles`: lockfile parsers used by the vulnerability scan
//! - `secrets` : API key / secret scan (`--secrets`)
//! - `osv`     : OSV.dev batch queries shared by `npm` and `vulns`
//! - `net`     : HTTP through the system `curl`
//! - `envfile` : API keys from the environment or a `.env` file
//! - `tui`     : interactive dashboard

mod checks;
mod config;
mod envfile;
mod history;
mod lockfiles;
mod net;
mod npm;
mod osv;
mod progress;
mod report;
mod runner;
mod score;
mod secrets;
mod tui;
mod vulns;

use checks::{Check, CheckResult};
use clap::{ArgAction, Parser};
use colored::Colorize;
use config::Config;
use report::{Format, Report};
use runner::SystemRunner;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

/// Command-line arguments. `clap` generates the parser and the `--help`
/// output from the fields and doc comments of this struct.
#[derive(Debug, Parser)]
#[command(
    name = "swordcheck",
    version,
    about = "SwordCheck by SwordSec: a read-only security check-up. Audits macOS settings, finds known vulnerabilities, npm malware and stray API keys.",
    disable_help_flag = true,
    disable_version_flag = true,
    override_usage = "swordcheck [OPTIONS]",
    help_template = "{name} {version}\n{about}\n\nUsage: {usage}\n\nOptions:\n{options}\n{after-help}",
    after_help = "Exit code:\n  0  no failed checks and the score is above the threshold\n  1  at least one check failed or the score is below --min-score\n  2  usage or configuration error\n  3  an online lookup failed, so the scan is incomplete (--npm / --vulns with --online)\n\nThe tool never changes a setting: it shows what to fix and you apply it.\n\nConfiguration: ./audit.toml or ~/.config/swordcheck/audit.toml"
)]
struct Cli {
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Text, value_name = "FORMAT")]
    format: Format,

    /// Shortcut for `--format json`
    #[arg(long, conflicts_with = "format")]
    json: bool,

    /// Write the report to a file instead of the terminal
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Run only these checks (comma-separated ids)
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    only: Vec<String>,

    /// Skip these checks (comma-separated ids)
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    skip: Vec<String>,

    /// Exit with code 1 if the score is below this value (for CI)
    #[arg(long, value_name = "SCORE", value_parser = clap::value_parser!(u32).range(0..=100))]
    min_score: Option<u32>,

    /// Print only the score
    #[arg(short, long)]
    quiet: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Path to the configuration file
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// List the checks with their ids, weights and CIS sections
    #[arg(long)]
    list: bool,

    /// List past audits
    #[arg(long)]
    history: bool,

    /// Do not save this run to the history and do not compare against it
    #[arg(long)]
    no_history: bool,

    /// Open the interactive dashboard
    #[arg(long, conflicts_with_all = ["json", "output", "quiet", "min_score"])]
    tui: bool,

    /// Scan all npm packages (global + projects) for malware
    #[arg(long, group = "network_mode", conflicts_with_all = ["tui", "list", "history", "only", "skip", "min_score", "no_history", "config"])]
    npm: bool,

    /// With --npm: scan only this directory (repeatable)
    #[arg(long, value_name = "DIR", requires = "npm")]
    npm_path: Vec<PathBuf>,

    /// With --npm or --vulns: query online databases (sends package names and versions only)
    #[arg(long, requires = "network_mode")]
    online: bool,

    /// List known vulnerabilities in project dependencies, macOS, common apps and Homebrew formulae
    #[arg(long, group = "network_mode", conflicts_with_all = ["tui", "list", "history", "secrets", "only", "skip", "min_score", "no_history", "config"])]
    vulns: bool,

    /// With --vulns: scan only the lockfiles under this path (repeatable; skips macOS, apps and Homebrew)
    #[arg(long, value_name = "PATH", requires = "vulns")]
    vulns_path: Vec<PathBuf>,

    /// Search .env and configuration files for API keys / secrets
    #[arg(long, conflicts_with_all = ["tui", "list", "history", "npm", "only", "skip", "min_score", "no_history", "config"])]
    secrets: bool,

    /// With --secrets: scan only this directory or file (repeatable)
    #[arg(long, value_name = "PATH", requires = "secrets")]
    secrets_path: Vec<PathBuf>,

    /// Show help
    #[arg(short = 'h', long, action = ArgAction::Help)]
    help: Option<bool>,

    /// Show version
    #[arg(short = 'V', long, action = ArgAction::Version)]
    version: Option<bool>,
}

fn main() -> ExitCode {
    // On invalid arguments clap prints its own message and exits with code 2.
    let cli = Cli::parse();

    // All errors propagated with `?` inside `run` are handled here in one place.
    match run(cli) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{} {message}", "Error:".red().bold());
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    // Color codes are meaningless if the output is not going to a terminal (file, pipe).
    if cli.no_color || cli.output.is_some() || !std::io::stdout().is_terminal() {
        colored::control::set_override(false);
    }

    // The commands used are macOS-specific. `cfg!` yields true/false at compile time.
    if !cfg!(target_os = "macos") {
        return Err("This tool only runs on macOS.".to_string());
    }

    // The scan modes do not use the audit configuration or the check list.
    if cli.npm {
        return run_npm(&cli);
    }
    if cli.secrets {
        return run_secrets(&cli);
    }
    if cli.vulns {
        return run_vulns(&cli);
    }

    // A configuration picked up from the current directory can skip or
    // exempt checks, so say that it is in effect.
    if cli.config.is_none() && !cli.quiet && std::path::Path::new("audit.toml").is_file() {
        eprintln!("{} using ./audit.toml from the current directory.", "Note:".dimmed());
    }
    let config = Config::load(cli.config.as_deref())?;
    let mut checks = checks::registry();
    validate_ids(&cli, &config, &checks)?;

    if cli.list {
        print_check_list(&checks, &config);
        return Ok(ExitCode::SUCCESS);
    }

    let history_path = history::history_path();
    if cli.history {
        let path = history_path.ok_or("Could not determine the history directory (HOME is not set).")?;
        print_history(&history::load(&path)?);
        return Ok(ExitCode::SUCCESS);
    }

    // Select the checks to run: --only, --skip and the skip list in the configuration.
    checks.retain(|check| {
        let id = check.id();
        let wanted = cli.only.is_empty() || cli.only.iter().any(|only| only == id);
        let skipped = cli.skip.iter().chain(&config.skip).any(|skip| skip == id);
        wanted && !skipped
    });
    if checks.is_empty() {
        return Err("No checks left to run (review your --only / --skip selections).".to_string());
    }

    let runner = SystemRunner::new();
    let os_version = checks::os_version(&runner);

    // Without any argument, an interactive terminal gets the dashboard;
    // scripts and pipes keep getting the plain report.
    let bare = std::env::args_os().len() == 1 && std::io::stdout().is_terminal();
    if cli.tui || bare {
        if !std::io::stdout().is_terminal() {
            return Err("--tui requires an interactive terminal.".to_string());
        }
        let setup = tui::Setup {
            // Partial runs cannot be compared with a full audit.
            save_history: !cli.no_history && cli.only.is_empty() && cli.skip.is_empty(),
            check_ids: checks.iter().map(|check| check.id().to_string()).collect(),
            config,
            os_version,
        };
        tui::run(setup).map_err(|err| format!("Could not run the dashboard: {err}"))?;
        return Ok(ExitCode::SUCCESS);
    }

    let results = checks::run_checks(&checks, &runner, &config);

    // Partial runs (--only/--skip) are not written to the history: their
    // scores cannot be compared with a full audit.
    let use_history = !cli.no_history && cli.only.is_empty() && cli.skip.is_empty();
    let mut records = Vec::new();
    let mut history_file = None;
    if use_history && let Some(path) = history_path {
        match history::load(&path) {
            Ok(loaded) => {
                records = loaded;
                history_file = Some(path);
            }
            // A corrupt history must not block the audit; warn and continue without it.
            Err(err) => eprintln!("{} history unavailable: {err}", "Warning:".yellow()),
        }
    }

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let format = if cli.json { Format::Json } else { cli.format };
    let report = Report::new(timestamp.clone(), os_version.clone(), results, records.last());
    emit(&cli, &report.render(format, cli.quiet))?;

    // A run in which nothing could be evaluated has no score worth comparing.
    if let Some(path) = history_file.filter(|_| report.scorable) {
        let record = history::RunRecord::new(timestamp, os_version, report.score, &report.checks);
        if let Err(err) = history::append(&path, records, record) {
            eprintln!("{} could not save history: {err}", "Warning:".yellow());
        }
    }

    Ok(exit_code(&cli, &config, &report))
}

/// `--npm`: scans installed npm packages in detail. The exit code is 1 if a
/// confirmed malicious package was found; heuristic script warnings do not
/// affect the code. A failed `--online` lookup gives `EXIT_INCOMPLETE`.
fn run_npm(cli: &Cli) -> Result<ExitCode, String> {
    let format = text_or_json(cli, "--npm")?;

    let roots = if cli.npm_path.is_empty() {
        npm::all_roots(&SystemRunner::new())
    } else {
        let mut roots = Vec::new();
        for path in &cli.npm_path {
            if !path.is_dir() {
                return Err(format!("{} is not a directory.", path.display()));
            }
            roots.extend(npm::roots_under(path));
        }
        roots
    };

    let mut scan = npm::scan(&roots);

    // If OSV cannot be reached, the local results are still shown.
    let mut online = false;
    let mut incomplete = false;
    if cli.online {
        match npm::osv_lookup(&scan.installed) {
            Ok(hits) => {
                scan.add_osv(hits);
                online = true;
            }
            Err(err) => {
                incomplete = true;
                eprintln!("{} OSV query failed: {err}. Only the built-in list was checked.", "Warning:".yellow());
            }
        }
    }

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let report = npm::NpmReport::new(timestamp, online, scan);
    let found_malware = report.scan.malware().next().is_some();

    let rendered = match format {
        Format::Json => report.to_json(),
        _ if cli.quiet => format!(
            "{} malicious, {} suspicious",
            report.scan.malware().count(),
            report.scan.suspicious().count()
        ),
        _ => report.to_text(),
    };
    emit(cli, &rendered)?;

    Ok(match (found_malware, incomplete) {
        (true, _) => ExitCode::FAILURE,
        (false, true) => ExitCode::from(EXIT_INCOMPLETE),
        (false, false) => ExitCode::SUCCESS,
    })
}

/// `--secrets`: scans files that may hold secrets. The exit code is 1 if a
/// secret was found in a file tracked in git; ordinary secrets inside `.env`
/// do not affect the code.
fn run_secrets(cli: &Cli) -> Result<ExitCode, String> {
    let format = text_or_json(cli, "--secrets")?;

    let files = if cli.secrets_path.is_empty() {
        secrets::default_files()
    } else {
        let mut files = Vec::new();
        for path in &cli.secrets_path {
            if !path.exists() {
                return Err(format!("{} not found.", path.display()));
            }
            files.extend(secrets::files_under(path));
        }
        files
    };

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let report = secrets::SecretsReport::new(timestamp, secrets::scan(&files));
    let exposed = report.scan.tracked().next().is_some();

    let rendered = match format {
        Format::Json => report.to_json(),
        _ if cli.quiet => format!(
            "{} secrets, {} locations, {} tracked in git",
            report.scan.unique_secrets(),
            report.scan.findings.len(),
            report.scan.tracked().count()
        ),
        _ => report.to_text(),
    };
    emit(cli, &rendered)?;

    Ok(if exposed { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

/// `--vulns`: lists known vulnerabilities in project dependencies, macOS and
/// common applications. The exit code is 1 when a known-exploited
/// vulnerability (or malware) is found; other findings do not affect it.
/// A failed `--online` lookup gives `EXIT_INCOMPLETE`.
fn run_vulns(cli: &Cli) -> Result<ExitCode, String> {
    let format = text_or_json(cli, "--vulns")?;

    // An explicit path narrows the scan to those projects.
    let (paths, system) = if cli.vulns_path.is_empty() {
        (lockfiles::default_files(), vulns::system_items(&SystemRunner::new()))
    } else {
        let mut paths = Vec::new();
        for path in &cli.vulns_path {
            if !path.exists() {
                return Err(format!("{} not found.", path.display()));
            }
            let named_like_one = path.file_name().is_some_and(|name| lockfiles::is_lockfile(&name.to_string_lossy()));
            if path.is_file() && !named_like_one {
                return Err(format!("{} is not a lockfile this tool can read.", path.display()));
            }
            paths.extend(lockfiles::files_under(path));
        }
        (paths, vulns::System::default())
    };
    // Progress goes to stderr so that it never mixes with the report.
    let progress = if !cli.quiet && std::io::stderr().is_terminal() {
        progress::Progress::stderr()
    } else {
        progress::Progress::none()
    };
    let lockfiles = vulns::read_lockfiles(&paths, &progress);

    let scan = if cli.online {
        let cache = history::history_path()
            .and_then(|path| path.parent().map(|dir| dir.join("cache")))
            .ok_or("Could not determine the cache directory (HOME is not set).")?;
        let options = vulns::Online { cache, progress };
        vulns::scan(&lockfiles, system, &options)
    } else {
        vulns::offline(&lockfiles, system)
    };

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let report = vulns::VulnReport::new(timestamp, scan);
    let exploited = report.scan.exploited();

    let rendered = match format {
        Format::Json => report.to_json(),
        _ if cli.quiet => format!(
            "{} findings, {} known-exploited",
            report.scan.findings.len(),
            exploited
        ),
        _ => report.to_text(),
    };
    emit(cli, &rendered)?;

    // A failed lookup may hide an exploited vulnerability: never report success.
    Ok(match (exploited > 0, report.scan.warnings.is_empty()) {
        (true, _) => ExitCode::FAILURE,
        (false, false) => ExitCode::from(EXIT_INCOMPLETE),
        (false, true) => ExitCode::SUCCESS,
    })
}

/// Exit code for a scan whose online lookup failed: the result is incomplete,
/// so a script must not read it as "nothing found".
const EXIT_INCOMPLETE: u8 = 3;

/// The scan modes only have a text and a JSON report.
fn text_or_json(cli: &Cli, mode: &str) -> Result<Format, String> {
    match if cli.json { Format::Json } else { cli.format } {
        format @ (Format::Text | Format::Json) => Ok(format),
        _ => Err(format!("{mode} only supports the text and json formats.")),
    }
}

/// Prints the report, or writes it to the `--output` file.
fn emit(cli: &Cli, rendered: &str) -> Result<(), String> {
    match &cli.output {
        Some(path) => {
            std::fs::write(path, format!("{rendered}\n"))
                .map_err(|err| format!("Could not write {}: {err}", path.display()))?;
            if !cli.quiet {
                eprintln!("Report written: {}", path.display());
            }
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// Determines the exit code, for use in scripts and CI.
fn exit_code(cli: &Cli, config: &Config, report: &Report) -> ExitCode {
    // The threshold on the command line takes precedence over the one in the configuration.
    let min_score = cli.min_score.or(config.min_score);
    let below_threshold = min_score.is_some_and(|min| report.score < min);

    if below_threshold && !cli.quiet {
        eprintln!(
            "{} score {} is below the threshold ({}).",
            "Warning:".yellow(),
            report.score,
            min_score.unwrap_or_default()
        );
    }

    if below_threshold || report.checks.iter().any(CheckResult::is_failure) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Validates the check ids referenced on the command line and in the
/// configuration, so that a typo does not silently turn into "do nothing".
fn validate_ids(cli: &Cli, config: &Config, checks: &[Box<dyn Check>]) -> Result<(), String> {
    let known: Vec<&str> = checks.iter().map(|check| check.id()).collect();
    let referenced = cli
        .only
        .iter()
        .chain(&cli.skip)
        .map(String::as_str)
        .chain(config.referenced_ids());

    for id in referenced {
        if !known.contains(&id) {
            return Err(format!(
                "Unknown check id: `{id}`. Valid ids: {}",
                known.join(", ")
            ));
        }
    }
    Ok(())
}

/// `--list`: prints all checks as a table.
fn print_check_list(checks: &[Box<dyn Check>], config: &Config) {
    println!(
        "{}",
        format!(
            "{:<16} {:>7}  {:<8} {:<8} {:<9} {}",
            "ID", "WEIGHT", "SEVERITY", "CIS", "REMEDY", "NAME"
        )
        .bold()
    );
    for check in checks {
        let weight = config
            .weights
            .get(check.id())
            .copied()
            .unwrap_or_else(|| check.weight());
        let mut name = check.name().to_string();
        if config.skip.iter().any(|skip| skip == check.id()) {
            name.push_str(" (skipped)");
        } else if config.exceptions.contains_key(check.id()) {
            name.push_str(" (exception)");
        }
        println!(
            "{:<16} {:>7}  {:<8} {:<8} {:<9} {}",
            check.id(),
            weight,
            check.severity().label(),
            check.cis().unwrap_or("–"),
            if check.fix().is_some() { "command" } else { "settings" },
            name
        );
    }
}

/// `--history`: prints past audits from oldest to newest.
fn print_history(records: &[history::RunRecord]) {
    if records.is_empty() {
        println!("No audits recorded yet.");
        return;
    }
    println!(
        "{}",
        format!("{:<17} {:>5}  {:<5} {:<14} {}", "DATE", "SCORE", "GRADE", "SYSTEM", "ISSUES").bold()
    );
    for record in records {
        let count = |status| record.checks.values().filter(|s| **s == status).count();
        println!(
            "{:<17} {:>5}  {:<5} {:<14} {} failed, {} warned",
            report::short_time(&record.timestamp),
            record.score,
            score::grade(record.score),
            record.os_version,
            count(checks::Status::Fail),
            count(checks::Status::Warn),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("swordcheck").chain(args.iter().copied()))
    }

    #[test]
    fn clap_definition_is_consistent() {
        // Catches mistakes such as clashing short names or missing `requires` targets.
        Cli::command().debug_assert();
    }

    #[test]
    fn comma_separated_lists_are_split() {
        let cli = parse(&["--only", "filevault,sip", "--skip", "ssh"]).unwrap();
        assert_eq!(cli.only, ["filevault", "sip"]);
        assert_eq!(cli.skip, ["ssh"]);
    }

    #[test]
    fn invalid_combinations_are_rejected() {
        assert!(parse(&["--fix"]).is_err(), "the tool is read-only: there is no fix mode");
        assert!(parse(&["--min-score", "101"]).is_err());
        assert!(parse(&["--unknown"]).is_err());
        assert!(parse(&["--online"]).is_err(), "--online only with --npm or --vulns");
        assert!(parse(&["--vulns", "--online", "--vulns-path", "a"]).is_ok());
        assert!(parse(&["--vulns", "--npm"]).is_err());
        assert!(parse(&["--vulns-path", "."]).is_err(), "--vulns-path only with --vulns");
        assert!(parse(&["--npm-path", "."]).is_err());
        assert!(parse(&["--npm", "--only", "sip"]).is_err(), "audit options do not apply to the scan modes");
        assert!(parse(&["--vulns", "--min-score", "80"]).is_err());
        assert!(parse(&["--secrets", "--no-history"]).is_err());
        assert!(parse(&["--npm", "--online", "--npm-path", "a", "--npm-path", "b"]).is_ok());
        assert!(parse(&["--secrets-path", "."]).is_err(), "--secrets-path only with --secrets");
        assert!(parse(&["--secrets", "--npm"]).is_err());
        assert!(parse(&["--secrets", "--json", "--secrets-path", "a"]).is_ok());
    }

    #[test]
    fn unknown_id_is_an_error() {
        let checks = checks::registry();
        let config = Config::default();

        let cli = parse(&["--only", "filevalt"]).unwrap();
        let error = validate_ids(&cli, &config, &checks).unwrap_err();
        assert!(error.contains("filevalt"));

        let cli = parse(&["--only", "filevault"]).unwrap();
        assert!(validate_ids(&cli, &config, &checks).is_ok());

        let config = Config::parse("skip = [\"missing\"]").unwrap();
        assert!(validate_ids(&parse(&[]).unwrap(), &config, &checks).is_err());
    }
}
