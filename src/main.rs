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
//! - `full_report`: one HTML page with every module (`--report`)
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
mod full_report;
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
use clap::{ArgAction, ArgGroup, Parser};
use colored::Colorize;
use config::Config;
use report::{Format, Report};
use runner::SystemRunner;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};
use std::path::{Path, PathBuf};
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
    after_help = "Exit code:\n  0  no failed checks and the score is above the threshold\n  1  at least one check failed or the score is below --min-score\n     (--report: also malware, a known-exploited vulnerability or a secret in a git-tracked file)\n  2  usage or configuration error\n  3  the scan is incomplete: an online lookup failed (--npm / --vulns / --report with --online),\n     a lockfile could not be read (--vulns / --report), or git could not tell whether\n     a file with a secret is tracked (--secrets / --report)\n\nThe tool never changes a setting: it shows what to fix and you apply it.\n\nConfiguration: ./audit.toml or ~/.config/swordcheck/audit.toml"
,
    // The path options of a scan also narrow that scan inside `--report`.
    group(ArgGroup::new("npm_scope").args(["npm", "report"])),
    group(ArgGroup::new("vulns_scope").args(["vulns", "report"])),
    group(ArgGroup::new("secrets_scope").args(["secrets", "report"]))
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

    /// With --npm or --report: scan only this directory (repeatable)
    #[arg(long, value_name = "DIR", requires = "npm_scope")]
    npm_path: Vec<PathBuf>,

    /// With --npm, --vulns or --report: query online databases (sends package names and versions only)
    #[arg(long, requires = "network_mode")]
    online: bool,

    /// List known vulnerabilities in project dependencies, macOS, common apps and Homebrew formulae
    #[arg(long, group = "network_mode", conflicts_with_all = ["tui", "list", "history", "secrets", "only", "skip", "min_score", "no_history", "config"])]
    vulns: bool,

    /// With --vulns or --report: scan only the lockfiles under this path (repeatable; skips macOS, apps and Homebrew)
    #[arg(long, value_name = "PATH", requires = "vulns_scope")]
    vulns_path: Vec<PathBuf>,

    /// Search .env and configuration files for API keys / secrets
    #[arg(long, conflicts_with_all = ["tui", "list", "history", "npm", "only", "skip", "min_score", "no_history", "config"])]
    secrets: bool,

    /// With --secrets or --report: scan only this directory or file (repeatable)
    #[arg(long, value_name = "PATH", requires = "secrets_scope")]
    secrets_path: Vec<PathBuf>,

    /// Run the audit and every scan, and write one HTML report to this file
    #[arg(long, value_name = "FILE", group = "network_mode", conflicts_with_all = ["tui", "list", "history", "npm", "vulns", "secrets", "format", "json", "output", "quiet"])]
    report: Option<PathBuf>,

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
            note(format_args!("{} {message}", "Error:".red().bold()));
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

    // A file that cannot be written fails now, not after a long scan.
    if let Some(path) = cli.report.as_ref().or(cli.output.as_ref()) {
        check_output(path)?;
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
        note(format_args!(
            "{} using ./audit.toml from the current directory.",
            "Note:".dimmed()
        ));
    }
    let config = Config::load(cli.config.as_deref())?;
    let mut checks = checks::registry();
    validate_ids(&cli, &config, &checks)?;

    if cli.list {
        out(check_list(&checks, &config).trim_end())?;
        return Ok(ExitCode::SUCCESS);
    }

    let history_path = history::history_path();
    if cli.history {
        let path = history_path.ok_or("Could not determine the history directory (HOME is not set).")?;
        out(history_table(&history::load(&path)?).trim_end())?;
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

    if let Some(path) = &cli.report {
        return run_report(&cli, path, &checks, &config, &runner, os_version, history_path);
    }

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
    let (records, history_file) = load_history(&cli, history_path);

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let format = if cli.json { Format::Json } else { cli.format };
    let report = Report::new(timestamp, os_version, results, records.last());
    emit(&cli, &report.render(format, cli.quiet))?;
    save_history(history_file, records, &report);

    Ok(exit_code(&cli, &config, &report))
}

/// Loads the history to compare a full audit with. Partial runs
/// (--only/--skip) and `--no-history` get none: their scores cannot be
/// compared with a full audit. Also returns the file to save the run to.
fn load_history(cli: &Cli, history_path: Option<PathBuf>) -> (Vec<history::RunRecord>, Option<PathBuf>) {
    let use_history = !cli.no_history && cli.only.is_empty() && cli.skip.is_empty();
    if use_history && let Some(path) = history_path {
        match history::load(&path) {
            Ok(records) => return (records, Some(path)),
            // A corrupt history must not block the audit; warn and continue without it.
            Err(err) => note(format_args!("{} history unavailable: {err}", "Warning:".yellow())),
        }
    }
    (Vec::new(), None)
}

/// Adds the audit to the history file returned by `load_history`.
fn save_history(history_file: Option<PathBuf>, records: Vec<history::RunRecord>, report: &Report) {
    // A run in which nothing could be evaluated has no score worth comparing.
    if let Some(path) = history_file.filter(|_| report.scorable) {
        let record = history::RunRecord::new(
            report.timestamp.clone(),
            report.os_version.clone(),
            report.score,
            &report.checks,
        );
        if let Err(err) = history::append(&path, records, record) {
            note(format_args!("{} could not save history: {err}", "Warning:".yellow()));
        }
    }
}

/// `--report FILE`: runs the audit and every scan, and writes one HTML page.
/// The exit code is 1 when the audit fails (as without `--report`) or a scan
/// finds malware, a known-exploited vulnerability or a secret in a file
/// tracked in git; otherwise `EXIT_INCOMPLETE` when an online lookup failed.
fn run_report(
    cli: &Cli,
    path: &Path,
    checks: &[Box<dyn Check>],
    config: &Config,
    runner: &SystemRunner,
    os_version: String,
    history_path: Option<PathBuf>,
) -> Result<ExitCode, String> {
    // Check the paths before the slow part starts.
    let lockfile_paths = match cli.vulns_path.as_slice() {
        [] => lockfiles::default_files(),
        paths => vulns_paths(paths)?,
    };
    let npm_roots = match cli.npm_path.as_slice() {
        [] => npm::all_roots(runner),
        paths => npm_roots(paths)?,
    };
    let secret_files = match cli.secrets_path.as_slice() {
        [] => secrets::default_files(),
        paths => secret_files(paths)?,
    };
    // Every module reports what it is doing, one line each, on stderr.
    let progress = progress::Progress::stderr();

    progress.stage("Auditing macOS settings");
    let results = checks::run_checks(checks, runner, config);
    let (records, history_file) = load_history(cli, history_path);
    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let audit = Report::new(timestamp, os_version, results, records.last());

    // An explicit path narrows the vulnerability scan to those projects.
    let system = if cli.vulns_path.is_empty() {
        vulns::system_items(runner)
    } else {
        vulns::System::default()
    };
    let (lockfiles, skipped) = vulns::read_lockfiles(&lockfile_paths, &progress);
    let mut vulns = if cli.online {
        let options = vulns::Online {
            cache: cache_dir()?,
            progress: progress.clone(),
        };
        vulns::scan(&lockfiles, system, &options)
    } else {
        vulns::offline(&lockfiles, system)
    };
    vulns.skipped = skipped;

    let mut npm = npm::scan_with(&npm_roots, &progress);
    let npm_lookup = cli
        .online
        .then(|| npm::osv_lookup_with(&npm.installed, &progress).map(|hits| npm.add_osv(hits)));

    let secrets = secrets::scan_with(&secret_files, &progress);

    let report = full_report::FullReport {
        audit,
        online: cli.online,
        vulns,
        npm,
        npm_lookup,
        secrets,
        home: std::env::var_os("HOME").map(PathBuf::from),
    };
    std::fs::write(path, report.to_html()).map_err(|err| format!("Could not write {}: {err}", path.display()))?;
    written(path);

    let audit_failed = exit_code(cli, config, &report.audit) == ExitCode::FAILURE;
    let threat = report.found_threat();
    let incomplete = report.incomplete();
    save_history(history_file, records, &report.audit);
    Ok(match (audit_failed || threat, incomplete) {
        (true, _) => ExitCode::FAILURE,
        (false, true) => ExitCode::from(EXIT_INCOMPLETE),
        (false, false) => ExitCode::SUCCESS,
    })
}

/// The `--npm-path` directories as scan roots.
fn npm_roots(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut roots = Vec::new();
    for path in paths {
        if !path.is_dir() {
            return Err(format!("{} is not a directory.", path.display()));
        }
        roots.extend(npm::roots_under(path));
    }
    Ok(roots)
}

/// The files under the `--secrets-path` paths.
fn secret_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for path in paths {
        if !path.exists() {
            return Err(format!("{} not found.", path.display()));
        }
        files.extend(secrets::files_under(path));
    }
    Ok(files)
}

/// The lockfiles under the `--vulns-path` paths.
fn vulns_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    for path in paths {
        if !path.exists() {
            return Err(format!("{} not found.", path.display()));
        }
        let named_like_one = path
            .file_name()
            .is_some_and(|name| lockfiles::is_lockfile(&name.to_string_lossy()));
        if path.is_file() && !named_like_one {
            return Err(format!("{} is not a lockfile this tool can read.", path.display()));
        }
        found.extend(lockfiles::files_under(path));
    }
    Ok(found)
}

/// Where online lookups cache their answers: next to the history.
fn cache_dir() -> Result<PathBuf, String> {
    history::history_path()
        .and_then(|path| path.parent().map(|dir| dir.join("cache")))
        .ok_or_else(|| "Could not determine the cache directory (HOME is not set).".to_string())
}

/// `--npm`: scans installed npm packages in detail. The exit code is 1 if a
/// confirmed malicious package was found; heuristic script warnings do not
/// affect the code. A failed `--online` lookup gives `EXIT_INCOMPLETE`.
fn run_npm(cli: &Cli) -> Result<ExitCode, String> {
    let format = text_or_json(cli, "--npm")?;

    let roots = if cli.npm_path.is_empty() {
        npm::all_roots(&SystemRunner::new())
    } else {
        npm_roots(&cli.npm_path)?
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
                note(format_args!(
                    "{} OSV query failed: {err}. Only the built-in list was checked.",
                    "Warning:".yellow()
                ));
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
        secret_files(&cli.secrets_path)?
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

    // A file whose git status is unknown may be tracked: not a clean result.
    let unknown = report.scan.git_unknown().next().is_some();
    Ok(match (exposed, unknown) {
        (true, _) => ExitCode::FAILURE,
        (false, true) => ExitCode::from(EXIT_INCOMPLETE),
        (false, false) => ExitCode::SUCCESS,
    })
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
        (vulns_paths(&cli.vulns_path)?, vulns::System::default())
    };
    // Progress goes to stderr so that it never mixes with the report.
    let progress = if !cli.quiet && std::io::stderr().is_terminal() {
        progress::Progress::stderr()
    } else {
        progress::Progress::none()
    };
    let (lockfiles, skipped) = vulns::read_lockfiles(&paths, &progress);

    let mut scan = if cli.online {
        let options = vulns::Online {
            cache: cache_dir()?,
            progress,
        };
        vulns::scan(&lockfiles, system, &options)
    } else {
        vulns::offline(&lockfiles, system)
    };
    scan.skipped = skipped;

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let report = vulns::VulnReport::new(timestamp, scan);
    let exploited = report.scan.exploited();

    let rendered = match format {
        Format::Json => report.to_json(),
        _ if cli.quiet => format!("{} findings, {} known-exploited", report.scan.findings.len(), exploited),
        _ => report.to_text(),
    };
    emit(cli, &rendered)?;

    // A failed lookup or an unread lockfile may hide an exploited
    // vulnerability: never report success.
    Ok(match (exploited > 0, report.scan.incomplete()) {
        (true, _) => ExitCode::FAILURE,
        (false, true) => ExitCode::from(EXIT_INCOMPLETE),
        (false, false) => ExitCode::SUCCESS,
    })
}

/// Exit code for a scan that is incomplete (a lookup failed, a lockfile could
/// not be read): a script must not read it as "nothing found".
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
                written(path);
            }
        }
        None => out(rendered)?,
    }
    Ok(())
}

/// Prints to stdout. A reader that went away (`| head`, `| true`) only
/// stopped wanting the output, so the exit code must still describe the
/// run; any other failure (a full disk behind `>`) is an error.
fn out(text: &str) -> Result<(), String> {
    write_out(std::io::stdout(), text)
}

fn write_out(mut sink: impl std::io::Write, text: &str) -> Result<(), String> {
    match writeln!(sink, "{text}") {
        Err(err) if err.kind() != std::io::ErrorKind::BrokenPipe => Err(format!("Could not write the output: {err}")),
        _ => Ok(()),
    }
}

/// Prints a line to stderr. Like `written`, a closed stderr is not an error.
fn note(line: std::fmt::Arguments) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Says where the report went. A closed stderr (`2>&1 | head`) is not an
/// error: the report is written and the exit code still has to be right.
fn written(path: &Path) {
    let _ = writeln!(std::io::stderr(), "Report written: {}", path.display());
}

/// Checks that an output file can be created where asked: its folder exists
/// and it is not a folder itself. Permissions only show when writing.
fn check_output(path: &Path) -> Result<(), String> {
    if path.is_dir() {
        return Err(format!("{} is a directory.", path.display()));
    }
    let folder = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !folder.is_dir() {
        return Err(format!(
            "Could not write {}: the folder {} does not exist.",
            path.display(),
            folder.display()
        ));
    }
    Ok(())
}

/// Determines the exit code, for use in scripts and CI.
fn exit_code(cli: &Cli, config: &Config, report: &Report) -> ExitCode {
    // The threshold on the command line takes precedence over the one in the configuration.
    let min_score = cli.min_score.or(config.min_score);
    let below_threshold = min_score.is_some_and(|min| report.score < min);

    if below_threshold && !cli.quiet {
        note(format_args!(
            "{} score {} is below the threshold ({}).",
            "Warning:".yellow(),
            report.score,
            min_score.unwrap_or_default()
        ));
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
            return Err(format!("Unknown check id: `{id}`. Valid ids: {}", known.join(", ")));
        }
    }
    Ok(())
}

/// `--list`: all checks as a table.
fn check_list(checks: &[Box<dyn Check>], config: &Config) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
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
        let _ = writeln!(
            out,
            "{:<16} {:>7}  {:<8} {:<8} {:<9} {}",
            check.id(),
            weight,
            check.severity().label(),
            check.cis().unwrap_or("–"),
            if check.fix().is_some() { "command" } else { "settings" },
            name
        );
    }
    out
}

/// `--history`: past audits from oldest to newest.
fn history_table(records: &[history::RunRecord]) -> String {
    if records.is_empty() {
        return "No audits recorded yet.".to_string();
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}",
        format!(
            "{:<17} {:>5}  {:<5} {:<14} {}",
            "DATE", "SCORE", "GRADE", "SYSTEM", "ISSUES"
        )
        .bold()
    );
    for record in records {
        let count = |status| record.checks.values().filter(|s| **s == status).count();
        let _ = writeln!(
            out,
            "{:<17} {:>5}  {:<5} {:<14} {} failed, {} warned",
            report::short_time(&record.timestamp),
            record.score,
            score::grade(record.score),
            record.os_version,
            count(checks::Status::Fail),
            count(checks::Status::Warn),
        );
    }
    out
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
        assert!(
            parse(&["--fix"]).is_err(),
            "the tool is read-only: there is no fix mode"
        );
        assert!(parse(&["--min-score", "101"]).is_err());
        assert!(parse(&["--unknown"]).is_err());
        assert!(parse(&["--online"]).is_err(), "--online only with --npm or --vulns");
        assert!(parse(&["--vulns", "--online", "--vulns-path", "a"]).is_ok());
        assert!(parse(&["--vulns", "--npm"]).is_err());
        assert!(parse(&["--vulns-path", "."]).is_err(), "--vulns-path only with --vulns");
        assert!(parse(&["--npm-path", "."]).is_err());
        assert!(
            parse(&["--npm", "--only", "sip"]).is_err(),
            "audit options do not apply to the scan modes"
        );
        assert!(parse(&["--vulns", "--min-score", "80"]).is_err());
        assert!(parse(&["--secrets", "--no-history"]).is_err());
        assert!(parse(&["--npm", "--online", "--npm-path", "a", "--npm-path", "b"]).is_ok());
        assert!(
            parse(&["--secrets-path", "."]).is_err(),
            "--secrets-path only with --secrets"
        );
        assert!(parse(&["--secrets", "--npm"]).is_err());
        assert!(parse(&["--secrets", "--json", "--secrets-path", "a"]).is_ok());

        // `--report` runs every module: the scan paths and --online narrow it,
        // the output options of the other modes do not apply.
        assert!(
            parse(&[
                "--report",
                "r.html",
                "--online",
                "--npm-path",
                "a",
                "--vulns-path",
                "b",
                "--secrets-path",
                "c"
            ])
            .is_ok()
        );
        assert!(
            parse(&[
                "--report",
                "r.html",
                "--only",
                "sip",
                "--no-history",
                "--min-score",
                "80"
            ])
            .is_ok()
        );
        for other in ["--npm", "--vulns", "--secrets", "--json", "--tui", "--quiet"] {
            assert!(parse(&["--report", "r.html", other]).is_err(), "{other}");
        }
        assert!(parse(&["--report", "r.html", "--format", "html"]).is_err());
        assert!(parse(&["--report", "r.html", "--output", "o"]).is_err());
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

    #[test]
    fn a_reader_that_went_away_is_not_an_error() {
        // `| head` after head exited: the run goes on with its own exit code.
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        assert_eq!(write_out(writer, "report"), Ok(()));
        // Any other failure loses the report: that is an error.
        let read_only = std::fs::File::open("Cargo.toml").unwrap();
        let error = write_out(read_only, "report").unwrap_err();
        assert!(error.starts_with("Could not write the output:"), "{error}");
        let mut written = Vec::new();
        assert_eq!(write_out(&mut written, "report"), Ok(()));
        assert_eq!(written, b"report\n");
    }

    #[test]
    fn list_and_history_tables() {
        let checks = checks::registry();
        let config = Config::parse("skip = [\"airdrop\"]\n[exceptions]\nssh = \"on purpose\"").unwrap();
        let list = check_list(&checks, &config);
        assert_eq!(list.lines().count(), checks.len() + 1);
        assert!(list.contains("AirDrop visibility (skipped)"), "{list}");
        assert!(list.contains("Remote Login (SSH) (exception)"), "{list}");

        assert_eq!(history_table(&[]), "No audits recorded yet.");
        let results = [
            score::tests::result("firewall", checks::Status::Fail, 20),
            score::tests::result("sip", checks::Status::Warn, 20),
        ];
        let record = history::RunRecord::new("2026-11-20T14:05:00+03:00".into(), "macOS 26".into(), 25, &results);
        let table = history_table(&[record]);
        assert!(table.starts_with("DATE"), "{table}");
        assert!(table.contains("2026-11-20 14:05"), "{table}");
        assert!(table.contains("1 failed, 1 warned"), "{table}");
    }

    #[test]
    fn a_score_below_the_threshold_fails() {
        let report = Report::new(
            "2026-11-20T14:05:00+03:00".into(),
            "macOS 26".into(),
            vec![score::tests::result("sip", checks::Status::Warn, 20)],
            None,
        );
        let below = parse(&["--min-score", "80"]).unwrap();
        assert_eq!(exit_code(&below, &Config::default(), &report), ExitCode::FAILURE);
        let above = parse(&["--min-score", "40"]).unwrap();
        assert_eq!(exit_code(&above, &Config::default(), &report), ExitCode::SUCCESS);
    }
}
