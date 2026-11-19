//! macOS security checks.
//!
//! Each check is a small type that implements the `Check` trait. A check only
//! runs read-only commands and produces an `Outcome`; fixed information such
//! as the name, weight and severity comes from the trait methods. To add a new
//! check: write the type, implement `Check`, add it to the `registry()` list.

mod accounts;
mod network;
mod persistence;
mod supply_chain;
mod system;

use crate::config::Config;
use crate::progress::Progress;
use crate::runner::CommandRunner;
use serde::{Deserialize, Serialize, Serializer};

/// The result of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// No problem.
    Pass,
    /// There is something that deserves attention.
    Warn,
    /// An important security measure is missing.
    Fail,
    /// The state could not be determined (command failed, no permission, etc.).
    Unknown,
}

impl Status {
    /// The label used in output.
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Unknown => "UNKNOWN",
        }
    }
}

/// The severity of a check: how serious is it if a problem turns up?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The variable part a check produces when it is run.
#[derive(Debug)]
pub struct Outcome {
    pub status: Status,
    pub detail: String,
    pub advice: &'static str,
}

impl Outcome {
    // Short constructor functions: thanks to `impl Into<String>` both `&str`
    // and `String` are accepted.
    pub fn pass(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            detail: detail.into(),
            advice: "",
        }
    }

    pub fn warn(detail: impl Into<String>, advice: &'static str) -> Self {
        Self {
            status: Status::Warn,
            detail: detail.into(),
            advice,
        }
    }

    pub fn fail(detail: impl Into<String>, advice: &'static str) -> Self {
        Self {
            status: Status::Fail,
            detail: detail.into(),
            advice,
        }
    }

    pub fn unknown(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Unknown,
            detail: detail.into(),
            advice: "",
        }
    }
}

/// A command that fixes a problem. It is only run in `--fix` mode and only
/// if the user confirms.
#[derive(Debug, Clone, Copy)]
pub struct Fix {
    pub program: &'static str,
    pub args: &'static [&'static str],
    /// Does the command require administrator privileges (sudo)?
    pub sudo: bool,
}

impl Fix {
    /// The full command line to show to the user.
    pub fn command_line(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.sudo {
            parts.push("sudo".to_string());
        }
        parts.push(self.program.to_string());
        for arg in self.args {
            // We wrap arguments that contain spaces in quotes.
            if arg.contains(' ') {
                parts.push(format!("\"{arg}\""));
            } else {
                parts.push(arg.to_string());
            }
        }
        parts.join(" ")
    }
}

// In JSON output we show the fix as a single command-line string.
impl Serialize for Fix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.command_line())
    }
}

/// The common interface implemented by all checks.
///
/// The `Sync` bound is there so that checks can be run in parallel.
pub trait Check: Sync {
    /// The short identifier used on the command line and in the configuration.
    fn id(&self) -> &'static str;
    /// The name shown to the user.
    fn name(&self) -> &'static str;
    /// The default weight in the score.
    fn weight(&self) -> u32;
    fn severity(&self) -> Severity;
    /// The relevant CIS Apple macOS Benchmark section (if any).
    fn cis(&self) -> Option<&'static str> {
        None
    }
    /// The automatic fix command (if any).
    fn fix(&self) -> Option<Fix> {
        None
    }
    /// Runs the check. It must not change any setting.
    fn run(&self, runner: &dyn CommandRunner) -> Outcome;
}

/// The full report of a single check: fixed information + the run result.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub name: &'static str,
    pub status: Status,
    pub severity: Severity,
    pub weight: u32,
    pub cis: Option<&'static str>,
    pub detail: String,
    pub advice: &'static str,
    /// The justification, if an exception is defined in the configuration.
    /// Checks with an exception do not affect the score or the exit code.
    pub exempt: Option<String>,
    pub fix: Option<Fix>,
}

impl CheckResult {
    /// Is the check an issue (a Fail/Warn with no exception defined)?
    pub fn is_issue(&self) -> bool {
        self.exempt.is_none() && matches!(self.status, Status::Fail | Status::Warn)
    }

    /// Is it a failure that affects the exit code?
    pub fn is_failure(&self) -> bool {
        self.exempt.is_none() && self.status == Status::Fail
    }
}

/// All known checks, in the order they appear in the output.
pub fn registry() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(system::FileVault),
        Box::new(system::Sip),
        Box::new(system::Gatekeeper),
        Box::new(system::AutoUpdate),
        Box::new(system::PendingUpdates),
        Box::new(system::XProtect),
        Box::new(network::Firewall),
        Box::new(network::StealthMode),
        Box::new(network::Ssh),
        Box::new(network::Sharing),
        Box::new(network::AirDrop),
        Box::new(accounts::AutoLogin),
        Box::new(accounts::GuestAccount),
        Box::new(accounts::ScreenLock),
        Box::new(accounts::SudoNoPassword),
        Box::new(persistence::LaunchItems),
        Box::new(supply_chain::NpmPackages),
    ]
}

/// Runs a single check and applies the configuration (weight, exception).
pub fn run_one(check: &dyn Check, runner: &dyn CommandRunner, config: &Config) -> CheckResult {
    let outcome = check.run(runner);
    build_result(check, outcome, config)
}

fn build_result(check: &dyn Check, outcome: Outcome, config: &Config) -> CheckResult {
    CheckResult {
        id: check.id(),
        name: check.name(),
        status: outcome.status,
        severity: check.severity(),
        // Use the weight from the configuration if given, otherwise the default.
        weight: config
            .weights
            .get(check.id())
            .copied()
            .unwrap_or_else(|| check.weight()),
        cis: check.cis(),
        detail: outcome.detail,
        advice: outcome.advice,
        exempt: config.exceptions.get(check.id()).cloned(),
        fix: check.fix(),
    }
}

/// Runs the given checks in parallel; results keep the input order.
///
/// `std::thread::scope` lets the threads borrow local data such as `checks`,
/// `runner` and `config`: all threads are guaranteed to have finished before
/// the scope ends.
pub fn run_checks(
    checks: &[Box<dyn Check>],
    runner: &dyn CommandRunner,
    config: &Config,
) -> Vec<CheckResult> {
    run_checks_with(checks, runner, config, &Progress::none())
}

/// Like `run_checks`, reporting each check as it finishes.
pub fn run_checks_with(
    checks: &[Box<dyn Check>],
    runner: &dyn CommandRunner,
    config: &Config,
    progress: &Progress,
) -> Vec<CheckResult> {
    progress.stage(format!("Running {} security checks", checks.len()));
    // Checks finish in any order; the counter turns that into "n of total".
    let finished = std::sync::atomic::AtomicUsize::new(0);
    let finished = &finished;

    std::thread::scope(|scope| {
        let handles: Vec<_> = checks
            .iter()
            .map(|check| {
                scope.spawn(move || {
                    let result = run_one(check.as_ref(), runner, config);
                    let done = finished.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    progress.step(done, checks.len());
                    progress.note(format!("{:<8} {}", result.status.label(), result.name));
                    result
                })
            })
            .collect();

        handles
            .into_iter()
            .zip(checks)
            .map(|(handle, check)| {
                // If a check panics, instead of bringing down the whole
                // program we report that check as "unknown".
                handle.join().unwrap_or_else(|_| {
                    build_result(
                        check.as_ref(),
                        Outcome::unknown("The check terminated unexpectedly."),
                        config,
                    )
                })
            })
            .collect()
    })
}

/// Returns the macOS version in the form "macOS 26.6.2".
pub fn os_version(runner: &dyn CommandRunner) -> String {
    stdout_of(runner, "sw_vers", &["-productVersion"])
        .map(|version| format!("macOS {version}"))
        .unwrap_or_else(|_| "macOS (version could not be read)".to_string())
}

// ---- Helpers shared by the checks ----

/// Runs the command and returns its stdout; on failure gives an error description.
fn stdout_of(runner: &dyn CommandRunner, program: &str, args: &[&str]) -> Result<String, String> {
    runner.run(program, args)?.into_stdout()
}

/// The three possible states of a `defaults read` result.
enum Pref {
    Value(String),
    /// The key has never been defined.
    Missing,
    Error(String),
}

/// Reads a macOS preferences key.
fn read_pref(runner: &dyn CommandRunner, domain: &str, key: &str) -> Pref {
    match runner.run("defaults", &["read", domain, key]) {
        Err(err) => Pref::Error(err),
        Ok(out) if out.success => Pref::Value(out.stdout),
        // Older macOS says "does not exist"; newer releases say "Could not find key".
        Ok(out) if out.stderr.contains("does not exist") || out.stderr.contains("Could not find") => {
            Pref::Missing
        }
        Ok(out) => Pref::Error(out.combined()),
    }
}

/// Is the given port being listened on in the `netstat -an -p tcp` output?
///
/// Lines look like this: `tcp4 0 0 *.22 *.* LISTEN`
/// The 4th field is the local address, the 6th field is the connection state.
fn listening_on(netstat_output: &str, port: u16) -> bool {
    let suffix = format!(".{port}");
    netstat_output.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() >= 6 && fields[3].ends_with(&suffix) && fields[5] == "LISTEN"
    })
}

/// The shared command that lists listening TCP ports.
fn netstat(runner: &dyn CommandRunner) -> Result<String, String> {
    stdout_of(runner, "netstat", &["-an", "-p", "tcp"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    #[test]
    fn finds_open_port() {
        let sample = "\
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.5000         *.*                    LISTEN";
        assert!(listening_on(sample, 22));
        assert!(listening_on(sample, 5000));
    }

    #[test]
    fn does_not_confuse_similar_ports() {
        let sample = "\
tcp4       0      0  *.8022                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.2222         *.*                    LISTEN";
        assert!(!listening_on(sample, 22));
    }

    #[test]
    fn does_not_count_non_listening_connection() {
        let sample = "tcp4  0  0  10.0.0.5.22  10.0.0.9.51234  ESTABLISHED";
        assert!(!listening_on(sample, 22));
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<&str> = registry().iter().map(|check| check.id()).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "two checks share the same id");
    }

    #[test]
    fn returns_unknown_when_commands_fail() {
        // Empty mock: every command gives an "undefined" error. No check
        // should panic or mistakenly say "pass".
        let runner = MockRunner::new();
        let config = Config::default();
        for result in run_checks(&registry(), &runner, &config) {
            if matches!(result.id, "launch-items" | "npm-packages") {
                continue; // They read the file system; they do not depend on commands.
            }
            assert_eq!(
                result.status,
                Status::Unknown,
                "{} should have returned Unknown on a command error",
                result.id
            );
        }
    }

    #[test]
    fn config_applies_weight_and_exception() {
        let runner = MockRunner::new().ok("fdesetup status", "FileVault is Off.");
        let mut config = Config::default();
        config.weights.insert("filevault".into(), 40);
        config
            .exceptions
            .insert("filevault".into(), "test machine".into());

        let result = run_one(&system::FileVault, &runner, &config);
        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.weight, 40);
        assert!(
            !result.is_failure(),
            "a check with an exception does not count as a failure"
        );
    }

    #[test]
    fn fix_command_line() {
        let fix = Fix {
            program: "defaults",
            args: &["write", "x", "Contacts Only"],
            sudo: true,
        };
        assert_eq!(
            fix.command_line(),
            "sudo defaults write x \"Contacts Only\""
        );
    }
}
