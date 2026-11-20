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
use crate::runner::{CmdOutput, CommandRunner};
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

/// A suggested command that remedies a problem.
///
/// The tool is strictly read-only: it never runs this command. It is only
/// shown to the user, who may choose to run it themselves. A check therefore
/// offers a `Fix` only when that single command is a correct and complete
/// remedy on current macOS; otherwise its advice text describes the steps
/// (for instance the System Settings path) and there is no `Fix`.
#[derive(Debug, Clone, Copy)]
pub struct Fix {
    pub program: &'static str,
    pub args: &'static [&'static str],
    /// Does the command require administrator privileges (sudo)?
    pub sudo: bool,
}

impl Fix {
    /// The full command line to show to the user (with `sudo` if needed).
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

// In JSON output we show the suggestion as a single command-line string.
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
    /// The command suggested to the user to remedy a finding (if any).
    ///
    /// It is displayed, never executed. Return `None` unless one command is
    /// a correct and complete remedy; put step-by-step guidance in the
    /// advice of the `Outcome` instead.
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
pub fn run_checks(checks: &[Box<dyn Check>], runner: &dyn CommandRunner, config: &Config) -> Vec<CheckResult> {
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
        Ok(out) if out.stderr.contains("does not exist") || out.stderr.contains("Could not find") => Pref::Missing,
        Ok(out) => Pref::Error(out.combined()),
    }
}

/// The outcome for a status command whose answer we could not interpret.
///
/// Neither "on" nor "off" was recognised, so the state is Unknown; guessing
/// "off" would report e.g. a disk as unencrypted because a tool printed
/// nothing. The raw output goes into the detail so the cause can be seen.
fn unrecognised(command: &str, out: &CmdOutput) -> Outcome {
    let raw = out.combined();
    let failed = if out.success { "" } else { " and exited with an error" };
    if raw.is_empty() {
        Outcome::unknown(format!("`{command}` produced no output{failed}."))
    } else {
        Outcome::unknown(format!(
            "`{command}` gave an unrecognised answer{failed}: {}",
            one_line(&raw)
        ))
    }
}

/// Squeezes (possibly multi-line) command output into one line of limited
/// length, for use inside a detail text.
fn one_line(text: &str) -> String {
    const MAX_CHARS: usize = 200;
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() > MAX_CHARS {
        let cut: String = joined.chars().take(MAX_CHARS).collect();
        format!("{cut}...")
    } else {
        joined
    }
}

/// A TCP socket in the LISTEN state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    port: u16,
    /// Bound to a loopback address: only reachable from this Mac itself.
    loopback: bool,
}

/// Extracts the listening sockets from the `netstat -an -p tcp` output.
///
/// Lines look like this: `tcp4 0 0 *.22 *.* LISTEN`
/// The 4th field is the local address, the 6th field is the connection state.
///
/// Returns `Err` if the output does not have that layout. A changed column
/// layout must not look like "nothing is listening".
fn listeners(netstat_output: &str) -> Result<Vec<Listener>, String> {
    const NETSTAT_HEADER: [&str; 8] = [
        "Proto", "Recv-Q", "Send-Q", "Local", "Address", "Foreign", "Address", "(state)",
    ];

    let mut found = Vec::new();
    // Have we seen anything that shows this is the output we expect?
    let mut recognised = false;

    for line in netstat_output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if !fields.first().is_some_and(|proto| proto.starts_with("tcp")) {
            // The title line, or the column header we know:
            // "Proto Recv-Q Send-Q  Local Address  Foreign Address  (state)".
            if fields == NETSTAT_HEADER {
                recognised = true;
            }
            continue;
        }

        let socket =
            parse_socket_line(&fields).ok_or_else(|| format!("Unrecognised netstat line: {}", one_line(line)))?;
        recognised = true;
        found.extend(socket);
    }

    if recognised {
        Ok(found)
    } else if netstat_output.trim().is_empty() {
        Err("netstat produced no output.".to_string())
    } else {
        Err(format!("Unrecognised netstat output: {}", one_line(netstat_output)))
    }
}

/// Interprets the fields of one `tcp...` line. `None` if the line does not
/// have the expected layout; `Some(None)` if it is not a listening socket.
fn parse_socket_line(fields: &[&str]) -> Option<Option<Listener>> {
    if fields.len() < 6 {
        return None;
    }
    // Both addresses are "<host>.<port>", where either part may be `*`.
    let (host, port) = split_address(fields[3])?;
    split_address(fields[4])?;
    // States are words like LISTEN, ESTABLISHED, CLOSE_WAIT, FIN_WAIT_1.
    let state = fields[5];
    let is_state = state.len() >= 4
        && state
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !is_state {
        return None;
    }

    if state != "LISTEN" {
        return Some(None);
    }
    // A listening socket always has a port number.
    let port = port?;
    Some(Some(Listener {
        port,
        loopback: is_loopback(host),
    }))
}

/// Splits "<host>.<port>" at the last dot. The port is `None` for `*`.
/// Returns `None` if the text is not an address of that form.
fn split_address(address: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = address.rsplit_once('.')?;
    if host.is_empty() {
        return None;
    }
    match port {
        "*" => Some((host, None)),
        number => number.parse().ok().map(|port| (host, Some(port))),
    }
}

/// Is this local address one that only this Mac itself can reach?
fn is_loopback(host: &str) -> bool {
    // IPv4 127.0.0.0/8, also in its IPv4-mapped IPv6 form.
    let v4 = host.strip_prefix("::ffff:").unwrap_or(host);
    let is_v4_loopback = v4.starts_with("127.") && v4.split('.').count() == 4;
    // `fe80::1%lo0` is the link-local address of the loopback interface.
    is_v4_loopback || host == "::1" || host == "localhost" || host.ends_with("%lo0")
}

/// The shared command that lists listening TCP ports.
fn netstat(runner: &dyn CommandRunner) -> Result<String, String> {
    stdout_of(runner, "netstat", &["-an", "-p", "tcp"])
}

/// Listening sockets that belong to the current user, from `lsof`.
///
/// Without root `lsof` cannot see other users' sockets (the system `sshd`
/// socket is held by launchd), so this complements the launchd lookup: it
/// catches a server the user started themselves, such as a Homebrew `sshd`.
/// Any problem running `lsof` gives an empty list rather than an error.
fn own_listeners(runner: &dyn CommandRunner) -> Vec<Listener> {
    // `lsof` exits with 1 when nothing matches, so the exit code is ignored.
    let Ok(out) = runner.run("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"]) else {
        return Vec::new();
    };
    out.stdout.lines().filter_map(parse_lsof_line).collect()
}

/// A line looks like this:
/// `sshd 812 alice 7u IPv4 0x… 0t0 TCP *:22 (LISTEN)`
fn parse_lsof_line(line: &str) -> Option<Listener> {
    let mut fields = line.split_whitespace().rev();
    if fields.next()? != "(LISTEN)" {
        return None;
    }
    let (host, port) = fields.next()?.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some(Listener {
        port: port.parse().ok()?,
        loopback: is_loopback(host),
    })
}

/// A system service that launchd starts on demand.
struct Daemon {
    label: &'static str,
    plist: &'static str,
}

const SSHD: Daemon = Daemon {
    label: "com.openssh.sshd",
    plist: "/System/Library/LaunchDaemons/ssh.plist",
};
const SCREEN_SHARING: Daemon = Daemon {
    label: "com.apple.screensharing",
    plist: "/System/Library/LaunchDaemons/com.apple.screensharing.plist",
};
const FILE_SHARING: Daemon = Daemon {
    label: "com.apple.smbd",
    plist: "/System/Library/LaunchDaemons/com.apple.smbd.plist",
};

/// Is the service switched on in launchd?
///
/// This is the second source for the sharing checks. Recent macOS releases
/// hide internet sockets from `netstat` for some callers (it prints nothing
/// and still exits 0), and an empty socket list must not be read as
/// "nothing is listening".
///
/// The Sharing switches in System Settings are stored as launchd overrides
/// (`launchctl print-disabled system`); without an override the `Disabled`
/// key of the service's own plist decides.
fn daemon_enabled(runner: &dyn CommandRunner, daemon: &Daemon) -> Result<bool, String> {
    let overrides = stdout_of(runner, "launchctl", &["print-disabled", "system"])?;
    if !overrides.contains("=>") {
        return Err("Unrecognised `launchctl print-disabled` output.".to_string());
    }
    let quoted = format!("\"{}\"", daemon.label);
    for line in overrides.lines() {
        if let Some((name, state)) = line.split_once("=>")
            && name.trim() == quoted
        {
            return match state.trim() {
                "enabled" | "false" => Ok(true),
                "disabled" | "true" => Ok(false),
                other => Err(format!("Unrecognised launchd state for {}: {other}", daemon.label)),
            };
        }
    }

    let default = runner.run("plutil", &["-extract", "Disabled", "raw", "-o", "-", daemon.plist])?;
    match (default.success, default.stdout.trim()) {
        (true, "true") => Ok(false),
        (true, "false") => Ok(true),
        _ => Err(format!(
            "Could not read the default state of {}: {}",
            daemon.label,
            one_line(&default.combined())
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    /// The ports with a listener that is reachable from the network.
    fn exposed(sample: &str) -> Vec<u16> {
        listeners(sample)
            .unwrap()
            .into_iter()
            .filter(|listener| !listener.loopback)
            .map(|listener| listener.port)
            .collect()
    }

    #[test]
    fn finds_open_port() {
        let sample = "\
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.5000         *.*                    LISTEN";
        assert_eq!(
            listeners(sample).unwrap(),
            [
                Listener {
                    port: 22,
                    loopback: false
                },
                Listener {
                    port: 5000,
                    loopback: true
                },
            ]
        );
    }

    #[test]
    fn does_not_confuse_similar_ports() {
        let sample = "\
tcp4       0      0  *.8022                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.2222         *.*                    LISTEN";
        assert!(listeners(sample).unwrap().iter().all(|listener| listener.port != 22));
    }

    #[test]
    fn does_not_count_non_listening_connection() {
        let sample = "tcp4  0  0  10.0.0.5.22  10.0.0.9.51234  ESTABLISHED";
        assert_eq!(listeners(sample).unwrap(), []);
    }

    #[test]
    fn loopback_listeners_are_not_exposed() {
        // Real output from this machine, plus tunnel endpoints on loopback.
        let sample = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  172.20.10.3.57019      142.251.154.119.443    ESTABLISHED
tcp6       0      0  *.49493                *.*                    LISTEN
tcp4       0      0  127.0.0.1.5900         *.*                    LISTEN
tcp4       0      0  127.0.0.1.22           *.*                    LISTEN
tcp6       0      0  ::1.22                 *.*                    LISTEN
tcp6       0      0  fe80::1%lo0.8021       *.*                    LISTEN
tcp4       0      0  127.12.0.9.3283        *.*                    LISTEN
tcp46      0      0  *.443                  *.*                    LISTEN
tcp4       0      0  192.168.1.20.445       *.*                    LISTEN
tcp6       0      0  fe80::aede:48ff%en5.548 *.*                   LISTEN
tcp4       0      0  *.*                    *.*                    CLOSED";
        assert_eq!(exposed(sample), [49493, 443, 445, 548]);
    }

    #[test]
    fn loopback_addresses() {
        for host in [
            "127.0.0.1",
            "127.255.0.3",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1%lo0",
            "localhost",
        ] {
            assert!(is_loopback(host), "{host}");
        }
        for host in [
            "*",
            "10.0.0.5",
            "192.168.127.1",
            "1127.0.0.1",
            "::",
            "fe80::1%en0",
            "2001:db8::1",
        ] {
            assert!(!is_loopback(host), "{host}");
        }
    }

    #[test]
    fn changed_netstat_layout_is_an_error() {
        // No output at all.
        assert!(listeners("").is_err());
        assert!(listeners("  \n").is_err());
        // Not netstat output.
        assert!(listeners("netstat: illegal option").is_err());
        // A column was inserted or removed: the address is no longer field 4.
        assert!(listeners("tcp4  0  0  0x0  *.22  *.*  LISTEN").is_err());
        assert!(listeners("tcp4  0  *.22  *.*  LISTEN").is_err());
        // The state column moved or turned into something else.
        assert!(listeners("tcp4  0  0  *.22  *.*  0").is_err());
        assert!(listeners("tcp4  0  0  *.22  *.*  listen").is_err());
        // A listening socket without a port number makes no sense.
        assert!(listeners("tcp4  0  0  *.*  *.*  LISTEN").is_err());
        // A header with different columns and no sockets to judge by.
        assert!(listeners("Proto Local Address State").is_err());

        // Only the header: netstat ran, and nothing is listening.
        let header = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)";
        assert_eq!(listeners(header).unwrap(), []);
    }

    #[test]
    fn unrecognised_output_keeps_the_raw_text() {
        let out = CmdOutput {
            stdout: "line one\n   line two".to_string(),
            stderr: String::new(),
            success: true,
        };
        let outcome = unrecognised("tool status", &out);
        assert_eq!(outcome.status, Status::Unknown);
        assert!(outcome.detail.contains("`tool status`"));
        assert!(outcome.detail.contains("line one line two"), "{}", outcome.detail);

        let silent = unrecognised("tool status", &CmdOutput::default());
        assert!(silent.detail.contains("no output"));
        assert!(silent.detail.contains("exited with an error"));

        assert_eq!(one_line(&"x".repeat(500)).chars().count(), 203);
    }

    #[test]
    fn os_version_needs_a_successful_command() {
        let ok = MockRunner::new().ok("sw_vers -productVersion", "27.2.1");
        assert_eq!(os_version(&ok), "macOS 27.2.1");
        // A failed command that printed something is not a version.
        let failed = MockRunner::new().fail_stdout("sw_vers -productVersion", "usage: sw_vers");
        assert_eq!(os_version(&failed), "macOS (version could not be read)");
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
            if result.id == "npm-packages" {
                continue; // It reads the file system; it does not depend on commands.
            }
            if result.id == "launch-items" && result.detail.starts_with("0 items examined") {
                continue; // This machine has no launch items, so nothing needed a command.
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
        config.exceptions.insert("filevault".into(), "test machine".into());

        let result = run_one(&system::FileVault, &runner, &config);
        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.weight, 40);
        assert!(
            !result.is_failure(),
            "a check with an exception does not count as a failure"
        );
    }

    #[test]
    fn empty_or_failed_commands_never_pass_or_fail() {
        // Every status command "succeeds" but prints nothing, and likewise
        // fails while printing something unhelpful: neither is an answer.
        let registry = registry();
        let config = Config::default();
        let firewall = "/usr/libexec/ApplicationFirewall/socketfilterfw";
        let commands = [
            ("filevault", "fdesetup status".to_string()),
            ("sip", "csrutil status".to_string()),
            ("gatekeeper", "spctl --status".to_string()),
            ("firewall", format!("{firewall} --getglobalstate")),
            ("stealth", format!("{firewall} --getstealthmode")),
            ("ssh", "netstat -an -p tcp".to_string()),
            ("sharing", "netstat -an -p tcp".to_string()),
            ("screen-lock", "sysadminctl -screenLock status".to_string()),
        ];
        for (id, command) in commands {
            let check = registry.iter().find(|check| check.id() == id).unwrap();
            for runner in [
                MockRunner::new().ok(&command, ""),
                MockRunner::new().fail_stdout(&command, "usage: see the manual"),
            ] {
                let result = run_one(check.as_ref(), &runner, &config);
                assert_eq!(result.status, Status::Unknown, "{id}: {}", result.detail);
            }
        }
    }

    #[test]
    fn suggested_commands() {
        // The tool only displays these; each must be a complete remedy by
        // itself. Checks that need several steps give advice instead.
        let mut suggestions: Vec<(&str, String)> = registry()
            .iter()
            .filter_map(|check| check.fix().map(|fix| (check.id(), fix.command_line())))
            .collect();
        suggestions.sort();
        assert_eq!(
            suggestions,
            [
                (
                    "firewall",
                    "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on".to_string()
                ),
                ("guest", "sudo sysadminctl -guestAccount off".to_string()),
                (
                    "stealth",
                    "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on".to_string()
                ),
            ]
        );
    }

    #[test]
    fn fix_command_line() {
        let fix = Fix {
            program: "defaults",
            args: &["write", "x", "Contacts Only"],
            sudo: true,
        };
        assert_eq!(fix.command_line(), "sudo defaults write x \"Contacts Only\"");
    }
}
