//! External command execution layer.
//!
//! Checks do not run system commands directly with `std::process::Command`;
//! they go through the `CommandRunner` trait. That way tests can supply fake
//! (mock) output instead of running the real command: "dependency injection".

use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a single command may run before it is killed. A hung helper
/// (`npm root -g`, `sysadminctl`, `plutil`, ...) must not hang the audit.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// The raw result of a command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    pub stdout: String,
    pub stderr: String,
    /// True if the exit code is 0.
    pub success: bool,
}

impl CmdOutput {
    /// Joins stdout and stderr into a single text. Some tools
    /// (e.g. `sysadminctl`) write the actual information to stderr.
    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr).trim().to_string()
    }

    /// Returns stdout if the command exited with code 0, otherwise an error
    /// description (stderr, or failing that whatever was written to stdout).
    ///
    /// A failed command is never treated as a success, even if it printed
    /// something: callers that need to interpret the output of a command
    /// that signals its answer through the exit code (e.g. `spctl --status`)
    /// must look at the `CmdOutput` fields themselves.
    pub fn into_stdout(self) -> Result<String, String> {
        if self.success {
            Ok(self.stdout)
        } else if !self.stderr.is_empty() {
            Err(self.stderr)
        } else if !self.stdout.is_empty() {
            Err(format!("command failed: {}", self.stdout))
        } else {
            Err("command returned an unexpected exit code".to_string())
        }
    }
}

/// Anything that can run commands. The `Sync` bound lets the same runner be
/// shared across multiple threads.
pub trait CommandRunner: Sync {
    /// `Err` is returned when the command produced no usable result at all:
    /// it could not be started (e.g. the program does not exist) or it did
    /// not finish within the time limit.
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String>;
}

/// Runs real system commands and caches the results.
///
/// Several checks use the same command (e.g. `netstat`); thanks to the cache
/// the command runs only once. The `Mutex` lets parallel checks access the
/// map safely.
///
/// Every command is subject to a time limit (`COMMAND_TIMEOUT` by default);
/// a command that exceeds it is killed and reported as an `Err`.
pub struct SystemRunner {
    cache: Mutex<HashMap<String, Result<CmdOutput, String>>>,
    timeout: Duration,
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self::with_timeout(COMMAND_TIMEOUT)
    }
}

impl SystemRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// A runner with a custom per-command time limit.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            timeout,
        }
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        let key = command_key(program, args);

        // We hold the lock only while looking at the map and release it
        // while the command runs, so other checks do not have to wait.
        if let Some(cached) = self.cache.lock().unwrap().get(&key) {
            return cached.clone();
        }

        let result = run_with_timeout(program, args, self.timeout);

        self.cache.lock().unwrap().insert(key, result.clone());
        result
    }
}

/// Runs the command, giving up (and killing it) after `timeout`.
///
/// stdout and stderr are drained by two helper threads while we wait, so a
/// command that writes more than a pipe buffer cannot deadlock against us.
/// The helpers hand their data over through channels rather than being
/// joined: if a command left a grandchild behind that keeps the pipe open,
/// we stop waiting instead of blocking forever.
fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<CmdOutput, String> {
    /// How often we look whether the command has finished.
    const POLL: Duration = Duration::from_millis(10);
    /// After the command exits its output is normally complete at once; this
    /// is how long we wait for it at the very least.
    const DRAIN_GRACE: Duration = Duration::from_secs(1);

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("could not run `{program}`: {err}"))?;

    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());

    let timed_out =
        || format!("`{program}` did not finish within {} seconds", timeout.as_secs_f32());
    let deadline = Instant::now() + timeout;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                // Kill it and reap it so no zombie is left behind.
                let _ = child.kill();
                let _ = child.wait();
                return Err(timed_out());
            }
            Ok(None) => std::thread::sleep(POLL),
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not wait for `{program}`: {err}"));
            }
        }
    };

    let drain_deadline = deadline.max(Instant::now() + DRAIN_GRACE);
    let collect = |receiver: mpsc::Receiver<Vec<u8>>| {
        receiver
            .recv_timeout(drain_deadline.saturating_duration_since(Instant::now()))
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
            .map_err(|_| timed_out())
    };

    Ok(CmdOutput {
        stdout: collect(stdout)?,
        stderr: collect(stderr)?,
        success: status.success(),
    })
}

/// Reads a pipe to its end on a separate thread and sends the bytes back.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            // A read error just ends the output early.
            let _ = pipe.read_to_end(&mut bytes);
        }
        // The receiver may have stopped waiting; that is fine.
        let _ = sender.send(bytes);
    });
    receiver
}

/// Cache and mock key: the program and its arguments joined with spaces.
fn command_key(program: &str, args: &[&str]) -> String {
    let mut key = program.to_string();
    for arg in args {
        key.push(' ');
        key.push_str(arg);
    }
    key
}

/// Fake runner for tests: returns predefined outputs.
#[cfg(test)]
#[derive(Default)]
pub struct MockRunner {
    responses: HashMap<String, Result<CmdOutput, String>>,
}

#[cfg(test)]
impl MockRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Defines a successful (exit code 0) command.
    pub fn ok(mut self, command: &str, stdout: &str) -> Self {
        self.respond(command, stdout, "", true)
    }

    /// Defines a failing command; the message is treated as written to stderr.
    pub fn fail(mut self, command: &str, stderr: &str) -> Self {
        self.respond(command, "", stderr, false)
    }

    /// Defines a command that exits with a non-zero code but still writes
    /// to stdout (e.g. `spctl --status` when Gatekeeper is disabled).
    pub fn fail_stdout(self, command: &str, stdout: &str) -> Self {
        self.respond(command, stdout, "", false)
    }

    /// Defines a command that yields no result at all (could not be started
    /// or timed out).
    pub fn error(mut self, command: &str, message: &str) -> Self {
        self.responses
            .insert(command.to_string(), Err(message.to_string()));
        self
    }

    fn respond(mut self, command: &str, stdout: &str, stderr: &str, success: bool) -> Self {
        self.responses.insert(
            command.to_string(),
            Ok(CmdOutput {
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
                success,
            }),
        );
        self
    }

    /// Defines a command that succeeds but writes its output to stderr.
    pub fn ok_stderr(mut self, command: &str, stderr: &str) -> Self {
        self.respond(command, "", stderr, true)
    }
}

#[cfg(test)]
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        let key = command_key(program, args);
        self.responses
            .get(&key)
            .cloned()
            .unwrap_or_else(|| Err(format!("mock: undefined command `{key}`")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(stdout: &str, stderr: &str, success: bool) -> CmdOutput {
        CmdOutput {
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            success,
        }
    }

    #[test]
    fn failed_command_is_never_a_success() {
        assert_eq!(output("fine", "", true).into_stdout(), Ok("fine".to_string()));
        // Empty output of a successful command is still a success.
        assert_eq!(output("", "", true).into_stdout(), Ok(String::new()));

        // A failure stays a failure even when something was printed.
        assert_eq!(
            output("partial", "boom", false).into_stdout(),
            Err("boom".to_string())
        );
        let err = output("only stdout", "", false).into_stdout().unwrap_err();
        assert!(err.contains("only stdout"), "{err}");
        assert!(output("", "", false).into_stdout().is_err());
    }

    #[test]
    fn mock_runner_variants() {
        let runner = MockRunner::new()
            .ok("a", "out")
            .fail("b", "err")
            .fail_stdout("c", "out")
            .error("d", "timed out");
        assert!(runner.run("a", &[]).unwrap().success);
        assert!(!runner.run("b", &[]).unwrap().success);
        let c = runner.run("c", &[]).unwrap();
        assert!(!c.success && c.stdout == "out");
        assert_eq!(runner.run("d", &[]), Err("timed out".to_string()));
        assert!(runner.run("undefined", &[]).is_err());
    }

    #[test]
    fn system_runner_captures_output_and_exit_code() {
        let runner = SystemRunner::new();
        let ok = runner.run("/bin/sh", &["-c", "echo out; echo err >&2"]).unwrap();
        assert_eq!(ok, output("out", "err", true));

        let failed = runner.run("/bin/sh", &["-c", "echo out; exit 3"]).unwrap();
        assert!(!failed.success);
        assert!(failed.into_stdout().is_err());

        assert!(runner.run("/nonexistent/program", &[]).is_err());
    }

    #[test]
    fn hung_command_times_out() {
        let runner = SystemRunner::with_timeout(Duration::from_millis(200));
        let started = Instant::now();
        let err = runner.run("/bin/sleep", &["30"]).unwrap_err();
        assert!(err.contains("did not finish"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10), "the command was not killed");

        // The timeout is cached like any other result.
        let again = Instant::now();
        assert!(runner.run("/bin/sleep", &["30"]).is_err());
        assert!(again.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn large_output_does_not_deadlock() {
        // Far more than a pipe buffer (64 KiB), on both streams.
        let runner = SystemRunner::with_timeout(Duration::from_secs(15));
        let script = "head -c 300000 /dev/zero | tr '\\0' a; head -c 300000 /dev/zero | tr '\\0' b >&2";
        let out = runner.run("/bin/sh", &["-c", script]).unwrap();
        assert!(out.success);
        assert_eq!(out.stdout.len(), 300_000);
        assert_eq!(out.stderr.len(), 300_000);
    }

    #[test]
    fn default_timeout_is_set() {
        // `Default` must not silently give a zero time limit.
        assert_eq!(SystemRunner::default().timeout, COMMAND_TIMEOUT);
        assert_eq!(SystemRunner::new().timeout, COMMAND_TIMEOUT);
    }
}
