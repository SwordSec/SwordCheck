//! External command execution layer.
//!
//! Checks do not run system commands directly with `std::process::Command`;
//! they go through the `CommandRunner` trait. That way tests can supply fake
//! (mock) output instead of running the real command: "dependency injection".

use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

/// The raw result of a command.
#[derive(Debug, Clone, Default)]
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

    /// The old `run` behavior: returns the output if the command succeeded or
    /// stdout is non-empty, otherwise the error description.
    pub fn into_stdout(self) -> Result<String, String> {
        if self.success || !self.stdout.is_empty() {
            Ok(self.stdout)
        } else if self.stderr.is_empty() {
            Err("command returned an unexpected exit code".to_string())
        } else {
            Err(self.stderr)
        }
    }
}

/// Anything that can run commands. The `Sync` bound lets the same runner be
/// shared across multiple threads.
pub trait CommandRunner: Sync {
    /// `Err` is returned only when the command could not be started at all
    /// (e.g. the program does not exist).
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String>;
}

/// Runs real system commands and caches the results.
///
/// Several checks use the same command (e.g. `netstat`); thanks to the cache
/// the command runs only once. The `Mutex` lets parallel checks access the
/// map safely.
#[derive(Default)]
pub struct SystemRunner {
    cache: Mutex<HashMap<String, Result<CmdOutput, String>>>,
}

impl SystemRunner {
    pub fn new() -> Self {
        Self::default()
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

        let result = Command::new(program)
            .args(args)
            .output()
            .map(|output| CmdOutput {
                stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                success: output.status.success(),
            })
            .map_err(|err| format!("could not run `{program}`: {err}"));

        self.cache.lock().unwrap().insert(key, result.clone());
        result
    }
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
    responses: HashMap<String, CmdOutput>,
}

#[cfg(test)]
impl MockRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Defines a successful (exit code 0) command.
    pub fn ok(mut self, command: &str, stdout: &str) -> Self {
        self.responses.insert(
            command.to_string(),
            CmdOutput {
                stdout: stdout.to_string(),
                stderr: String::new(),
                success: true,
            },
        );
        self
    }

    /// Defines a failing command; the message is treated as written to stderr.
    pub fn fail(mut self, command: &str, stderr: &str) -> Self {
        self.responses.insert(
            command.to_string(),
            CmdOutput {
                stdout: String::new(),
                stderr: stderr.to_string(),
                success: false,
            },
        );
        self
    }

    /// Defines a command that succeeds but writes its output to stderr.
    pub fn ok_stderr(mut self, command: &str, stderr: &str) -> Self {
        self.responses.insert(
            command.to_string(),
            CmdOutput {
                stdout: String::new(),
                stderr: stderr.to_string(),
                success: true,
            },
        );
        self
    }
}

#[cfg(test)]
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        let key = command_key(program, args);
        self.responses
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("mock: undefined command `{key}`"))
    }
}
