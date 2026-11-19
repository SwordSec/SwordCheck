//! Account and session checks: automatic login, guest, screen lock, sudo.

use super::{Check, Fix, Outcome, Pref, Severity, read_pref};
use crate::runner::CommandRunner;

const LOGIN_WINDOW: &str = "/Library/Preferences/com.apple.loginwindow";

/// Is passwordless automatic login configured?
pub struct AutoLogin;

impl Check for AutoLogin {
    fn id(&self) -> &'static str {
        "auto-login"
    }
    fn name(&self) -> &'static str {
        "Automatic login"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.12.3")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: "defaults",
            args: &["delete", LOGIN_WINDOW, "autoLoginUser"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match read_pref(runner, LOGIN_WINDOW, "autoLoginUser") {
            // If the key exists a user name is returned: automatic login is on.
            Pref::Value(user) if !user.is_empty() => Outcome::fail(
                format!("User '{user}' logs in automatically without a password."),
                "Turn off automatic login in System Settings > Users & Groups.",
            ),
            // If the key is missing, automatic login is already off.
            Pref::Value(_) | Pref::Missing => Outcome::pass("Automatic login is off."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

/// Is the guest account enabled?
pub struct GuestAccount;

impl Check for GuestAccount {
    fn id(&self) -> &'static str {
        "guest"
    }
    fn name(&self) -> &'static str {
        "Guest account"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.12.1")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: "sysadminctl",
            args: &["-guestAccount", "off"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match read_pref(runner, LOGIN_WINDOW, "GuestEnabled") {
            Pref::Value(value) if value == "1" => Outcome::fail(
                "The guest account is enabled.",
                "Turn off Guest User in System Settings > Users & Groups.",
            ),
            Pref::Value(_) | Pref::Missing => Outcome::pass("The guest account is disabled."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

/// How soon is the password required after the screen locks?
pub struct ScreenLock;

/// We warn if the lock delay is longer than this many seconds.
const MAX_LOCK_DELAY_SECS: u64 = 5;

/// The interpretation of the `sysadminctl -screenLock status` output.
#[derive(Debug, PartialEq, Eq)]
enum LockDelay {
    Immediate,
    Seconds(u64),
    Off,
}

/// Possible outputs:
/// - "screenLock delay is immediate"
/// - "screenLock delay is 300 seconds"
/// - "screenLock is off"
fn parse_lock_delay(output: &str) -> Option<LockDelay> {
    if output.contains("screenLock is off") {
        return Some(LockDelay::Off);
    }
    // `split_once` splits the text in two at the first match; `?` exits the
    // function with `None` if there is no match.
    let (_, rest) = output.split_once("screenLock delay is ")?;
    let mut words = rest.split_whitespace();
    match words.next()? {
        "immediate" => Some(LockDelay::Immediate),
        number => number.parse().ok().map(LockDelay::Seconds),
    }
}

impl Check for ScreenLock {
    fn id(&self) -> &'static str {
        "screen-lock"
    }
    fn name(&self) -> &'static str {
        "Screen lock password"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.10")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        const ADVICE: &str = "Set the require-password delay to \"Immediately\" in System Settings > Lock Screen.";

        // `sysadminctl` writes its information to stderr, so we look at the combined output.
        let output = match runner.run("sysadminctl", &["-screenLock", "status"]) {
            Ok(out) => out.combined(),
            Err(err) => return Outcome::unknown(err),
        };

        match parse_lock_delay(&output) {
            Some(LockDelay::Immediate) => {
                Outcome::pass("The password is required immediately after locking.")
            }
            Some(LockDelay::Seconds(secs)) if secs <= MAX_LOCK_DELAY_SECS => {
                Outcome::pass(format!("The password is required after {secs} seconds."))
            }
            Some(LockDelay::Seconds(secs)) => Outcome::warn(
                format!("The password is required {secs} seconds after locking."),
                ADVICE,
            ),
            Some(LockDelay::Off) => {
                Outcome::fail("The screen lock does not require a password.", ADVICE)
            }
            None => Outcome::unknown("The screen lock state could not be read."),
        }
    }
}

/// Can the user run sudo without a password?
///
/// `sudo -n -l` does not run any command; it only lists the user's sudo
/// rules. `-n` prevents a password prompt.
pub struct SudoNoPassword;

impl Check for SudoNoPassword {
    fn id(&self) -> &'static str {
        "sudo"
    }
    fn name(&self) -> &'static str {
        "Passwordless sudo"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        let out = match runner.run("sudo", &["-n", "-l"]) {
            Ok(out) => out,
            Err(err) => return Outcome::unknown(err),
        };
        let text = out.combined();

        if text.contains("NOPASSWD") {
            Outcome::fail(
                "The sudo rules contain NOPASSWD: commands can run without a password.",
                "Remove the NOPASSWD rules in /etc/sudoers and /etc/sudoers.d with `sudo visudo`.",
            )
        } else if text.contains("password is required") {
            Outcome::pass("sudo requires a password.")
        } else if out.success {
            // The list came back without a password but there is no NOPASSWD:
            // that means a recently entered password is still cached.
            Outcome::pass("No NOPASSWD rule (sudo session is cached).")
        } else {
            Outcome::unknown(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::runner::MockRunner;

    const MISSING: &str = "The domain/default pair of (x, y) does not exist";

    #[test]
    fn automatic_login() {
        let cmd = format!("defaults read {LOGIN_WINDOW} autoLoginUser");

        let on = MockRunner::new().ok(&cmd, "alice");
        let outcome = AutoLogin.run(&on);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("alice"));

        let off = MockRunner::new().fail(&cmd, MISSING);
        assert_eq!(AutoLogin.run(&off).status, Status::Pass);

        let broken = MockRunner::new().fail(&cmd, "permission denied");
        assert_eq!(AutoLogin.run(&broken).status, Status::Unknown);
    }

    #[test]
    fn guest_account() {
        let cmd = format!("defaults read {LOGIN_WINDOW} GuestEnabled");
        assert_eq!(
            GuestAccount.run(&MockRunner::new().ok(&cmd, "1")).status,
            Status::Fail
        );
        assert_eq!(
            GuestAccount.run(&MockRunner::new().ok(&cmd, "0")).status,
            Status::Pass
        );
    }

    #[test]
    fn lock_delay_parsing() {
        // The real output starts with date and process information.
        let line = "2026-11-10 00:25:54.846 sysadminctl[73455:795705] screenLock delay is immediate";
        assert_eq!(parse_lock_delay(line), Some(LockDelay::Immediate));
        assert_eq!(
            parse_lock_delay("screenLock delay is 300 seconds"),
            Some(LockDelay::Seconds(300))
        );
        assert_eq!(parse_lock_delay("screenLock is off"), Some(LockDelay::Off));
        assert_eq!(parse_lock_delay("nonsense output"), None);
    }

    #[test]
    fn screen_lock_states() {
        let cmd = "sysadminctl -screenLock status";
        let status = |text: &str| ScreenLock.run(&MockRunner::new().ok_stderr(cmd, text)).status;

        assert_eq!(status("screenLock delay is immediate"), Status::Pass);
        assert_eq!(status("screenLock delay is 5 seconds"), Status::Pass);
        assert_eq!(status("screenLock delay is 900 seconds"), Status::Warn);
        assert_eq!(status("screenLock is off"), Status::Fail);
    }

    #[test]
    fn sudo_rules() {
        let cmd = "sudo -n -l";

        let asks = MockRunner::new().fail(cmd, "sudo: a password is required");
        assert_eq!(SudoNoPassword.run(&asks).status, Status::Pass);

        let nopasswd = MockRunner::new().ok(cmd, "(ALL) NOPASSWD: ALL");
        assert_eq!(SudoNoPassword.run(&nopasswd).status, Status::Fail);

        let cached = MockRunner::new().ok(cmd, "(ALL) ALL");
        assert_eq!(SudoNoPassword.run(&cached).status, Status::Pass);
    }
}
