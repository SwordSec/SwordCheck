//! Network checks: firewall, remote login and sharing services.

use super::{Check, Fix, Outcome, Pref, Severity, listening_on, netstat, read_pref, stdout_of};
use crate::runner::CommandRunner;

const FIREWALL_TOOL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Is the application firewall on?
pub struct Firewall;

impl Check for Firewall {
    fn id(&self) -> &'static str {
        "firewall"
    }
    fn name(&self) -> &'static str {
        "Firewall"
    }
    fn weight(&self) -> u32 {
        20
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.2.1")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: FIREWALL_TOOL,
            args: &["--setglobalstate", "on"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match stdout_of(runner, FIREWALL_TOOL, &["--getglobalstate"]) {
            // Output: "Firewall is enabled. (State = 1)"
            Ok(out) if out.contains("is enabled") => {
                Outcome::pass("The application firewall is on.")
            }
            Ok(_) => Outcome::fail(
                "The application firewall is off.",
                "Turn it on in System Settings > Network > Firewall.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Is the firewall's stealth mode (not responding to pings and port scans) on?
pub struct StealthMode;

impl Check for StealthMode {
    fn id(&self) -> &'static str {
        "stealth"
    }
    fn name(&self) -> &'static str {
        "Firewall stealth mode"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.2.2")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: FIREWALL_TOOL,
            args: &["--setstealthmode", "on"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match stdout_of(runner, FIREWALL_TOOL, &["--getstealthmode"]) {
            Ok(out) if stealth_enabled(&out) => Outcome::pass("Stealth mode is on."),
            Ok(_) => Outcome::warn(
                "Stealth mode is off.",
                "Turn on stealth mode in System Settings > Network > Firewall > Options.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Depending on the macOS version the output may be either
/// "Firewall stealth mode is on" or "Stealth mode enabled".
fn stealth_enabled(output: &str) -> bool {
    let output = output.to_lowercase();
    output.contains("is on") || (output.contains("enabled") && !output.contains("disabled"))
}

/// Is TCP port 22 (SSH) being listened on?
pub struct Ssh;

impl Check for Ssh {
    fn id(&self) -> &'static str {
        "ssh"
    }
    fn name(&self) -> &'static str {
        "Remote Login (SSH)"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.3.3")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: "systemsetup",
            args: &["-f", "-setremotelogin", "off"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match netstat(runner) {
            Ok(out) if listening_on(&out, 22) => Outcome::warn(
                "Port 22 is listening (SSH is on).",
                "If you don't need it, turn off Remote Login in System Settings > General > Sharing.",
            ),
            Ok(_) => Outcome::pass("Port 22 is not listening."),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Are services such as screen/file sharing exposed to the network?
pub struct Sharing;

/// (port, service name)
const SHARING_PORTS: [(u16, &str); 4] = [
    (5900, "Screen Sharing (5900)"),
    (445, "File Sharing/SMB (445)"),
    (548, "File Sharing/AFP (548)"),
    (3283, "Remote Management (3283)"),
];

impl Check for Sharing {
    fn id(&self) -> &'static str {
        "sharing"
    }
    fn name(&self) -> &'static str {
        "Sharing services"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.3.3")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match netstat(runner) {
            Ok(out) => {
                let open: Vec<&str> = SHARING_PORTS
                    .iter()
                    .filter(|(port, _)| listening_on(&out, *port))
                    .map(|(_, name)| *name)
                    .collect();

                if open.is_empty() {
                    Outcome::pass("Screen and file sharing are off.")
                } else {
                    Outcome::warn(
                        format!("Open services: {}.", open.join(", ")),
                        "Turn off the services you don't use in System Settings > General > Sharing.",
                    )
                }
            }
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Is AirDrop open to everyone?
pub struct AirDrop;

impl Check for AirDrop {
    fn id(&self) -> &'static str {
        "airdrop"
    }
    fn name(&self) -> &'static str {
        "AirDrop visibility"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.3.1.1")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match read_pref(runner, "com.apple.sharingd", "DiscoverableMode") {
            Pref::Value(mode) if mode == "Everyone" => Outcome::warn(
                "AirDrop is open to everyone.",
                "Choose \"Contacts Only\" in System Settings > General > AirDrop & Handoff.",
            ),
            Pref::Value(mode) => Outcome::pass(format!("AirDrop mode: {mode}.")),
            Pref::Missing => Outcome::unknown("The AirDrop setting was not found."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::runner::MockRunner;

    const NETSTAT: &str = "netstat -an -p tcp";

    #[test]
    fn stealth_mode_outputs() {
        assert!(stealth_enabled("Firewall stealth mode is on"));
        assert!(stealth_enabled("Stealth mode enabled"));
        assert!(!stealth_enabled("Firewall stealth mode is off"));
        assert!(!stealth_enabled("Stealth mode disabled"));
    }

    #[test]
    fn fails_when_firewall_is_off() {
        let cmd = format!("{FIREWALL_TOOL} --getglobalstate");
        let off = MockRunner::new().ok(&cmd, "Firewall is disabled. (State = 0)");
        assert_eq!(Firewall.run(&off).status, Status::Fail);

        let on = MockRunner::new().ok(&cmd, "Firewall is enabled. (State = 1)");
        assert_eq!(Firewall.run(&on).status, Status::Pass);
    }

    #[test]
    fn ssh_and_sharing_ports() {
        let runner = MockRunner::new().ok(
            NETSTAT,
            "tcp4  0  0  *.22    *.*  LISTEN\n\
             tcp4  0  0  *.5900  *.*  LISTEN\n\
             tcp4  0  0  *.5000  *.*  LISTEN",
        );
        assert_eq!(Ssh.run(&runner).status, Status::Warn);

        let sharing = Sharing.run(&runner);
        assert_eq!(sharing.status, Status::Warn);
        assert!(sharing.detail.contains("Screen Sharing"));
        assert!(!sharing.detail.contains("SMB"));
    }

    #[test]
    fn passes_when_ports_are_closed() {
        let runner = MockRunner::new().ok(NETSTAT, "tcp4  0  0  127.0.0.1.5000  *.*  LISTEN");
        assert_eq!(Ssh.run(&runner).status, Status::Pass);
        assert_eq!(Sharing.run(&runner).status, Status::Pass);
    }

    #[test]
    fn airdrop_modes() {
        let cmd = "defaults read com.apple.sharingd DiscoverableMode";
        let everyone = MockRunner::new().ok(cmd, "Everyone");
        assert_eq!(AirDrop.run(&everyone).status, Status::Warn);

        let off = MockRunner::new().ok(cmd, "Off");
        assert_eq!(AirDrop.run(&off).status, Status::Pass);
    }
}
