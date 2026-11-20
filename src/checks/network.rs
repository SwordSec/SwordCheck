//! Network checks: firewall, remote login and sharing services.

use super::{
    Check, FILE_SHARING, Fix, Listener, Outcome, Pref, SCREEN_SHARING, SSHD, Severity, daemon_enabled, listeners,
    netstat, read_pref, unrecognised,
};
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
        let out = match runner.run(FIREWALL_TOOL, &["--getglobalstate"]) {
            Ok(out) => out,
            Err(err) => return Outcome::unknown(err),
        };
        match firewall_enabled(&out.combined()) {
            Some(true) => Outcome::pass("The application firewall is on."),
            Some(false) => Outcome::fail(
                "The application firewall is off.",
                "Turn it on in System Settings > Network > Firewall.",
            ),
            None => unrecognised("socketfilterfw --getglobalstate", &out),
        }
    }
}

/// Interprets `socketfilterfw --getglobalstate`:
/// - "Firewall is enabled. (State = 1)"
/// - "Firewall is disabled. (State = 0)"
/// - State = 2 is "block all incoming connections", which is also on.
///
/// `None` means the output was not recognised.
fn firewall_enabled(output: &str) -> Option<bool> {
    let output = output.to_lowercase();
    if output.contains("state = 0") || output.contains("firewall is disabled") {
        Some(false)
    } else if output.contains("state = 1")
        || output.contains("state = 2")
        || output.contains("firewall is enabled")
    {
        Some(true)
    } else {
        None
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
        let out = match runner.run(FIREWALL_TOOL, &["--getstealthmode"]) {
            Ok(out) => out,
            Err(err) => return Outcome::unknown(err),
        };
        match stealth_enabled(&out.combined()) {
            Some(true) => Outcome::pass("Stealth mode is on."),
            Some(false) => Outcome::warn(
                "Stealth mode is off.",
                "Turn on stealth mode in System Settings > Network > Firewall > Options.",
            ),
            None => unrecognised("socketfilterfw --getstealthmode", &out),
        }
    }
}

/// Depending on the macOS version the output is either
/// "Firewall stealth mode is on" / "... is off" or
/// "Stealth mode enabled" / "Stealth mode disabled".
///
/// `None` means the output was not recognised.
fn stealth_enabled(output: &str) -> Option<bool> {
    let output = output.to_lowercase();
    if !output.contains("stealth mode") {
        None
    } else if output.contains("is off") || output.contains("disabled") {
        Some(false)
    } else if output.contains("is on") || output.contains("enabled") {
        Some(true)
    } else {
        None
    }
}

/// Is TCP port 22 (SSH) reachable from the network?
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
    // No suggested command: `sudo systemsetup -f -setremotelogin off` only
    // works when the terminal has Full Disk Access (macOS 13 and later), so
    // on its own it is not a dependable remedy. The advice text covers it.

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match netstat(runner).and_then(|out| listeners(&out)) {
            Ok(found) => match exposure(&found, 22) {
                Exposure::Network => Outcome::warn(
                    "Port 22 is listening (SSH is on).",
                    "If you don't need it, turn off Remote Login in System Settings > General > Sharing. \
                     The command-line equivalent, `sudo systemsetup -f -setremotelogin off`, only works on \
                     macOS 13 and later if your terminal app has Full Disk Access \
                     (System Settings > Privacy & Security > Full Disk Access).",
                ),
                Exposure::LoopbackOnly => Outcome::pass(
                    "Port 22 is listening on the loopback interface only; it is not reachable from the network.",
                ),
                Exposure::Closed => Outcome::pass("Port 22 is not listening."),
            },
            // No usable socket list: ask launchd whether the service is on.
            Err(err) => match daemon_enabled(runner, &SSHD) {
                Ok(true) => Outcome::warn(
                    "Remote Login is switched on in launchd (the socket list was unavailable).",
                    "If you don't need it, turn off Remote Login in System Settings > General > Sharing.",
                ),
                Ok(false) => Outcome::pass("Remote Login is switched off in launchd (the socket list was unavailable)."),
                Err(launchd) => Outcome::unknown(format!("{err} {launchd}")),
            },
        }
    }
}

/// How far a port can be reached.
#[derive(Debug, PartialEq, Eq)]
enum Exposure {
    /// Nothing is listening on it.
    Closed,
    /// Only reachable from this Mac itself (e.g. an SSH tunnel).
    LoopbackOnly,
    /// Listening on an address other machines can reach.
    Network,
}

fn exposure(listeners: &[Listener], port: u16) -> Exposure {
    let mut on_port = listeners.iter().filter(|listener| listener.port == port).peekable();
    if on_port.peek().is_none() {
        Exposure::Closed
    } else if on_port.all(|listener| listener.loopback) {
        Exposure::LoopbackOnly
    } else {
        Exposure::Network
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
        match netstat(runner).and_then(|out| listeners(&out)) {
            Ok(found) => {
                // A port bound to loopback only (e.g. a VNC server reached
                // through an SSH tunnel) is not exposed to the network.
                let open: Vec<&str> = SHARING_PORTS
                    .iter()
                    .filter(|(port, _)| exposure(&found, *port) == Exposure::Network)
                    .map(|(_, name)| *name)
                    .collect();

                if open.is_empty() {
                    Outcome::pass("Screen and file sharing are not reachable from the network.")
                } else {
                    Outcome::warn(
                        format!("Open services: {}.", open.join(", ")),
                        "Turn off the services you don't use (Screen Sharing, File Sharing, Remote Management) \
                         in System Settings > General > Sharing.",
                    )
                }
            }
            // No usable socket list: ask launchd which services are on.
            Err(err) => {
                let services = [("Screen Sharing", &SCREEN_SHARING), ("File Sharing (SMB)", &FILE_SHARING)];
                let mut enabled = Vec::new();
                for (name, daemon) in services {
                    match daemon_enabled(runner, daemon) {
                        Ok(true) => enabled.push(name),
                        Ok(false) => {}
                        Err(launchd) => return Outcome::unknown(format!("{err} {launchd}")),
                    }
                }
                if enabled.is_empty() {
                    Outcome::pass(
                        "Screen Sharing and File Sharing are switched off in launchd (the socket list was unavailable).",
                    )
                } else {
                    Outcome::warn(
                        format!("Switched on in launchd: {} (the socket list was unavailable).", enabled.join(", ")),
                        "Turn off the services you don't use (Screen Sharing, File Sharing, Remote Management) \
                         in System Settings > General > Sharing.",
                    )
                }
            }
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
                "Choose \"Contacts Only\" or \"No One\" for AirDrop in System Settings > General > AirDrop & Handoff.",
            ),
            // "Off" is what the "No One" choice is stored as.
            Pref::Value(mode) if mode == "Contacts Only" || mode == "Off" => {
                Outcome::pass(format!("AirDrop mode: {mode}."))
            }
            Pref::Value(mode) => Outcome::unknown(format!("Unrecognised AirDrop mode: {mode:?}.")),
            // The key only appears once the user picks a mode. Until then
            // macOS uses its default, which is never "Everyone": that mode
            // has to be chosen explicitly.
            Pref::Missing => Outcome::pass(
                "AirDrop visibility was never changed from the macOS default, which is not open to everyone.",
            ),
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
    const OVERRIDES: &str = "launchctl print-disabled system";

    fn default_of(plist: &str) -> String {
        format!("plutil -extract Disabled raw -o - {plist}")
    }

    #[test]
    fn empty_socket_list_falls_back_to_launchd() {
        // netstat prints nothing but exits 0: that is not "port 22 is closed".
        let silent = || MockRunner::new().ok(NETSTAT, "");

        let on = silent().ok(OVERRIDES, "disabled services = {\n\t\"com.openssh.sshd\" => enabled\n}");
        let outcome = Ssh.run(&on);
        assert_eq!(outcome.status, Status::Warn, "{}", outcome.detail);

        let off = silent().ok(OVERRIDES, "disabled services = {\n\t\"com.openssh.sshd\" => disabled\n}");
        assert_eq!(Ssh.run(&off).status, Status::Pass);

        // No override: the service's own plist decides.
        let other = "disabled services = {\n\t\"com.apple.ftpd\" => disabled\n}";
        let by_default = silent().ok(OVERRIDES, other).ok(&default_of(SSHD.plist), "true");
        assert_eq!(Ssh.run(&by_default).status, Status::Pass);
        let default_on = silent().ok(OVERRIDES, other).ok(&default_of(SSHD.plist), "false");
        assert_eq!(Ssh.run(&default_on).status, Status::Warn);

        // Neither source is usable: no verdict.
        assert_eq!(Ssh.run(&silent()).status, Status::Unknown);
        assert_eq!(Ssh.run(&silent().ok(OVERRIDES, other)).status, Status::Unknown);
        assert_eq!(Ssh.run(&silent().ok(OVERRIDES, "")).status, Status::Unknown);
    }

    #[test]
    fn sharing_falls_back_to_launchd() {
        let silent = || MockRunner::new().ok(NETSTAT, "");
        let state = |screen: &str, files: &str| {
            format!("disabled services = {{\n\t\"com.apple.screensharing\" => {screen}\n\t\"com.apple.smbd\" => {files}\n}}")
        };
        assert_eq!(Sharing.run(&silent().ok(OVERRIDES, &state("disabled", "disabled"))).status, Status::Pass);

        let outcome = Sharing.run(&silent().ok(OVERRIDES, &state("disabled", "enabled")));
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("File Sharing") && !outcome.detail.contains("Screen Sharing"), "{}", outcome.detail);

        assert_eq!(Sharing.run(&silent()).status, Status::Unknown);
    }

    #[test]
    fn stealth_mode_outputs() {
        assert_eq!(stealth_enabled("Firewall stealth mode is on"), Some(true));
        assert_eq!(stealth_enabled("Stealth mode enabled"), Some(true));
        assert_eq!(stealth_enabled("Firewall stealth mode is off"), Some(false));
        assert_eq!(stealth_enabled("Stealth mode disabled"), Some(false));
        assert_eq!(stealth_enabled(""), None);
        assert_eq!(stealth_enabled("usage: socketfilterfw [options]"), None);
    }

    #[test]
    fn stealth_mode_states() {
        let cmd = format!("{FIREWALL_TOOL} --getstealthmode");
        let status = |text: &str| StealthMode.run(&MockRunner::new().ok(&cmd, text)).status;
        assert_eq!(status("Firewall stealth mode is on"), Status::Pass);
        assert_eq!(status("Firewall stealth mode is off"), Status::Warn);
        // Unrecognised output is not a verdict.
        assert_eq!(status(""), Status::Unknown);
        assert_eq!(status("something new"), Status::Unknown);
    }

    #[test]
    fn fails_when_firewall_is_off() {
        let cmd = format!("{FIREWALL_TOOL} --getglobalstate");
        let off = MockRunner::new().ok(&cmd, "Firewall is disabled. (State = 0)");
        assert_eq!(Firewall.run(&off).status, Status::Fail);

        let on = MockRunner::new().ok(&cmd, "Firewall is enabled. (State = 1)");
        assert_eq!(Firewall.run(&on).status, Status::Pass);

        let block_all = MockRunner::new().ok(&cmd, "Firewall is on. (State = 2)");
        assert_eq!(Firewall.run(&block_all).status, Status::Pass);
    }

    #[test]
    fn firewall_unrecognised_output_is_unknown() {
        let cmd = format!("{FIREWALL_TOOL} --getglobalstate");

        let empty = Firewall.run(&MockRunner::new().ok(&cmd, ""));
        assert_eq!(empty.status, Status::Unknown);

        let odd = Firewall.run(&MockRunner::new().ok(&cmd, "Firewall settings are managed"));
        assert_eq!(odd.status, Status::Unknown);
        assert!(odd.detail.contains("Firewall settings are managed"), "{}", odd.detail);

        let failed = Firewall.run(&MockRunner::new().fail(&cmd, "not permitted"));
        assert_eq!(failed.status, Status::Unknown);
        assert!(failed.detail.contains("not permitted"));
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
    fn loopback_listeners_are_not_exposed() {
        // An SSH tunnel endpoint and a local-only VNC server.
        let runner = MockRunner::new().ok(
            NETSTAT,
            "tcp4  0  0  127.0.0.1.22    *.*  LISTEN\n\
             tcp6  0  0  ::1.22          *.*  LISTEN\n\
             tcp4  0  0  127.0.0.1.5900  *.*  LISTEN\n\
             tcp6  0  0  ::1.445         *.*  LISTEN",
        );
        let ssh = Ssh.run(&runner);
        assert_eq!(ssh.status, Status::Pass);
        assert!(ssh.detail.contains("loopback"), "{}", ssh.detail);
        assert_eq!(Sharing.run(&runner).status, Status::Pass);

        // The same port on a real interface as well is exposed.
        let both = MockRunner::new().ok(
            NETSTAT,
            "tcp4  0  0  127.0.0.1.22      *.*  LISTEN\n\
             tcp4  0  0  192.168.1.10.22   *.*  LISTEN\n\
             tcp4  0  0  127.0.0.1.5900    *.*  LISTEN\n\
             tcp6  0  0  fe80::1%en0.5900  *.*  LISTEN",
        );
        assert_eq!(Ssh.run(&both).status, Status::Warn);
        assert_eq!(Sharing.run(&both).status, Status::Warn);
    }

    #[test]
    fn changed_netstat_layout_is_unknown_not_pass() {
        // An extra column shifts the address and state fields.
        let shifted = MockRunner::new().ok(
            NETSTAT,
            "Proto Recv-Q Send-Q Flags Local Address Foreign Address (state)\n\
             tcp4  0  0  0x1  *.22  *.*  LISTEN",
        );
        assert_eq!(Ssh.run(&shifted).status, Status::Unknown);
        assert_eq!(Sharing.run(&shifted).status, Status::Unknown);

        let empty = MockRunner::new().ok(NETSTAT, "");
        assert_eq!(Ssh.run(&empty).status, Status::Unknown);
        assert_eq!(Sharing.run(&empty).status, Status::Unknown);

        let garbage = MockRunner::new().ok(NETSTAT, "netstat: unexpected message");
        let outcome = Ssh.run(&garbage);
        assert_eq!(outcome.status, Status::Unknown);
        assert!(outcome.detail.contains("unexpected message"), "{}", outcome.detail);

        // A failed netstat is not trusted even if it printed something.
        let failed = MockRunner::new().fail_stdout(NETSTAT, "tcp4  0  0  *.80  *.*  LISTEN");
        assert_eq!(Ssh.run(&failed).status, Status::Unknown);
    }

    #[test]
    fn ssh_has_no_single_command_remedy() {
        // `systemsetup` needs Full Disk Access; the advice must say so.
        assert!(Ssh.fix().is_none());
        let runner = MockRunner::new().ok(NETSTAT, "tcp4  0  0  *.22  *.*  LISTEN");
        let advice = Ssh.run(&runner).advice;
        assert!(advice.contains("System Settings > General > Sharing"));
        assert!(advice.contains("Full Disk Access"));
    }

    #[test]
    fn airdrop_modes() {
        let cmd = "defaults read com.apple.sharingd DiscoverableMode";
        let everyone = MockRunner::new().ok(cmd, "Everyone");
        assert_eq!(AirDrop.run(&everyone).status, Status::Warn);

        let off = MockRunner::new().ok(cmd, "Off");
        assert_eq!(AirDrop.run(&off).status, Status::Pass);

        let contacts = MockRunner::new().ok(cmd, "Contacts Only");
        assert_eq!(AirDrop.run(&contacts).status, Status::Pass);

        let odd = MockRunner::new().ok(cmd, "");
        assert_eq!(AirDrop.run(&odd).status, Status::Unknown);
    }

    #[test]
    fn airdrop_default_is_not_unknown() {
        let cmd = "defaults read com.apple.sharingd DiscoverableMode";
        for message in [
            "The domain/default pair of (com.apple.sharingd, DiscoverableMode) does not exist",
            "Error: Could not find key 'DiscoverableMode' in domain 'com.apple.sharingd'.",
        ] {
            let never_set = MockRunner::new().fail(cmd, message);
            let outcome = AirDrop.run(&never_set);
            assert_eq!(outcome.status, Status::Pass);
            assert!(outcome.detail.contains("default"), "{}", outcome.detail);
        }

        let broken = MockRunner::new().fail(cmd, "permission denied");
        assert_eq!(AirDrop.run(&broken).status, Status::Unknown);
    }
}
