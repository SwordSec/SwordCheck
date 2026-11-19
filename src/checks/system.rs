//! System protection checks: disk encryption, SIP, Gatekeeper, updates.

use super::{Check, Fix, Outcome, Pref, Severity, read_pref, stdout_of};
use crate::runner::CommandRunner;
use std::time::{SystemTime, UNIX_EPOCH};

const SOFTWARE_UPDATE: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

/// Is FileVault disk encryption on?
pub struct FileVault;

impl Check for FileVault {
    fn id(&self) -> &'static str {
        "filevault"
    }
    fn name(&self) -> &'static str {
        "FileVault (disk encryption)"
    }
    fn weight(&self) -> u32 {
        25
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.6.6")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match stdout_of(runner, "fdesetup", &["status"]) {
            // Output: "FileVault is On."
            Ok(out) if out.contains("FileVault is On") => {
                Outcome::pass("Disk encryption is enabled.")
            }
            Ok(out) => Outcome::fail(
                format!("FileVault is off ({out})."),
                "Turn it on in System Settings > Privacy & Security > FileVault.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Is System Integrity Protection (SIP) on?
pub struct Sip;

impl Check for Sip {
    fn id(&self) -> &'static str {
        "sip"
    }
    fn name(&self) -> &'static str {
        "System Integrity Protection (SIP)"
    }
    fn weight(&self) -> u32 {
        20
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cis(&self) -> Option<&'static str> {
        Some("5.1.2")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match stdout_of(runner, "csrutil", &["status"]) {
            // Output: "System Integrity Protection status: enabled."
            Ok(out) if out.contains("status: enabled") => Outcome::pass("SIP is enabled."),
            Ok(_) => Outcome::fail(
                "SIP is disabled.",
                "Run `csrutil enable` in Recovery mode to turn SIP back on.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Are Gatekeeper app assessments on?
pub struct Gatekeeper;

impl Check for Gatekeeper {
    fn id(&self) -> &'static str {
        "gatekeeper"
    }
    fn name(&self) -> &'static str {
        "Gatekeeper"
    }
    fn weight(&self) -> u32 {
        15
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.6.5")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match stdout_of(runner, "spctl", &["--status"]) {
            // Output: "assessments enabled"
            Ok(out) if out.contains("assessments enabled") => {
                Outcome::pass("App assessments are enabled.")
            }
            Ok(_) => Outcome::fail(
                "Gatekeeper is disabled.",
                "Enable it in System Settings > Privacy & Security.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Are automatic update checking and installation on?
pub struct AutoUpdate;

impl Check for AutoUpdate {
    fn id(&self) -> &'static str {
        "auto-update"
    }
    fn name(&self) -> &'static str {
        "Automatic updates"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cis(&self) -> Option<&'static str> {
        Some("1.2")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: "defaults",
            args: &["write", SOFTWARE_UPDATE, "AutomaticCheckEnabled", "-bool", "true"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        // (key, name to show to the user)
        const KEYS: [(&str, &str); 4] = [
            ("AutomaticCheckEnabled", "checking for updates"),
            ("AutomaticDownload", "automatic download"),
            ("AutomaticallyInstallMacOSUpdates", "installing macOS updates"),
            ("CriticalUpdateInstall", "installing security responses"),
        ];

        let mut disabled: Vec<&str> = Vec::new();
        let mut enabled = 0;
        let mut first_error: Option<String> = None;

        for (key, label) in KEYS {
            match read_pref(runner, SOFTWARE_UPDATE, key) {
                Pref::Value(value) if value == "0" => disabled.push(label),
                Pref::Value(_) => enabled += 1,
                // If the key is missing the macOS default applies; we don't judge it.
                Pref::Missing => {}
                Pref::Error(err) => first_error = first_error.or(Some(err)),
            }
        }

        if disabled.contains(&"checking for updates") {
            Outcome::fail(
                "Automatic checking for updates is off.",
                "Turn on Automatic Updates in System Settings > General > Software Update.",
            )
        } else if !disabled.is_empty() {
            Outcome::warn(
                format!("Disabled options: {}.", disabled.join(", ")),
                "Turn on all options under System Settings > General > Software Update > Automatic Updates.",
            )
        } else if enabled > 0 {
            Outcome::pass("Automatic update options are on.")
        } else {
            Outcome::unknown(
                first_error.unwrap_or_else(|| "Update preferences were not found.".to_string()),
            )
        }
    }
}

/// Are there updates waiting to be installed?
///
/// `softwareupdate -l` is slow because it queries over the network; instead
/// we read the count the system recorded at its last check.
pub struct PendingUpdates;

impl Check for PendingUpdates {
    fn id(&self) -> &'static str {
        "pending-updates"
    }
    fn name(&self) -> &'static str {
        "Pending updates"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("1.1")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        const ADVICE: &str = "Install the updates from System Settings > General > Software Update.";

        // Newer macOS versions keep the recommended updates as a list;
        // `plutil -extract` gives that list as JSON.
        let plist = format!("{SOFTWARE_UPDATE}.plist");
        let listed = runner
            .run(
                "plutil",
                &["-extract", "RecommendedUpdates", "json", "-o", "-", &plist],
            )
            .ok()
            .filter(|out| out.success)
            .and_then(|out| pending_update_names(&out.stdout));

        if let Some(names) = listed {
            return if names.is_empty() {
                Outcome::pass("No pending updates.")
            } else {
                Outcome::warn(format!("Waiting to be installed: {}.", names.join(", ")), ADVICE)
            };
        }

        // Older versions only record the count.
        match read_pref(runner, SOFTWARE_UPDATE, "LastRecommendedUpdatesAvailable") {
            Pref::Value(value) => match value.parse::<u32>() {
                Ok(0) => Outcome::pass("No pending updates."),
                Ok(count) => {
                    Outcome::warn(format!("{count} update(s) waiting to be installed."), ADVICE)
                }
                Err(_) => Outcome::unknown(format!("Unexpected value: {value}")),
            },
            Pref::Missing => Outcome::unknown("The update record was not found."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

/// Extracts the names of the pending updates from the `RecommendedUpdates`
/// JSON array. Upgrades to a new major version ("_major") are optional, so
/// they are not counted. Returns `None` if the input is not a valid JSON array.
fn pending_update_names(json: &str) -> Option<Vec<String>> {
    let updates: Vec<serde_json::Value> = serde_json::from_str(json).ok()?;
    Some(
        updates
            .iter()
            .filter(|update| {
                !update["Identifier"]
                    .as_str()
                    .is_some_and(|id| id.ends_with("_major"))
            })
            .map(|update| {
                update["Display Name"]
                    .as_str()
                    .unwrap_or("unnamed update")
                    .to_string()
            })
            .collect(),
    )
}

/// Are the XProtect malware signatures up to date?
pub struct XProtect;

/// We warn if the signatures are older than this many days.
const XPROTECT_MAX_AGE_DAYS: u64 = 45;

/// The locations where the XProtect bundle may be found (newer versions use the first).
const XPROTECT_BUNDLES: [&str; 2] = [
    "/var/protected/xprotect/XProtect.bundle",
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
];

impl Check for XProtect {
    fn id(&self) -> &'static str {
        "xprotect"
    }
    fn name(&self) -> &'static str {
        "XProtect signatures"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        // For each location collect the (modification time, version) pair and
        // pick the newest. `filter_map` drops the ones that fail.
        let newest = XPROTECT_BUNDLES
            .iter()
            .filter_map(|bundle| {
                let plist = format!("{bundle}/Contents/Info.plist");
                let modified: u64 = stdout_of(runner, "stat", &["-f", "%m", &plist])
                    .ok()?
                    .parse()
                    .ok()?;
                let info = format!("{bundle}/Contents/Info");
                let version = match read_pref(runner, &info, "CFBundleShortVersionString") {
                    Pref::Value(version) => version,
                    _ => "?".to_string(),
                };
                Some((modified, version))
            })
            .max_by_key(|(modified, _)| *modified);

        let Some((modified, version)) = newest else {
            return Outcome::unknown("The XProtect bundle was not found.");
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        xprotect_outcome(&version, age_in_days(now, modified))
    }
}

/// The difference in days between two Unix timestamps (never goes negative).
fn age_in_days(now: u64, then: u64) -> u64 {
    now.saturating_sub(then) / 86_400
}

fn xprotect_outcome(version: &str, age_days: u64) -> Outcome {
    if age_days <= XPROTECT_MAX_AGE_DAYS {
        Outcome::pass(format!("Version {version}, updated {age_days} days ago."))
    } else {
        Outcome::warn(
            format!("Version {version}, not updated for {age_days} days."),
            "Turn on the \"Install Security Responses and system files\" option under Automatic Updates.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::runner::MockRunner;

    const MISSING: &str = "The domain/default pair of (x, y) does not exist";

    fn pref_cmd(key: &str) -> String {
        format!("defaults read {SOFTWARE_UPDATE} {key}")
    }

    #[test]
    fn filevault_on_and_off() {
        let on = MockRunner::new().ok("fdesetup status", "FileVault is On.");
        assert_eq!(FileVault.run(&on).status, Status::Pass);

        let off = MockRunner::new().ok("fdesetup status", "FileVault is Off.");
        assert_eq!(FileVault.run(&off).status, Status::Fail);
    }

    #[test]
    fn fails_when_sip_and_gatekeeper_are_disabled() {
        let runner = MockRunner::new()
            .ok(
                "csrutil status",
                "System Integrity Protection status: disabled.",
            )
            .ok("spctl --status", "assessments disabled");
        assert_eq!(Sip.run(&runner).status, Status::Fail);
        assert_eq!(Gatekeeper.run(&runner).status, Status::Fail);
    }

    #[test]
    fn auto_update_does_not_penalize_missing_key() {
        // The real state on this machine: the check key is missing, the others are 1.
        let runner = MockRunner::new()
            .fail(&pref_cmd("AutomaticCheckEnabled"), MISSING)
            .ok(&pref_cmd("AutomaticDownload"), "1")
            .ok(&pref_cmd("AutomaticallyInstallMacOSUpdates"), "1")
            .ok(&pref_cmd("CriticalUpdateInstall"), "1");
        assert_eq!(AutoUpdate.run(&runner).status, Status::Pass);
    }

    #[test]
    fn auto_update_distinguishes_disabled_options() {
        let check_off = MockRunner::new()
            .ok(&pref_cmd("AutomaticCheckEnabled"), "0")
            .ok(&pref_cmd("AutomaticDownload"), "1")
            .ok(&pref_cmd("AutomaticallyInstallMacOSUpdates"), "1")
            .ok(&pref_cmd("CriticalUpdateInstall"), "1");
        assert_eq!(AutoUpdate.run(&check_off).status, Status::Fail);

        let install_off = MockRunner::new()
            .ok(&pref_cmd("AutomaticCheckEnabled"), "1")
            .ok(&pref_cmd("AutomaticDownload"), "1")
            .ok(&pref_cmd("AutomaticallyInstallMacOSUpdates"), "0")
            .ok(&pref_cmd("CriticalUpdateInstall"), "1");
        let outcome = AutoUpdate.run(&install_off);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("installing macOS updates"));
    }

    #[test]
    fn pending_update_count() {
        let none = MockRunner::new().ok(&pref_cmd("LastRecommendedUpdatesAvailable"), "0");
        assert_eq!(PendingUpdates.run(&none).status, Status::Pass);

        let two = MockRunner::new().ok(&pref_cmd("LastRecommendedUpdatesAvailable"), "2");
        assert_eq!(PendingUpdates.run(&two).status, Status::Warn);
    }

    #[test]
    fn pending_update_list() {
        // A shortened version of the real output taken from this machine.
        let json = r#"[
            {"Identifier":"Safari27.2TahoeAuto","Display Name":"Safari"},
            {"Identifier":"MSU_UPDATE_25G332_patch_26.7.2_minor","Display Name":"macOS Tahoe 26.7.2"},
            {"Identifier":"MSU_UPDATE_26B123_patch_27.2_major","Display Name":"macOS 27.2"}
        ]"#;
        assert_eq!(
            pending_update_names(json).unwrap(),
            ["Safari", "macOS Tahoe 26.7.2"],
            "a major version upgrade is not counted"
        );
        assert_eq!(pending_update_names("[]").unwrap(), Vec::<String>::new());
        assert_eq!(pending_update_names("garbage"), None);

        let cmd = format!("plutil -extract RecommendedUpdates json -o - {SOFTWARE_UPDATE}.plist");
        let pending = MockRunner::new().ok(&cmd, json);
        let outcome = PendingUpdates.run(&pending);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("Safari"));

        let none = MockRunner::new().ok(&cmd, "[]");
        assert_eq!(PendingUpdates.run(&none).status, Status::Pass);
    }

    #[test]
    fn xprotect_age() {
        assert_eq!(age_in_days(86_400 * 10, 86_400 * 3), 7);
        assert_eq!(age_in_days(5, 100), 0, "a future date does not go negative");
        assert_eq!(xprotect_outcome("5371", 10).status, Status::Pass);
        assert_eq!(xprotect_outcome("5371", 90).status, Status::Warn);
    }
}
