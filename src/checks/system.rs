//! System protection checks: disk encryption, SIP, Gatekeeper, updates.

use super::{Check, Outcome, Pref, Severity, one_line, read_pref, stdout_of, unrecognised};
use crate::runner::CommandRunner;
use std::time::{SystemTime, UNIX_EPOCH};

const SOFTWARE_UPDATE: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

/// The current time as a Unix timestamp.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

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
        let out = match runner.run("fdesetup", &["status"]) {
            Ok(out) => out,
            Err(err) => return Outcome::unknown(err),
        };
        let text = out.combined();
        // Output: "FileVault is On." / "FileVault is Off.", possibly followed
        // by a line about encryption or decryption being in progress.
        if text.contains("FileVault is On") {
            // FileVault still says "On" while it decrypts the disk, which is
            // what turning it off does: the disk is on its way to plain text.
            if text.contains("Decryption") {
                Outcome::fail(
                    format!(
                        "FileVault is being turned off: the disk is being decrypted ({}).",
                        one_line(&text)
                    ),
                    "Turn FileVault back on in System Settings > Privacy & Security > FileVault.",
                )
            } else if text.contains("in progress") {
                Outcome::pass(format!("Disk encryption is enabled ({}).", one_line(&text)))
            } else {
                Outcome::pass("Disk encryption is enabled.")
            }
        } else if text.contains("FileVault is Off") {
            Outcome::fail(
                format!("FileVault is off ({}).", one_line(&text)),
                "Turn it on in System Settings > Privacy & Security > FileVault.",
            )
        } else {
            unrecognised("fdesetup status", &out)
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
        const ADVICE: &str = "Start the Mac in Recovery mode, open Terminal from the Utilities menu, \
             run `csrutil enable` and restart.";

        let out = match runner.run("csrutil", &["status"]) {
            Ok(out) => out,
            Err(err) => return Outcome::unknown(err),
        };
        let text = out.combined();
        // Output: "System Integrity Protection status: enabled." or
        // "... status: disabled.". When only some protections were turned
        // off the status is "unknown (Custom Configuration)." (older
        // releases: "enabled (Custom Configuration).") followed by a list.
        if text.contains("Custom Configuration") {
            Outcome::fail(
                "SIP has a custom configuration: some of its protections are turned off.",
                ADVICE,
            )
        } else if text.contains("status: enabled") {
            Outcome::pass("SIP is enabled.")
        } else if text.contains("status: disabled") {
            Outcome::fail("SIP is disabled.", ADVICE)
        } else {
            unrecognised("csrutil status", &out)
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
        let out = match runner.run("spctl", &["--status"]) {
            Ok(out) => out,
            Err(err) => return Outcome::unknown(err),
        };
        // Output: "assessments enabled" or "assessments disabled". `spctl`
        // exits with a non-zero code in the disabled case, so the exit code
        // alone does not tell an answer from an error; the text does.
        let text = out.combined();
        if text.contains("assessments enabled") {
            Outcome::pass("App assessments are enabled.")
        } else if text.contains("assessments disabled") {
            Outcome::fail(
                "Gatekeeper is disabled.",
                "In System Settings > Privacy & Security, under \"Allow applications from\", \
                 choose \"App Store & Known Developers\" (or \"App Store\").",
            )
        } else {
            unrecognised("spctl --status", &out)
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
    // No suggested command: the check looks at four separate preferences, so
    // no single `defaults write` is a complete remedy. The advice text gives
    // the System Settings path that covers all of them.

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        const ADVICE: &str = "Open System Settings > General > Software Update, click the (i) button next to \
             \"Automatic Updates\" and turn on every option: \"Download new updates when available\", \
             \"Install macOS updates\", \"Install application updates from the App Store\" and \
             \"Install Security Responses and system files\"; then click Done.";

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
                Pref::Value(value) => match value.as_str() {
                    "0" | "false" | "NO" => disabled.push(label),
                    "1" | "true" | "YES" => enabled += 1,
                    other => {
                        first_error.get_or_insert(format!("Unexpected value for {key}: {other:?}"));
                    }
                },
                // If the key is missing the macOS default applies; we don't judge it.
                Pref::Missing => {}
                Pref::Error(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }

        if disabled.contains(&"checking for updates") {
            Outcome::fail("Automatic checking for updates is off.", ADVICE)
        } else if !disabled.is_empty() {
            Outcome::warn(format!("Disabled options: {}.", disabled.join(", ")), ADVICE)
        } else if let Some(err) = first_error {
            // Some option could not be read, so "all on" would be a guess.
            Outcome::unknown(err)
        } else if enabled > 0 {
            Outcome::pass("Automatic update options are on.")
        } else {
            Outcome::unknown("Update preferences were not found.")
        }
    }
}

/// Are there updates waiting to be installed?
///
/// `softwareupdate -l` is slow because it queries over the network; instead
/// we read the list the system recorded at its last check. That record is
/// only as good as it is recent, so we also look at when the last successful
/// check took place.
pub struct PendingUpdates;

/// If the last successful update check is older than this many days, the
/// recorded list of pending updates is not trusted.
const MAX_CHECK_AGE_DAYS: u64 = 14;

/// What the system recorded about pending updates.
#[derive(Debug, PartialEq, Eq)]
enum Pending {
    /// Newer macOS versions keep the recommended updates as a list.
    Names(Vec<String>),
    /// Older versions only record the count.
    Count(u32),
}

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
        match recorded_pending(runner) {
            Ok(pending) => pending_outcome(&pending, last_check_age_days(runner, unix_now())),
            Err(detail) => Outcome::unknown(detail),
        }
    }
}

/// Reads the pending updates the system recorded at its last check.
fn recorded_pending(runner: &dyn CommandRunner) -> Result<Pending, String> {
    // `plutil -extract` gives the list as JSON.
    let plist = format!("{SOFTWARE_UPDATE}.plist");
    let listed = runner
        .run("plutil", &["-extract", "RecommendedUpdates", "json", "-o", "-", &plist])
        .ok()
        .filter(|out| out.success)
        .and_then(|out| pending_update_names(&out.stdout));
    if let Some(names) = listed {
        return Ok(Pending::Names(names));
    }

    match read_pref(runner, SOFTWARE_UPDATE, "LastRecommendedUpdatesAvailable") {
        Pref::Value(value) => value
            .parse::<u32>()
            .map(Pending::Count)
            .map_err(|_| format!("Unexpected value: {value}")),
        Pref::Missing => Err("The update record was not found.".to_string()),
        Pref::Error(err) => Err(err),
    }
}

/// How many days ago macOS last completed an update check, according to the
/// Software Update preferences. `Err` describes why that is not known.
fn last_check_age_days(runner: &dyn CommandRunner, now: u64) -> Result<u64, String> {
    let plist = format!("{SOFTWARE_UPDATE}.plist");
    // `raw` prints a date as ISO 8601 ("2026-11-20T08:09:58Z").
    for key in ["LastSuccessfulDate", "LastFullSuccessfulDate"] {
        let out = runner.run("plutil", &["-extract", key, "raw", "-o", "-", &plist])?;
        if !out.success {
            continue; // The key is missing; try the next one.
        }
        return parse_timestamp(&out.stdout)
            .map(|checked| age_in_days(now, checked))
            .ok_or_else(|| format!("unrecognised date for {key}: {:?}", out.stdout));
    }
    Err("no successful check is recorded".to_string())
}

/// Parses the date formats macOS tools print: ISO 8601 from `plutil`
/// ("2026-11-20T08:09:58Z") and the `defaults read` style
/// ("2026-11-20 08:09:58 +0000"). Returns a Unix timestamp.
fn parse_timestamp(text: &str) -> Option<u64> {
    let text = text.trim();
    let parsed = chrono::DateTime::parse_from_rfc3339(text)
        .or_else(|_| chrono::DateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S %z"))
        .ok()?;
    u64::try_from(parsed.timestamp()).ok()
}

/// Turns the recorded list and the age of the last check into a verdict.
fn pending_outcome(pending: &Pending, check_age_days: Result<u64, String>) -> Outcome {
    const ADVICE: &str = "Install the updates from System Settings > General > Software Update.";
    const ADVICE_STALE: &str = "Open System Settings > General > Software Update so that macOS checks for updates now, \
         and turn on automatic checking there (the (i) button next to \"Automatic Updates\").";

    let waiting = match pending {
        Pending::Names(names) if !names.is_empty() => Some(format!("Waiting to be installed: {}.", names.join(", "))),
        Pending::Count(count) if *count > 0 => Some(format!("{count} update(s) waiting to be installed.")),
        _ => None,
    };

    // Known pending updates are a finding however old the record is.
    if let Some(mut detail) = waiting {
        if let Ok(age) = &check_age_days
            && *age > MAX_CHECK_AGE_DAYS
        {
            detail.push_str(&format!(
                " The last successful check was {age} days ago, so there may be more."
            ));
        }
        return Outcome::warn(detail, ADVICE);
    }

    // An empty list only means "up to date" if the check behind it is recent.
    match check_age_days {
        Ok(age) if age <= MAX_CHECK_AGE_DAYS => Outcome::pass(match age {
            0 => "No pending updates (last checked today).".to_string(),
            1 => "No pending updates (last checked yesterday).".to_string(),
            _ => format!("No pending updates (last checked {age} days ago)."),
        }),
        Ok(age) => Outcome::warn(
            format!(
                "No pending updates are recorded, but macOS last checked successfully {age} days ago; \
                 the record is out of date."
            ),
            ADVICE_STALE,
        ),
        Err(reason) => Outcome::unknown(format!(
            "No pending updates are recorded, but when macOS last checked could not be determined ({reason})."
        )),
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
            .filter(|update| !update["Identifier"].as_str().is_some_and(|id| id.ends_with("_major")))
            .map(|update| update["Display Name"].as_str().unwrap_or("unnamed update").to_string())
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
                let modified: u64 = stdout_of(runner, "stat", &["-f", "%m", &plist]).ok()?.parse().ok()?;
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

        xprotect_outcome(&version, age_in_days(unix_now(), modified))
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
            "Open System Settings > General > Software Update, click the (i) button next to \
             \"Automatic Updates\" and turn on \"Install Security Responses and system files\".",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::runner::MockRunner;

    const MISSING: &str = "The domain/default pair of (x, y) does not exist";
    const NO_KEY: &str = "x.plist: Could not extract value, error: No value at that key path or invalid key path: Key";

    fn pref_cmd(key: &str) -> String {
        format!("defaults read {SOFTWARE_UPDATE} {key}")
    }

    fn extract_cmd(key: &str, format: &str) -> String {
        format!("plutil -extract {key} {format} -o - {SOFTWARE_UPDATE}.plist")
    }

    /// A date `days` days in the past, the way `plutil -extract ... raw` prints it.
    fn days_ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    /// Adds a last successful check `days` days ago to the mock.
    fn checked(runner: MockRunner, days: i64) -> MockRunner {
        runner.ok(&extract_cmd("LastSuccessfulDate", "raw"), &days_ago(days))
    }

    #[test]
    fn filevault_on_and_off() {
        let on = MockRunner::new().ok("fdesetup status", "FileVault is On.");
        assert_eq!(FileVault.run(&on).status, Status::Pass);

        let encrypting = MockRunner::new().ok(
            "fdesetup status",
            "FileVault is On.\nEncryption in progress: Percent completed = 40",
        );
        assert_eq!(FileVault.run(&encrypting).status, Status::Pass);

        let off = MockRunner::new().ok("fdesetup status", "FileVault is Off.");
        let outcome = FileVault.run(&off);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("FileVault is Off"), "{}", outcome.detail);
    }

    #[test]
    fn filevault_being_decrypted_is_not_a_pass() {
        // Turning FileVault off decrypts the disk while `fdesetup` still says "On".
        let decrypting = MockRunner::new().ok(
            "fdesetup status",
            "FileVault is On.\nDecryption in progress: Percent completed = 88",
        );
        let outcome = FileVault.run(&decrypting);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("being decrypted"), "{}", outcome.detail);
        assert!(outcome.advice.contains("Turn FileVault back on"), "{}", outcome.advice);
    }

    #[test]
    fn unrecognised_output_is_unknown_not_fail() {
        // Empty output used to be reported as "FileVault is off ()."
        let cases: [(&str, &dyn Check); 3] = [
            ("fdesetup status", &FileVault),
            ("csrutil status", &Sip),
            ("spctl --status", &Gatekeeper),
        ];
        for (command, check) in cases {
            let empty = check.run(&MockRunner::new().ok(command, ""));
            assert_eq!(empty.status, Status::Unknown, "{command}: empty output");
            assert!(empty.detail.contains("no output"), "{}", empty.detail);

            let odd = check.run(&MockRunner::new().ok(command, "some new wording"));
            assert_eq!(odd.status, Status::Unknown, "{command}: unrecognised output");
            assert!(odd.detail.contains("some new wording"), "{}", odd.detail);

            // A failed command with output on stdout is not an answer either.
            let failed = check.run(&MockRunner::new().fail_stdout(command, "usage: tool [options]"));
            assert_eq!(failed.status, Status::Unknown, "{command}: failed command");
            assert!(failed.detail.contains("usage: tool"), "{}", failed.detail);

            let error = check.run(&MockRunner::new().fail(command, "Operation not permitted"));
            assert_eq!(error.status, Status::Unknown, "{command}: error");
            assert!(error.detail.contains("Operation not permitted"), "{}", error.detail);
        }
    }

    #[test]
    fn fails_when_sip_and_gatekeeper_are_disabled() {
        let runner = MockRunner::new()
            .ok("csrutil status", "System Integrity Protection status: disabled.")
            // `spctl --status` exits with code 1 when assessments are disabled.
            .fail_stdout("spctl --status", "assessments disabled");
        assert_eq!(Sip.run(&runner).status, Status::Fail);
        assert_eq!(Gatekeeper.run(&runner).status, Status::Fail);

        let enabled = MockRunner::new()
            .ok("csrutil status", "System Integrity Protection status: enabled.")
            .ok("spctl --status", "assessments enabled");
        assert_eq!(Sip.run(&enabled).status, Status::Pass);
        assert_eq!(Gatekeeper.run(&enabled).status, Status::Pass);
    }

    #[test]
    fn sip_custom_configuration_fails() {
        let runner = MockRunner::new().ok(
            "csrutil status",
            "System Integrity Protection status: unknown (Custom Configuration).\n\n\
             Configuration:\n\tKext Signing: disabled\n\tFilesystem Protections: enabled",
        );
        let outcome = Sip.run(&runner);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("custom configuration"));
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
    fn auto_update_unreadable_option_is_not_a_pass() {
        let unreadable = MockRunner::new()
            .ok(&pref_cmd("AutomaticCheckEnabled"), "1")
            .ok(&pref_cmd("AutomaticDownload"), "1")
            .fail(&pref_cmd("AutomaticallyInstallMacOSUpdates"), "permission denied")
            .ok(&pref_cmd("CriticalUpdateInstall"), "1");
        assert_eq!(AutoUpdate.run(&unreadable).status, Status::Unknown);

        let odd = MockRunner::new()
            .ok(&pref_cmd("AutomaticCheckEnabled"), "maybe")
            .ok(&pref_cmd("AutomaticDownload"), "1")
            .ok(&pref_cmd("AutomaticallyInstallMacOSUpdates"), "1")
            .ok(&pref_cmd("CriticalUpdateInstall"), "1");
        assert_eq!(AutoUpdate.run(&odd).status, Status::Unknown);
    }

    #[test]
    fn auto_update_guidance_covers_every_option() {
        // One `defaults write` cannot fix four preferences: no suggested
        // command, complete steps in the advice instead.
        assert!(AutoUpdate.fix().is_none());

        let all_off = MockRunner::new()
            .ok(&pref_cmd("AutomaticCheckEnabled"), "1")
            .ok(&pref_cmd("AutomaticDownload"), "0")
            .ok(&pref_cmd("AutomaticallyInstallMacOSUpdates"), "0")
            .ok(&pref_cmd("CriticalUpdateInstall"), "0");
        let advice = AutoUpdate.run(&all_off).advice;
        assert!(advice.contains("System Settings > General > Software Update"));
        for option in [
            "Download new updates",
            "Install macOS updates",
            "Install Security Responses",
        ] {
            assert!(advice.contains(option), "advice does not mention {option}");
        }
    }

    #[test]
    fn pending_update_count() {
        let count = pref_cmd("LastRecommendedUpdatesAvailable");

        let none = checked(MockRunner::new().ok(&count, "0"), 1);
        assert_eq!(PendingUpdates.run(&none).status, Status::Pass);

        let two = checked(MockRunner::new().ok(&count, "2"), 1);
        assert_eq!(PendingUpdates.run(&two).status, Status::Warn);

        let odd = checked(MockRunner::new().ok(&count, "many"), 1);
        assert_eq!(PendingUpdates.run(&odd).status, Status::Unknown);
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

        let cmd = extract_cmd("RecommendedUpdates", "json");
        let pending = checked(MockRunner::new().ok(&cmd, json), 0);
        let outcome = PendingUpdates.run(&pending);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("Safari"));

        let none = checked(MockRunner::new().ok(&cmd, "[]"), 0);
        let outcome = PendingUpdates.run(&none);
        assert_eq!(outcome.status, Status::Pass);
        assert!(outcome.detail.contains("last checked today"), "{}", outcome.detail);
    }

    #[test]
    fn stale_empty_list_is_not_a_pass() {
        let list = extract_cmd("RecommendedUpdates", "json");

        // Automatic checking is off: the empty list is months old.
        let stale = checked(MockRunner::new().ok(&list, "[]"), 90);
        let outcome = PendingUpdates.run(&stale);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("90 days ago"), "{}", outcome.detail);
        assert!(outcome.advice.contains("Software Update"));

        // No date recorded at all (neither key exists).
        let undated = MockRunner::new()
            .ok(&list, "[]")
            .fail(&extract_cmd("LastSuccessfulDate", "raw"), NO_KEY)
            .fail(&extract_cmd("LastFullSuccessfulDate", "raw"), NO_KEY);
        assert_eq!(PendingUpdates.run(&undated).status, Status::Unknown);

        // The date cannot be read (plutil missing or timed out).
        let unreadable = MockRunner::new().ok(&list, "[]");
        assert_eq!(PendingUpdates.run(&unreadable).status, Status::Unknown);

        // The date is there but makes no sense.
        let garbled = MockRunner::new()
            .ok(&list, "[]")
            .ok(&extract_cmd("LastSuccessfulDate", "raw"), "soon");
        assert_eq!(PendingUpdates.run(&garbled).status, Status::Unknown);

        // The older key is used when the newer one is missing.
        let fallback = MockRunner::new()
            .ok(&list, "[]")
            .fail(&extract_cmd("LastSuccessfulDate", "raw"), NO_KEY)
            .ok(&extract_cmd("LastFullSuccessfulDate", "raw"), &days_ago(2));
        assert_eq!(PendingUpdates.run(&fallback).status, Status::Pass);

        // The same rule applies to the count recorded by older versions.
        let stale_count = checked(
            MockRunner::new().ok(&pref_cmd("LastRecommendedUpdatesAvailable"), "0"),
            30,
        );
        assert_eq!(PendingUpdates.run(&stale_count).status, Status::Warn);
    }

    #[test]
    fn pending_outcome_boundaries() {
        let none = Pending::Names(Vec::new());
        assert_eq!(pending_outcome(&none, Ok(0)).status, Status::Pass);
        assert_eq!(pending_outcome(&none, Ok(MAX_CHECK_AGE_DAYS)).status, Status::Pass);
        assert_eq!(pending_outcome(&none, Ok(MAX_CHECK_AGE_DAYS + 1)).status, Status::Warn);
        assert_eq!(pending_outcome(&none, Err("x".into())).status, Status::Unknown);
        assert_eq!(pending_outcome(&Pending::Count(0), Ok(15)).status, Status::Warn);

        // Known pending updates are reported whatever the age of the record.
        let some = Pending::Names(vec!["Safari".to_string()]);
        assert_eq!(pending_outcome(&some, Ok(0)).status, Status::Warn);
        assert_eq!(pending_outcome(&some, Err("x".into())).status, Status::Warn);
        let old = pending_outcome(&some, Ok(40));
        assert_eq!(old.status, Status::Warn);
        assert!(old.detail.contains("Safari") && old.detail.contains("40 days ago"));
        assert_eq!(pending_outcome(&Pending::Count(3), Ok(1)).status, Status::Warn);
    }

    #[test]
    fn timestamps() {
        // 2026-11-20T08:09:58Z, in both formats macOS prints.
        assert_eq!(parse_timestamp("2026-11-20T08:09:58Z"), Some(1_795_162_198));
        assert_eq!(parse_timestamp("2026-11-20 08:09:58 +0000"), Some(1_795_162_198));
        assert_eq!(parse_timestamp(" 2026-11-20T08:09:58Z\n"), Some(1_795_162_198));
        assert_eq!(parse_timestamp(""), None);
        assert_eq!(parse_timestamp("yesterday"), None);
    }

    #[test]
    fn xprotect_age() {
        assert_eq!(age_in_days(86_400 * 10, 86_400 * 3), 7);
        assert_eq!(age_in_days(5, 100), 0, "a future date does not go negative");
        assert_eq!(xprotect_outcome("5371", 10).status, Status::Pass);
        assert_eq!(xprotect_outcome("5371", 90).status, Status::Warn);
    }
}
