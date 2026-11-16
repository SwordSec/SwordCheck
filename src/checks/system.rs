//! Sistem koruma kontrolleri: disk şifreleme, SIP, Gatekeeper, güncellemeler.

use super::{Check, Fix, Outcome, Pref, Severity, read_pref, stdout_of};
use crate::runner::CommandRunner;
use std::time::{SystemTime, UNIX_EPOCH};

const SOFTWARE_UPDATE: &str = "/Library/Preferences/com.apple.SoftwareUpdate";

/// FileVault disk şifrelemesi açık mı?
pub struct FileVault;

impl Check for FileVault {
    fn id(&self) -> &'static str {
        "filevault"
    }
    fn name(&self) -> &'static str {
        "FileVault (disk şifreleme)"
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
            // Çıktı: "FileVault is On."
            Ok(out) if out.contains("FileVault is On") => Outcome::pass("Disk şifrelemesi etkin."),
            Ok(out) => Outcome::fail(
                format!("FileVault kapalı ({out})."),
                "Sistem Ayarları > Gizlilik ve Güvenlik > FileVault bölümünden aç.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Sistem Bütünlüğü Koruması (SIP) açık mı?
pub struct Sip;

impl Check for Sip {
    fn id(&self) -> &'static str {
        "sip"
    }
    fn name(&self) -> &'static str {
        "Sistem bütünlüğü koruması (SIP)"
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
            // Çıktı: "System Integrity Protection status: enabled."
            Ok(out) if out.contains("status: enabled") => Outcome::pass("SIP etkin."),
            Ok(_) => Outcome::fail(
                "SIP devre dışı.",
                "Kurtarma modunda `csrutil enable` çalıştırıp SIP'i yeniden aç.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Gatekeeper uygulama değerlendirmeleri açık mı?
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
            // Çıktı: "assessments enabled"
            Ok(out) if out.contains("assessments enabled") => {
                Outcome::pass("Uygulama değerlendirmeleri etkin.")
            }
            Ok(_) => Outcome::fail(
                "Gatekeeper devre dışı.",
                "Sistem Ayarları > Gizlilik ve Güvenlik bölümünden etkinleştir.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Otomatik güncelleme denetimi ve kurulumu açık mı?
pub struct AutoUpdate;

impl Check for AutoUpdate {
    fn id(&self) -> &'static str {
        "auto-update"
    }
    fn name(&self) -> &'static str {
        "Otomatik güncellemeler"
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
        // (anahtar, kullanıcıya gösterilecek ad)
        const KEYS: [(&str, &str); 4] = [
            ("AutomaticCheckEnabled", "güncelleme denetimi"),
            ("AutomaticDownload", "otomatik indirme"),
            ("AutomaticallyInstallMacOSUpdates", "macOS güncellemelerini kurma"),
            ("CriticalUpdateInstall", "güvenlik yanıtlarını kurma"),
        ];

        let mut disabled: Vec<&str> = Vec::new();
        let mut enabled = 0;
        let mut first_error: Option<String> = None;

        for (key, label) in KEYS {
            match read_pref(runner, SOFTWARE_UPDATE, key) {
                Pref::Value(value) if value == "0" => disabled.push(label),
                Pref::Value(_) => enabled += 1,
                // Anahtar yoksa macOS varsayılanı geçerlidir; yorum yapmıyoruz.
                Pref::Missing => {}
                Pref::Error(err) => first_error = first_error.or(Some(err)),
            }
        }

        if disabled.contains(&"güncelleme denetimi") {
            Outcome::fail(
                "Otomatik güncelleme denetimi kapalı.",
                "Sistem Ayarları > Genel > Yazılım Güncelleme > Otomatik Güncellemeler'i aç.",
            )
        } else if !disabled.is_empty() {
            Outcome::warn(
                format!("Kapalı seçenekler: {}.", disabled.join(", ")),
                "Sistem Ayarları > Genel > Yazılım Güncelleme > Otomatik Güncellemeler'de tüm seçenekleri aç.",
            )
        } else if enabled > 0 {
            Outcome::pass("Otomatik güncelleme seçenekleri açık.")
        } else {
            Outcome::unknown(
                first_error.unwrap_or_else(|| "Güncelleme tercihleri bulunamadı.".to_string()),
            )
        }
    }
}

/// Kurulmayı bekleyen güncelleme var mı?
///
/// `softwareupdate -l` ağ üzerinden sorgu yaptığı için yavaştır; bunun
/// yerine sistemin son denetimde kaydettiği sayıyı okuyoruz.
pub struct PendingUpdates;

impl Check for PendingUpdates {
    fn id(&self) -> &'static str {
        "pending-updates"
    }
    fn name(&self) -> &'static str {
        "Bekleyen güncellemeler"
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
        const ADVICE: &str = "Sistem Ayarları > Genel > Yazılım Güncelleme'den güncellemeleri kur.";

        // Yeni macOS sürümleri önerilen güncellemeleri bir liste olarak tutar;
        // `plutil -extract` o listeyi JSON olarak verir.
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
                Outcome::pass("Bekleyen güncelleme yok.")
            } else {
                Outcome::warn(format!("Kurulmayı bekleyenler: {}.", names.join(", ")), ADVICE)
            };
        }

        // Eski sürümler yalnızca sayıyı kaydeder.
        match read_pref(runner, SOFTWARE_UPDATE, "LastRecommendedUpdatesAvailable") {
            Pref::Value(value) => match value.parse::<u32>() {
                Ok(0) => Outcome::pass("Bekleyen güncelleme yok."),
                Ok(count) => {
                    Outcome::warn(format!("{count} güncelleme kurulmayı bekliyor."), ADVICE)
                }
                Err(_) => Outcome::unknown(format!("Beklenmeyen değer: {value}")),
            },
            Pref::Missing => Outcome::unknown("Güncelleme kaydı bulunamadı."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

/// `RecommendedUpdates` JSON dizisinden bekleyen güncellemelerin adlarını
/// çıkarır. Yeni ana sürüme yükseltmeler ("_major") isteğe bağlı olduğu için
/// sayılmaz. Girdi geçerli bir JSON dizisi değilse `None` döner.
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
                    .unwrap_or("adsız güncelleme")
                    .to_string()
            })
            .collect(),
    )
}

/// XProtect kötü amaçlı yazılım imzaları güncel mi?
pub struct XProtect;

/// İmzalar bu kadar günden eskiyse uyarı veririz.
const XPROTECT_MAX_AGE_DAYS: u64 = 45;

/// XProtect paketinin bulunabileceği konumlar (yeni sürümler ilkini kullanır).
const XPROTECT_BUNDLES: [&str; 2] = [
    "/var/protected/xprotect/XProtect.bundle",
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
];

impl Check for XProtect {
    fn id(&self) -> &'static str {
        "xprotect"
    }
    fn name(&self) -> &'static str {
        "XProtect imzaları"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        // Her konum için (değişiklik zamanı, sürüm) çiftini topla ve en
        // yenisini seç. `filter_map` başarısız olanları eler.
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
            return Outcome::unknown("XProtect paketi bulunamadı.");
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        xprotect_outcome(&version, age_in_days(now, modified))
    }
}

/// İki Unix zaman damgası arasındaki gün farkı (negatife düşmez).
fn age_in_days(now: u64, then: u64) -> u64 {
    now.saturating_sub(then) / 86_400
}

fn xprotect_outcome(version: &str, age_days: u64) -> Outcome {
    if age_days <= XPROTECT_MAX_AGE_DAYS {
        Outcome::pass(format!("Sürüm {version}, {age_days} gün önce güncellendi."))
    } else {
        Outcome::warn(
            format!("Sürüm {version}, {age_days} gündür güncellenmedi."),
            "Otomatik güncellemelerde \"Güvenlik Yanıtları ve sistem dosyaları\" seçeneğini aç.",
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
    fn filevault_acik_ve_kapali() {
        let on = MockRunner::new().ok("fdesetup status", "FileVault is On.");
        assert_eq!(FileVault.run(&on).status, Status::Pass);

        let off = MockRunner::new().ok("fdesetup status", "FileVault is Off.");
        assert_eq!(FileVault.run(&off).status, Status::Fail);
    }

    #[test]
    fn sip_ve_gatekeeper_kapaliyken_basarisiz() {
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
    fn otomatik_guncelleme_eksik_anahtari_cezalandirmaz() {
        // Bu makinedeki gerçek durum: denetim anahtarı yok, diğerleri 1.
        let runner = MockRunner::new()
            .fail(&pref_cmd("AutomaticCheckEnabled"), MISSING)
            .ok(&pref_cmd("AutomaticDownload"), "1")
            .ok(&pref_cmd("AutomaticallyInstallMacOSUpdates"), "1")
            .ok(&pref_cmd("CriticalUpdateInstall"), "1");
        assert_eq!(AutoUpdate.run(&runner).status, Status::Pass);
    }

    #[test]
    fn otomatik_guncelleme_kapali_secenekleri_ayirir() {
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
        assert!(outcome.detail.contains("macOS güncellemelerini kurma"));
    }

    #[test]
    fn bekleyen_guncelleme_sayisi() {
        let none = MockRunner::new().ok(&pref_cmd("LastRecommendedUpdatesAvailable"), "0");
        assert_eq!(PendingUpdates.run(&none).status, Status::Pass);

        let two = MockRunner::new().ok(&pref_cmd("LastRecommendedUpdatesAvailable"), "2");
        assert_eq!(PendingUpdates.run(&two).status, Status::Warn);
    }

    #[test]
    fn bekleyen_guncelleme_listesi() {
        // Bu makineden alınan gerçek çıktının kısaltılmış hali.
        let json = r#"[
            {"Identifier":"Safari27.2TahoeAuto","Display Name":"Safari"},
            {"Identifier":"MSU_UPDATE_25G332_patch_26.7.2_minor","Display Name":"macOS Tahoe 26.7.2"},
            {"Identifier":"MSU_UPDATE_26B123_patch_27.2_major","Display Name":"macOS 27.2"}
        ]"#;
        assert_eq!(
            pending_update_names(json).unwrap(),
            ["Safari", "macOS Tahoe 26.7.2"],
            "ana sürüm yükseltmesi sayılmaz"
        );
        assert_eq!(pending_update_names("[]").unwrap(), Vec::<String>::new());
        assert_eq!(pending_update_names("bozuk"), None);

        let cmd = format!("plutil -extract RecommendedUpdates json -o - {SOFTWARE_UPDATE}.plist");
        let pending = MockRunner::new().ok(&cmd, json);
        let outcome = PendingUpdates.run(&pending);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("Safari"));

        let none = MockRunner::new().ok(&cmd, "[]");
        assert_eq!(PendingUpdates.run(&none).status, Status::Pass);
    }

    #[test]
    fn xprotect_yasi() {
        assert_eq!(age_in_days(86_400 * 10, 86_400 * 3), 7);
        assert_eq!(age_in_days(5, 100), 0, "gelecekteki tarih negatif olmaz");
        assert_eq!(xprotect_outcome("5371", 10).status, Status::Pass);
        assert_eq!(xprotect_outcome("5371", 90).status, Status::Warn);
    }
}
