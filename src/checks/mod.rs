//! macOS güvenlik kontrolleri.
//!
//! Her kontrol `Check` trait'ini uygulayan küçük bir tiptir. Kontrol yalnızca
//! salt okunur komutlar çalıştırır ve bir `Outcome` üretir; ad, ağırlık,
//! önem derecesi gibi sabit bilgiler trait metotlarından gelir. Yeni bir
//! kontrol eklemek için: tipi yaz, `Check` uygula, `registry()` listesine ekle.

mod accounts;
mod network;
mod persistence;
mod system;

use crate::config::Config;
use crate::runner::CommandRunner;
use serde::{Deserialize, Serialize, Serializer};

/// Bir kontrolün sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Sorun yok.
    Pass,
    /// Dikkat edilmesi gereken bir durum var.
    Warn,
    /// Önemli bir güvenlik önlemi eksik.
    Fail,
    /// Durum tespit edilemedi (komut çalışmadı, izin yok vb.).
    Unknown,
}

impl Status {
    /// Çıktılarda kullanılan Türkçe etiket.
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "GEÇTİ",
            Status::Warn => "UYARI",
            Status::Fail => "BAŞARISIZ",
            Status::Unknown => "BİLİNMİYOR",
        }
    }
}

/// Kontrolün önem derecesi: sorun çıkarsa ne kadar ciddi?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "düşük",
            Severity::Medium => "orta",
            Severity::High => "yüksek",
            Severity::Critical => "kritik",
        }
    }
}

/// Bir kontrolün çalıştırılınca ürettiği değişken kısım.
#[derive(Debug)]
pub struct Outcome {
    pub status: Status,
    pub detail: String,
    pub advice: &'static str,
}

impl Outcome {
    // Kısa kurucu fonksiyonlar: `impl Into<String>` sayesinde hem `&str`
    // hem `String` kabul edilir.
    pub fn pass(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            detail: detail.into(),
            advice: "",
        }
    }

    pub fn warn(detail: impl Into<String>, advice: &'static str) -> Self {
        Self {
            status: Status::Warn,
            detail: detail.into(),
            advice,
        }
    }

    pub fn fail(detail: impl Into<String>, advice: &'static str) -> Self {
        Self {
            status: Status::Fail,
            detail: detail.into(),
            advice,
        }
    }

    pub fn unknown(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Unknown,
            detail: detail.into(),
            advice: "",
        }
    }
}

/// Bir sorunu düzelten komut. Yalnızca `--fix` modunda ve kullanıcı
/// onaylarsa çalıştırılır.
#[derive(Debug, Clone, Copy)]
pub struct Fix {
    pub program: &'static str,
    pub args: &'static [&'static str],
    /// Komut yönetici yetkisi (sudo) gerektiriyor mu?
    pub sudo: bool,
}

impl Fix {
    /// Kullanıcıya gösterilecek tam komut satırı.
    pub fn command_line(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.sudo {
            parts.push("sudo".to_string());
        }
        parts.push(self.program.to_string());
        for arg in self.args {
            // Boşluk içeren argümanları tırnak içine alıyoruz.
            if arg.contains(' ') {
                parts.push(format!("\"{arg}\""));
            } else {
                parts.push(arg.to_string());
            }
        }
        parts.join(" ")
    }
}

// JSON çıktısında düzeltmeyi tek bir komut satırı metni olarak gösteriyoruz.
impl Serialize for Fix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.command_line())
    }
}

/// Tüm kontrollerin uyguladığı ortak arayüz.
///
/// `Sync` şartı kontrollerin paralel çalıştırılabilmesi içindir.
pub trait Check: Sync {
    /// Komut satırında ve yapılandırmada kullanılan kısa kimlik.
    fn id(&self) -> &'static str;
    /// Kullanıcıya gösterilen ad.
    fn name(&self) -> &'static str;
    /// Puandaki varsayılan ağırlık.
    fn weight(&self) -> u32;
    fn severity(&self) -> Severity;
    /// İlgili CIS Apple macOS Benchmark bölümü (varsa).
    fn cis(&self) -> Option<&'static str> {
        None
    }
    /// Otomatik düzeltme komutu (varsa).
    fn fix(&self) -> Option<Fix> {
        None
    }
    /// Kontrolü çalıştırır. Hiçbir ayarı değiştirmemelidir.
    fn run(&self, runner: &dyn CommandRunner) -> Outcome;
}

/// Tek bir kontrolün tam raporu: sabit bilgiler + çalıştırma sonucu.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub name: &'static str,
    pub status: Status,
    pub severity: Severity,
    pub weight: u32,
    pub cis: Option<&'static str>,
    pub detail: String,
    pub advice: &'static str,
    /// Yapılandırmada istisna tanımlandıysa gerekçesi. İstisnalı kontroller
    /// puana ve çıkış koduna etki etmez.
    pub exempt: Option<String>,
    pub fix: Option<Fix>,
}

impl CheckResult {
    /// Kontrol sorunlu mu (istisna tanımlanmamış bir Fail/Warn)?
    pub fn is_issue(&self) -> bool {
        self.exempt.is_none() && matches!(self.status, Status::Fail | Status::Warn)
    }

    /// Çıkış kodunu etkileyen başarısızlık mı?
    pub fn is_failure(&self) -> bool {
        self.exempt.is_none() && self.status == Status::Fail
    }
}

/// Bilinen tüm kontroller, çıktıda görünecekleri sırayla.
pub fn registry() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(system::FileVault),
        Box::new(system::Sip),
        Box::new(system::Gatekeeper),
        Box::new(system::AutoUpdate),
        Box::new(system::PendingUpdates),
        Box::new(system::XProtect),
        Box::new(network::Firewall),
        Box::new(network::StealthMode),
        Box::new(network::Ssh),
        Box::new(network::Sharing),
        Box::new(network::AirDrop),
        Box::new(accounts::AutoLogin),
        Box::new(accounts::GuestAccount),
        Box::new(accounts::ScreenLock),
        Box::new(accounts::SudoNoPassword),
        Box::new(persistence::LaunchItems),
    ]
}

/// Tek bir kontrolü çalıştırıp yapılandırmayı (ağırlık, istisna) uygular.
pub fn run_one(check: &dyn Check, runner: &dyn CommandRunner, config: &Config) -> CheckResult {
    let outcome = check.run(runner);
    build_result(check, outcome, config)
}

fn build_result(check: &dyn Check, outcome: Outcome, config: &Config) -> CheckResult {
    CheckResult {
        id: check.id(),
        name: check.name(),
        status: outcome.status,
        severity: check.severity(),
        // Yapılandırmada ağırlık verilmişse onu, yoksa varsayılanı kullan.
        weight: config
            .weights
            .get(check.id())
            .copied()
            .unwrap_or_else(|| check.weight()),
        cis: check.cis(),
        detail: outcome.detail,
        advice: outcome.advice,
        exempt: config.exceptions.get(check.id()).cloned(),
        fix: check.fix(),
    }
}

/// Verilen kontrolleri paralel çalıştırır; sonuçlar giriş sırasını korur.
///
/// `std::thread::scope`, iş parçacıklarının `checks`, `runner` ve `config`
/// gibi yerel verileri ödünç almasına izin verir: kapsam bitmeden tüm
/// iş parçacıkları tamamlanmış olur.
pub fn run_checks(
    checks: &[Box<dyn Check>],
    runner: &dyn CommandRunner,
    config: &Config,
) -> Vec<CheckResult> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = checks
            .iter()
            .map(|check| scope.spawn(move || run_one(check.as_ref(), runner, config)))
            .collect();

        handles
            .into_iter()
            .zip(checks)
            .map(|(handle, check)| {
                // Bir kontrol panic ederse tüm programı düşürmek yerine
                // o kontrolü "bilinmiyor" olarak raporluyoruz.
                handle.join().unwrap_or_else(|_| {
                    build_result(
                        check.as_ref(),
                        Outcome::unknown("Kontrol beklenmedik şekilde sonlandı."),
                        config,
                    )
                })
            })
            .collect()
    })
}

/// macOS sürümünü "macOS 26.6.2" biçiminde döndürür.
pub fn os_version(runner: &dyn CommandRunner) -> String {
    stdout_of(runner, "sw_vers", &["-productVersion"])
        .map(|version| format!("macOS {version}"))
        .unwrap_or_else(|_| "macOS (sürüm okunamadı)".to_string())
}

// ---- Kontrollerin ortak kullandığı yardımcılar ----

/// Komutu çalıştırıp stdout'u döndürür; başarısızsa hata açıklaması verir.
fn stdout_of(runner: &dyn CommandRunner, program: &str, args: &[&str]) -> Result<String, String> {
    runner.run(program, args)?.into_stdout()
}

/// `defaults read` sonucunun üç olası hali.
enum Pref {
    Value(String),
    /// Anahtar hiç tanımlanmamış.
    Missing,
    Error(String),
}

/// macOS tercih (preferences) anahtarını okur.
fn read_pref(runner: &dyn CommandRunner, domain: &str, key: &str) -> Pref {
    match runner.run("defaults", &["read", domain, key]) {
        Err(err) => Pref::Error(err),
        Ok(out) if out.success => Pref::Value(out.stdout),
        Ok(out) if out.stderr.contains("does not exist") => Pref::Missing,
        Ok(out) => Pref::Error(out.combined()),
    }
}

/// `netstat -an -p tcp` çıktısında verilen port dinleniyor mu?
///
/// Satırlar şöyle görünür: `tcp4 0 0 *.22 *.* LISTEN`
/// 4. alan yerel adres, 6. alan bağlantı durumudur.
fn listening_on(netstat_output: &str, port: u16) -> bool {
    let suffix = format!(".{port}");
    netstat_output.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() >= 6 && fields[3].ends_with(&suffix) && fields[5] == "LISTEN"
    })
}

/// Dinlenen TCP portlarını listeleyen ortak komut.
fn netstat(runner: &dyn CommandRunner) -> Result<String, String> {
    stdout_of(runner, "netstat", &["-an", "-p", "tcp"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    #[test]
    fn acik_portu_bulur() {
        let sample = "\
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.5000         *.*                    LISTEN";
        assert!(listening_on(sample, 22));
        assert!(listening_on(sample, 5000));
    }

    #[test]
    fn benzer_portlari_karistirmaz() {
        let sample = "\
tcp4       0      0  *.8022                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.2222         *.*                    LISTEN";
        assert!(!listening_on(sample, 22));
    }

    #[test]
    fn dinlemeyen_baglantiyi_saymaz() {
        let sample = "tcp4  0  0  10.0.0.5.22  10.0.0.9.51234  ESTABLISHED";
        assert!(!listening_on(sample, 22));
    }

    #[test]
    fn kimlikler_benzersiz() {
        let mut ids: Vec<&str> = registry().iter().map(|check| check.id()).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "aynı kimliğe sahip iki kontrol var");
    }

    #[test]
    fn komutlar_calismazsa_bilinmiyor_doner() {
        // Boş mock: her komut "tanımsız" hatası verir. Hiçbir kontrol
        // panic etmemeli ya da yanlışlıkla "geçti" dememeli.
        let runner = MockRunner::new();
        let config = Config::default();
        for result in run_checks(&registry(), &runner, &config) {
            if result.id == "launch-items" {
                continue; // Dosya sistemini okur; komutlara bağlı değildir.
            }
            assert_eq!(
                result.status,
                Status::Unknown,
                "{} komut hatasında Unknown dönmeliydi",
                result.id
            );
        }
    }

    #[test]
    fn yapilandirma_agirlik_ve_istisna_uygular() {
        let runner = MockRunner::new().ok("fdesetup status", "FileVault is Off.");
        let mut config = Config::default();
        config.weights.insert("filevault".into(), 40);
        config
            .exceptions
            .insert("filevault".into(), "test makinesi".into());

        let result = run_one(&system::FileVault, &runner, &config);
        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.weight, 40);
        assert!(!result.is_failure(), "istisnalı kontrol başarısız sayılmaz");
    }

    #[test]
    fn duzeltme_komut_satiri() {
        let fix = Fix {
            program: "defaults",
            args: &["write", "x", "Contacts Only"],
            sudo: true,
        };
        assert_eq!(
            fix.command_line(),
            "sudo defaults write x \"Contacts Only\""
        );
    }
}
