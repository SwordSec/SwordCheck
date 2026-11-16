//! Ağ kontrolleri: güvenlik duvarı, uzak giriş ve paylaşım servisleri.

use super::{Check, Fix, Outcome, Pref, Severity, listening_on, netstat, read_pref, stdout_of};
use crate::runner::CommandRunner;

const FIREWALL_TOOL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Uygulama güvenlik duvarı açık mı?
pub struct Firewall;

impl Check for Firewall {
    fn id(&self) -> &'static str {
        "firewall"
    }
    fn name(&self) -> &'static str {
        "Güvenlik duvarı"
    }
    fn weight(&self) -> u32 {
        20
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.2.1")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: FIREWALL_TOOL,
            args: &["--setglobalstate", "on"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match stdout_of(runner, FIREWALL_TOOL, &["--getglobalstate"]) {
            // Çıktı: "Firewall is enabled. (State = 1)"
            Ok(out) if out.contains("is enabled") => {
                Outcome::pass("Uygulama güvenlik duvarı açık.")
            }
            Ok(_) => Outcome::fail(
                "Uygulama güvenlik duvarı kapalı.",
                "Sistem Ayarları > Ağ > Güvenlik Duvarı bölümünden aç.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Güvenlik duvarı gizli modu (ping ve port taramalarına yanıt vermeme) açık mı?
pub struct StealthMode;

impl Check for StealthMode {
    fn id(&self) -> &'static str {
        "stealth"
    }
    fn name(&self) -> &'static str {
        "Güvenlik duvarı gizli modu"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.2.2")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: FIREWALL_TOOL,
            args: &["--setstealthmode", "on"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match stdout_of(runner, FIREWALL_TOOL, &["--getstealthmode"]) {
            Ok(out) if stealth_enabled(&out) => Outcome::pass("Gizli mod açık."),
            Ok(_) => Outcome::warn(
                "Gizli mod kapalı.",
                "Sistem Ayarları > Ağ > Güvenlik Duvarı > Seçenekler'den gizli modu aç.",
            ),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// macOS sürümüne göre çıktı "Firewall stealth mode is on" ya da
/// "Stealth mode enabled" biçiminde olabilir.
fn stealth_enabled(output: &str) -> bool {
    let output = output.to_lowercase();
    output.contains("is on") || (output.contains("enabled") && !output.contains("disabled"))
}

/// 22 numaralı TCP portu (SSH) dinleniyor mu?
pub struct Ssh;

impl Check for Ssh {
    fn id(&self) -> &'static str {
        "ssh"
    }
    fn name(&self) -> &'static str {
        "Uzak giriş (SSH)"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.3.3")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: "systemsetup",
            args: &["-f", "-setremotelogin", "off"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match netstat(runner) {
            Ok(out) if listening_on(&out, 22) => Outcome::warn(
                "22 numaralı port dinleniyor (SSH açık).",
                "İhtiyacın yoksa Sistem Ayarları > Genel > Paylaşım > Uzak Giriş'i kapat.",
            ),
            Ok(_) => Outcome::pass("22 numaralı port dinlenmiyor."),
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// Ekran/dosya paylaşımı gibi servisler ağa açık mı?
pub struct Sharing;

/// (port, servis adı)
const SHARING_PORTS: [(u16, &str); 4] = [
    (5900, "Ekran Paylaşımı (5900)"),
    (445, "Dosya Paylaşımı/SMB (445)"),
    (548, "Dosya Paylaşımı/AFP (548)"),
    (3283, "Uzaktan Yönetim (3283)"),
];

impl Check for Sharing {
    fn id(&self) -> &'static str {
        "sharing"
    }
    fn name(&self) -> &'static str {
        "Paylaşım servisleri"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.3.3")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match netstat(runner) {
            Ok(out) => {
                let open: Vec<&str> = SHARING_PORTS
                    .iter()
                    .filter(|(port, _)| listening_on(&out, *port))
                    .map(|(_, name)| *name)
                    .collect();

                if open.is_empty() {
                    Outcome::pass("Ekran ve dosya paylaşımı kapalı.")
                } else {
                    Outcome::warn(
                        format!("Açık servisler: {}.", open.join(", ")),
                        "Kullanmadığın servisleri Sistem Ayarları > Genel > Paylaşım'dan kapat.",
                    )
                }
            }
            Err(err) => Outcome::unknown(err),
        }
    }
}

/// AirDrop herkese açık mı?
pub struct AirDrop;

impl Check for AirDrop {
    fn id(&self) -> &'static str {
        "airdrop"
    }
    fn name(&self) -> &'static str {
        "AirDrop görünürlüğü"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.3.1.1")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match read_pref(runner, "com.apple.sharingd", "DiscoverableMode") {
            Pref::Value(mode) if mode == "Everyone" => Outcome::warn(
                "AirDrop herkese açık.",
                "Sistem Ayarları > Genel > AirDrop ve Handoff'tan \"Yalnızca Kişiler\" seç.",
            ),
            Pref::Value(mode) => Outcome::pass(format!("AirDrop modu: {mode}.")),
            Pref::Missing => Outcome::unknown("AirDrop ayarı bulunamadı."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::runner::MockRunner;

    const NETSTAT: &str = "netstat -an -p tcp";

    #[test]
    fn gizli_mod_ciktilari() {
        assert!(stealth_enabled("Firewall stealth mode is on"));
        assert!(stealth_enabled("Stealth mode enabled"));
        assert!(!stealth_enabled("Firewall stealth mode is off"));
        assert!(!stealth_enabled("Stealth mode disabled"));
    }

    #[test]
    fn guvenlik_duvari_kapaliyken_basarisiz() {
        let cmd = format!("{FIREWALL_TOOL} --getglobalstate");
        let off = MockRunner::new().ok(&cmd, "Firewall is disabled. (State = 0)");
        assert_eq!(Firewall.run(&off).status, Status::Fail);

        let on = MockRunner::new().ok(&cmd, "Firewall is enabled. (State = 1)");
        assert_eq!(Firewall.run(&on).status, Status::Pass);
    }

    #[test]
    fn ssh_ve_paylasim_portlari() {
        let runner = MockRunner::new().ok(
            NETSTAT,
            "tcp4  0  0  *.22    *.*  LISTEN\n\
             tcp4  0  0  *.5900  *.*  LISTEN\n\
             tcp4  0  0  *.5000  *.*  LISTEN",
        );
        assert_eq!(Ssh.run(&runner).status, Status::Warn);

        let sharing = Sharing.run(&runner);
        assert_eq!(sharing.status, Status::Warn);
        assert!(sharing.detail.contains("Ekran Paylaşımı"));
        assert!(!sharing.detail.contains("SMB"));
    }

    #[test]
    fn portlar_kapaliyken_gecer() {
        let runner = MockRunner::new().ok(NETSTAT, "tcp4  0  0  127.0.0.1.5000  *.*  LISTEN");
        assert_eq!(Ssh.run(&runner).status, Status::Pass);
        assert_eq!(Sharing.run(&runner).status, Status::Pass);
    }

    #[test]
    fn airdrop_modlari() {
        let cmd = "defaults read com.apple.sharingd DiscoverableMode";
        let everyone = MockRunner::new().ok(cmd, "Everyone");
        assert_eq!(AirDrop.run(&everyone).status, Status::Warn);

        let off = MockRunner::new().ok(cmd, "Off");
        assert_eq!(AirDrop.run(&off).status, Status::Pass);
    }
}
