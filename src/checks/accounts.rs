//! Hesap ve oturum kontrolleri: otomatik giriş, misafir, ekran kilidi, sudo.

use super::{Check, Fix, Outcome, Pref, Severity, read_pref};
use crate::runner::CommandRunner;

const LOGIN_WINDOW: &str = "/Library/Preferences/com.apple.loginwindow";

/// Parolasız otomatik giriş yapılandırılmış mı?
pub struct AutoLogin;

impl Check for AutoLogin {
    fn id(&self) -> &'static str {
        "auto-login"
    }
    fn name(&self) -> &'static str {
        "Otomatik giriş"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.12.3")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: "defaults",
            args: &["delete", LOGIN_WINDOW, "autoLoginUser"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match read_pref(runner, LOGIN_WINDOW, "autoLoginUser") {
            // Anahtar varsa bir kullanıcı adı döner: otomatik giriş açık.
            Pref::Value(user) if !user.is_empty() => Outcome::fail(
                format!("'{user}' kullanıcısı parolasız otomatik giriş yapıyor."),
                "Sistem Ayarları > Kullanıcılar ve Gruplar > Otomatik girişi kapat.",
            ),
            // Anahtar yoksa otomatik giriş zaten kapalıdır.
            Pref::Value(_) | Pref::Missing => Outcome::pass("Otomatik giriş kapalı."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

/// Misafir hesabı açık mı?
pub struct GuestAccount;

impl Check for GuestAccount {
    fn id(&self) -> &'static str {
        "guest"
    }
    fn name(&self) -> &'static str {
        "Misafir hesabı"
    }
    fn weight(&self) -> u32 {
        5
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.12.1")
    }
    fn fix(&self) -> Option<Fix> {
        Some(Fix {
            program: "sysadminctl",
            args: &["-guestAccount", "off"],
            sudo: true,
        })
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        match read_pref(runner, LOGIN_WINDOW, "GuestEnabled") {
            Pref::Value(value) if value == "1" => Outcome::fail(
                "Misafir hesabı açık.",
                "Sistem Ayarları > Kullanıcılar ve Gruplar > Misafir Kullanıcı'yı kapat.",
            ),
            Pref::Value(_) | Pref::Missing => Outcome::pass("Misafir hesabı kapalı."),
            Pref::Error(err) => Outcome::unknown(err),
        }
    }
}

/// Ekran kilitlendikten sonra parola ne kadar sürede isteniyor?
pub struct ScreenLock;

/// Kilit gecikmesi bu saniyeden uzunsa uyarı veririz.
const MAX_LOCK_DELAY_SECS: u64 = 5;

/// `sysadminctl -screenLock status` çıktısının yorumu.
#[derive(Debug, PartialEq, Eq)]
enum LockDelay {
    Immediate,
    Seconds(u64),
    Off,
}

/// Olası çıktılar:
/// - "screenLock delay is immediate"
/// - "screenLock delay is 300 seconds"
/// - "screenLock is off"
fn parse_lock_delay(output: &str) -> Option<LockDelay> {
    if output.contains("screenLock is off") {
        return Some(LockDelay::Off);
    }
    // `split_once` metni ilk eşleşmede ikiye böler; `?` eşleşme yoksa
    // fonksiyondan `None` ile çıkar.
    let (_, rest) = output.split_once("screenLock delay is ")?;
    let mut words = rest.split_whitespace();
    match words.next()? {
        "immediate" => Some(LockDelay::Immediate),
        number => number.parse().ok().map(LockDelay::Seconds),
    }
}

impl Check for ScreenLock {
    fn id(&self) -> &'static str {
        "screen-lock"
    }
    fn name(&self) -> &'static str {
        "Ekran kilidi parolası"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cis(&self) -> Option<&'static str> {
        Some("2.10")
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        const ADVICE: &str = "Sistem Ayarları > Kilitli Ekran'da parola isteme süresini \"Hemen\" yap.";

        // `sysadminctl` bilgiyi stderr'e yazdığı için birleşik çıktıya bakıyoruz.
        let output = match runner.run("sysadminctl", &["-screenLock", "status"]) {
            Ok(out) => out.combined(),
            Err(err) => return Outcome::unknown(err),
        };

        match parse_lock_delay(&output) {
            Some(LockDelay::Immediate) => Outcome::pass("Kilit sonrası parola hemen isteniyor."),
            Some(LockDelay::Seconds(secs)) if secs <= MAX_LOCK_DELAY_SECS => {
                Outcome::pass(format!("Parola {secs} saniye sonra isteniyor."))
            }
            Some(LockDelay::Seconds(secs)) => Outcome::warn(
                format!("Parola kilitten {secs} saniye sonra isteniyor."),
                ADVICE,
            ),
            Some(LockDelay::Off) => Outcome::fail("Ekran kilidi parola istemiyor.", ADVICE),
            None => Outcome::unknown("Ekran kilidi durumu okunamadı."),
        }
    }
}

/// Kullanıcı sudo'yu parolasız çalıştırabiliyor mu?
///
/// `sudo -n -l` hiçbir komut çalıştırmaz; yalnızca kullanıcının sudo
/// kurallarını listeler. `-n` parola sorulmasını engeller.
pub struct SudoNoPassword;

impl Check for SudoNoPassword {
    fn id(&self) -> &'static str {
        "sudo"
    }
    fn name(&self) -> &'static str {
        "Parolasız sudo"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        let out = match runner.run("sudo", &["-n", "-l"]) {
            Ok(out) => out,
            Err(err) => return Outcome::unknown(err),
        };
        let text = out.combined();

        if text.contains("NOPASSWD") {
            Outcome::fail(
                "sudo kurallarında NOPASSWD var: komutlar parolasız çalışabiliyor.",
                "`sudo visudo` ile /etc/sudoers ve /etc/sudoers.d içindeki NOPASSWD kurallarını kaldır.",
            )
        } else if text.contains("password is required") {
            Outcome::pass("sudo parola istiyor.")
        } else if out.success {
            // Liste parolasız geldi ama NOPASSWD yok: yakın zamanda girilen
            // parola hâlâ önbellekte demektir.
            Outcome::pass("NOPASSWD kuralı yok (sudo oturumu önbellekte).")
        } else {
            Outcome::unknown(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::runner::MockRunner;

    const MISSING: &str = "The domain/default pair of (x, y) does not exist";

    #[test]
    fn otomatik_giris() {
        let cmd = format!("defaults read {LOGIN_WINDOW} autoLoginUser");

        let on = MockRunner::new().ok(&cmd, "ayse");
        let outcome = AutoLogin.run(&on);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("ayse"));

        let off = MockRunner::new().fail(&cmd, MISSING);
        assert_eq!(AutoLogin.run(&off).status, Status::Pass);

        let broken = MockRunner::new().fail(&cmd, "izin reddedildi");
        assert_eq!(AutoLogin.run(&broken).status, Status::Unknown);
    }

    #[test]
    fn misafir_hesabi() {
        let cmd = format!("defaults read {LOGIN_WINDOW} GuestEnabled");
        assert_eq!(
            GuestAccount.run(&MockRunner::new().ok(&cmd, "1")).status,
            Status::Fail
        );
        assert_eq!(
            GuestAccount.run(&MockRunner::new().ok(&cmd, "0")).status,
            Status::Pass
        );
    }

    #[test]
    fn kilit_gecikmesi_ayristirma() {
        // Gerçek çıktı tarih ve süreç bilgisiyle başlar.
        let line = "2026-11-10 00:25:54.846 sysadminctl[73455:795705] screenLock delay is immediate";
        assert_eq!(parse_lock_delay(line), Some(LockDelay::Immediate));
        assert_eq!(
            parse_lock_delay("screenLock delay is 300 seconds"),
            Some(LockDelay::Seconds(300))
        );
        assert_eq!(parse_lock_delay("screenLock is off"), Some(LockDelay::Off));
        assert_eq!(parse_lock_delay("anlamsız çıktı"), None);
    }

    #[test]
    fn ekran_kilidi_durumlari() {
        let cmd = "sysadminctl -screenLock status";
        let status = |text: &str| ScreenLock.run(&MockRunner::new().ok_stderr(cmd, text)).status;

        assert_eq!(status("screenLock delay is immediate"), Status::Pass);
        assert_eq!(status("screenLock delay is 5 seconds"), Status::Pass);
        assert_eq!(status("screenLock delay is 900 seconds"), Status::Warn);
        assert_eq!(status("screenLock is off"), Status::Fail);
    }

    #[test]
    fn sudo_kurallari() {
        let cmd = "sudo -n -l";

        let asks = MockRunner::new().fail(cmd, "sudo: a password is required");
        assert_eq!(SudoNoPassword.run(&asks).status, Status::Pass);

        let nopasswd = MockRunner::new().ok(cmd, "(ALL) NOPASSWD: ALL");
        assert_eq!(SudoNoPassword.run(&nopasswd).status, Status::Fail);

        let cached = MockRunner::new().ok(cmd, "(ALL) ALL");
        assert_eq!(SudoNoPassword.run(&cached).status, Status::Pass);
    }
}
