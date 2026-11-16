//! `--fix` modu: düzeltilebilir sorunlar için komutu gösterir ve kullanıcı
//! onaylarsa çalıştırır.
//!
//! Aracın geri kalanı salt okunurdur; sistemde değişiklik yapan tek yer
//! burasıdır. Bu yüzden her komut açıkça gösterilir ve tek tek onay istenir.

use crate::checks::{Check, CheckResult, Fix};
use crate::config::Config;
use crate::report;
use crate::runner::SystemRunner;
use colored::Colorize;
use std::io::{BufRead, IsTerminal, Write};
use std::process::Command;

pub struct FixOptions {
    /// Komutları yalnızca göster, çalıştırma.
    pub dry_run: bool,
    /// Onay sormadan uygula.
    pub yes: bool,
}

/// Düzeltme turunun özeti.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FixSummary {
    pub applied: usize,
    pub failed: usize,
    pub skipped: usize,
}

/// Sorunlu kontrolleri dolaşıp düzeltmeleri uygular.
pub fn run_fixes(
    results: &[CheckResult],
    checks: &[Box<dyn Check>],
    config: &Config,
    options: &FixOptions,
) -> FixSummary {
    let mut summary = FixSummary::default();
    let (fixable, manual) = split_issues(results);

    println!();
    println!("{}", " Düzeltme modu ".on_magenta().white().bold());

    if fixable.is_empty() {
        println!("Otomatik düzeltilebilecek bir sorun yok.");
    }

    for (result, fix) in fixable {
        println!();
        println!("{} {}", "▸".cyan(), result.name.bold());
        println!("  Sorun: {}", result.detail);
        println!("  Komut: {}", fix.command_line().cyan());

        if options.dry_run {
            println!("  {}", "[dry-run] komut çalıştırılmadı.".dimmed());
            summary.skipped += 1;
            continue;
        }
        if !options.yes && !confirm("  Uygulansın mı? [e/H] ") {
            println!("  {}", "Atlandı.".dimmed());
            summary.skipped += 1;
            continue;
        }

        match apply(&fix) {
            Ok(()) => {
                // Düzeltmenin işe yaradığını varsaymıyoruz: kontrolü yeniden
                // çalıştırıp sonucu gösteriyoruz. Yeni runner = boş önbellek.
                let check = checks.iter().find(|check| check.id() == result.id);
                let verified = check.map(|check| {
                    crate::checks::run_one(check.as_ref(), &SystemRunner::new(), config)
                });
                match verified {
                    Some(after) if !after.is_issue() => {
                        println!("  {}", report::text_line(&after));
                        summary.applied += 1;
                    }
                    Some(after) => {
                        println!("  {}", report::text_line(&after));
                        println!(
                            "  {}",
                            "Komut çalıştı ama sorun sürüyor; elle kontrol et.".yellow()
                        );
                        summary.failed += 1;
                    }
                    None => summary.applied += 1,
                }
            }
            Err(err) => {
                println!("  {} {err}", "Başarısız:".red().bold());
                summary.failed += 1;
            }
        }
    }

    if !manual.is_empty() {
        println!();
        println!("{}", "Elle düzeltilmesi gerekenler".bold());
        for result in manual {
            println!("  {} {}: {}", "•".yellow(), result.name.bold(), result.advice);
        }
    }

    println!();
    if options.dry_run {
        println!(
            "{}",
            "Önizleme tamamlandı; hiçbir ayar değiştirilmedi.".dimmed()
        );
    } else {
        println!(
            "Düzeltme özeti: {} uygulandı · {} başarısız · {} atlandı",
            summary.applied, summary.failed, summary.skipped
        );
    }
    summary
}

/// Sorunları "otomatik düzeltilebilir" ve "elle düzeltilecek" diye ayırır.
/// İstisnalı kontrollere dokunulmaz (`is_issue` onları dışarıda bırakır).
fn split_issues(results: &[CheckResult]) -> (Vec<(&CheckResult, Fix)>, Vec<&CheckResult>) {
    let mut fixable = Vec::new();
    let mut manual = Vec::new();
    for result in results.iter().filter(|result| result.is_issue()) {
        match result.fix {
            Some(fix) => fixable.push((result, fix)),
            None => manual.push(result),
        }
    }
    (fixable, manual)
}

/// Kullanıcıdan evet/hayır yanıtı alır. Girdi terminal değilse (ör. betik
/// içinde) güvenli tarafta kalıp "hayır" sayarız.
fn confirm(prompt: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        println!("{prompt}(etkileşimli terminal yok; `--yes` ile onay verilebilir)");
        return false;
    }
    print!("{prompt}");
    let _ = std::io::stdout().flush();

    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }
    is_yes(&answer)
}

fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "e" | "evet" | "y" | "yes"
    )
}

/// Düzeltme komutunu çalıştırır. Girdi/çıktı terminale bağlı kalır; böylece
/// `sudo` parolayı doğrudan kullanıcıya sorabilir.
fn apply(fix: &Fix) -> Result<(), String> {
    let mut command = if fix.sudo {
        let mut command = Command::new("sudo");
        command.arg(fix.program);
        command
    } else {
        Command::new(fix.program)
    };

    let status = command
        .args(fix.args)
        .status()
        .map_err(|err| format!("komut başlatılamadı: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("komut hata koduyla bitti ({status})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::score::tests::result;

    const FIX: Fix = Fix {
        program: "true",
        args: &[],
        sudo: false,
    };

    #[test]
    fn evet_yanitlari() {
        for yes in ["e", "E", "evet", "y", "YES", " e\n"] {
            assert!(is_yes(yes), "{yes:?} evet sayılmalı");
        }
        for no in ["", "\n", "h", "hayır", "n", "belki"] {
            assert!(!is_yes(no), "{no:?} hayır sayılmalı");
        }
    }

    #[test]
    fn sorunlari_dogru_ayirir() {
        let mut fixable = result("firewall", Status::Fail, 20);
        fixable.fix = Some(FIX);

        let manual = result("filevault", Status::Fail, 25);

        let mut passing = result("sip", Status::Pass, 20);
        passing.fix = Some(FIX);

        let mut exempt = result("ssh", Status::Warn, 10);
        exempt.fix = Some(FIX);
        exempt.exempt = Some("bilerek açık".into());

        let results = [fixable, manual, passing, exempt];
        let (fixable, manual) = split_issues(&results);

        assert_eq!(fixable.len(), 1);
        assert_eq!(fixable[0].0.id, "firewall");
        assert_eq!(manual.len(), 1);
        assert_eq!(manual[0].id, "filevault");
    }

    #[test]
    fn dry_run_hicbir_sey_uygulamaz() {
        let mut fixable = result("firewall", Status::Fail, 20);
        // Çalışırsa başarısız olacak bir komut: dry-run'da hiç çağrılmamalı.
        fixable.fix = Some(Fix {
            program: "false",
            args: &[],
            sudo: false,
        });

        let summary = run_fixes(
            &[fixable],
            &[],
            &Config::default(),
            &FixOptions {
                dry_run: true,
                yes: true,
            },
        );
        assert_eq!(
            summary,
            FixSummary {
                applied: 0,
                failed: 0,
                skipped: 1
            }
        );
    }

    #[test]
    fn komut_basari_ve_hata_durumu() {
        assert!(apply(&FIX).is_ok());
        let failing = Fix {
            program: "false",
            args: &[],
            sudo: false,
        };
        assert!(apply(&failing).is_err());
    }
}
