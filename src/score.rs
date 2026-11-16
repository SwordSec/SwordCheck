//! Puan ve not hesaplama.

use crate::checks::{CheckResult, Status};
use serde::Serialize;

/// Ağırlıklı puanı (0-100) hesaplar.
///
/// Pass = tam puan, Warn = yarım puan, Fail = 0 puan.
/// Unknown ve istisnalı kontroller paydaya dahil edilmez; böylece tespit
/// edilemeyen ya da bilerek kabul edilen bir durum puanı düşürmez.
pub fn calculate_score(results: &[CheckResult]) -> u32 {
    let mut earned: u32 = 0;
    let mut possible: u32 = 0;

    for result in results.iter().filter(|result| result.exempt.is_none()) {
        match result.status {
            Status::Pass => {
                // Yarım puanlar tam sayı kalsın diye her şeyi 2 ile çarpıyoruz.
                earned += result.weight * 2;
                possible += result.weight * 2;
            }
            Status::Warn => {
                earned += result.weight;
                possible += result.weight * 2;
            }
            Status::Fail => possible += result.weight * 2,
            Status::Unknown => {}
        }
    }

    // `possible` sıfırsa `earned` de sıfırdır; max(1) sıfıra bölmeyi önler.
    earned * 100 / possible.max(1)
}

/// Puanın harf notu.
pub fn grade(score: u32) -> &'static str {
    match score {
        90.. => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

/// Durumlara göre kontrol sayıları.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub unknown: usize,
    pub exempt: usize,
}

impl Summary {
    pub fn from_results(results: &[CheckResult]) -> Self {
        let mut summary = Self::default();
        for result in results {
            if result.exempt.is_some() {
                summary.exempt += 1;
                continue;
            }
            match result.status {
                Status::Pass => summary.pass += 1,
                Status::Warn => summary.warn += 1,
                Status::Fail => summary.fail += 1,
                Status::Unknown => summary.unknown += 1,
            }
        }
        summary
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::checks::Severity;

    /// Testlerde kullanılan kısa sonuç üretici (diğer modüller de kullanır).
    pub fn result(id: &'static str, status: Status, weight: u32) -> CheckResult {
        CheckResult {
            id,
            name: id,
            status,
            severity: Severity::Medium,
            weight,
            cis: None,
            detail: format!("{id} ayrıntısı"),
            advice: "öneri",
            exempt: None,
            fix: None,
        }
    }

    #[test]
    fn hepsi_gecerse_yuz() {
        let results = [result("a", Status::Pass, 25), result("b", Status::Pass, 10)];
        assert_eq!(calculate_score(&results), 100);
    }

    #[test]
    fn uyari_yarim_puan_basarisiz_sifir() {
        let results = [
            result("a", Status::Pass, 50),
            result("b", Status::Warn, 30),
            result("c", Status::Fail, 20),
        ];
        // 50 + 15 + 0 = 65
        assert_eq!(calculate_score(&results), 65);
    }

    #[test]
    fn tek_agirlikli_uyari_yuvarlama_hatasi_yapmaz() {
        // Eski hesap 5 / 2 = 2 diyerek puanı düşük gösteriyordu.
        let results = [result("a", Status::Warn, 5)];
        assert_eq!(calculate_score(&results), 50);
    }

    #[test]
    fn bilinmeyen_ve_istisna_paydaya_girmez() {
        let mut exempt = result("c", Status::Fail, 50);
        exempt.exempt = Some("gerekçe".into());
        let results = [
            result("a", Status::Pass, 10),
            result("b", Status::Unknown, 90),
            exempt,
        ];
        assert_eq!(calculate_score(&results), 100);
    }

    #[test]
    fn bos_listede_sifira_bolmez() {
        assert_eq!(calculate_score(&[]), 0);
    }

    #[test]
    fn harf_notlari() {
        assert_eq!(grade(100), "A");
        assert_eq!(grade(90), "A");
        assert_eq!(grade(89), "B");
        assert_eq!(grade(60), "C");
        assert_eq!(grade(59), "D");
        assert_eq!(grade(0), "F");
    }

    #[test]
    fn ozet_sayilari() {
        let mut exempt = result("d", Status::Warn, 5);
        exempt.exempt = Some("gerekçe".into());
        let results = [
            result("a", Status::Pass, 1),
            result("b", Status::Fail, 1),
            result("c", Status::Unknown, 1),
            exempt,
        ];
        assert_eq!(
            Summary::from_results(&results),
            Summary {
                pass: 1,
                warn: 0,
                fail: 1,
                unknown: 1,
                exempt: 1
            }
        );
    }
}
