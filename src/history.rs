//! Denetim geçmişi: her çalıştırma `~/.macos-audit/history.json` dosyasına
//! eklenir ve bir sonraki çalıştırmada önceki durumla karşılaştırılır.

use crate::checks::{CheckResult, Status};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Dosyada tutulacak en fazla kayıt sayısı.
const MAX_RECORDS: usize = 100;

/// Tek bir denetim çalıştırmasının özeti.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    /// RFC 3339 biçiminde yerel zaman.
    pub timestamp: String,
    pub os_version: String,
    pub score: u32,
    /// Kontrol kimliği → durum. `BTreeMap` anahtarları sıralı tutar;
    /// dosya her yazımda aynı düzende olur.
    pub checks: BTreeMap<String, Status>,
}

impl RunRecord {
    pub fn new(timestamp: String, os_version: String, score: u32, results: &[CheckResult]) -> Self {
        Self {
            timestamp,
            os_version,
            score,
            checks: results
                .iter()
                .map(|result| (result.id.to_string(), result.status))
                .collect(),
        }
    }
}

/// Bir kontrolün iki çalıştırma arasındaki durum değişikliği.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Change {
    pub id: &'static str,
    pub name: &'static str,
    pub from: Status,
    pub to: Status,
}

impl Change {
    /// Değişiklik iyiye mi gidiyor? (Pass en iyi, Fail en kötü.)
    pub fn improved(&self) -> bool {
        rank(self.to) > rank(self.from)
    }
}

fn rank(status: Status) -> u8 {
    match status {
        Status::Fail => 0,
        Status::Warn => 1,
        Status::Unknown => 2,
        Status::Pass => 3,
    }
}

/// Geçmiş dosyasının yolu. `MACOS_AUDIT_HOME` ortam değişkeni ile dizin
/// değiştirilebilir (testlerde ve denemelerde kullanışlı).
pub fn history_path() -> Option<PathBuf> {
    let dir = match std::env::var_os("MACOS_AUDIT_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(&std::env::var_os("HOME")?).join(".macos-audit"),
    };
    Some(dir.join("history.json"))
}

/// Geçmiş kayıtlarını okur. Dosya yoksa boş liste döner; bozuksa hata verir
/// (üzerine yazıp veriyi kaybetmemek için).
pub fn load(path: &Path) -> Result<Vec<RunRecord>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|err| format!("{} ayrıştırılamadı: {err}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(format!("{} okunamadı: {err}", path.display())),
    }
}

/// Yeni kaydı ekleyip dosyayı yazar; en eski kayıtlar `MAX_RECORDS` aşılınca
/// silinir.
pub fn append(path: &Path, mut records: Vec<RunRecord>, record: RunRecord) -> Result<(), String> {
    records.push(record);
    if records.len() > MAX_RECORDS {
        let excess = records.len() - MAX_RECORDS;
        records.drain(..excess);
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|err| format!("{} oluşturulamadı: {err}", dir.display()))?;
    }
    let json = serde_json::to_string_pretty(&records).map_err(|err| err.to_string())?;
    std::fs::write(path, json).map_err(|err| format!("{} yazılamadı: {err}", path.display()))
}

/// Önceki kayıtla şimdiki sonuçlar arasında durumu değişen kontroller.
/// Önceki kayıtta bulunmayan (yeni eklenen) kontroller değişiklik sayılmaz.
pub fn diff(previous: &RunRecord, results: &[CheckResult]) -> Vec<Change> {
    results
        .iter()
        .filter_map(|result| {
            let from = *previous.checks.get(result.id)?;
            (from != result.status).then_some(Change {
                id: result.id,
                name: result.name,
                from,
                to: result.status,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::tests::result;

    fn record(score: u32, results: &[CheckResult]) -> RunRecord {
        RunRecord::new("2026-11-10T10:00:00+03:00".into(), "macOS 26".into(), score, results)
    }

    #[test]
    fn degisen_kontrolleri_bulur() {
        let before = record(
            50,
            &[
                result("firewall", Status::Fail, 20),
                result("sip", Status::Pass, 20),
            ],
        );
        let now = [
            result("firewall", Status::Pass, 20),
            result("sip", Status::Pass, 20),
            result("yeni", Status::Fail, 5), // önceki kayıtta yok: sayılmaz
        ];

        let changes = diff(&before, &now);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, "firewall");
        assert!(changes[0].improved());
    }

    #[test]
    fn kotulesme_iyilesme_sayilmaz() {
        let change = Change {
            id: "x",
            name: "x",
            from: Status::Pass,
            to: Status::Warn,
        };
        assert!(!change.improved());
    }

    #[test]
    fn yazip_geri_okur_ve_sinirlar() {
        let dir = std::env::temp_dir().join(format!("macos-audit-hist-{}", std::process::id()));
        let path = dir.join("history.json");

        assert!(load(&path).unwrap().is_empty(), "dosya yokken boş liste");

        let results = [result("a", Status::Pass, 1)];
        for score in 0..(MAX_RECORDS as u32 + 5) {
            let records = load(&path).unwrap();
            append(&path, records, record(score, &results)).unwrap();
        }

        let records = load(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(records.len(), MAX_RECORDS);
        assert_eq!(records.last().unwrap().score, MAX_RECORDS as u32 + 4);
        assert_eq!(records[0].score, 5, "en eski 5 kayıt silinmeli");
        assert_eq!(records[0].checks["a"], Status::Pass);
    }

    #[test]
    fn bozuk_dosya_hata_verir() {
        let dir = std::env::temp_dir().join(format!("macos-audit-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        std::fs::write(&path, "{ bozuk").unwrap();

        let loaded = load(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(loaded.is_err());
    }
}
