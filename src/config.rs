//! `audit.toml` yapılandırma dosyası.
//!
//! Örnek:
//!
//! ```toml
//! min_score = 80
//! skip = ["airdrop"]
//!
//! [weights]
//! filevault = 40
//!
//! [exceptions]
//! ssh = "Geliştirme sunucusu, SSH bilerek açık"
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Yapılandırma. Tüm alanlar isteğe bağlıdır (`#[serde(default)]`);
/// `deny_unknown_fields` yazım hatalarını sessizce yutmak yerine bildirir.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Puan bu değerin altındaysa çıkış kodu 1 olur.
    pub min_score: Option<u32>,
    /// Hiç çalıştırılmayacak kontrollerin kimlikleri.
    pub skip: Vec<String>,
    /// Kontrol kimliği → puandaki ağırlık.
    pub weights: HashMap<String, u32>,
    /// Kontrol kimliği → istisna gerekçesi. İstisnalı kontrol çalışır ve
    /// gösterilir ama puana ve çıkış koduna etki etmez.
    pub exceptions: HashMap<String, String>,
}

impl Config {
    /// Yapılandırmayı yükler.
    ///
    /// `explicit` verilmişse o dosya zorunludur. Verilmemişse sırayla
    /// `./audit.toml` ve `~/.config/macos-audit/audit.toml` denenir; hiçbiri
    /// yoksa varsayılan (boş) yapılandırma döner.
    pub fn load(explicit: Option<&Path>) -> Result<Self, String> {
        let path = match explicit {
            Some(path) => Some(path.to_path_buf()),
            None => default_paths().into_iter().find(|path| path.is_file()),
        };

        match path {
            Some(path) => {
                let text = std::fs::read_to_string(&path)
                    .map_err(|err| format!("{} okunamadı: {err}", path.display()))?;
                Self::parse(&text).map_err(|err| format!("{}: {err}", path.display()))
            }
            None => Ok(Self::default()),
        }
    }

    /// TOML metnini ayrıştırır.
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Config = toml::from_str(text).map_err(|err| err.to_string())?;
        if config.min_score.is_some_and(|score| score > 100) {
            return Err("min_score 0 ile 100 arasında olmalı".to_string());
        }
        Ok(config)
    }

    /// Yapılandırmada geçen tüm kontrol kimlikleri (doğrulama için).
    pub fn referenced_ids(&self) -> impl Iterator<Item = &str> {
        self.skip
            .iter()
            .chain(self.weights.keys())
            .chain(self.exceptions.keys())
            .map(String::as_str)
    }
}

fn default_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("audit.toml")];
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(Path::new(&home).join(".config/macos-audit/audit.toml"));
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tam_ornek_ayristirilir() {
        let config = Config::parse(
            r#"
            min_score = 80
            skip = ["airdrop"]

            [weights]
            filevault = 40

            [exceptions]
            ssh = "bilerek açık"
            "#,
        )
        .unwrap();

        assert_eq!(config.min_score, Some(80));
        assert_eq!(config.skip, ["airdrop"]);
        assert_eq!(config.weights["filevault"], 40);
        assert_eq!(config.exceptions["ssh"], "bilerek açık");

        let mut ids: Vec<&str> = config.referenced_ids().collect();
        ids.sort_unstable();
        assert_eq!(ids, ["airdrop", "filevault", "ssh"]);
    }

    #[test]
    fn bos_dosya_varsayilan_verir() {
        let config = Config::parse("").unwrap();
        assert!(config.min_score.is_none());
        assert!(config.skip.is_empty());
    }

    #[test]
    fn bilinmeyen_alan_ve_gecersiz_puan_reddedilir() {
        assert!(Config::parse("minscore = 80").is_err());
        assert!(Config::parse("min_score = 150").is_err());
    }
}
