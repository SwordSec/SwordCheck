//! Dış komut çalıştırma katmanı.
//!
//! Kontroller sistem komutlarını doğrudan `std::process::Command` ile değil,
//! `CommandRunner` trait'i üzerinden çalıştırır. Böylece testlerde gerçek
//! komut yerine sahte (mock) çıktılar verebiliriz: "dependency injection".

use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

/// Bir komutun ham sonucu.
#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub stdout: String,
    pub stderr: String,
    /// Çıkış kodu 0 ise true.
    pub success: bool,
}

impl CmdOutput {
    /// stdout ve stderr'i tek metinde birleştirir. Bazı araçlar
    /// (ör. `sysadminctl`) asıl bilgiyi stderr'e yazar.
    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr).trim().to_string()
    }

    /// Eski `run` davranışı: komut başarılıysa ya da stdout doluysa çıktıyı,
    /// aksi halde hata açıklamasını döndürür.
    pub fn into_stdout(self) -> Result<String, String> {
        if self.success || !self.stdout.is_empty() {
            Ok(self.stdout)
        } else if self.stderr.is_empty() {
            Err("komut beklenmeyen bir çıkış kodu döndürdü".to_string())
        } else {
            Err(self.stderr)
        }
    }
}

/// Komut çalıştırabilen her şey. `Sync` şartı, aynı runner'ın birden çok
/// iş parçacığından (thread) paylaşılabilmesi içindir.
pub trait CommandRunner: Sync {
    /// `Err` yalnızca komut hiç başlatılamadığında döner (ör. program yok).
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String>;
}

/// Gerçek sistem komutlarını çalıştırır ve sonuçları önbelleğe alır.
///
/// Birkaç kontrol aynı komutu kullanır (ör. `netstat`); önbellek sayesinde
/// komut bir kez çalışır. `Mutex`, paralel kontrollerin haritaya güvenle
/// erişmesini sağlar.
#[derive(Default)]
pub struct SystemRunner {
    cache: Mutex<HashMap<String, Result<CmdOutput, String>>>,
}

impl SystemRunner {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        let key = command_key(program, args);

        // Kilidi yalnızca haritaya bakarken tutuyoruz; komut çalışırken
        // bırakıyoruz ki diğer kontroller beklemesin.
        if let Some(cached) = self.cache.lock().unwrap().get(&key) {
            return cached.clone();
        }

        let result = Command::new(program)
            .args(args)
            .output()
            .map(|output| CmdOutput {
                stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                success: output.status.success(),
            })
            .map_err(|err| format!("`{program}` çalıştırılamadı: {err}"));

        self.cache.lock().unwrap().insert(key, result.clone());
        result
    }
}

/// Önbellek ve mock anahtarı: program ve argümanlar boşlukla birleştirilir.
fn command_key(program: &str, args: &[&str]) -> String {
    let mut key = program.to_string();
    for arg in args {
        key.push(' ');
        key.push_str(arg);
    }
    key
}

/// Testler için sahte runner: önceden tanımlanan çıktıları döndürür.
#[cfg(test)]
#[derive(Default)]
pub struct MockRunner {
    responses: HashMap<String, CmdOutput>,
}

#[cfg(test)]
impl MockRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Başarılı (çıkış kodu 0) bir komut tanımlar.
    pub fn ok(mut self, command: &str, stdout: &str) -> Self {
        self.responses.insert(
            command.to_string(),
            CmdOutput {
                stdout: stdout.to_string(),
                stderr: String::new(),
                success: true,
            },
        );
        self
    }

    /// Başarısız bir komut tanımlar; mesaj stderr'e yazılmış sayılır.
    pub fn fail(mut self, command: &str, stderr: &str) -> Self {
        self.responses.insert(
            command.to_string(),
            CmdOutput {
                stdout: String::new(),
                stderr: stderr.to_string(),
                success: false,
            },
        );
        self
    }

    /// Başarılı ama çıktısını stderr'e yazan bir komut tanımlar.
    pub fn ok_stderr(mut self, command: &str, stderr: &str) -> Self {
        self.responses.insert(
            command.to_string(),
            CmdOutput {
                stdout: String::new(),
                stderr: stderr.to_string(),
                success: true,
            },
        );
        self
    }
}

#[cfg(test)]
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        let key = command_key(program, args);
        self.responses
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("mock: tanımsız komut `{key}`"))
    }
}
