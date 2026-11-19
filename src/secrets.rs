//! Secret taraması (`--secrets`): bu makinede hangi API anahtarı nerede duruyor?
//!
//! Geliştirici makinelerinde anahtarlar `.env` dosyalarına, kabuk
//! geçmişine, araç yapılandırmalarına dağılır. Bu modül o dosyaları bulur,
//! sağlayıcıya özel düzenli ifadelerle (`RULES`) tarar ve "hangi sağlayıcı →
//! hangi dosyalar" özetini çıkarır.
//!
//! Üç tür işaret aranır:
//! 1. **Sağlayıcı kalıpları**: öneki belli anahtarlar (`sk-ant-…`, `AKIA…`,
//!    `ghp_…`). Kesine yakın bulgulardır.
//! 2. **Genel atamalar**: adı `SECRET`, `TOKEN`, `PASSWORD`, `API_KEY` içeren
//!    değişkenler. Değer yeterince rastgele görünüyorsa raporlanır (sezgisel).
//! 3. **Parolasız özel anahtarlar**: şifrelenmemiş PEM / OpenSSH anahtarları.
//!
//! Güvenlik kuralları:
//! - Tarama salt okunurdur ve ağa çıkmaz.
//! - Ham anahtar değeri hiçbir çıktıya yazılmaz; raporlarda yalnızca maskeli
//!   hali (`sk-ant-api0…a3F9`) bulunur. Ham değer yalnızca aynı anahtarın
//!   farklı dosyalardaki kopyalarını eşleştirmek için bellekte tutulur.

use colored::Colorize;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

// ---- Kurallar ----

/// Bir sağlayıcının anahtar kalıbı. Desende yakalama grubu varsa anahtar
/// 1. gruptur, yoksa eşleşmenin tamamıdır.
struct Rule {
    id: &'static str,
    provider: &'static str,
    pattern: &'static str,
    /// Doluysa kural yalnızca adı bu parçayı içeren dosyalarda çalışır.
    file_hint: Option<&'static str>,
}

const fn rule(id: &'static str, provider: &'static str, pattern: &'static str) -> Rule {
    Rule { id, provider, pattern, file_hint: None }
}

const PRIVATE_KEY: &str = "private-key";
const GENERIC: &str = "generic";
const URL_PASSWORD: &str = "url-password";

/// Sıra önemlidir: bir metin parçasını ilk eşleşen kural sahiplenir.
const RULES: &[Rule] = &[
    rule("anthropic", "Anthropic", r"\bsk-ant-[A-Za-z0-9_-]{24,}"),
    rule("openrouter", "OpenRouter", r"\bsk-or-v1-[a-f0-9]{64}\b"),
    rule("openai", "OpenAI", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{24,}"),
    rule("openai-legacy", "OpenAI", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    rule("aws-access-key", "AWS", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    rule(
        "aws-secret-key",
        "AWS",
        r#"(?i)aws_secret_access_key["']?\s*[=:]\s*["']?([A-Za-z0-9/+]{40})\b"#,
    ),
    rule("google-api-key", "Google", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    rule("google-oauth-secret", "Google", r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
    rule("digitalocean", "DigitalOcean", r"\bdo[por]_v1_[a-f0-9]{64}\b"),
    rule("github", "GitHub", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    rule("github-pat", "GitHub", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    rule("gitlab", "GitLab", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    rule("slack", "Slack", r"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
    rule(
        "slack-webhook",
        "Slack",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}",
    ),
    rule("stripe", "Stripe", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    rule("sendgrid", "SendGrid", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    rule("twilio", "Twilio", r"\bSK[0-9a-f]{32}\b"),
    rule("npm", "npm", r"\bnpm_[A-Za-z0-9]{36}\b"),
    rule("huggingface", "Hugging Face", r"\bhf_[A-Za-z0-9]{34,}\b"),
    rule("groq", "Groq", r"\bgsk_[A-Za-z0-9]{40,}\b"),
    rule("telegram", "Telegram", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    rule(
        PRIVATE_KEY,
        "Özel anahtar (parolasız)",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    ),
    Rule {
        id: "docker-auth",
        provider: "Docker registry",
        pattern: r#""auth"\s*:\s*"([A-Za-z0-9+/=]{16,})""#,
        file_hint: Some("config.json"),
    },
    Rule {
        id: "kube-client-key",
        provider: "Kubernetes",
        pattern: r"client-key-data:\s*([A-Za-z0-9+/=]{40,})",
        file_hint: None,
    },
    Rule {
        id: "netrc",
        provider: "netrc parolası",
        pattern: r"\bpassword\s+(\S{4,})",
        file_hint: Some("netrc"),
    },
    rule(
        "jwt",
        "JWT",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    rule(
        URL_PASSWORD,
        "URL içinde parola",
        r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\x22]{1,64}:([^\s@/'\x22]{4,})@[A-Za-z0-9\[]",
    ),
];

/// Genel atama: 1. grup değişken adı, 2. grup değer.
const GENERIC_PATTERN: &str = r#"(?i)\b([a-z0-9_.-]*(?:secret|token|passwd|password|api_?key|apikey|private_?key|access_?key)[a-z0-9_.-]*)["']?\s*[=:]\s*["']?([^\s"'`,;#]{8,})"#;

/// Bir eşleşmenin hemen solundaki `AD=` ya da `"ad": "` parçasından adı alır.
const NAME_PATTERN: &str = r#"([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[=:]\s*["']?$"#;

struct Compiled {
    rules: Vec<(&'static Rule, Regex)>,
    generic: Regex,
    name: Regex,
}

/// Düzenli ifadeleri derlemek pahalıdır; ilk kullanımda bir kez derlenir.
static COMPILED: LazyLock<Compiled> = LazyLock::new(|| Compiled {
    rules: RULES
        .iter()
        .map(|rule| (rule, Regex::new(rule.pattern).expect("kural deseni geçerli")))
        .collect(),
    generic: Regex::new(GENERIC_PATTERN).expect("genel desen geçerli"),
    name: Regex::new(NAME_PATTERN).expect("ad deseni geçerli"),
});

// ---- Sonuç tipleri ----

/// Bir dosyada bulunan tek bir anahtar.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub provider: &'static str,
    pub rule: &'static str,
    /// Anahtarın maskeli hali; ham değer asla serileştirilmez.
    pub masked: String,
    /// Anahtarın atandığı değişken adı (bulunabildiyse).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub path: PathBuf,
    pub line: usize,
    /// Aynı anahtarın bu dosyada kaç kez geçtiği.
    pub occurrences: usize,
    /// Aynı numara = aynı anahtar (farklı dosyalardaki kopyalar).
    pub secret_id: usize,
    /// Dosya bir git deposunda izleniyor mu (commit'lenmiş mi)?
    pub git_tracked: bool,
    /// Dosya izni, sekizlik (ör. `644`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Grup ya da diğer kullanıcılar dosyayı okuyabiliyor mu?
    pub others_can_read: bool,
    #[serde(skip)]
    secret: String,
}

/// Sağlayıcı başına özet satırı.
#[derive(Debug, Serialize, PartialEq)]
pub struct ProviderSummary {
    pub provider: &'static str,
    pub secrets: usize,
    pub locations: usize,
    pub git_tracked: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Scan {
    pub files_scanned: usize,
    pub summary: Vec<ProviderSummary>,
    pub findings: Vec<Finding>,
}

impl Scan {
    pub fn unique_secrets(&self) -> usize {
        self.findings.iter().map(|f| f.secret_id).collect::<BTreeSet<_>>().len()
    }

    pub fn tracked(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| finding.git_tracked)
    }
}

// ---- Metin taraması ----

/// Dosya içeriğinde bulunan ham eşleşme.
struct Match {
    rule: &'static str,
    provider: &'static str,
    secret: String,
    name: Option<String>,
    offset: usize,
}

/// Metindeki tüm anahtarları bulur. `file_name` yalnızca `file_hint`
/// kuralları için kullanılır.
fn scan_text(file_name: &str, text: &str) -> Vec<Match> {
    let compiled = &*COMPILED;
    let mut matches = Vec::new();
    // Sahiplenilen bayt aralıkları: aynı parçayı ikinci bir kural raporlamasın.
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let overlaps = |taken: &[(usize, usize)], start: usize, end: usize| {
        taken.iter().any(|&(s, e)| start < e && s < end)
    };

    // `.env.example` gibi şablonlar bilerek depoya konur ve uydurma
    // parolalar içerir; orada yalnızca gerçek anahtar kalıpları aranır.
    let template = is_template(file_name);

    for (rule, regex) in &compiled.rules {
        if rule.file_hint.is_some_and(|hint| !file_name.contains(hint))
            || (template && rule.id == URL_PASSWORD)
        {
            continue;
        }
        for captures in regex.captures_iter(text) {
            let whole = captures.get(0).expect("0. grup her zaman vardır");
            let value = captures.get(1).unwrap_or(whole);
            if overlaps(&taken, value.start(), value.end()) {
                continue;
            }
            let secret = if rule.id == PRIVATE_KEY {
                if key_is_encrypted(&text[whole.end()..]) {
                    continue;
                }
                // Her özel anahtar ayrı sayılır; içeriği karşılaştırmıyoruz.
                format!("pem@{}", whole.start())
            } else {
                if is_placeholder(value.as_str()) {
                    continue;
                }
                value.as_str().to_string()
            };
            taken.push((value.start(), value.end()));
            matches.push(Match {
                rule: rule.id,
                provider: rule.provider,
                secret,
                name: name_before(text, whole.start()),
                offset: whole.start(),
            });
        }
    }

    if template {
        return matches;
    }
    for captures in compiled.generic.captures_iter(text) {
        let (Some(name), Some(value)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        if overlaps(&taken, value.start(), value.end())
            || !looks_secret(name.as_str(), value.as_str())
        {
            continue;
        }
        taken.push((value.start(), value.end()));
        matches.push(Match {
            rule: GENERIC,
            provider: "Genel (ada göre)",
            secret: value.as_str().to_string(),
            name: Some(name.as_str().to_string()),
            offset: name.start(),
        });
    }

    matches
}

/// Eşleşmenin bulunduğu satırda, hemen solundaki değişken adını döndürür.
fn name_before(text: &str, offset: usize) -> Option<String> {
    let line_start = text[..offset].rfind('\n').map_or(0, |index| index + 1);
    let prefix = &text[line_start..offset];
    let captures = COMPILED.name.captures(prefix)?;
    Some(captures.get(1)?.as_str().to_string())
}

/// PEM başlığından sonraki gövde şifreli (parolalı) bir anahtara mı ait?
fn key_is_encrypted(after_header: &str) -> bool {
    // Eski PEM biçimi şifrelemeyi başlıkta belirtir.
    let head: String = after_header.chars().take(200).collect();
    if head.contains("ENCRYPTED") {
        return true;
    }
    // OpenSSH biçiminde şifre adı gövdenin başındadır. Parolasız anahtarda
    // bu ad "none"dır; base64 hali her zaman aynı önekle başlar.
    const OPENSSH_MAGIC: &str = "b3BlbnNzaC1rZXktdjEA";
    const OPENSSH_NONE: &str = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";
    // JSON içine gömülü anahtarlarda satır sonu `\n` iki karakteri olarak yazılır.
    let body: String = head.replace("\\n", "").split_whitespace().collect();
    body.starts_with(OPENSSH_MAGIC) && !body.starts_with(OPENSSH_NONE)
}

/// Dosya bir şablon mu (`.env.example`, `config.sample.json`)?
fn is_template(file_name: &str) -> bool {
    const MARKERS: [&str; 5] = ["example", "sample", "template", ".dist", ".defaults"];
    let lower = file_name.to_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Belgelerden kopyalanmış örnek / yer tutucu değerleri eler.
fn is_placeholder(value: &str) -> bool {
    const MARKERS: [&str; 20] = [
        "example", "sample", "placeholder", "changeme", "change_me", "change-me", "your_", "your-",
        "yourkey", "xxxx", "dummy", "redacted", "insert", "<", ">", "${", "$(", "{{", "***", "...",
    ];
    let lower = value.to_lowercase();
    let distinct: BTreeSet<char> = lower.chars().collect();
    distinct.len() <= 3 || MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Genel atamalarda değer gerçekten bir sır gibi mi görünüyor?
fn looks_secret(name: &str, value: &str) -> bool {
    const LITERALS: [&str; 6] = ["true", "false", "null", "none", "undefined", "required"];
    let lower = value.to_lowercase();
    if is_placeholder(value)
        || LITERALS.contains(&lower.as_str())
        // Değişken, yol, URL ya da kod parçası: sır değil, sırrın adresi.
        || value.starts_with(['$', '/', '~', '.', '%', '@', '[', '{', '!'])
        || lower.starts_with("http")
        || value.contains(['(', ')', '\\'])
        || value.chars().all(|c| c.is_ascii_digit())
        // `…TokenDate: 2026-01-31T…` gibi tarihler.
        || is_date(value)
    {
        return false;
    }
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let mixed_case = value.chars().any(char::is_lowercase) && value.chars().any(char::is_uppercase);
    let is_password = name.to_lowercase().contains("pass");
    entropy(value) >= 3.0 && (has_digit || mixed_case || is_password)
}

/// Değer `YYYY-AA-GG` ile mi başlıyor?
fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&index| bytes[index].is_ascii_digit())
}

/// Shannon entropisi (karakter başına bit). Rastgele anahtarlarda yüksek,
/// sözcüklerde düşüktür.
fn entropy(value: &str) -> f64 {
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in value.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let total = value.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Anahtarı tanınabilir ama kullanılamaz hale getirir.
fn mask(rule: &str, secret: &str) -> String {
    if rule == PRIVATE_KEY {
        return "(özel anahtar)".to_string();
    }
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();
    // Kısa değerlerde baş/son göstermek değerin çoğunu açığa çıkarır.
    if len < 16 {
        return format!("•••• ({len} karakter)");
    }
    let head: String = chars[..(len / 4).min(12)].iter().collect();
    let tail: String = chars[len - 4..].iter().collect();
    format!("{head}…{tail}")
}

// ---- Dosya taraması ----

/// Bu boyuttan büyük dosyalar okunmaz.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Tek bir dosyayı tarar. Okunamayan ve ikili dosyalar `None` döner.
fn scan_file(path: &Path) -> Option<Vec<Finding>> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.iter().take(1024).any(|&byte| byte == 0) {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    let file_name = path.file_name()?.to_string_lossy();

    // Aynı anahtar dosyada birçok kez geçebilir (ör. kabuk geçmişi);
    // ilk konumu saklayıp tekrarları sayıyoruz.
    let mut findings: Vec<Finding> = Vec::new();
    for found in scan_text(&file_name, &text) {
        if let Some(existing) = findings.iter_mut().find(|f| f.secret == found.secret) {
            existing.occurrences += 1;
            continue;
        }
        findings.push(Finding {
            provider: found.provider,
            rule: found.rule,
            masked: mask(found.rule, &found.secret),
            name: found.name,
            path: path.to_path_buf(),
            line: text[..found.offset].matches('\n').count() + 1,
            occurrences: 1,
            secret_id: 0,
            git_tracked: false,
            mode: None,
            others_can_read: false,
            // Özel anahtarlar dosyaya özgüdür; yol eklenince kopya sayılmazlar.
            secret: if found.rule == PRIVATE_KEY {
                format!("{}:{}", path.display(), found.secret)
            } else {
                found.secret
            },
        });
    }

    if !findings.is_empty() {
        let mode = file_mode(&metadata);
        let tracked = git_tracked(path);
        for finding in &mut findings {
            finding.git_tracked = tracked;
            finding.mode = mode.map(|mode| format!("{mode:o}"));
            finding.others_can_read = mode.is_some_and(|mode| mode & 0o044 != 0);
        }
    }
    Some(findings)
}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_: &std::fs::Metadata) -> Option<u32> {
    None
}

/// Dosya bir git deposunda izleniyor mu? `git` yoksa ya da dosya depo
/// dışındaysa `false`.
fn git_tracked(path: &Path) -> bool {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Dosyaları iş parçacıklarına dağıtarak tarar ve sonucu özetler.
pub fn scan(files: &[PathBuf]) -> Scan {
    let next = AtomicUsize::new(0);
    let scanned = AtomicUsize::new(0);
    let collected: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(4, usize::from).min(files.len().max(1));

    // `scope`, iş parçacıklarının yerel değişkenleri ödünç almasına izin
    // verir: kapsam bitmeden hepsinin tamamlandığı garantidir.
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                // Ortak sayaç iş kuyruğu görevi görür: her iş parçacığı
                // sıradaki dosyanın indisini alır.
                while let Some(path) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                    if let Some(findings) = scan_file(path) {
                        scanned.fetch_add(1, Ordering::Relaxed);
                        if !findings.is_empty() {
                            collected.lock().expect("kilit zehirlenmedi").extend(findings);
                        }
                    }
                }
            });
        }
    });

    let mut findings = collected.into_inner().expect("kilit zehirlenmedi");
    // İş parçacığı sırası rastgeledir; çıktı her çalıştırmada aynı olsun.
    findings.sort_by(|a, b| {
        (a.provider, &a.masked, &a.path, a.line).cmp(&(b.provider, &b.masked, &b.path, b.line))
    });

    let mut ids: BTreeMap<String, usize> = BTreeMap::new();
    for finding in &mut findings {
        let next_id = ids.len() + 1;
        finding.secret_id = *ids.entry(finding.secret.clone()).or_insert(next_id);
    }

    Scan {
        files_scanned: scanned.into_inner(),
        summary: summarize(&findings),
        findings,
    }
}

fn summarize(findings: &[Finding]) -> Vec<ProviderSummary> {
    let mut by_provider: BTreeMap<&'static str, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        by_provider.entry(finding.provider).or_default().push(finding);
    }
    by_provider
        .into_iter()
        .map(|(provider, items)| ProviderSummary {
            provider,
            secrets: items.iter().map(|f| f.secret_id).collect::<BTreeSet<_>>().len(),
            locations: items.len(),
            git_tracked: items.iter().filter(|f| f.git_tracked).count(),
        })
        .collect()
}

// ---- Taranacak dosyaların bulunması ----

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Ev dizininde anahtar barındırdığı bilinen dosyalar.
const HOME_FILES: [&str; 38] = [
    ".aws/credentials",
    ".aws/config",
    ".npmrc",
    ".yarnrc.yml",
    ".netrc",
    ".pypirc",
    ".pgpass",
    ".my.cnf",
    ".s3cfg",
    ".boto",
    ".git-credentials",
    ".gitconfig",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".config/hub",
    ".config/doctl/config.yaml",
    ".config/gcloud/application_default_credentials.json",
    ".config/fish/config.fish",
    ".cargo/credentials.toml",
    ".cargo/credentials",
    ".gem/credentials",
    ".terraform.d/credentials.tfrc.json",
    ".zsh_history",
    ".bash_history",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".claude.json",
    ".claude/settings.json",
    ".cursor/mcp.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    "Library/Application Support/Code/User/settings.json",
];

/// Proje içindeki gizli dizinlerde bakılan dosyalar (gizli dizinlerin
/// geri kalanı dolaşılmaz).
const HIDDEN_PROJECT_FILES: [&str; 7] = [
    ".git/config",
    ".vscode/settings.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".aws/credentials",
];

/// İçine inilmeyen dizinler: bağımlılıklar ve derleme çıktıları.
const SKIP_DIRS: [&str; 19] = [
    "testdata", "_testfiles", "fixtures",
    "node_modules", "target", "vendor", "Pods", "venv", "env", "__pycache__", "dist", "build",
    "DerivedData", "site-packages", "bower_components", "Carthage", "coverage", "out", "tmp",
];

/// Varsayılan hedefler: ev dizinindeki bilinen dosyalar, `~/.ssh` ve
/// ev dizini altındaki projeler.
pub fn default_files() -> Vec<PathBuf> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = HOME_FILES.iter().map(|relative| home.join(relative)).collect();

    // `~/.ssh` içindeki her dosya özel anahtar olabilir; adlar serbesttir.
    if let Ok(entries) = std::fs::read_dir(home.join(".ssh")) {
        files.extend(entries.flatten().map(|entry| entry.path()).filter(|path| {
            path.extension().is_none_or(|extension| extension != "pub")
        }));
    }

    // Büyük ve proje içermeyen üst düzey klasörler atlanır.
    const SKIP_TOP: [&str; 6] = ["Library", "Applications", "Music", "Movies", "Pictures", "Public"];
    files.extend(walk(&home, &SKIP_TOP));
    unique_files(files)
}

/// Kullanıcının verdiği yol: dosyaysa kendisi, dizinse altındaki adaylar.
pub fn files_under(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    unique_files(walk(path, &[]))
}

/// `base` altında anahtar barındırabilecek dosyaları arar. Gizli dizinler,
/// bağımlılık dizinleri ve sembolik bağlantılar atlanır.
fn walk(base: &Path, skip_top: &[&str]) -> Vec<PathBuf> {
    /// Ev dizininden başlayınca monorepo alt paketlerine yetecek derinlik.
    const MAX_DEPTH: usize = 9;

    fn visit(dir: &Path, depth: usize, skip: &[&str], found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        found.extend(HIDDEN_PROJECT_FILES.iter().map(|relative| dir.join(relative)).filter(|p| p.is_file()));

        for entry in entries.flatten() {
            // `file_type` bağlantıyı izlemez; sembolik bağlantılar ne dosya
            // ne dizin sayılıp atlanır (döngü ve kopya riskine karşı).
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if kind.is_file() {
                if is_candidate(&name) {
                    found.push(entry.path());
                }
            } else if kind.is_dir()
                && depth < MAX_DEPTH
                && !name.starts_with('.')
                && !SKIP_DIRS.contains(&name.as_ref())
                && !skip.contains(&name.as_ref())
                // Go modül önbelleği (`~/go/pkg`): başkalarının kodu ve test anahtarları.
                && !(name == "pkg" && dir.file_name().is_some_and(|parent| parent == "go"))
            {
                // Atlama listesi yalnızca en üst düzey için geçerlidir.
                visit(&entry.path(), depth + 1, &[], found);
            }
        }
    }

    let mut found = Vec::new();
    visit(base, 0, skip_top, &mut found);
    found
}

/// Dosya adı anahtar barındırmaya aday mı?
fn is_candidate(name: &str) -> bool {
    const EXACT: [&str; 12] = [
        ".npmrc", ".netrc", ".pypirc", ".mcp.json", ".envrc", "credentials.json", "credentials",
        "secrets.json", "secrets.yml", "secrets.yaml", "secrets.toml", "local.settings.json",
    ];
    const SUFFIXES: [&str; 7] = [".env", ".tfstate", ".tfvars", ".pem", ".key", ".p8", ".tfstate.backup"];
    let lower = name.to_lowercase();
    lower.starts_with(".env")
        || EXACT.contains(&lower.as_str())
        || SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
        || (lower.starts_with("service-account") && lower.ends_with(".json"))
}

/// Var olan dosyaları gerçek yollarına çevirip yinelenenleri eler.
fn unique_files(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let unique: BTreeSet<PathBuf> = candidates
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.is_file())
        .collect();
    unique.into_iter().collect()
}

// ---- Rapor (--secrets) ----

/// `--secrets` modunun çıktısı.
#[derive(Debug, Serialize)]
pub struct SecretsReport {
    pub tool: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    #[serde(flatten)]
    pub scan: Scan,
}

impl SecretsReport {
    pub fn new(timestamp: String, scan: Scan) -> Self {
        Self {
            tool: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            timestamp,
            scan,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("rapor JSON'a çevrilebilir")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let rule = "─".repeat(78).dimmed();
        let scan = &self.scan;
        let home = home();
        let short = |path: &Path| display_path(path, home.as_deref());

        let _ = writeln!(out);
        let _ = writeln!(out, "{}", " Secret / API Anahtarı Taraması ".on_blue().white().bold());
        let _ = writeln!(
            out,
            " {} dosya tarandı · {} anahtar · {} konum",
            scan.files_scanned,
            scan.unique_secrets(),
            scan.findings.len()
        );
        let _ = writeln!(out, "{rule}");

        if scan.findings.is_empty() {
            let _ = writeln!(out, "{}", "Anahtar bulunmadı.".green().bold());
            return out.trim_end().to_string();
        }

        let _ = writeln!(out, "{}", "ÖZET".bold());
        for row in &scan.summary {
            let tracked = if row.git_tracked > 0 {
                format!("  {} konum git'te izleniyor", row.git_tracked).red().bold().to_string()
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "  {:<26} {:>3} anahtar {:>4} konum{tracked}",
                row.provider, row.secrets, row.locations
            );
        }
        let _ = writeln!(out, "{rule}");

        // Sağlayıcı → anahtar → konumlar. Bulgular zaten bu sırada.
        let mut provider = "";
        let mut secret_id = 0;
        for finding in &scan.findings {
            if finding.provider != provider {
                provider = finding.provider;
                secret_id = 0;
                let _ = writeln!(out);
                let _ = writeln!(out, "{}", provider.bold());
            }
            if finding.secret_id != secret_id {
                secret_id = finding.secret_id;
                let copies = scan.findings.iter().filter(|f| f.secret_id == secret_id).count();
                let note = if copies > 1 {
                    format!("  ({copies} yerde)").yellow().to_string()
                } else {
                    String::new()
                };
                let _ = writeln!(out, "  {}{note}", finding.masked.cyan());
            }

            let mut flags = Vec::new();
            if let Some(name) = &finding.name {
                flags.push(name.clone());
            }
            if finding.occurrences > 1 {
                flags.push(format!("{}×", finding.occurrences));
            }
            if finding.git_tracked {
                flags.push("GIT'TE İZLENİYOR".red().bold().to_string());
            }
            if finding.others_can_read && let Some(mode) = &finding.mode {
                flags.push(format!("izin {mode}").yellow().to_string());
            }
            let _ = writeln!(
                out,
                "      {}:{}  {}",
                short(&finding.path),
                finding.line,
                flags.join(" · ").dimmed()
            );
        }

        let _ = writeln!(out);
        let _ = writeln!(out, "{rule}");
        let tracked = scan.tracked().count();
        if tracked > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!("{tracked} anahtar git'te izlenen bir dosyada duruyor.").red().bold()
            );
            let _ = writeln!(
                out,
                "Depo paylaşıldıysa anahtarı sızmış say: sağlayıcıdan iptal edip yenile,\n\
                 dosyayı `.gitignore`'a ekle ve `git rm --cached` ile izlemeden çıkar."
            );
        }
        let loose = scan.findings.iter().filter(|f| f.others_can_read).count();
        if loose > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!("{loose} konumda dosya diğer kullanıcılarca okunabilir: `chmod 600 DOSYA`.").yellow()
            );
        }
        let _ = writeln!(
            out,
            "{}",
            "Değerler maskelidir. \"Genel\" bulgular sezgiseldir; yanlış alarm olabilir.".dimmed()
        );
        out.trim_end().to_string()
    }
}

/// Ev dizinini `~` ile kısaltır.
fn display_path(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|home| path.strip_prefix(home).ok()) {
        Some(relative) => format!("~/{}", relative.display()),
        None => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test bitince silinen geçici dizin (`Drop` ile).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("macos-audit-secrets-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // macOS'ta geçici dizin bir sembolik bağlantının altındadır.
            Self(dir.canonicalize().unwrap())
        }

        fn write(&self, relative: &str, content: &str) -> PathBuf {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Belirlenimli, rastgele görünen bir dizge üretir. Sahte anahtarlar
    /// kaynak koda yazılmaz ki depo taramaları (ve bu araç) alarm vermesin.
    fn random(alphabet: &str, len: usize, seed: u64) -> String {
        let alphabet: Vec<char> = alphabet.chars().collect();
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                alphabet[(state >> 33) as usize % alphabet.len()]
            })
            .collect()
    }

    const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const HEX: &str = "0123456789abcdef";
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    fn anthropic_key(seed: u64) -> String {
        format!("sk-ant-api03-{}", random(ALNUM, 80, seed))
    }

    fn rules_hit(file_name: &str, text: &str) -> Vec<&'static str> {
        scan_text(file_name, text).iter().map(|found| found.rule).collect()
    }

    #[test]
    fn saglayici_kaliplari_taninir() {
        let cases = [
            ("anthropic", anthropic_key(1)),
            ("openai", format!("sk-proj-{}", random(ALNUM, 48, 2))),
            ("aws-access-key", format!("AKIA{}", random(UPPER, 16, 3))),
            ("google-api-key", format!("AIza{}", random(ALNUM, 35, 4))),
            ("digitalocean", format!("dop_v1_{}", random(HEX, 64, 5))),
            ("github", format!("ghp_{}", random(ALNUM, 36, 6))),
            ("gitlab", format!("glpat-{}", random(ALNUM, 20, 7))),
            ("stripe", format!("sk_live_{}", random(ALNUM, 24, 8))),
            ("npm", format!("npm_{}", random(ALNUM, 36, 9))),
            ("huggingface", format!("hf_{}", random(ALNUM, 34, 10))),
            ("openrouter", format!("sk-or-v1-{}", random(HEX, 64, 11))),
        ];
        for (expected, key) in cases {
            let text = format!("KEY={key}\n");
            assert_eq!(rules_hit(".env", &text), [expected], "{expected} tanınmalı");
        }
    }

    #[test]
    fn aws_gizli_anahtari_adindan_taninir() {
        let text = format!(
            "[default]\naws_access_key_id = AKIA{}\naws_secret_access_key = {}\n",
            random(UPPER, 16, 1),
            random(ALNUM, 40, 2)
        );
        assert_eq!(rules_hit("credentials", &text), ["aws-access-key", "aws-secret-key"]);
    }

    #[test]
    fn degisken_adi_ve_satir_bulunur() {
        let text = format!("# yorum\nexport ANTHROPIC_API_KEY=\"{}\"\n", anthropic_key(1));
        let found = scan_text(".zshrc", &text);
        assert_eq!(found.len(), 1, "genel kural aynı değeri ikinci kez raporlamamalı");
        assert_eq!(found[0].name.as_deref(), Some("ANTHROPIC_API_KEY"));

        let text = format!("{{\n  \"apiKey\": \"{}\"\n}}", anthropic_key(1));
        assert_eq!(scan_text("a.json", &text)[0].name.as_deref(), Some("apiKey"));
    }

    #[test]
    fn yer_tutucular_elenir() {
        let text = "\
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
            API_KEY=your_api_key_here\n\
            SECRET_KEY=${SECRET_KEY}\n\
            DB_PASSWORD=changeme123\n\
            AUTH_TOKEN=$(gh auth token)\n\
            PRIVATE_KEY_PATH=/Users/biri/.ssh/id_ed25519\n\
            TOKEN_TTL=86400000\n\
            API_KEY_HEADER=x-api-key-name\n\
            ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n";
        assert!(rules_hit(".env", text).is_empty(), "{:?}", rules_hit(".env", text));
    }

    #[test]
    fn genel_atama_rastgele_degerde_yakalanir() {
        let text = format!("MY_SERVICE_TOKEN={}\nDB_PASSWORD='{}'\n", random(ALNUM, 32, 1), random(ALNUM, 14, 2));
        let found = scan_text(".env", &text);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.rule == GENERIC));
        assert_eq!(found[0].name.as_deref(), Some("MY_SERVICE_TOKEN"));
    }

    #[test]
    fn sablon_dosyalarda_yalnizca_gercek_kaliplar_aranir() {
        let key = anthropic_key(1);
        let text = format!(
            "DB_PASSWORD={}\nDATABASE_URL=postgres://app:{}@localhost/app\nANTHROPIC_API_KEY={key}\n",
            random(ALNUM, 14, 2),
            random(ALNUM, 14, 3)
        );
        assert_eq!(rules_hit(".env.example", &text), ["anthropic"]);
        assert_eq!(rules_hit(".env", &text).len(), 3);
    }

    #[test]
    fn tarih_degerleri_sir_sayilmaz() {
        assert!(rules_hit("a.json", "\"firstTokenDate\": \"2026-01-31T10:20:30.000Z\"").is_empty());
    }

    #[test]
    fn url_icindeki_parola_yakalanir() {
        let password = random(ALNUM, 16, 1);
        let text = format!("DATABASE_URL=postgres://app:{password}@db.internal:5432/app\n");
        let found = scan_text(".env", &text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "url-password");
        assert_eq!(found[0].secret, password);
        assert!(rules_hit(".env", "URL=https://example.com:8080/a@b\n").is_empty());
    }

    #[test]
    fn dosya_ipucu_olan_kurallar_baska_dosyada_calismaz() {
        let text = format!("machine api.github.com login ben password {}\n", random(ALNUM, 20, 1));
        assert_eq!(rules_hit(".netrc", &text), ["netrc"]);
        assert!(rules_hit("notlar.txt", &text).is_empty());
    }

    #[test]
    fn yalnizca_parolasiz_ozel_anahtar_raporlanir() {
        let plain = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ{}\n",
            random(ALNUM, 40, 1)
        );
        assert_eq!(rules_hit("id_ed25519", &plain), [PRIVATE_KEY]);

        let encrypted = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHI{}\n",
            random(ALNUM, 40, 1)
        );
        assert!(rules_hit("id_ed25519", &encrypted).is_empty());

        let old_encrypted = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB\n";
        assert!(rules_hit("id_rsa", old_encrypted).is_empty());
        assert!(rules_hit("a.pem", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n").is_empty());

        // Servis hesabı JSON'unda anahtar tek satıra gömülüdür.
        let json = format!("\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n\"", random(ALNUM, 40, 2));
        assert_eq!(rules_hit("sa.json", &json), [PRIVATE_KEY]);
    }

    #[test]
    fn maske_degeri_gizler() {
        let key = anthropic_key(1);
        let masked = mask("anthropic", &key);
        assert!(masked.starts_with("sk-ant-api03"));
        assert!(masked.chars().count() < 20);
        assert!(!mask(GENERIC, "kisaparola1").contains("kisa"));
        assert_eq!(mask(PRIVATE_KEY, "pem@0"), "(özel anahtar)");
    }

    #[test]
    fn aday_dosyalar_bulunur_bagimliliklar_atlanir() {
        let dir = TempDir::new("walk");
        dir.write("app/.env", "A=1");
        dir.write("app/.env.production", "A=1");
        dir.write("app/config/prod.env", "A=1");
        dir.write("app/infra/terraform.tfstate", "{}");
        dir.write("app/.git/config", "[core]");
        dir.write("app/.git/HEAD", "ref");
        dir.write("app/src/main.rs", "fn main() {}");
        dir.write("app/node_modules/pkg/.env", "A=1");
        dir.write("app/.cache/.env", "A=1");
        dir.write("go/pkg/mod/lib/server.key", "x");
        dir.write("app/internal/testdata/ca.pem", "x");

        let found: Vec<String> = files_under(&dir.0)
            .iter()
            .map(|path| path.strip_prefix(&dir.0).unwrap().display().to_string())
            .collect();
        assert_eq!(
            found,
            ["app/.env", "app/.env.production", "app/.git/config", "app/config/prod.env", "app/infra/terraform.tfstate"]
        );
    }

    #[test]
    fn ayni_anahtar_dosyalar_arasinda_eslestirilir() {
        let dir = TempDir::new("scan");
        let shared = anthropic_key(1);
        let other = anthropic_key(2);
        dir.write("a/.env", &format!("ANTHROPIC_API_KEY={shared}\nX={shared}\n"));
        dir.write("b/.env", &format!("CLAUDE_KEY={shared}\nOTHER={other}\n"));
        dir.write("c/.env", "DEBUG=true\n");

        let scan = scan(&files_under(&dir.0));
        assert_eq!(scan.files_scanned, 3);
        assert_eq!(scan.findings.len(), 3);
        assert_eq!(scan.unique_secrets(), 2);
        assert_eq!(
            scan.summary,
            [ProviderSummary { provider: "Anthropic", secrets: 2, locations: 3, git_tracked: 0 }]
        );

        let in_a = scan.findings.iter().find(|f| f.path.ends_with("a/.env")).unwrap();
        assert_eq!(in_a.occurrences, 2);
        assert_eq!(in_a.line, 1);
        let ids: BTreeSet<usize> = scan
            .findings
            .iter()
            .filter(|f| f.secret == shared)
            .map(|f| f.secret_id)
            .collect();
        assert_eq!(ids.len(), 1, "aynı anahtar aynı numarayı alır");
    }

    #[test]
    fn ham_deger_raporlara_sizmaz() {
        let dir = TempDir::new("leak");
        let key = anthropic_key(1);
        let password = random(ALNUM, 12, 2);
        dir.write(".env", &format!("ANTHROPIC_API_KEY={key}\nDB_PASSWORD={password}\n"));

        let report = SecretsReport::new("2026-01-01T00:00:00+00:00".to_string(), scan(&files_under(&dir.0)));
        assert_eq!(report.scan.findings.len(), 2);
        for rendered in [report.to_json(), report.to_text()] {
            assert!(!rendered.contains(&key));
            assert!(!rendered.contains(&key[20..]));
            assert!(!rendered.contains(&password));
        }
        assert!(report.to_json().contains("\"provider\": \"Anthropic\""));
    }

    #[test]
    fn gitte_izlenen_dosya_isaretlenir() {
        let dir = TempDir::new("git");
        dir.write("tracked.env", &format!("K={}\n", anthropic_key(1)));
        dir.write("untracked.env", &format!("K={}\n", anthropic_key(2)));
        let git = |args: &[&str]| {
            Command::new("git").arg("-C").arg(&dir.0).args(args).output().is_ok_and(|o| o.status.success())
        };
        if !git(&["init", "-q"]) || !git(&["add", "tracked.env"]) {
            return; // git yoksa bu test anlamsız
        }

        let scan = scan(&files_under(&dir.0));
        let tracked: Vec<_> = scan.tracked().map(|f| f.path.file_name().unwrap().to_owned()).collect();
        assert_eq!(tracked, ["tracked.env"]);
    }

    #[test]
    fn entropi_sozcukle_rastgeleyi_ayirir() {
        assert!(entropy("aaaaaaaa") < 0.1);
        assert!(entropy("password") < 3.0);
        assert!(entropy(&random(ALNUM, 32, 1)) > 4.0);
    }
}
