//! Vulnerability scan (`--vulns`): which known vulnerabilities affect the
//! software on this machine, and which of them matter most?
//!
//! Two inventories are checked:
//! 1. **Project dependencies** from lockfiles (see `lockfiles`), looked up in
//!    OSV.dev.
//! 2. **macOS, well-known applications and Homebrew formulae**, looked up in
//!    the NVD by product name and version. Only the applications in `APPS`
//!    and the formulae in `FORMULAE` are covered.
//!
//! Finding a vulnerability is the easy part; a typical machine has hundreds.
//! The scan therefore ranks them with two signals:
//! - **CISA KEV**: the vulnerability is known to be exploited in the wild.
//! - **EPSS**: the estimated probability that it will be exploited soon.
//!
//! Without `--online` nothing leaves the machine and only the inventory is
//! shown. With `--online`, package names and versions (never file paths or
//! contents) are sent to the services above. Responses are cached under
//! `~/.swordcheck/cache`.

use crate::lockfiles::{self, Lockfile, Package};
use crate::net::{self, run_curl};
use crate::osv;
use crate::progress::Progress;
use crate::runner::CommandRunner;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// EPSS accepts a comma-separated list; keep URLs comfortably short.
const EPSS_BATCH: usize = 100;
/// KEV and NVD answers are reused for a day.
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Advisories downloaded per curl invocation.
const DOWNLOAD_BATCH: usize = 40;
/// Number of example lockfiles stored per finding.
const MAX_PATHS: usize = 3;

// ---- Result types ----

/// Severity of a vulnerability. The order is the sort order (worst first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Unknown => "UNRATED",
        }
    }

    /// Maps a CVSS base score to its qualitative rating.
    fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Unknown,
        }
    }
}

/// A CISA Known Exploited Vulnerabilities entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Kev {
    pub date_added: String,
    /// Known to be used in ransomware campaigns.
    pub ransomware: bool,
}

/// A vulnerable dependency: one advisory affecting one package version.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub ecosystem: &'static str,
    pub package: String,
    pub version: String,
    /// Advisory id (GHSA-…, RUSTSEC-…, MAL-…).
    pub id: String,
    pub cves: Vec<String>,
    pub summary: String,
    pub severity: Severity,
    /// The advisory describes malware rather than a bug.
    pub malware: bool,
    /// Versions that contain the fix, when the advisory lists them.
    pub fixed: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev: Option<Kev>,
    /// Probability (0–1) of exploitation in the next 30 days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    /// Number of lockfiles that pin this version.
    pub lockfile_count: usize,
    /// Example lockfiles (at most `MAX_PATHS`).
    pub lockfiles: Vec<PathBuf>,
}

/// A known-exploited vulnerability affecting an installed product.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SystemVuln {
    pub cve: String,
    pub name: String,
    pub date_added: String,
}

/// Where an installed product was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// macOS itself.
    Os,
    /// An application bundle in an `Applications` directory.
    App,
    /// A formula in the Homebrew Cellar.
    Homebrew,
}

/// macOS itself, an installed application or a Homebrew formula.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SystemItem {
    pub source: Source,
    pub name: String,
    pub version: String,
    /// The NVD product identifier that was queried.
    pub cpe: String,
    /// `false` until the NVD has been asked about this product.
    pub checked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub exploited: Vec<SystemVuln>,
}

impl SystemItem {
    /// Name and version as shown in reports.
    pub fn title(&self) -> String {
        match self.source {
            Source::Homebrew => format!("{} {} (Homebrew)", self.name, self.version),
            _ => format!("{} {}", self.name, self.version),
        }
    }
}

/// The installed products that can be looked up.
#[derive(Debug, Default)]
pub struct System {
    pub items: Vec<SystemItem>,
    /// Homebrew formulae that are installed but not in `FORMULAE`.
    pub unmatched_formulae: usize,
}

/// Vulnerability counts for one lockfile.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct ProjectSummary {
    pub path: PathBuf,
    pub packages: usize,
    pub exploited: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

impl ProjectSummary {
    fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.unknown
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Scan {
    /// Were the online databases queried?
    pub online: bool,
    pub lockfiles: usize,
    /// Unique (ecosystem, name, version) triples across all lockfiles.
    pub packages: usize,
    pub by_ecosystem: BTreeMap<&'static str, usize>,
    pub system: Vec<SystemItem>,
    /// Installed Homebrew formulae that could not be looked up.
    pub unmatched_formulae: usize,
    pub findings: Vec<Finding>,
    pub projects: Vec<ProjectSummary>,
    /// Lookups that failed; the rest of the scan is still reported.
    pub warnings: Vec<String>,
}

impl Scan {
    /// Findings that are known to be exploited, in dependencies or the system.
    pub fn exploited(&self) -> usize {
        self.exploited_dependencies() + self.system.iter().map(|item| item.exploited.len()).sum::<usize>()
    }

    fn exploited_dependencies(&self) -> usize {
        self.findings.iter().filter(|f| f.kev.is_some() || f.malware).count()
    }

    /// Says how many Homebrew formulae were left out, if any.
    pub fn unmatched_note(&self) -> Option<String> {
        (self.unmatched_formulae > 0).then(|| {
            format!(
                "{} other Homebrew formulae are not in the lookup table and were not checked",
                self.unmatched_formulae
            )
        })
    }

    fn count(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }
}

// ---- Inventory ----

/// Parses the given lockfiles, dropping those without any package.
pub fn read_lockfiles(paths: &[PathBuf], progress: &Progress) -> Vec<Lockfile> {
    progress.stage(format!("Reading {} lockfiles", paths.len()));
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut lockfiles = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        if let Some(lockfile) = lockfiles::parse_file(path).filter(|lockfile| !lockfile.packages.is_empty()) {
            progress.note(format!(
                "{} ({} packages)",
                crate::secrets::display_path(path, home.as_deref()),
                lockfile.packages.len()
            ));
            lockfiles.push(lockfile);
        }
        progress.step(index + 1, paths.len());
    }
    lockfiles
}

/// An application we know how to look up: bundle identifier → NVD
/// `vendor:product`. Matching by bundle id (not by file name) means a
/// renamed or look-alike app is never mistaken for the real one.
const APPS: &[(&str, &str)] = &[
    ("com.google.Chrome", "google:chrome"),
    ("org.mozilla.firefox", "mozilla:firefox"),
    ("org.mozilla.thunderbird", "mozilla:thunderbird"),
    ("com.microsoft.edgemac", "microsoft:edge_chromium"),
    ("com.apple.Safari", "apple:safari"),
    ("com.apple.dt.Xcode", "apple:xcode"),
    ("us.zoom.xos", "zoom:zoom"),
    ("com.microsoft.VSCode", "microsoft:visual_studio_code"),
    ("org.virtualbox.app.VirtualBox", "oracle:vm_virtualbox"),
    ("org.videolan.vlc", "videolan:vlc_media_player"),
    ("com.teamviewer.TeamViewer", "teamviewer:teamviewer"),
    ("com.philandro.anydesk", "anydesk:anydesk"),
    ("org.torproject.torbrowser", "torproject:tor_browser"),
    ("org.wireshark.Wireshark", "wireshark:wireshark"),
    ("com.vmware.fusion", "vmware:fusion"),
    ("com.parallels.desktop.console", "parallels:parallels_desktop"),
    ("org.keepassxc.keepassxc", "keepassxc:keepassxc"),
    ("org.libreoffice.script", "libreoffice:libreoffice"),
    ("com.brave.Browser", "brave:brave"),
    ("com.operasoftware.Opera", "opera:opera_browser"),
    ("com.docker.docker", "docker:desktop"),
    ("com.microsoft.teams2", "microsoft:teams"),
    ("org.filezilla-project.filezilla", "filezilla-project:filezilla_client"),
    ("com.googlecode.iterm2", "iterm2:iterm2"),
    ("org.whispersystems.signal-desktop", "signal:signal-desktop"),
    ("ru.keepcoder.Telegram", "telegram:telegram"),
    ("com.postmanlabs.mac", "postman:postman"),
    ("md.obsidian", "obsidian:obsidian"),
    ("com.bitwarden.desktop", "bitwarden:bitwarden"),
    ("org.pgadmin.pgadmin4", "pgadmin:pgadmin_4"),
    ("org.openvpn.client.app", "openvpn:connect"),
    ("com.cloudflare.1dot1dot1dot1.macos", "cloudflare:warp"),
    ("com.electron.ollama", "ollama:ollama"),
    ("com.todesktop.230313mzl4w4u92", "anysphere:cursor"),
    ("com.anthropic.claudefordesktop", "anthropic:claude_desktop"),
    ("com.adobe.Reader", "adobe:acrobat_reader_dc"),
    ("com.1password.1password", "1password:1password"),
    ("org.audacityteam.audacity", "audacityteam:audacity"),
    ("org.qbittorrent.qBittorrent", "qbittorrent:qbittorrent"),
    ("org.m0k.transmission", "transmissionbt:transmission"),
];

/// A Homebrew formula we know how to look up: formula → NVD
/// `vendor:product`. Versioned formulae (`openssl@3`) use the entry of the
/// unversioned name. Every entry was checked against the NVD.
const FORMULAE: &[(&str, &str)] = &[
    ("activemq", "apache:activemq"),
    ("apache-spark", "apache:spark"),
    ("bash", "gnu:bash"),
    ("bind", "isc:bind"),
    ("consul", "hashicorp:consul"),
    ("couchdb", "apache:couchdb"),
    ("curl", "haxx:curl"),
    ("deno", "deno:deno"),
    ("dnsmasq", "thekelleys:dnsmasq"),
    ("dovecot", "dovecot:dovecot"),
    ("exiftool", "exiftool_project:exiftool"),
    ("exim", "exim:exim"),
    ("expat", "libexpat_project:libexpat"),
    ("ffmpeg", "ffmpeg:ffmpeg"),
    ("freetype", "freetype:freetype"),
    ("ghostscript", "artifex:ghostscript"),
    ("git", "git-scm:git"),
    ("gitea", "gitea:gitea"),
    ("gnupg", "gnupg:gnupg"),
    ("gnutls", "gnu:gnutls"),
    ("go", "golang:go"),
    ("grafana", "grafana:grafana"),
    ("haproxy", "haproxy:haproxy"),
    ("helm", "helm:helm"),
    ("httpd", "apache:http_server"),
    ("imagemagick", "imagemagick:imagemagick"),
    ("jenkins", "jenkins:jenkins"),
    ("jenkins-lts", "jenkins:jenkins"),
    ("kafka", "apache:kafka"),
    ("krb5", "mit:kerberos_5"),
    ("libarchive", "libarchive:libarchive"),
    ("libpng", "libpng:libpng"),
    ("libpq", "postgresql:postgresql"),
    ("libssh", "libssh:libssh"),
    ("libssh2", "libssh2:libssh2"),
    ("libtiff", "libtiff:libtiff"),
    ("libvpx", "webmproject:libvpx"),
    ("libxml2", "xmlsoft:libxml2"),
    ("lua", "lua:lua"),
    ("mariadb", "mariadb:mariadb"),
    ("memcached", "memcached:memcached"),
    ("minio", "minio:minio"),
    ("mysql", "oracle:mysql"),
    ("mysql-client", "oracle:mysql"),
    ("neovim", "neovim:neovim"),
    ("net-snmp", "net-snmp:net-snmp"),
    ("nginx", "f5:nginx"),
    ("node", "nodejs:node.js"),
    ("nuclei", "projectdiscovery:nuclei"),
    ("openjdk", "oracle:openjdk"),
    ("openldap", "openldap:openldap"),
    ("openssl", "openssl:openssl"),
    ("openvpn", "openvpn:openvpn"),
    ("pcre2", "pcre:pcre2"),
    ("perl", "perl:perl"),
    ("php", "php:php"),
    ("pnpm", "pnpm:pnpm"),
    ("postgresql", "postgresql:postgresql"),
    ("proftpd", "proftpd:proftpd"),
    ("python", "python:python"),
    ("qemu", "qemu:qemu"),
    ("redis", "redis:redis"),
    ("rsync", "samba:rsync"),
    ("ruby", "ruby-lang:ruby"),
    ("rust", "rust-lang:rust"),
    ("salt", "saltstack:salt"),
    ("samba", "samba:samba"),
    ("sevenzip", "7-zip:7-zip"),
    ("solr", "apache:solr"),
    ("sqlite", "sqlite:sqlite"),
    ("squid", "squid-cache:squid"),
    ("subversion", "apache:subversion"),
    ("tomcat", "apache:tomcat"),
    ("tor", "torproject:tor"),
    ("vault", "hashicorp:vault"),
    ("vim", "vim:vim"),
    ("webp", "webmproject:libwebp"),
    ("wget", "gnu:wget"),
    ("wireshark", "wireshark:wireshark"),
    ("xz", "tukaani:xz"),
    ("zlib", "zlib:zlib"),
    ("zsh", "zsh:zsh"),
];

/// Builds the list of products to look up: macOS, recognized apps and
/// recognized Homebrew formulae.
pub fn system_items(runner: &dyn CommandRunner) -> System {
    let mut system = System {
        items: app_items(runner),
        unmatched_formulae: 0,
    };
    for cellar in homebrew_cellars() {
        let (items, unmatched) = homebrew_items(&cellar);
        system.items.extend(items);
        system.unmatched_formulae += unmatched;
    }
    system
}

/// macOS plus the applications in `APPS`.
fn app_items(runner: &dyn CommandRunner) -> Vec<SystemItem> {
    let mut items = Vec::new();
    let read = |program: &str, args: &[&str]| {
        runner
            .run(program, args)
            .ok()
            .filter(|out| out.success)
            .map(|out| out.stdout.trim().to_string())
    };

    if let Some(version) = read("sw_vers", &["-productVersion"]).as_deref().and_then(clean_version) {
        items.push(system_item(
            Source::Os,
            "macOS",
            &version,
            format!("cpe:2.3:o:apple:macos:{version}:*:*:*:*:*:*:*"),
        ));
    }

    let mut dirs = vec![PathBuf::from("/Applications")];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(Path::new(&home).join("Applications"));
    }
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut apps: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "app"))
            .collect();
        apps.sort();

        for app in apps {
            let plist = app.join("Contents/Info.plist");
            let plist = plist.to_string_lossy();
            // `plutil` reads both XML and binary property lists.
            let extract = |key: &str| read("plutil", &["-extract", key, "raw", "-o", "-", &plist]);
            let Some(product) = extract("CFBundleIdentifier").and_then(|id| {
                APPS.iter()
                    .find(|(bundle, _)| *bundle == id)
                    .map(|(_, product)| *product)
            }) else {
                continue;
            };
            let Some(version) = extract("CFBundleShortVersionString").as_deref().and_then(clean_version) else {
                continue;
            };
            let name = app
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            items.push(system_item(
                Source::App,
                &name,
                &version,
                format!("cpe:2.3:a:{product}:{version}:*:*:*:*:*:*:*"),
            ));
        }
    }
    items
}

/// The Cellar of every Homebrew installation: a custom prefix, Apple
/// silicon and Intel.
fn homebrew_cellars() -> Vec<PathBuf> {
    let mut prefixes: Vec<PathBuf> = std::env::var_os("HOMEBREW_PREFIX")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    for default in ["/opt/homebrew", "/usr/local"] {
        if !prefixes.iter().any(|prefix| prefix == Path::new(default)) {
            prefixes.push(PathBuf::from(default));
        }
    }
    prefixes
        .into_iter()
        .map(|prefix| prefix.join("Cellar"))
        .filter(|cellar| cellar.is_dir())
        .collect()
}

/// Reads a Cellar (`Cellar/<formula>/<version>/`) without running `brew`.
/// Returns the formulae that can be looked up and the number that cannot.
fn homebrew_items(cellar: &Path) -> (Vec<SystemItem>, usize) {
    let subdirs = |dir: &Path| {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    };

    let mut items = Vec::new();
    let mut unmatched = 0;
    for formula in subdirs(cellar) {
        let versions = subdirs(&cellar.join(&formula));
        let found: Vec<SystemItem> = versions
            .iter()
            .filter_map(|version| formula_item(&formula, version))
            .collect();
        if found.is_empty() && !versions.is_empty() {
            unmatched += 1;
        }
        items.extend(found);
    }
    (items, unmatched)
}

/// The lookup for one installed formula version, if the formula is known.
fn formula_item(formula: &str, version: &str) -> Option<SystemItem> {
    let base = formula.split('@').next()?;
    let product = FORMULAE
        .iter()
        .find(|(name, _)| *name == base)
        .map(|(_, product)| *product)?;
    let version = clean_version(strip_revision(version))?;
    Some(system_item(
        Source::Homebrew,
        formula,
        &version,
        format!("cpe:2.3:a:{product}:{version}:*:*:*:*:*:*:*"),
    ))
}

/// Drops Homebrew's own rebuild counter: `8.11.1_2` is upstream `8.11.1`.
fn strip_revision(version: &str) -> &str {
    match version.rsplit_once('_') {
        Some((upstream, revision)) if !revision.is_empty() && revision.bytes().all(|b| b.is_ascii_digit()) => upstream,
        _ => version,
    }
}

fn system_item(source: Source, name: &str, version: &str, cpe: String) -> SystemItem {
    SystemItem {
        source,
        name: name.to_string(),
        version: version.to_string(),
        cpe,
        checked: false,
        error: None,
        exploited: Vec::new(),
    }
}

/// Reduces a display version such as `7.1.9 (88375)` to `7.1.9`. Versions
/// that do not start with a digit (`Build 4215`) cannot be looked up.
fn clean_version(raw: &str) -> Option<String> {
    let version = raw.split_whitespace().next()?;
    let valid = version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    valid.then(|| version.to_string())
}

/// The inventory without any lookups (used when `--online` is not given).
pub fn offline(lockfiles: &[Lockfile], system: System) -> Scan {
    let unique = unique_packages(lockfiles);
    Scan {
        online: false,
        lockfiles: lockfiles.len(),
        packages: unique.len(),
        by_ecosystem: count_ecosystems(&unique),
        system: system.items,
        unmatched_formulae: system.unmatched_formulae,
        ..Scan::default()
    }
}

/// Every distinct package, with the lockfiles that pin it.
fn unique_packages(lockfiles: &[Lockfile]) -> BTreeMap<&Package, Vec<&Path>> {
    let mut unique: BTreeMap<&Package, Vec<&Path>> = BTreeMap::new();
    for lockfile in lockfiles {
        for package in &lockfile.packages {
            unique.entry(package).or_default().push(&lockfile.path);
        }
    }
    unique
}

fn count_ecosystems(unique: &BTreeMap<&Package, Vec<&Path>>) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for package in unique.keys() {
        *counts.entry(package.ecosystem).or_default() += 1;
    }
    counts
}

// ---- Online scan ----

/// Options for the online scan.
pub struct Online {
    /// Directory for cached responses.
    pub cache: PathBuf,
    /// Where to report progress (NVD lookups are rate-limited and slow).
    pub progress: Progress,
}

/// Looks everything up. A failing service adds a warning instead of
/// aborting, so partial results are still shown.
pub fn scan(lockfiles: &[Lockfile], system: System, options: &Online) -> Scan {
    let System {
        items: mut system,
        unmatched_formulae,
    } = system;
    let mut warnings = Vec::new();
    let unique = unique_packages(lockfiles);
    let packages: Vec<&Package> = unique.keys().copied().collect();

    // 1. Which advisories affect which package?
    let progress = &options.progress;
    let hits = osv_query(&packages, progress).unwrap_or_else(|err| {
        warnings.push(format!("OSV lookup failed: {err}"));
        Vec::new()
    });

    // The dashboard cancels by dropping its end of the progress channel.
    // Nothing is reported then, so stop before the next round of requests.
    if progress.cancelled() {
        return Scan::default();
    }

    // 2. Advisory details (summary, severity, fixed versions).
    let wanted: BTreeMap<&str, &str> = hits
        .iter()
        .map(|hit| (hit.id.as_str(), hit.modified.as_str()))
        .collect();
    let (advisories, download_error) = osv_details(&wanted, &options.cache.join("osv"), progress);
    let without_details = wanted.keys().filter(|id| !advisories.contains_key(**id)).count();
    if without_details > 0 {
        let reason = download_error.unwrap_or_else(|| "the advisory could not be read".to_string());
        warnings.push(format!(
            "Details of {without_details} advisories could not be downloaded ({reason}); they are listed unrated."
        ));
    }

    // 3. Prioritization data.
    progress.stage("Loading the CISA known-exploited catalog");
    let kev = load_kev(&options.cache).unwrap_or_else(|err| {
        warnings.push(format!("CISA KEV download failed: {err}"));
        BTreeMap::new()
    });
    progress.note(format!("{} known-exploited vulnerabilities in the catalog", kev.len()));
    let cves: BTreeSet<&str> = advisories
        .values()
        .flat_map(|a| a.cves.iter().map(String::as_str))
        .collect();
    let (epss, epss_error) = epss_lookup(&cves, progress);
    if let Some(err) = epss_error {
        warnings.push(format!(
            "EPSS lookup failed for some CVEs ({err}); those are ranked by severity only."
        ));
    }

    let unavailable = Advisory {
        cves: Vec::new(),
        summary: "Advisory details could not be downloaded.".to_string(),
        severity: Severity::Unknown,
        fixed: Vec::new(),
    };
    let mut findings = Vec::new();
    for hit in &hits {
        // A hit whose details are missing is still a finding: dropping it
        // could hide the one advisory that matters.
        let advisory = advisories.get(hit.id.as_str()).unwrap_or(&unavailable);
        let package = packages[hit.package];
        let paths = &unique[package];
        findings.push(Finding {
            ecosystem: package.ecosystem,
            package: package.name.clone(),
            version: package.version.clone(),
            id: hit.id.clone(),
            cves: advisory.cves.clone(),
            summary: advisory.summary.clone(),
            severity: advisory.severity,
            malware: hit.id.starts_with("MAL-"),
            fixed: advisory.fixed_for(package),
            kev: advisory
                .cves
                .iter()
                .find_map(|cve| kev.get(cve.as_str()))
                .map(|entry| entry.kev.clone()),
            // An advisory may alias several CVEs; the riskiest one counts.
            epss: advisory
                .cves
                .iter()
                .filter_map(|cve| epss.get(cve.as_str()).copied())
                .reduce(f64::max),
            lockfile_count: paths.len(),
            lockfiles: paths.iter().take(MAX_PATHS).map(|path| path.to_path_buf()).collect(),
        });
    }
    let mut findings = merge_duplicates(findings);
    findings.sort_by(priority);

    // 4. macOS, applications and Homebrew formulae.
    nvd_lookup(&mut system, &kev, options, &mut warnings);

    Scan {
        online: true,
        lockfiles: lockfiles.len(),
        packages: unique.len(),
        by_ecosystem: count_ecosystems(&unique),
        projects: summarize_projects(lockfiles, &findings, &hits, &packages),
        system,
        unmatched_formulae,
        findings,
        warnings,
    }
}

/// Several databases (GitHub, PyPA, RustSec…) often describe the same CVE,
/// not always with the same list of aliases. Keeps one finding per package
/// version and CVE: findings that share a CVE are combined into the one with
/// a severity rating, keeping the CVEs, fixed versions, KEV status and EPSS
/// of all of them.
fn merge_duplicates(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_package: BTreeMap<(&'static str, String, String), Vec<Finding>> = BTreeMap::new();
    for finding in findings {
        let key = (finding.ecosystem, finding.package.clone(), finding.version.clone());
        let group = by_package.entry(key).or_default();
        let mut combined = finding;
        // One finding can link two that looked unrelated so far.
        while let Some(index) = group.iter().position(|kept| same_vulnerability(kept, &combined)) {
            combined = combine(group.swap_remove(index), combined);
        }
        group.push(combined);
    }
    by_package.into_values().flatten().collect()
}

/// Do two findings for the same package version describe the same
/// vulnerability? Advisories without a CVE are only merged with themselves.
fn same_vulnerability(a: &Finding, b: &Finding) -> bool {
    a.id == b.id || a.cves.iter().any(|cve| b.cves.contains(cve))
}

/// Merges two findings for the same vulnerability without losing any of the
/// signals the ranking depends on.
fn combine(a: Finding, b: Finding) -> Finding {
    // `Severity` orders worst-first with `Unknown` last, so the smaller value
    // is the more informative one.
    let (mut kept, other) = if b.severity < a.severity { (b, a) } else { (a, b) };
    let cves: BTreeSet<String> = kept.cves.drain(..).chain(other.cves).collect();
    kept.cves = cves.into_iter().collect();
    let fixed: BTreeSet<String> = kept.fixed.drain(..).chain(other.fixed).collect();
    kept.fixed = fixed.into_iter().collect();
    kept.kev = match (kept.kev.take(), other.kev) {
        (Some(kev), Some(more)) if more.ransomware && !kev.ransomware => Some(more),
        (kev, more) => kev.or(more),
    };
    kept.epss = kept.epss.into_iter().chain(other.epss).reduce(f64::max);
    kept.malware |= other.malware;
    kept
}

/// Sort order: exploited first, then by exploit probability, then severity.
fn priority(a: &Finding, b: &Finding) -> std::cmp::Ordering {
    let key = |f: &Finding| (!(f.kev.is_some() || f.malware), -f.epss.unwrap_or(0.0), f.severity);
    let (a_key, b_key) = (key(a), key(b));
    a_key
        .0
        .cmp(&b_key.0)
        // Floats are only partially ordered (NaN); EPSS values never are NaN.
        .then(a_key.1.partial_cmp(&b_key.1).unwrap_or(std::cmp::Ordering::Equal))
        .then(a_key.2.cmp(&b_key.2))
        .then_with(|| (&a.package, &a.version, &a.id).cmp(&(&b.package, &b.version, &b.id)))
}

fn summarize_projects(
    lockfiles: &[Lockfile],
    findings: &[Finding],
    hits: &[OsvHit],
    packages: &[&Package],
) -> Vec<ProjectSummary> {
    // (package, advisory id) → finding, to count per lockfile.
    let by_key: BTreeMap<(&str, &str, &str, &str), &Finding> = findings
        .iter()
        .map(|f| ((f.ecosystem, f.package.as_str(), f.version.as_str(), f.id.as_str()), f))
        .collect();

    let mut projects: Vec<ProjectSummary> = lockfiles
        .iter()
        .map(|lockfile| {
            let mut summary = ProjectSummary {
                path: lockfile.path.clone(),
                packages: lockfile.packages.len(),
                ..ProjectSummary::default()
            };
            for hit in hits {
                let package = packages[hit.package];
                if !lockfile.packages.contains(package) {
                    continue;
                }
                let key = (
                    package.ecosystem,
                    package.name.as_str(),
                    package.version.as_str(),
                    hit.id.as_str(),
                );
                let Some(finding) = by_key.get(&key) else {
                    continue;
                };
                if finding.kev.is_some() || finding.malware {
                    summary.exploited += 1;
                }
                match finding.severity {
                    Severity::Critical => summary.critical += 1,
                    Severity::High => summary.high += 1,
                    Severity::Medium => summary.medium += 1,
                    Severity::Low => summary.low += 1,
                    Severity::Unknown => summary.unknown += 1,
                }
            }
            summary
        })
        .filter(|summary| summary.total() > 0)
        .collect();
    projects.sort_by(|a, b| {
        (b.exploited, b.critical, b.high, b.total()).cmp(&(a.exploited, a.critical, a.high, a.total()))
    });
    projects
}

// ---- OSV.dev ----

/// An advisory id that applies to `packages[package]`.
#[derive(Debug, PartialEq)]
struct OsvHit {
    package: usize,
    id: String,
    /// Last modification time; used to refresh the cached advisory.
    modified: String,
}

fn osv_query(packages: &[&Package], progress: &Progress) -> Result<Vec<OsvHit>, String> {
    progress.stage(format!("Asking OSV.dev about {} packages", packages.len()));
    let queries: Vec<osv::Query> = packages
        .iter()
        .map(|p| osv::Query {
            ecosystem: p.ecosystem,
            name: &p.name,
            version: &p.version,
        })
        .collect();
    let results = osv::query(&queries, |done, total| progress.step(done, total))?;
    Ok(flatten_hits(results))
}

fn flatten_hits(results: Vec<Vec<osv::Vuln>>) -> Vec<OsvHit> {
    results
        .into_iter()
        .enumerate()
        .flat_map(|(package, vulns)| {
            vulns.into_iter().map(move |vuln| OsvHit {
                package,
                id: vuln.id,
                modified: vuln.modified,
            })
        })
        .collect()
}

/// The parts of an OSV advisory the report needs.
#[derive(Debug, PartialEq)]
struct Advisory {
    cves: Vec<String>,
    summary: String,
    severity: Severity,
    /// (ecosystem, package name, fixed version).
    fixed: Vec<(String, String, String)>,
}

impl Advisory {
    fn fixed_for(&self, package: &Package) -> Vec<String> {
        let fixed: BTreeSet<&str> = self
            .fixed
            .iter()
            .filter(|(ecosystem, name, _)| {
                ecosystem == package.ecosystem && same_package(ecosystem, name, &package.name)
            })
            .map(|(_, _, version)| version.as_str())
            .collect();
        fixed.into_iter().map(str::to_string).collect()
    }
}

/// Do two names refer to the same package? PyPI treats `-`, `_` and `.` as
/// the same character and ignores case (PEP 503).
fn same_package(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem != "PyPI" {
        return a.eq_ignore_ascii_case(b);
    }
    let normalize = |name: &str| {
        let mut out = String::new();
        for c in name.chars() {
            match c {
                '-' | '_' | '.' if out.ends_with('-') => {}
                '-' | '_' | '.' => out.push('-'),
                _ => out.push(c.to_ascii_lowercase()),
            }
        }
        out
    };
    normalize(a) == normalize(b)
}

fn parse_advisory(text: &str) -> Option<Advisory> {
    let value: Value = serde_json::from_str(text).ok()?;
    let id = value.get("id")?.as_str()?;
    let strings = |key: &str| -> Vec<&str> {
        value
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };

    let mut cves: BTreeSet<&str> = strings("aliases")
        .into_iter()
        .filter(|alias| alias.starts_with("CVE-"))
        .collect();
    // Some databases reference the CVE under `upstream` or use it as the id.
    cves.extend(
        strings("upstream")
            .into_iter()
            .filter(|alias| alias.starts_with("CVE-")),
    );
    if id.starts_with("CVE-") {
        cves.insert(id);
    }

    // GitHub advisories carry a ready-made rating; others only a CVSS vector.
    let label = value.pointer("/database_specific/severity").and_then(Value::as_str);
    let severity = match label.map(str::to_ascii_uppercase).as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MODERATE" | "MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => value
            .get("severity")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("score")?.as_str())
            .find_map(cvss3_score)
            .map_or(Severity::Unknown, Severity::from_score),
    };

    let mut fixed = Vec::new();
    for affected in value.get("affected").and_then(Value::as_array).into_iter().flatten() {
        let (Some(ecosystem), Some(name)) = (
            affected.pointer("/package/ecosystem").and_then(Value::as_str),
            affected.pointer("/package/name").and_then(Value::as_str),
        ) else {
            continue;
        };
        for range in affected.get("ranges").and_then(Value::as_array).into_iter().flatten() {
            // `GIT` ranges list commit hashes, not versions a user can install.
            if range.get("type").and_then(Value::as_str) == Some("GIT") {
                continue;
            }
            for event in range.get("events").and_then(Value::as_array).into_iter().flatten() {
                if let Some(version) = event.get("fixed").and_then(Value::as_str) {
                    // `Debian:12` style ecosystems carry a release suffix.
                    let ecosystem = ecosystem.split(':').next().unwrap_or(ecosystem);
                    fixed.push((ecosystem.to_string(), name.to_string(), version.to_string()));
                }
            }
        }
    }

    let summary = value
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| value.get("details").and_then(Value::as_str))
        .unwrap_or_default();
    Some(Advisory {
        cves: cves.into_iter().map(str::to_string).collect(),
        summary: first_line(summary, 160),
        severity,
        fixed,
    })
}

/// First line of `text`, shortened to `max` characters.
fn first_line(text: &str, max: usize) -> String {
    let line = text.lines().next().unwrap_or_default().trim();
    if line.chars().count() <= max {
        return line.to_string();
    }
    let short: String = line.chars().take(max - 1).collect();
    format!("{}…", short.trim_end())
}

/// CVSS v3.x base score from a vector such as
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8). Returns `None` for
/// other CVSS versions or malformed vectors.
fn cvss3_score(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:3.") {
        return None;
    }
    let metrics: BTreeMap<&str, &str> = vector
        .split('/')
        .skip(1)
        .filter_map(|part| part.split_once(':'))
        .collect();
    let metric = |name: &str| metrics.get(name).copied();

    let scope_changed = metric("S")? == "C";
    let attack_vector = match metric("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let complexity = match metric("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let privileges = match (metric("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let interaction = match metric("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let impact_of = |name: &str| match metric(name)? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let iss = 1.0 - (1.0 - impact_of("C")?) * (1.0 - impact_of("I")?) * (1.0 - impact_of("A")?);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * attack_vector * complexity * privileges * interaction;
    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    // The specification rounds up to one decimal.
    Some((raw.min(10.0) * 10.0 - 1e-9).ceil() / 10.0)
}

/// Returns the advisories for `wanted` (id → last modified), downloading
/// the ones that are missing from the cache or have changed since. Whatever
/// could be read is returned together with the download error, if any: the
/// caller reports the ids that are missing.
fn osv_details(
    wanted: &BTreeMap<&str, &str>,
    cache: &Path,
    progress: &Progress,
) -> (BTreeMap<String, Advisory>, Option<String>) {
    let file_of = |id: &str| cache.join(format!("{id}.json"));
    let load = |path: &Path| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| parse_advisory(&text))
    };
    // Ids become file names and URL parts; anything unusual is skipped.
    let safe = |id: &str| {
        !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };

    // The batch endpoint and the advisory itself do not always agree on the
    // modification time, so we remember the batch value we downloaded for.
    let index_path = cache.join("index.json");
    let mut index: BTreeMap<String, String> = std::fs::read_to_string(&index_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();

    let mut advisories = BTreeMap::new();
    let mut missing = Vec::new();
    for (&id, &modified) in wanted {
        if !safe(id) {
            continue;
        }
        let fresh = index.get(id).is_some_and(|seen| seen == modified);
        match load(&file_of(id)).filter(|_| fresh) {
            Some(advisory) => {
                advisories.insert(id.to_string(), advisory);
            }
            None => missing.push(id),
        }
    }
    if missing.is_empty() {
        return (advisories, None);
    }

    if let Err(err) = std::fs::create_dir_all(cache) {
        return (advisories, Some(format!("could not create {}: {err}", cache.display())));
    }
    progress.stage(format!(
        "Downloading {} advisories ({} already cached)",
        missing.len(),
        advisories.len()
    ));
    // Downloads go to a `.part` file first, so a failed or half-written
    // download never replaces (or passes for) a good cached advisory.
    let part_of = |id: &str| cache.join(format!("{id}.json.part"));
    // One curl process downloads a batch in parallel; the list of URL/output
    // pairs is passed as a config file on stdin. Batches exist only so that
    // progress can be reported between them.
    let mut error = None;
    let mut downloaded = 0;
    for batch in missing.chunks(DOWNLOAD_BATCH) {
        if progress.cancelled() {
            break;
        }
        let mut config = String::new();
        for id in batch {
            let url = format!("{}/{id}", osv::VULN_URL);
            let _ = writeln!(
                config,
                "url = {}\noutput = {}",
                net::quote(&url),
                net::quote(&part_of(id).to_string_lossy())
            );
        }
        if let Err(err) = run_curl(
            &[
                "--parallel",
                "--parallel-max",
                "16",
                "--max-time",
                "300",
                "--config",
                "-",
            ],
            Some(&config),
        ) {
            error = Some(err);
        }
        downloaded += batch.len();
        progress.step(downloaded, missing.len());
        progress.note(batch.last().copied().unwrap_or_default());
    }

    for id in missing {
        let part = part_of(id);
        match load(&part) {
            Some(advisory) if std::fs::rename(&part, file_of(id)).is_ok() => {
                advisories.insert(id.to_string(), advisory);
                index.insert(id.to_string(), wanted[id].to_string());
            }
            _ => {
                let _ = std::fs::remove_file(&part);
                // An older copy is better than nothing, but it stays marked
                // as outdated so the next run tries again.
                if let Some(advisory) = load(&file_of(id)) {
                    advisories.insert(id.to_string(), advisory);
                }
            }
        }
    }
    if let Ok(text) = serde_json::to_string(&index) {
        store(&index_path, &text);
    }
    (advisories, error)
}

// ---- CISA KEV ----

#[derive(Debug, Clone, PartialEq)]
struct KevEntry {
    kev: Kev,
    name: String,
}

/// Loads the KEV catalog, refreshing the cached copy once a day.
fn load_kev(cache: &Path) -> Result<BTreeMap<String, KevEntry>, String> {
    let path = cache.join("kev.json");
    // A fresh copy that no longer parses is downloaded again.
    if let Some(parsed) = read_fresh(&path).and_then(|text| parse_kev(&text).ok()) {
        return Ok(parsed);
    }
    let downloaded = net::get(KEV_URL, &[]).and_then(|text| parse_kev(&text).map(|parsed| (parsed, text)));
    match downloaded {
        Ok((parsed, text)) => {
            store(&path, &text);
            Ok(parsed)
        }
        // A stale catalog is better than none.
        Err(err) => std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| parse_kev(&text).ok())
            .ok_or(err),
    }
}

fn parse_kev(text: &str) -> Result<BTreeMap<String, KevEntry>, String> {
    let value: Value = serde_json::from_str(text).map_err(|err| format!("invalid KEV catalog: {err}"))?;
    let entries = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or("KEV catalog has no `vulnerabilities`")?;
    Ok(entries
        .iter()
        .filter_map(|entry| {
            let field = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let cve = entry.get("cveID")?.as_str()?.to_string();
            let kev = Kev {
                date_added: field("dateAdded"),
                ransomware: field("knownRansomwareCampaignUse").eq_ignore_ascii_case("known"),
            };
            Some((
                cve,
                KevEntry {
                    kev,
                    name: field("vulnerabilityName"),
                },
            ))
        })
        .collect())
}

// ---- EPSS ----

/// Returns the scores that could be fetched and the first error, if any:
/// one failed request must not throw away the scores already received.
fn epss_lookup(cves: &BTreeSet<&str>, progress: &Progress) -> (BTreeMap<String, f64>, Option<String>) {
    progress.stage(format!("Fetching exploit probabilities (EPSS) for {} CVEs", cves.len()));
    let cves: Vec<&str> = cves.iter().copied().collect();
    let mut scores = BTreeMap::new();
    let mut error = None;
    for (index, chunk) in cves.chunks(EPSS_BATCH).enumerate() {
        if progress.cancelled() {
            break;
        }
        let url = format!("{EPSS_URL}?cve={}&limit={EPSS_BATCH}", chunk.join(","));
        match net::get(&url, &[]).and_then(|text| parse_epss(&text)) {
            Ok(found) => scores.extend(found),
            Err(err) => error = error.or(Some(err)),
        }
        progress.step((index * EPSS_BATCH + chunk.len()).min(cves.len()), cves.len());
    }
    (scores, error)
}

/// EPSS returns numbers as strings: `{"cve": "CVE-…", "epss": "0.20158"}`.
fn parse_epss(text: &str) -> Result<BTreeMap<String, f64>, String> {
    let value: Value = serde_json::from_str(text).map_err(|err| format!("invalid EPSS response: {err}"))?;
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or("EPSS response has no `data`")?;
    Ok(data
        .iter()
        .filter_map(|entry| {
            let score: f64 = entry.get("epss")?.as_str()?.parse().ok()?;
            Some((entry.get("cve")?.as_str()?.to_string(), score))
        })
        .collect())
}

// ---- NVD (macOS, applications and Homebrew formulae) ----

/// Asks the NVD which known-exploited CVEs affect each product version.
/// Without an API key the NVD allows 5 requests per 30 seconds, so uncached
/// lookups are spaced out; set `NVD_API_KEY` (environment or `.env`) to go
/// ten times faster.
fn nvd_lookup(
    items: &mut [SystemItem],
    kev: &BTreeMap<String, KevEntry>,
    options: &Online,
    warnings: &mut Vec<String>,
) {
    let api_key = crate::envfile::lookup("NVD_API_KEY");
    let headers: Vec<String> = api_key.iter().map(|key| format!("apiKey: {key}")).collect();
    let pause = Duration::from_millis(if api_key.is_some() { 700 } else { 6500 });
    let cache = options.cache.join("nvd");
    let total = items.len();
    let mut requested = false;
    let speed = if api_key.is_some() {
        "with an API key"
    } else {
        "no API key: slow"
    };
    options
        .progress
        .stage(format!("Checking {total} system products in the NVD ({speed})"));

    for (index, item) in items.iter_mut().enumerate() {
        if options.progress.cancelled() {
            return;
        }
        let path = cache.join(format!("{}.json", cache_name(&item.cpe)));
        // Only answers that parse are cached, so a proxy error page or an
        // empty body is retried on the next run instead of for a whole day.
        let cached = read_fresh(&path).and_then(|text| parse_nvd(&text, kev).ok());
        let exploited = match cached {
            Some(exploited) => Ok(exploited),
            None => {
                options.progress.note(format!("{} {}", item.name, item.version));
                if requested {
                    // Say why nothing seems to happen for a few seconds.
                    options
                        .progress
                        .note(format!("  waiting {:.1}s for the NVD rate limit", pause.as_secs_f32()));
                    std::thread::sleep(pause);
                }
                requested = true;
                let url = format!("{NVD_URL}?cpeName={}&isVulnerable&hasKev", item.cpe);
                net::get(&url, &headers).and_then(|text| {
                    let exploited = parse_nvd(&text, kev)?;
                    store(&path, &text);
                    Ok(exploited)
                })
            }
        };
        match exploited {
            Ok(exploited) => {
                item.checked = true;
                item.exploited = exploited;
            }
            Err(err) => item.error = Some(err),
        }
        options.progress.step(index + 1, total);
    }

    let failed = items.iter().filter(|item| item.error.is_some()).count();
    if failed > 0 {
        warnings.push(format!("NVD lookup failed for {failed} of {total} products."));
    }
}

/// Extracts the known-exploited CVEs from an NVD response.
fn parse_nvd(text: &str, kev: &BTreeMap<String, KevEntry>) -> Result<Vec<SystemVuln>, String> {
    let value: Value = serde_json::from_str(text).map_err(|err| format!("invalid NVD response: {err}"))?;
    let entries = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or("NVD response has no `vulnerabilities`")?;
    let mut exploited: Vec<SystemVuln> = entries
        .iter()
        .filter_map(|entry| {
            let cve = entry.get("cve")?;
            let id = cve.get("id")?.as_str()?;
            let field = |key: &str| cve.get(key).and_then(Value::as_str).map(str::to_string);
            let known = kev.get(id);
            Some(SystemVuln {
                cve: id.to_string(),
                name: field("cisaVulnerabilityName")
                    .or_else(|| known.map(|k| k.name.clone()))
                    .unwrap_or_default(),
                date_added: field("cisaExploitAdd")
                    .or_else(|| known.map(|k| k.kev.date_added.clone()))
                    .unwrap_or_default(),
            })
        })
        .collect();
    // Most recently added first.
    exploited.sort_by(|a, b| b.date_added.cmp(&a.date_added).then(a.cve.cmp(&b.cve)));
    Ok(exploited)
}

// ---- HTTP and cache helpers ----

/// A file name for a cache key. Every character outside `[A-Za-z0-9.-]` is
/// written as `_xx` (hex), so two different keys never share a file.
fn cache_name(key: &str) -> String {
    let mut name = String::new();
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-') {
            name.push(byte as char);
        } else {
            let _ = write!(name, "_{byte:02x}");
        }
    }
    name
}

/// Reads a cache file if it is younger than `CACHE_TTL`.
fn read_fresh(path: &Path) -> Option<String> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    (age < CACHE_TTL).then(|| std::fs::read_to_string(path).ok()).flatten()
}

/// Writes a cache file. Failures are ignored: the cache is an optimization.
fn store(path: &Path, text: &str) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, text);
}

// ---- Report (--vulns) ----

/// Number of dependency findings printed in the text report.
const TEXT_LIMIT: usize = 25;
/// Number of projects printed in the text report.
const PROJECT_LIMIT: usize = 15;

#[derive(Debug, Serialize)]
pub struct VulnReport {
    pub tool: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    #[serde(flatten)]
    pub scan: Scan,
}

impl VulnReport {
    pub fn new(timestamp: String, scan: Scan) -> Self {
        Self {
            tool: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            timestamp,
            scan,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("the report can be converted to JSON")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let rule = "─".repeat(78).dimmed();
        let scan = &self.scan;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let short = |path: &Path| crate::secrets::display_path(path, home.as_deref());

        let ecosystems: Vec<String> = scan
            .by_ecosystem
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect();
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", " Vulnerability Scan ".on_blue().white().bold());
        let _ = writeln!(
            out,
            " {} lockfiles · {} unique packages · {} system products",
            scan.lockfiles,
            scan.packages,
            scan.system.len()
        );
        if !ecosystems.is_empty() {
            let _ = writeln!(out, " {}", ecosystems.join(" · ").dimmed());
        }
        let _ = writeln!(out, "{rule}");

        if !scan.online {
            for item in &scan.system {
                let _ = writeln!(out, "  {}", item.title());
            }
            if let Some(note) = scan.unmatched_note() {
                let _ = writeln!(out, "  {}", note.dimmed());
            }
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{}",
                "Inventory only. Run with --online to look these up in OSV.dev, the NVD,\nCISA KEV and EPSS (package names and versions are sent; nothing else).".yellow()
            );
            return out.trim_end().to_string();
        }

        let _ = writeln!(
            out,
            "{}",
            "SYSTEM  (known-exploited vulnerabilities affecting the installed version)".bold()
        );
        for item in &scan.system {
            let title = item.title();
            if let Some(error) = &item.error {
                let _ = writeln!(
                    out,
                    "  {} {title:<34} {}",
                    "?".yellow(),
                    format!("lookup failed: {error}").dimmed()
                );
            } else if item.exploited.is_empty() {
                let _ = writeln!(out, "  {} {title:<34} {}", "✔".green(), "none".dimmed());
            } else {
                let _ = writeln!(
                    out,
                    "  {} {:<34} {}",
                    "✖".red(),
                    title.bold(),
                    format!("{} known-exploited — update this product", item.exploited.len())
                        .red()
                        .bold()
                );
                for vuln in item.exploited.iter().take(5) {
                    let _ = writeln!(
                        out,
                        "      {} {}",
                        vuln.cve,
                        format!("{} (added {})", vuln.name, vuln.date_added).dimmed()
                    );
                }
                if item.exploited.len() > 5 {
                    let _ = writeln!(
                        out,
                        "      {}",
                        format!("… and {} more", item.exploited.len() - 5).dimmed()
                    );
                }
            }
        }
        if scan.system.is_empty() {
            let _ = writeln!(out, "  {}", "not scanned".dimmed());
        }
        if let Some(note) = scan.unmatched_note() {
            let _ = writeln!(out, "  {}", note.dimmed());
        }
        let _ = writeln!(out, "{rule}");

        let exploited = scan.exploited_dependencies();
        let _ = writeln!(
            out,
            "{}  {} findings: {} critical · {} high · {} medium · {} low · {} unrated · {}",
            "DEPENDENCIES".bold(),
            scan.findings.len(),
            scan.count(Severity::Critical),
            scan.count(Severity::High),
            scan.count(Severity::Medium),
            scan.count(Severity::Low),
            scan.count(Severity::Unknown),
            format!("{exploited} known-exploited").bold()
        );

        for finding in scan.findings.iter().take(TEXT_LIMIT) {
            let mut tags = Vec::new();
            if finding.malware {
                tags.push("[MALWARE]".red().bold().to_string());
            }
            if let Some(kev) = &finding.kev {
                let label = if kev.ransomware { "[KEV · RANSOMWARE]" } else { "[KEV]" };
                tags.push(label.red().bold().to_string());
            }
            let severity = format!("[{}]", finding.severity.label());
            // Malware advisories carry no rating; "[MALWARE]" says enough.
            let show_severity = !(finding.malware && finding.severity == Severity::Unknown);
            tags.extend(show_severity.then(|| match finding.severity {
                Severity::Critical | Severity::High => severity.red().to_string(),
                Severity::Medium => severity.yellow().to_string(),
                _ => severity.dimmed().to_string(),
            }));
            let mut facts = vec![finding.cves.first().cloned().unwrap_or_else(|| finding.id.clone())];
            if let Some(epss) = finding.epss {
                facts.push(format!("EPSS {:.1}%", epss * 100.0));
            }
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{} {} {}  {}",
                tags.join(" "),
                format!("{} {}", finding.package, finding.version).bold(),
                format!("({})", finding.ecosystem).dimmed(),
                facts.join(" · ")
            );
            let fix = if finding.fixed.is_empty() {
                String::new()
            } else {
                format!(" — fixed in {}", finding.fixed.join(", "))
            };
            let _ = writeln!(out, "    {}{}", finding.summary, fix.green());
            let more = match finding.lockfile_count.saturating_sub(1) {
                0 => String::new(),
                more => format!(" (+{more} more)"),
            };
            if let Some(path) = finding.lockfiles.first() {
                let _ = writeln!(out, "    {}", format!("{}{more}", short(path)).dimmed());
            }
        }
        if scan.findings.len() > TEXT_LIMIT {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{}",
                format!(
                    "… and {} lower-priority findings (use --json for the full list)",
                    scan.findings.len() - TEXT_LIMIT
                )
                .dimmed()
            );
        }

        if !scan.projects.is_empty() {
            let _ = writeln!(out, "{rule}");
            let _ = writeln!(
                out,
                "{}",
                format!(
                    "{:<52} {:>4} {:>4} {:>4} {:>4} {:>4}",
                    "BY LOCKFILE", "KEV", "CRIT", "HIGH", "MED", "LOW"
                )
                .bold()
            );
            for project in scan.projects.iter().take(PROJECT_LIMIT) {
                let path = short(&project.path);
                // Keep the end of long paths: that is where the project name is.
                let path = match path.chars().count() {
                    n if n > 52 => format!("…{}", path.chars().skip(n - 51).collect::<String>()),
                    _ => path,
                };
                let _ = writeln!(
                    out,
                    "{path:<52} {:>4} {:>4} {:>4} {:>4} {:>4}",
                    project.exploited, project.critical, project.high, project.medium, project.low
                );
            }
            if scan.projects.len() > PROJECT_LIMIT {
                let _ = writeln!(
                    out,
                    "{}",
                    format!("… and {} more lockfiles", scan.projects.len() - PROJECT_LIMIT).dimmed()
                );
            }
        }

        let _ = writeln!(out, "{rule}");
        for warning in &scan.warnings {
            let _ = writeln!(out, "{} {warning}", "Warning:".yellow());
        }
        match scan.exploited() {
            0 => {
                let _ = writeln!(out, "{}", "No known-exploited vulnerabilities found.".green().bold());
            }
            count => {
                let _ = writeln!(
                    out,
                    "{}",
                    format!("Known-exploited vulnerabilities found: {count}. Fix these first.")
                        .red()
                        .bold()
                );
            }
        }
        let _ = writeln!(
            out,
            "{}",
            "Findings are ranked: known-exploited (KEV) first, then exploit probability (EPSS), then severity.\nApplications and Homebrew formulae are matched by name in the NVD; only well-known ones are covered.".dimmed()
        );
        out.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, version: &str) -> Package {
        Package {
            ecosystem: "npm",
            name: name.to_string(),
            version: version.to_string(),
        }
    }

    fn finding(name: &str, severity: Severity, epss: Option<f64>, kev: bool) -> Finding {
        Finding {
            ecosystem: "npm",
            package: name.to_string(),
            version: "1.0.0".to_string(),
            id: format!("GHSA-{name}"),
            cves: vec![format!("CVE-2024-{name}")],
            summary: format!("{name} summary"),
            severity,
            malware: false,
            fixed: vec!["1.0.1".to_string()],
            kev: kev.then(|| Kev {
                date_added: "2024-01-01".to_string(),
                ransomware: false,
            }),
            epss,
            lockfile_count: 1,
            lockfiles: vec![PathBuf::from("/projects/app/package-lock.json")],
        }
    }

    #[test]
    fn cvss3_scores_match_the_specification() {
        let score = |vector| cvss3_score(vector).unwrap();
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"), 7.2);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
        assert_eq!(score("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:N"), 0.0);
        assert_eq!(score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(
            cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            None
        );
        assert_eq!(cvss3_score("CVSS:3.1/AV:X"), None);
    }

    #[test]
    fn severity_thresholds() {
        assert_eq!(Severity::from_score(9.8), Severity::Critical);
        assert_eq!(Severity::from_score(7.0), Severity::High);
        assert_eq!(Severity::from_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_score(0.1), Severity::Low);
        assert_eq!(Severity::from_score(0.0), Severity::Unknown);
    }

    #[test]
    fn osv_results_become_hits_per_package() {
        let vuln = |id: &str, modified: &str| osv::Vuln {
            id: id.to_string(),
            modified: modified.to_string(),
        };
        let hits = flatten_hits(vec![
            vec![],
            vec![vuln("GHSA-x", "2025-01-01T00:00:00Z"), vuln("MAL-1", "")],
        ]);
        assert_eq!(hits.len(), 2);
        assert_eq!(
            hits[0],
            OsvHit {
                package: 1,
                id: "GHSA-x".to_string(),
                modified: "2025-01-01T00:00:00Z".to_string()
            }
        );
        assert_eq!((hits[1].package, hits[1].id.as_str()), (1, "MAL-1"));
    }

    #[test]
    fn fixed_versions_skip_commits_and_match_pypi_spellings() {
        let text = r#"{"id": "PYSEC-1", "affected": [
            {"package": {"name": "Typing_Extensions", "ecosystem": "PyPI"},
             "ranges": [{"type": "GIT", "events": [{"fixed": "0123456789abcdef0123456789abcdef01234567"}]},
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.1.0"}]}]}]}"#;
        let advisory = parse_advisory(text).unwrap();
        let installed = Package {
            ecosystem: "PyPI",
            name: "typing-extensions".to_string(),
            version: "4.0.0".to_string(),
        };
        assert_eq!(advisory.fixed_for(&installed), ["4.1.0"]);
        assert!(same_package("PyPI", "zope.interface", "Zope_Interface"));
        assert!(
            !same_package("npm", "left-pad", "left_pad"),
            "only PyPI folds separators"
        );
    }

    #[test]
    fn cache_names_never_collide() {
        assert_eq!(cache_name("cpe:2.3:a:x:y:1.0-1"), "cpe_3a2.3_3aa_3ax_3ay_3a1.0-1");
        assert_ne!(
            cache_name("a:signal-desktop:1.0-1"),
            cache_name("a:signal_desktop:1.0_1")
        );
        assert_ne!(cache_name("a_3a"), cache_name("a:"));
    }

    #[test]
    fn cached_advisories_are_used_only_while_current() {
        let cache = std::env::temp_dir().join(format!("swordcheck-osv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("GHSA-1.json"), r#"{"id": "GHSA-1", "summary": "cached"}"#).unwrap();
        std::fs::write(cache.join("index.json"), r#"{"GHSA-1": "t1"}"#).unwrap();

        // Unchanged since it was cached: no download is attempted.
        let wanted = BTreeMap::from([("GHSA-1", "t1"), ("../evil", "t1")]);
        let (advisories, error) = osv_details(&wanted, &cache, &Progress::none());
        std::fs::remove_dir_all(&cache).unwrap();
        assert_eq!(error, None);
        assert_eq!(
            advisories.keys().collect::<Vec<_>>(),
            ["GHSA-1"],
            "unsafe ids are never used as paths"
        );
        assert_eq!(advisories["GHSA-1"].summary, "cached");
    }

    #[test]
    fn advisory_fields_are_extracted() {
        let text = r#"{
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2026-10-17T02:55:38Z",
            "aliases": ["CVE-2021-23337", "SNYK-1"],
            "summary": "Command Injection in lodash",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"severity": "MODERATE"},
            "affected": [
                {"package": {"name": "lodash", "ecosystem": "npm"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]},
                {"package": {"name": "lodash-es", "ecosystem": "npm"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.22"}]}]}
            ]
        }"#;
        let advisory = parse_advisory(text).unwrap();
        assert_eq!(advisory.cves, ["CVE-2021-23337"]);
        assert_eq!(advisory.summary, "Command Injection in lodash");
        assert_eq!(
            advisory.severity,
            Severity::Medium,
            "the database rating wins over the vector"
        );
        assert_eq!(advisory.fixed_for(&package("lodash", "4.17.15")), ["4.17.21"]);
        assert!(advisory.fixed_for(&package("other", "1.0.0")).is_empty());
    }

    #[test]
    fn advisory_without_rating_uses_the_cvss_vector() {
        let text = r#"{"id": "RUSTSEC-2024-0001", "details": "First line.\nSecond line.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}"#;
        let advisory = parse_advisory(text).unwrap();
        assert_eq!(advisory.severity, Severity::Critical);
        assert_eq!(advisory.summary, "First line.");
        assert!(advisory.cves.is_empty());

        let bare = parse_advisory(r#"{"id": "CVE-2024-1"}"#).unwrap();
        assert_eq!(bare.severity, Severity::Unknown);
        assert_eq!(bare.cves, ["CVE-2024-1"]);
        assert!(parse_advisory("{}").is_none());
    }

    #[test]
    fn long_summaries_are_shortened() {
        assert_eq!(first_line("short", 10), "short");
        let shortened = first_line(&"word ".repeat(50), 20);
        assert_eq!(shortened.chars().count(), 20);
        assert!(shortened.ends_with('…'));
    }

    #[test]
    fn kev_and_epss_are_parsed() {
        let kev = parse_kev(r#"{"vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2024-1", "vulnerabilityName": "Other", "dateAdded": "2024-02-02", "knownRansomwareCampaignUse": "Unknown"}
        ]}"#)
        .unwrap();
        assert!(kev["CVE-2021-44228"].kev.ransomware);
        assert!(!kev["CVE-2024-1"].kev.ransomware);
        assert_eq!(kev["CVE-2024-1"].kev.date_added, "2024-02-02");
        assert!(parse_kev("{}").is_err());

        let epss = parse_epss(
            r#"{"data": [{"cve": "CVE-2021-44228", "epss": "0.999990000"}, {"cve": "CVE-X", "epss": "bad"}]}"#,
        )
        .unwrap();
        assert_eq!(epss.len(), 1);
        assert!((epss["CVE-2021-44228"] - 0.99999).abs() < 1e-9);
    }

    #[test]
    fn nvd_response_lists_exploited_cves_newest_first() {
        let kev = parse_kev(r#"{"vulnerabilities": [{"cveID": "CVE-2023-2", "vulnerabilityName": "From catalog", "dateAdded": "2023-05-05"}]}"#).unwrap();
        let text = r#"{"totalResults": 2, "vulnerabilities": [
            {"cve": {"id": "CVE-2023-1", "cisaExploitAdd": "2023-01-01", "cisaVulnerabilityName": "Older"}},
            {"cve": {"id": "CVE-2023-2"}}
        ]}"#;
        let exploited = parse_nvd(text, &kev).unwrap();
        assert_eq!(
            exploited[0],
            SystemVuln {
                cve: "CVE-2023-2".to_string(),
                name: "From catalog".to_string(),
                date_added: "2023-05-05".to_string()
            }
        );
        assert_eq!(exploited[1].cve, "CVE-2023-1");
        assert!(parse_nvd(r#"{"vulnerabilities": []}"#, &kev).unwrap().is_empty());
        assert!(parse_nvd("<html>rate limited</html>", &kev).is_err());
    }

    #[test]
    fn display_versions_are_cleaned() {
        assert_eq!(clean_version("7.1.9 (88375)").as_deref(), Some("7.1.9"));
        assert_eq!(clean_version("157.0.8103.79").as_deref(), Some("157.0.8103.79"));
        assert_eq!(clean_version("Build 4215"), None);
        assert_eq!(
            clean_version("1.0:*"),
            None,
            "characters with a meaning in CPE names are rejected"
        );
        assert_eq!(clean_version(""), None);
    }

    #[test]
    fn homebrew_formulae_map_to_nvd_products() {
        let item = formula_item("openssl@3", "3.4.0_1").unwrap();
        assert_eq!(item.source, Source::Homebrew);
        assert_eq!(item.cpe, "cpe:2.3:a:openssl:openssl:3.4.0:*:*:*:*:*:*:*");
        assert_eq!(item.title(), "openssl@3 3.4.0 (Homebrew)");

        assert!(formula_item("not-a-known-formula", "1.0").is_none());
        assert!(
            formula_item("curl", "HEAD-1a2b3c4").is_none(),
            "a build from git has no version to look up"
        );
        assert_eq!(strip_revision("8.11.1_2"), "8.11.1");
        assert_eq!(strip_revision("1.0_beta"), "1.0_beta");
        assert_eq!(strip_revision("7.1"), "7.1");
    }

    #[test]
    fn formula_table_is_well_formed() {
        let mut names = BTreeSet::new();
        for (formula, product) in FORMULAE {
            assert!(names.insert(formula), "{formula} is listed twice");
            assert!(!formula.contains('@'), "{formula}: list the unversioned name");
            let parts: Vec<&str> = product.split(':').collect();
            assert_eq!(parts.len(), 2, "{product} must be vendor:product");
            assert!(
                parts
                    .iter()
                    .all(|part| !part.is_empty() && !part.contains(['*', '?', ' ', '/'])),
                "{product}"
            );
            assert_eq!(*product, product.to_lowercase(), "CPE names are lowercase");
        }
    }

    #[test]
    fn cellar_is_read_without_running_brew() {
        let cellar = std::env::temp_dir().join(format!("swordcheck-cellar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cellar);
        for dir in [
            "curl/8.11.1_1",
            "openssl@3/3.4.0",
            "openssl@3/3.3.2",
            "some-private-tool/0.1.0",
            "empty",
            "curl/.metadata",
        ] {
            std::fs::create_dir_all(cellar.join(dir)).unwrap();
        }
        std::fs::write(cellar.join("stray-file"), "").unwrap();

        let (items, unmatched) = homebrew_items(&cellar);
        std::fs::remove_dir_all(&cellar).unwrap();

        let titles: Vec<String> = items.iter().map(SystemItem::title).collect();
        assert_eq!(
            titles,
            [
                "curl 8.11.1 (Homebrew)",
                "openssl@3 3.3.2 (Homebrew)",
                "openssl@3 3.4.0 (Homebrew)"
            ]
        );
        assert_eq!(
            unmatched, 1,
            "only the installed formula that is not in the table counts"
        );
        assert_eq!(
            homebrew_items(&cellar),
            (Vec::new(), 0),
            "a missing Cellar is not an error"
        );
    }

    #[test]
    fn findings_are_ranked_by_exploitation_then_probability_then_severity() {
        let mut findings = [
            finding("low-risk-critical", Severity::Critical, Some(0.001), false),
            finding("likely-medium", Severity::Medium, Some(0.9), false),
            finding("exploited-low", Severity::Low, None, true),
            finding("unscored-high", Severity::High, None, false),
            finding("unscored-critical", Severity::Critical, None, false),
        ];
        findings.sort_by(priority);
        let order: Vec<&str> = findings.iter().map(|f| f.package.as_str()).collect();
        assert_eq!(
            order,
            [
                "exploited-low",
                "likely-medium",
                "low-risk-critical",
                "unscored-critical",
                "unscored-high"
            ]
        );
    }

    #[test]
    fn same_cve_from_two_databases_is_reported_once() {
        let mut rated = finding("pkg", Severity::High, None, false);
        let mut unrated = finding("pkg", Severity::Unknown, None, false);
        unrated.id = "PYSEC-1".to_string();
        unrated.fixed = vec!["2.0.0".to_string()];
        rated.cves = vec!["CVE-2024-1".to_string()];
        unrated.cves = rated.cves.clone();
        let other = finding("other", Severity::Low, None, false);

        let merged = merge_duplicates(vec![unrated, rated, other]);
        assert_eq!(merged.len(), 2);
        let kept = merged.iter().find(|f| f.package == "pkg").unwrap();
        assert_eq!(kept.severity, Severity::High);
        assert_eq!(kept.id, "GHSA-pkg");
        assert_eq!(kept.fixed, ["1.0.1", "2.0.0"]);
    }

    #[test]
    fn merging_keeps_the_exploit_signals_of_every_copy() {
        // The rated advisory names one CVE; the unrated one also names a
        // second CVE that is known to be exploited.
        let mut rated = finding("pkg", Severity::High, None, false);
        rated.cves = vec!["CVE-2024-2".to_string()];
        let mut unrated = finding("pkg", Severity::Unknown, Some(0.9), true);
        unrated.id = "GO-1".to_string();
        unrated.cves = vec!["CVE-2024-1".to_string(), "CVE-2024-2".to_string()];

        let merged = merge_duplicates(vec![unrated, rated]);
        assert_eq!(merged.len(), 1, "a CVE shared by both is one vulnerability");
        let kept = &merged[0];
        assert_eq!((kept.id.as_str(), kept.severity), ("GHSA-pkg", Severity::High));
        assert_eq!(kept.cves, ["CVE-2024-1", "CVE-2024-2"]);
        assert!(kept.kev.is_some(), "the KEV status must survive the merge");
        assert_eq!(kept.epss, Some(0.9));
    }

    #[test]
    fn offline_scan_reports_the_inventory_only() {
        let lockfile = |path: &str, packages: &[Package]| Lockfile {
            path: PathBuf::from(path),
            packages: packages.iter().cloned().collect(),
        };
        let shared = package("shared", "1.0.0");
        let cargo = Package {
            ecosystem: "crates.io",
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
        };
        let lockfiles = [
            lockfile("/a/package-lock.json", &[shared.clone(), package("only-a", "1.0.0")]),
            lockfile("/b/package-lock.json", std::slice::from_ref(&shared)),
            lockfile("/c/Cargo.lock", &[cargo]),
        ];
        let scan = offline(
            &lockfiles,
            System {
                items: vec![system_item(Source::Os, "macOS", "15.0", "cpe".to_string())],
                unmatched_formulae: 4,
            },
        );
        assert!(!scan.online);
        assert_eq!((scan.lockfiles, scan.packages), (3, 3));
        assert_eq!(scan.by_ecosystem, BTreeMap::from([("crates.io", 1), ("npm", 2)]));
        assert_eq!(unique_packages(&lockfiles)[&shared].len(), 2);

        let text = VulnReport::new("now".to_string(), scan).to_text();
        assert!(text.contains("--online"));
        assert!(text.contains("macOS 15.0"));
        assert!(text.contains("4 other Homebrew formulae"));
    }

    #[test]
    fn report_shows_exploited_findings_and_projects() {
        let mut scan = Scan {
            online: true,
            lockfiles: 1,
            packages: 2,
            findings: vec![
                finding("pkg-a", Severity::High, Some(0.5), true),
                finding("pkg-b", Severity::Low, None, false),
            ],
            projects: vec![ProjectSummary {
                path: PathBuf::from("/projects/app/package-lock.json"),
                packages: 2,
                exploited: 1,
                high: 1,
                low: 1,
                ..Default::default()
            }],
            ..Scan::default()
        };
        scan.system = vec![SystemItem {
            exploited: vec![SystemVuln {
                cve: "CVE-2025-1".to_string(),
                name: "Browser bug".to_string(),
                date_added: "2025-01-01".to_string(),
            }],
            checked: true,
            ..system_item(Source::App, "Browser", "1.0", "cpe".to_string())
        }];
        assert_eq!(scan.exploited(), 2);

        colored::control::set_override(false);
        let text = VulnReport::new("now".to_string(), scan).to_text();
        assert!(
            text.contains("[KEV] [HIGH] pkg-a 1.0.0 (npm)  CVE-2024-pkg-a · EPSS 50.0%"),
            "{text}"
        );
        assert!(text.contains("fixed in 1.0.1"));
        assert!(text.contains("CVE-2025-1"));
        assert!(text.contains("Known-exploited vulnerabilities found: 2"));
        assert!(text.contains("BY LOCKFILE"));
    }
}
