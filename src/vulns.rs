//! Vulnerability scan (`--vulns`): which known vulnerabilities affect the
//! software on this machine, and which of them matter most?
//!
//! Two inventories are checked:
//! 1. **Project dependencies** from lockfiles (see `lockfiles`), looked up in
//!    OSV.dev.
//! 2. **macOS and well-known applications**, looked up in the NVD by product
//!    name and version. Only applications in `APPS` are covered.
//!
//! Finding a vulnerability is the easy part; a typical machine has hundreds.
//! The scan therefore ranks them with two signals:
//! - **CISA KEV**: the vulnerability is known to be exploited in the wild.
//! - **EPSS**: the estimated probability that it will be exploited soon.
//!
//! Without `--online` nothing leaves the machine and only the inventory is
//! shown. With `--online`, package names and versions (never file paths or
//! contents) are sent to the services above. Responses are cached under
//! `~/.macos-audit/cache`.

use crate::lockfiles::{self, Lockfile, Package};
use crate::progress::Progress;
use crate::runner::CommandRunner;
use colored::Colorize;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";
const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// OSV accepts at most 1000 queries per request.
const OSV_BATCH: usize = 1000;
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
    fn label(self) -> &'static str {
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

/// macOS itself or an installed application.
#[derive(Debug, Clone, Serialize)]
pub struct SystemItem {
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
    pub findings: Vec<Finding>,
    pub projects: Vec<ProjectSummary>,
    /// Lookups that failed; the rest of the scan is still reported.
    pub warnings: Vec<String>,
}

impl Scan {
    /// Findings that are known to be exploited, in dependencies or the system.
    pub fn exploited(&self) -> usize {
        self.findings.iter().filter(|f| f.kev.is_some() || f.malware).count()
            + self.system.iter().map(|item| item.exploited.len()).sum::<usize>()
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

/// Builds the list of products to look up: macOS plus recognized apps.
pub fn system_items(runner: &dyn CommandRunner) -> Vec<SystemItem> {
    let mut items = Vec::new();
    let read = |program: &str, args: &[&str]| {
        runner.run(program, args).ok().filter(|out| out.success).map(|out| out.stdout.trim().to_string())
    };

    if let Some(version) = read("sw_vers", &["-productVersion"]).as_deref().and_then(clean_version) {
        items.push(system_item("macOS", &version, format!("cpe:2.3:o:apple:macos:{version}:*:*:*:*:*:*:*")));
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
            let Some(product) = extract("CFBundleIdentifier")
                .and_then(|id| APPS.iter().find(|(bundle, _)| *bundle == id).map(|(_, product)| *product))
            else {
                continue;
            };
            let Some(version) = extract("CFBundleShortVersionString").as_deref().and_then(clean_version) else {
                continue;
            };
            let name = app.file_stem().map(|stem| stem.to_string_lossy().into_owned()).unwrap_or_default();
            items.push(system_item(&name, &version, format!("cpe:2.3:a:{product}:{version}:*:*:*:*:*:*:*")));
        }
    }
    items
}

fn system_item(name: &str, version: &str, cpe: String) -> SystemItem {
    SystemItem {
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
        && version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    valid.then(|| version.to_string())
}

/// The inventory without any lookups (used when `--online` is not given).
pub fn offline(lockfiles: &[Lockfile], system: Vec<SystemItem>) -> Scan {
    let unique = unique_packages(lockfiles);
    Scan {
        online: false,
        lockfiles: lockfiles.len(),
        packages: unique.len(),
        by_ecosystem: count_ecosystems(&unique),
        system,
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
pub fn scan(lockfiles: &[Lockfile], mut system: Vec<SystemItem>, options: &Online) -> Scan {
    let mut warnings = Vec::new();
    let unique = unique_packages(lockfiles);
    let packages: Vec<&Package> = unique.keys().copied().collect();

    // 1. Which advisories affect which package?
    let progress = &options.progress;
    let hits = osv_query(&packages, progress).unwrap_or_else(|err| {
        warnings.push(format!("OSV lookup failed: {err}"));
        Vec::new()
    });

    // 2. Advisory details (summary, severity, fixed versions).
    let wanted: BTreeMap<&str, &str> = hits.iter().map(|hit| (hit.id.as_str(), hit.modified.as_str())).collect();
    let advisories = osv_details(&wanted, &options.cache.join("osv"), progress).unwrap_or_else(|err| {
        warnings.push(format!("OSV advisory download failed: {err}"));
        BTreeMap::new()
    });

    // 3. Prioritization data.
    progress.stage("Loading the CISA known-exploited catalog");
    let kev = load_kev(&options.cache).unwrap_or_else(|err| {
        warnings.push(format!("CISA KEV download failed: {err}"));
        BTreeMap::new()
    });
    progress.note(format!("{} known-exploited vulnerabilities in the catalog", kev.len()));
    let cves: BTreeSet<&str> = advisories.values().flat_map(|a| a.cves.iter().map(String::as_str)).collect();
    let epss = epss_lookup(&cves, progress).unwrap_or_else(|err| {
        warnings.push(format!("EPSS lookup failed: {err}"));
        BTreeMap::new()
    });

    let mut findings = Vec::new();
    for hit in &hits {
        let Some(advisory) = advisories.get(hit.id.as_str()) else {
            continue;
        };
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
            kev: advisory.cves.iter().find_map(|cve| kev.get(cve.as_str())).map(|entry| entry.kev.clone()),
            // An advisory may alias several CVEs; the riskiest one counts.
            epss: advisory.cves.iter().filter_map(|cve| epss.get(cve.as_str()).copied()).reduce(f64::max),
            lockfile_count: paths.len(),
            lockfiles: paths.iter().take(MAX_PATHS).map(|path| path.to_path_buf()).collect(),
        });
    }
    let mut findings = merge_duplicates(findings);
    findings.sort_by(priority);

    // 4. macOS and applications.
    nvd_lookup(&mut system, &kev, options, &mut warnings);

    Scan {
        online: true,
        lockfiles: lockfiles.len(),
        packages: unique.len(),
        by_ecosystem: count_ecosystems(&unique),
        projects: summarize_projects(lockfiles, &findings, &hits, &packages),
        system,
        findings,
        warnings,
    }
}

/// Several databases (GitHub, PyPA, RustSec…) often describe the same CVE.
/// Keeps one finding per package version and CVE: the one with a severity
/// rating, with the fixed versions of all of them combined.
fn merge_duplicates(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: BTreeMap<(&'static str, String, String, String), Finding> = BTreeMap::new();
    for finding in findings {
        // Advisories without a CVE are only merged with themselves.
        let vulnerability = finding.cves.first().unwrap_or(&finding.id).clone();
        let key = (finding.ecosystem, finding.package.clone(), finding.version.clone(), vulnerability);
        match merged.get_mut(&key) {
            None => {
                merged.insert(key, finding);
            }
            Some(kept) => {
                let mut fixed: BTreeSet<String> = kept.fixed.drain(..).collect();
                fixed.extend(finding.fixed.iter().cloned());
                // `Severity` orders worst-first with `Unknown` last, so the
                // smaller value is the more informative one.
                if finding.severity < kept.severity {
                    *kept = finding;
                }
                kept.fixed = fixed.into_iter().collect();
            }
        }
    }
    merged.into_values().collect()
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
                let key = (package.ecosystem, package.name.as_str(), package.version.as_str(), hit.id.as_str());
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
    let batches = packages.len().div_ceil(OSV_BATCH);
    let mut hits = Vec::new();
    for (chunk_index, chunk) in packages.chunks(OSV_BATCH).enumerate() {
        let body = osv_request(chunk);
        let response = crate::npm::post_json(OSV_BATCH_URL, &body)?;
        hits.extend(parse_osv_batch(&response, chunk.len(), chunk_index * OSV_BATCH)?);
        progress.step(chunk_index + 1, batches);
        progress.note(format!("{} advisories match so far", hits.len()));
    }
    Ok(hits)
}

fn osv_request(packages: &[&Package]) -> String {
    let queries: Vec<Value> = packages
        .iter()
        .map(|p| json!({"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}))
        .collect();
    json!({ "queries": queries }).to_string()
}

/// Results come back in query order, one entry per query.
fn parse_osv_batch(response: &str, expected: usize, offset: usize) -> Result<Vec<OsvHit>, String> {
    let value: Value = serde_json::from_str(response).map_err(|err| format!("invalid OSV response: {err}"))?;
    let results = value.get("results").and_then(Value::as_array).ok_or("OSV response has no `results`")?;
    if results.len() != expected {
        return Err(format!("OSV returned {} results for {expected} queries", results.len()));
    }
    let mut hits = Vec::new();
    for (index, result) in results.iter().enumerate() {
        for vuln in result.get("vulns").and_then(Value::as_array).into_iter().flatten() {
            if let Some(id) = vuln.get("id").and_then(Value::as_str) {
                hits.push(OsvHit {
                    package: offset + index,
                    id: id.to_string(),
                    modified: vuln.get("modified").and_then(Value::as_str).unwrap_or_default().to_string(),
                });
            }
        }
    }
    Ok(hits)
}

/// The parts of an OSV advisory the report needs.
#[derive(Debug, PartialEq)]
struct Advisory {
    cves: Vec<String>,
    summary: String,
    severity: Severity,
    /// (ecosystem, package name, fixed version).
    fixed: Vec<(String, String, String)>,
    modified: String,
}

impl Advisory {
    fn fixed_for(&self, package: &Package) -> Vec<String> {
        let fixed: BTreeSet<&str> = self
            .fixed
            .iter()
            .filter(|(ecosystem, name, _)| ecosystem == package.ecosystem && name.eq_ignore_ascii_case(&package.name))
            .map(|(_, _, version)| version.as_str())
            .collect();
        fixed.into_iter().map(str::to_string).collect()
    }
}

fn parse_advisory(text: &str) -> Option<Advisory> {
    let value: Value = serde_json::from_str(text).ok()?;
    let id = value.get("id")?.as_str()?;
    let strings = |key: &str| -> Vec<&str> {
        value.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect()
    };

    let mut cves: BTreeSet<&str> = strings("aliases").into_iter().filter(|alias| alias.starts_with("CVE-")).collect();
    // Some databases reference the CVE under `upstream` or use it as the id.
    cves.extend(strings("upstream").into_iter().filter(|alias| alias.starts_with("CVE-")));
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
        modified: value.get("modified").and_then(Value::as_str).unwrap_or_default().to_string(),
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
    let metrics: BTreeMap<&str, &str> = vector.split('/').skip(1).filter_map(|part| part.split_once(':')).collect();
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
    let raw = if scope_changed { 1.08 * (impact + exploitability) } else { impact + exploitability };
    // The specification rounds up to one decimal.
    Some((raw.min(10.0) * 10.0 - 1e-9).ceil() / 10.0)
}

/// Returns the advisories for `wanted` (id → last modified), downloading
/// the ones that are missing from the cache or have changed since.
fn osv_details(
    wanted: &BTreeMap<&str, &str>,
    cache: &Path,
    progress: &Progress,
) -> Result<BTreeMap<String, Advisory>, String> {
    let file_of = |id: &str| cache.join(format!("{id}.json"));
    let load = |id: &str| std::fs::read_to_string(file_of(id)).ok().and_then(|text| parse_advisory(&text));
    // Ids become file names and URL parts; anything unusual is skipped.
    let safe = |id: &str| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));

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
        match load(id).filter(|_| fresh) {
            Some(advisory) => {
                advisories.insert(id.to_string(), advisory);
            }
            None => missing.push(id),
        }
    }
    if missing.is_empty() {
        return Ok(advisories);
    }

    std::fs::create_dir_all(cache).map_err(|err| format!("could not create {}: {err}", cache.display()))?;
    progress.stage(format!(
        "Downloading {} advisories ({} already cached)",
        missing.len(),
        advisories.len()
    ));
    // One curl process downloads a batch in parallel; the list of URL/output
    // pairs is passed as a config file on stdin. Batches exist only so that
    // progress can be reported between them.
    let mut status = Ok(String::new());
    let mut downloaded = 0;
    for batch in missing.chunks(DOWNLOAD_BATCH) {
        let mut config = String::new();
        for id in batch {
            let _ = writeln!(config, "url = \"{OSV_VULN_URL}/{id}\"\noutput = \"{}\"", file_of(id).display());
        }
        let outcome = run_curl(&["--parallel", "--parallel-max", "16", "--max-time", "300", "--config", "-"], Some(&config));
        if outcome.is_err() {
            status = outcome;
        }
        downloaded += batch.len();
        progress.step(downloaded, missing.len());
        progress.note(batch.last().copied().unwrap_or_default());
    }

    for id in missing {
        if let Some(advisory) = load(id) {
            advisories.insert(id.to_string(), advisory);
            index.insert(id.to_string(), wanted[id].to_string());
        }
    }
    if let Ok(text) = serde_json::to_string(&index) {
        store(&index_path, &text);
    }
    // Partial downloads still give partial results; only a total failure is an error.
    match status {
        Err(err) if advisories.is_empty() => Err(err),
        _ => Ok(advisories),
    }
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
    if let Some(text) = read_fresh(&path) {
        return parse_kev(&text);
    }
    match http_get(KEV_URL, &[]) {
        Ok(text) => {
            let parsed = parse_kev(&text)?;
            store(&path, &text);
            Ok(parsed)
        }
        // A stale catalog is better than none.
        Err(err) => match std::fs::read_to_string(&path) {
            Ok(text) => parse_kev(&text),
            Err(_) => Err(err),
        },
    }
}

fn parse_kev(text: &str) -> Result<BTreeMap<String, KevEntry>, String> {
    let value: Value = serde_json::from_str(text).map_err(|err| format!("invalid KEV catalog: {err}"))?;
    let entries = value.get("vulnerabilities").and_then(Value::as_array).ok_or("KEV catalog has no `vulnerabilities`")?;
    Ok(entries
        .iter()
        .filter_map(|entry| {
            let field = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let cve = entry.get("cveID")?.as_str()?.to_string();
            let kev = Kev {
                date_added: field("dateAdded"),
                ransomware: field("knownRansomwareCampaignUse").eq_ignore_ascii_case("known"),
            };
            Some((cve, KevEntry { kev, name: field("vulnerabilityName") }))
        })
        .collect())
}

// ---- EPSS ----

fn epss_lookup(cves: &BTreeSet<&str>, progress: &Progress) -> Result<BTreeMap<String, f64>, String> {
    progress.stage(format!("Fetching exploit probabilities (EPSS) for {} CVEs", cves.len()));
    let cves: Vec<&str> = cves.iter().copied().collect();
    let mut scores = BTreeMap::new();
    for (index, chunk) in cves.chunks(EPSS_BATCH).enumerate() {
        let url = format!("{EPSS_URL}?cve={}&limit={EPSS_BATCH}", chunk.join(","));
        scores.extend(parse_epss(&http_get(&url, &[])?)?);
        progress.step((index * EPSS_BATCH + chunk.len()).min(cves.len()), cves.len());
    }
    Ok(scores)
}

/// EPSS returns numbers as strings: `{"cve": "CVE-…", "epss": "0.20158"}`.
fn parse_epss(text: &str) -> Result<BTreeMap<String, f64>, String> {
    let value: Value = serde_json::from_str(text).map_err(|err| format!("invalid EPSS response: {err}"))?;
    let data = value.get("data").and_then(Value::as_array).ok_or("EPSS response has no `data`")?;
    Ok(data
        .iter()
        .filter_map(|entry| {
            let score: f64 = entry.get("epss")?.as_str()?.parse().ok()?;
            Some((entry.get("cve")?.as_str()?.to_string(), score))
        })
        .collect())
}

// ---- NVD (macOS and applications) ----

/// Asks the NVD which known-exploited CVEs affect each product version.
/// Without an API key the NVD allows 5 requests per 30 seconds, so uncached
/// lookups are spaced out; set `NVD_API_KEY` to go ten times faster.
fn nvd_lookup(items: &mut [SystemItem], kev: &BTreeMap<String, KevEntry>, options: &Online, warnings: &mut Vec<String>) {
    let api_key = std::env::var("NVD_API_KEY").ok().filter(|key| !key.is_empty());
    let headers: Vec<String> = api_key.iter().map(|key| format!("apiKey: {key}")).collect();
    let pause = Duration::from_millis(if api_key.is_some() { 700 } else { 6500 });
    let cache = options.cache.join("nvd");
    let total = items.len();
    let mut requested = false;
    options.progress.stage(format!("Checking macOS and {} apps in the NVD", total.saturating_sub(1)));

    for (index, item) in items.iter_mut().enumerate() {
        let file: String = item.cpe.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect();
        let path = cache.join(format!("{file}.json"));
        let text = match read_fresh(&path) {
            Some(text) => Ok(text),
            None => {
                options.progress.note(format!("{} {}", item.name, item.version));
                if requested {
                    // Say why nothing seems to happen for a few seconds.
                    options.progress.note(format!("  waiting {:.1}s for the NVD rate limit", pause.as_secs_f32()));
                    std::thread::sleep(pause);
                }
                requested = true;
                let url = format!("{NVD_URL}?cpeName={}&isVulnerable&hasKev", item.cpe);
                http_get(&url, &headers).inspect(|text| store(&path, text))
            }
        };
        match text.and_then(|text| parse_nvd(&text, kev)) {
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
    let entries = value.get("vulnerabilities").and_then(Value::as_array).ok_or("NVD response has no `vulnerabilities`")?;
    let mut exploited: Vec<SystemVuln> = entries
        .iter()
        .filter_map(|entry| {
            let cve = entry.get("cve")?;
            let id = cve.get("id")?.as_str()?;
            let field = |key: &str| cve.get(key).and_then(Value::as_str).map(str::to_string);
            let known = kev.get(id);
            Some(SystemVuln {
                cve: id.to_string(),
                name: field("cisaVulnerabilityName").or_else(|| known.map(|k| k.name.clone())).unwrap_or_default(),
                date_added: field("cisaExploitAdd").or_else(|| known.map(|k| k.kev.date_added.clone())).unwrap_or_default(),
            })
        })
        .collect();
    // Most recently added first.
    exploited.sort_by(|a, b| b.date_added.cmp(&a.date_added).then(a.cve.cmp(&b.cve)));
    Ok(exploited)
}

// ---- HTTP and cache helpers ----

fn http_get(url: &str, headers: &[String]) -> Result<String, String> {
    let mut args = vec!["--location", "--max-time", "60"];
    for header in headers {
        args.extend(["--header", header.as_str()]);
    }
    args.push(url);
    run_curl(&args, None)
}

/// Runs `curl` quietly; fails on HTTP errors. `stdin` feeds `--config -`.
fn run_curl(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let mut child = Command::new("curl")
        .args(["--silent", "--show-error", "--fail"])
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("could not run `curl`: {err}"))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes()).map_err(|err| format!("could not send the request: {err}"))?;
    }
    let output = child.wait_with_output().map_err(|err| format!("could not wait for `curl`: {err}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(message.lines().last().unwrap_or("curl failed").trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
        Self { tool: env!("CARGO_PKG_NAME"), version: env!("CARGO_PKG_VERSION"), timestamp, scan }
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

        let ecosystems: Vec<String> = scan.by_ecosystem.iter().map(|(name, count)| format!("{name} {count}")).collect();
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
                let _ = writeln!(out, "  {} {}", item.name, item.version.dimmed());
            }
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{}",
                "Inventory only. Run with --online to look these up in OSV.dev, the NVD,\nCISA KEV and EPSS (package names and versions are sent; nothing else).".yellow()
            );
            return out.trim_end().to_string();
        }

        let _ = writeln!(out, "{}", "SYSTEM  (known-exploited vulnerabilities affecting the installed version)".bold());
        for item in &scan.system {
            let title = format!("{} {}", item.name, item.version);
            if let Some(error) = &item.error {
                let _ = writeln!(out, "  {} {title:<34} {}", "?".yellow(), format!("lookup failed: {error}").dimmed());
            } else if item.exploited.is_empty() {
                let _ = writeln!(out, "  {} {title:<34} {}", "✔".green(), "none".dimmed());
            } else {
                let _ = writeln!(
                    out,
                    "  {} {:<34} {}",
                    "✖".red(),
                    title.bold(),
                    format!("{} known-exploited — update this product", item.exploited.len()).red().bold()
                );
                for vuln in item.exploited.iter().take(5) {
                    let _ = writeln!(out, "      {} {}", vuln.cve, format!("{} (added {})", vuln.name, vuln.date_added).dimmed());
                }
                if item.exploited.len() > 5 {
                    let _ = writeln!(out, "      {}", format!("… and {} more", item.exploited.len() - 5).dimmed());
                }
            }
        }
        if scan.system.is_empty() {
            let _ = writeln!(out, "  {}", "not scanned".dimmed());
        }
        let _ = writeln!(out, "{rule}");

        let exploited = scan.findings.iter().filter(|f| f.kev.is_some() || f.malware).count();
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
                format!("… and {} lower-priority findings (use --json for the full list)", scan.findings.len() - TEXT_LIMIT).dimmed()
            );
        }

        if !scan.projects.is_empty() {
            let _ = writeln!(out, "{rule}");
            let _ = writeln!(out, "{}", format!("{:<52} {:>4} {:>4} {:>4} {:>4} {:>4}", "BY LOCKFILE", "KEV", "CRIT", "HIGH", "MED", "LOW").bold());
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
                let _ = writeln!(out, "{}", format!("… and {} more lockfiles", scan.projects.len() - PROJECT_LIMIT).dimmed());
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
                let _ = writeln!(out, "{}", format!("Known-exploited vulnerabilities found: {count}. Fix these first.").red().bold());
            }
        }
        let _ = writeln!(
            out,
            "{}",
            "Findings are ranked: known-exploited (KEV) first, then exploit probability (EPSS), then severity.\nApplications are matched by name in the NVD; only well-known apps are covered.".dimmed()
        );
        out.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, version: &str) -> Package {
        Package { ecosystem: "npm", name: name.to_string(), version: version.to_string() }
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
            kev: kev.then(|| Kev { date_added: "2024-01-01".to_string(), ransomware: false }),
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
        assert_eq!(cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), None);
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
    fn osv_batch_maps_results_to_queries() {
        let (a, b) = (package("a", "1.0.0"), package("b", "2.0.0"));
        let request: Value = serde_json::from_str(&osv_request(&[&a, &b])).unwrap();
        assert_eq!(request["queries"][1]["package"]["name"], "b");
        assert_eq!(request["queries"][1]["package"]["ecosystem"], "npm");
        assert_eq!(request["queries"][1]["version"], "2.0.0");

        let response = r#"{"results": [{}, {"vulns": [{"id": "GHSA-x", "modified": "2025-01-01T00:00:00Z"}, {"id": "MAL-1"}]}]}"#;
        let hits = parse_osv_batch(response, 2, 1000).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], OsvHit { package: 1001, id: "GHSA-x".to_string(), modified: "2025-01-01T00:00:00Z".to_string() });
        assert_eq!(hits[1].modified, "");

        assert!(parse_osv_batch(response, 3, 0).is_err(), "result count must match");
        assert!(parse_osv_batch("not json", 1, 0).is_err());
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
        assert_eq!(advisory.severity, Severity::Medium, "the database rating wins over the vector");
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

        let epss = parse_epss(r#"{"data": [{"cve": "CVE-2021-44228", "epss": "0.999990000"}, {"cve": "CVE-X", "epss": "bad"}]}"#).unwrap();
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
        assert_eq!(exploited[0], SystemVuln { cve: "CVE-2023-2".to_string(), name: "From catalog".to_string(), date_added: "2023-05-05".to_string() });
        assert_eq!(exploited[1].cve, "CVE-2023-1");
        assert!(parse_nvd(r#"{"vulnerabilities": []}"#, &kev).unwrap().is_empty());
        assert!(parse_nvd("<html>rate limited</html>", &kev).is_err());
    }

    #[test]
    fn display_versions_are_cleaned() {
        assert_eq!(clean_version("7.1.9 (88375)").as_deref(), Some("7.1.9"));
        assert_eq!(clean_version("157.0.8103.79").as_deref(), Some("157.0.8103.79"));
        assert_eq!(clean_version("Build 4215"), None);
        assert_eq!(clean_version("1.0:*"), None, "characters with a meaning in CPE names are rejected");
        assert_eq!(clean_version(""), None);
    }

    #[test]
    fn findings_are_ranked_by_exploitation_then_probability_then_severity() {
        let mut findings = vec![
            finding("low-risk-critical", Severity::Critical, Some(0.001), false),
            finding("likely-medium", Severity::Medium, Some(0.9), false),
            finding("exploited-low", Severity::Low, None, true),
            finding("unscored-high", Severity::High, None, false),
            finding("unscored-critical", Severity::Critical, None, false),
        ];
        findings.sort_by(priority);
        let order: Vec<&str> = findings.iter().map(|f| f.package.as_str()).collect();
        assert_eq!(order, ["exploited-low", "likely-medium", "low-risk-critical", "unscored-critical", "unscored-high"]);
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
    fn offline_scan_reports_the_inventory_only() {
        let lockfile = |path: &str, packages: &[Package]| Lockfile {
            path: PathBuf::from(path),
            packages: packages.iter().cloned().collect(),
        };
        let shared = package("shared", "1.0.0");
        let cargo = Package { ecosystem: "crates.io", name: "serde".to_string(), version: "1.0.0".to_string() };
        let lockfiles = [
            lockfile("/a/package-lock.json", &[shared.clone(), package("only-a", "1.0.0")]),
            lockfile("/b/package-lock.json", &[shared.clone()]),
            lockfile("/c/Cargo.lock", &[cargo]),
        ];
        let scan = offline(&lockfiles, vec![system_item("macOS", "15.0", "cpe".to_string())]);
        assert!(!scan.online);
        assert_eq!((scan.lockfiles, scan.packages), (3, 3));
        assert_eq!(scan.by_ecosystem, BTreeMap::from([("crates.io", 1), ("npm", 2)]));
        assert_eq!(unique_packages(&lockfiles)[&shared].len(), 2);

        let text = VulnReport::new("now".to_string(), scan).to_text();
        assert!(text.contains("--online"));
        assert!(text.contains("macOS"));
    }

    #[test]
    fn report_shows_exploited_findings_and_projects() {
        let mut scan = Scan {
            online: true,
            lockfiles: 1,
            packages: 2,
            findings: vec![finding("pkg-a", Severity::High, Some(0.5), true), finding("pkg-b", Severity::Low, None, false)],
            projects: vec![ProjectSummary { path: PathBuf::from("/projects/app/package-lock.json"), packages: 2, exploited: 1, high: 1, low: 1, ..Default::default() }],
            ..Scan::default()
        };
        scan.system = vec![SystemItem {
            exploited: vec![SystemVuln { cve: "CVE-2025-1".to_string(), name: "Browser bug".to_string(), date_added: "2025-01-01".to_string() }],
            checked: true,
            ..system_item("Browser", "1.0", "cpe".to_string())
        }];
        assert_eq!(scan.exploited(), 2);

        colored::control::set_override(false);
        let text = VulnReport::new("now".to_string(), scan).to_text();
        assert!(text.contains("[KEV] [HIGH] pkg-a 1.0.0 (npm)  CVE-2024-pkg-a · EPSS 50.0%"), "{text}");
        assert!(text.contains("fixed in 1.0.1"));
        assert!(text.contains("CVE-2025-1"));
        assert!(text.contains("Known-exploited vulnerabilities found: 2"));
        assert!(text.contains("BY LOCKFILE"));
    }
}
