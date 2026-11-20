//! Lockfile discovery and parsing for the vulnerability scan (`--vulns`).
//!
//! A lockfile records the exact version of every dependency a project uses,
//! which is what a vulnerability database needs. Each parser here extracts
//! `(ecosystem, name, version)` triples and nothing else; no package code is
//! read or executed.
//!
//! The parsers are deliberately forgiving: a lockfile that cannot be parsed
//! yields no packages rather than an error, so one broken project does not
//! stop the scan.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// One pinned dependency. `ecosystem` uses the names OSV.dev expects.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Package {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
}

impl Package {
    fn new(ecosystem: &'static str, name: &str, version: &str) -> Option<Self> {
        let (name, version) = (name.trim(), version.trim());
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some(Self {
            ecosystem,
            name: name.to_string(),
            version: version.to_string(),
        })
    }
}

/// A parsed lockfile.
#[derive(Debug)]
pub struct Lockfile {
    pub path: PathBuf,
    pub packages: BTreeSet<Package>,
    /// Requirements files this one pulls in with `-r`; pip installs their
    /// pins too, so the caller reads them as well (see `parse_included`).
    pub includes: Vec<PathBuf>,
}

/// Lockfiles larger than this are not read.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Reads and parses a lockfile. `Ok(None)` if the file name is not a known
/// lockfile; `Err(reason)` if it is one but cannot be used, so the caller can
/// say that its packages were not checked.
pub fn parse_file(path: &Path) -> Result<Option<Lockfile>, &'static str> {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    let Some(parser) = parser_for(name) else {
        return Ok(None);
    };
    read(path, parser, is_requirements(name)).map(Some)
}

/// Reads a requirements file named by another one's `-r`, whatever its name
/// (`requirements/base.txt` is a common layout).
pub fn parse_included(path: &Path) -> Result<Lockfile, &'static str> {
    read(path, requirements_txt, true)
}

fn read(path: &Path, parser: fn(&str) -> Vec<Package>, requirements: bool) -> Result<Lockfile, &'static str> {
    if std::fs::metadata(path).map_err(unreadable)?.len() > MAX_BYTES {
        return Err("over 64 MB");
    }
    let text = decode(std::fs::read(path).map_err(unreadable)?).ok_or("not UTF-8 or UTF-16 text")?;
    let includes = if requirements {
        requirement_includes(&text, path)
    } else {
        Vec::new()
    };
    Ok(Lockfile {
        path: path.to_path_buf(),
        packages: parser(&text).into_iter().collect(),
        includes,
    })
}

/// Why a lockfile could not be read, in words for the report.
fn unreadable(err: std::io::Error) -> &'static str {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => "permission denied",
        _ => "could not be read",
    }
}

/// Decodes a lockfile. Windows editors and PowerShell's `pip freeze >` save
/// hand-written files such as `requirements.txt` with a byte order mark, as
/// UTF-8 or UTF-16; pip reads those, so the scan must too. Without a mark the
/// file must be UTF-8.
fn decode(bytes: Vec<u8>) -> Option<String> {
    fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Option<String> {
        let (pairs, []) = bytes.as_chunks::<2>() else {
            return None;
        };
        let units: Vec<u16> = pairs.iter().map(|&pair| unit(pair)).collect();
        String::from_utf16(&units).ok()
    }
    match bytes.as_slice() {
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8(rest.to_vec()).ok(),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        _ => String::from_utf8(bytes).ok(),
    }
}

/// Picks the parser for a file name. Function pointers (`fn(&str) -> …`) let
/// us return "which function to call" as a plain value.
fn parser_for(file_name: &str) -> Option<fn(&str) -> Vec<Package>> {
    Some(match file_name {
        "Cargo.lock" => cargo_lock,
        "package-lock.json" | "npm-shrinkwrap.json" => package_lock,
        "yarn.lock" => yarn_lock,
        "pnpm-lock.yaml" => pnpm_lock,
        "poetry.lock" | "uv.lock" => python_toml_lock,
        "Pipfile.lock" => pipfile_lock,
        "composer.lock" => composer_lock,
        "Gemfile.lock" => gemfile_lock,
        "go.mod" => go_mod,
        name if is_requirements(name) => requirements_txt,
        _ => return None,
    })
}

fn is_requirements(file_name: &str) -> bool {
    file_name.starts_with("requirements") && file_name.ends_with(".txt")
}

pub fn is_lockfile(file_name: &str) -> bool {
    parser_for(file_name).is_some()
}

// ---- Rust ----

/// The only `source` Cargo writes for crates.io, whichever protocol (git or
/// sparse) was used to download the index.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// `Cargo.lock`: only crates from crates.io. Path and git dependencies and
/// crates from an alternative (private) registry have no entry in a
/// vulnerability database, and their names are nobody else's business.
fn cargo_lock(text: &str) -> Vec<Package> {
    let Ok(lock) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    toml_packages(&lock)
        .filter(|package| package.get("source").and_then(toml::Value::as_str) == Some(CRATES_IO))
        .filter_map(|package| toml_package("crates.io", package))
        .collect()
}

/// The `[[package]]` tables of a TOML lockfile.
fn toml_packages(lock: &toml::Table) -> impl Iterator<Item = &toml::Table> {
    lock.get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
}

fn toml_package(ecosystem: &'static str, package: &toml::Table) -> Option<Package> {
    Package::new(
        ecosystem,
        package.get("name")?.as_str()?,
        package.get("version")?.as_str()?,
    )
}

// ---- JavaScript ----

/// `package-lock.json`: lockfile v2/v3 keeps a flat `packages` map keyed by
/// install path; v1 keeps a nested `dependencies` tree. Only packages that
/// came from a registry are reported: links, workspace packages, git
/// dependencies and local or remote tarballs are skipped.
fn package_lock(text: &str) -> Vec<Package> {
    let Ok(lock) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut found = Vec::new();

    /// `resolved` is absent for bundled dependencies and when npm is told to
    /// omit it; when present it must point at a registry.
    fn from_registry(entry: &Value) -> bool {
        match entry.get("resolved") {
            None => true,
            Some(resolved) => resolved.as_str().is_some_and(is_registry_tarball),
        }
    }

    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (path, entry) in packages {
            // The "" key is the project itself, and workspace packages are
            // listed under their own path outside `node_modules`.
            let Some((_, name)) = path.rsplit_once("node_modules/") else {
                continue;
            };
            if entry.get("link").and_then(Value::as_bool) == Some(true) || !from_registry(entry) {
                continue;
            }
            // An alias is installed under its alias; `name` is the real package.
            let name = entry.get("name").and_then(Value::as_str).unwrap_or(name);
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                found.extend(npm_package(name, version));
            }
        }
        return found;
    }

    fn walk(dependencies: &Value, found: &mut Vec<Package>) {
        let Some(dependencies) = dependencies.as_object() else {
            return;
        };
        for (name, entry) in dependencies {
            if let Some(version) = entry.get("version").and_then(Value::as_str)
                && from_registry(entry)
            {
                // An alias is recorded as `"version": "npm:real-name@1.2.3"`.
                // Git, URL and `file:` versions are rejected by `npm_package`.
                match version.strip_prefix("npm:").map(split_spec) {
                    Some(Some((real, version))) => found.extend(npm_package(real, version)),
                    Some(None) => {}
                    None => found.extend(npm_package(name, version)),
                }
            }
            if let Some(nested) = entry.get("dependencies") {
                walk(nested, found);
            }
        }
    }
    if let Some(dependencies) = lock.get("dependencies") {
        walk(dependencies, &mut found);
    }
    found
}

/// An npm package at a released version. Versions that are URLs, git refs,
/// local paths or protocol specs (`file:…`, `workspace:…`) are not registry
/// packages.
fn npm_package(name: &str, version: &str) -> Option<Package> {
    let version = version.trim();
    if !version.starts_with(|c: char| c.is_ascii_digit())
        || version.contains(|c: char| c == ':' || c == '/' || c.is_whitespace())
        // Yarn Berry's placeholder version for workspace packages.
        || version == "0.0.0-use.local"
    {
        return None;
    }
    Package::new("npm", name, version)
}

/// Whether a `resolved` URL is a tarball served by an npm registry
/// (`https://host/[prefix/]name/-/name-1.2.3.tgz`), as opposed to a git
/// repository, a local file or a tarball hosted somewhere else.
fn is_registry_tarball(resolved: &str) -> bool {
    let url = resolved.split(['#', '?']).next().unwrap_or(resolved);
    let Some(rest) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    match host {
        // GitHub Packages serves tarballs from `/download/<name>/<version>/<hash>`.
        "npm.pkg.github.com" => true,
        // Repository archives and release assets, never a registry.
        "github.com" | "codeload.github.com" => false,
        // `/download/` is the layout of the older cnpm mirrors.
        _ => url.ends_with(".tgz") && (rest.contains("/-/") || rest.contains("/download/")),
    }
}

/// Splits `name@rest` at the first `@` that follows the name, keeping the
/// leading `@` of a scope. Cutting at the first rather than the last `@`
/// matters because the rest may itself contain one (`alias@npm:real@^1.0.0`).
fn split_spec(spec: &str) -> Option<(&str, &str)> {
    let at = spec.char_indices().skip(1).find(|&(_, c)| c == '@')?.0;
    Some((&spec[..at], &spec[at + 1..]))
}

/// The fields of one `yarn.lock` entry that identify the package.
#[derive(Default)]
struct YarnEntry {
    /// The first spec of the header, e.g. `lodash@^4.17.0`.
    spec: String,
    version: Option<String>,
    /// Berry only: `name@protocol:reference`.
    resolution: Option<String>,
    /// Classic only: the download URL.
    resolved: Option<String>,
}

impl YarnEntry {
    fn package(&self) -> Option<Package> {
        let version = self.version.as_deref()?;

        // Berry states what the entry resolved to, which settles aliases
        // (`a@npm:b@^1` resolves to `b@npm:1.0.0`) and every non-registry
        // protocol (`workspace:`, `patch:`, `link:`, `portal:`, `file:`, git…).
        if let Some(resolution) = &self.resolution {
            let (name, reference) = split_spec(resolution)?;
            return reference
                .starts_with("npm:")
                .then(|| npm_package(name, version))
                .flatten();
        }

        // Classic: the header spec and the download URL are all there is.
        let (name, range) = split_spec(&self.spec)?;
        if self
            .resolved
            .as_deref()
            .is_some_and(|resolved| !is_registry_tarball(resolved))
        {
            return None;
        }
        let name = match range.strip_prefix("npm:") {
            // `alias@npm:real@^1.0.0`, `alias@npm:@scope/real@^1.0.0`.
            Some(target) => match split_spec(target) {
                Some((real, _)) => real,
                // `alias@npm:real` with no range; anything else after `npm:`
                // is a plain range for `name`.
                None if target.starts_with(|c: char| c == '@' || c.is_ascii_lowercase()) => target,
                None => name,
            },
            // Semver ranges and tags contain neither `:` nor `/`; protocols
            // (`file:`, `link:`, `git+ssh:`, `https:`, `patch:`, `workspace:`),
            // local paths and `user/repo` shorthands do.
            None if range.contains([':', '/']) => return None,
            None => name,
        };
        npm_package(name, version)
    }
}

/// `yarn.lock`, both classic (`version "1.2.3"`) and Berry (`version: 1.2.3`).
fn yarn_lock(text: &str) -> Vec<Package> {
    let mut found = Vec::new();
    let mut current: Option<YarnEntry> = None;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            // Header: `"a@^1", "a@^2":` (classic) or `"a@npm:^1, a@npm:^2":`
            // (Berry) — every spec names the same package.
            found.extend(current.take().and_then(|entry| entry.package()));
            let first = line
                .trim_end()
                .trim_end_matches(':')
                .split(',')
                .next()
                .unwrap_or_default();
            let spec = first.trim().trim_matches('"').to_string();
            current = Some(YarnEntry {
                spec,
                ..YarnEntry::default()
            });
            continue;
        }
        // Entry fields sit exactly two spaces deep; deeper lines are the
        // entry's own dependency lists, where `version` may be a package name.
        let Some(field) = line.strip_prefix("  ").filter(|rest| !rest.starts_with(' ')) else {
            continue;
        };
        let Some(entry) = current.as_mut() else {
            continue;
        };
        let (key, value) = field.split_once([' ', ':']).unwrap_or((field, ""));
        let value = value
            .trim()
            .trim_start_matches(':')
            .trim()
            .trim_matches('"')
            .to_string();
        match key {
            "version" => entry.version = Some(value),
            "resolution" => entry.resolution = Some(value),
            "resolved" => entry.resolved = Some(value),
            _ => {}
        }
    }
    found.extend(current.and_then(|entry| entry.package()));
    found
}

/// `pnpm-lock.yaml`: the keys of the top-level `packages:` map. The format
/// changed across lockfile versions:
///
/// - v5: `/name/1.2.3`, with peers after an underscore:
///   `/name/1.2.3_react@17.0.2`, `/@scope/name/1.2.3_@scope+peer@1.0.0`
/// - v6: `/name@1.2.3`, with peers in parentheses: `/name@1.2.3(react@18.0.0)`
/// - v9: `name@1.2.3`
fn pnpm_lock(text: &str) -> Vec<Package> {
    let mut found = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        // Package keys sit exactly two spaces deep.
        let Some(key) = line
            .strip_prefix("  ")
            .filter(|rest| in_packages && !rest.starts_with(' '))
        else {
            continue;
        };
        let key = key.trim_end().trim_end_matches(':').trim_matches(['\'', '"']);
        found.extend(pnpm_key(key));
    }
    found
}

/// Parses one key of pnpm's `packages:` map.
fn pnpm_key(key: &str) -> Option<Package> {
    // Registry packages start with `/` up to v6. Keys without it are
    // `name@version` in v9 and non-registry sources before that
    // (`github.com/user/repo/<commit>`, `file:packages/x`).
    let (key, slash) = match key.strip_prefix('/') {
        Some(rest) => (rest, true),
        None => (key, false),
    };
    // The name ends at the first `/` (v5) or `@` (v6+) after the scope, so a
    // peer suffix, which contains both characters, cannot be mistaken for it.
    let scope = if key.starts_with('@') { key.find('/')? + 1 } else { 0 };
    let end = scope + key[scope..].find(['/', '@'])?;
    let (name, version) = (&key[..end], &key[end + 1..]);
    if !slash && key[end..].starts_with('/') {
        return None;
    }
    // Drop peer suffixes: `(react@18.0.0)` or `_react@17.0.2`. A version
    // contains neither character; a git or tarball version (`name@https://…`)
    // is rejected by `npm_package`.
    let version = version.split(['(', '_']).next()?;
    npm_package(name, version)
}

// ---- Python ----

/// Normalises a PyPI project name (PEP 503): lowercase, with every run of
/// `-`, `_` and `.` replaced by one `-`. `Flask_SQLAlchemy` and
/// `flask-sqlalchemy` are the same project and must be one entry.
fn pypi_name(name: &str) -> String {
    let parts: Vec<String> = name
        .trim()
        .split(['-', '_', '.'])
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    parts.join("-")
}

fn pypi_package(name: &str, version: &str) -> Option<Package> {
    let version = version.trim();
    // A pinned version (PEP 440) has no wildcard, comparison or URL characters.
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '!' | '+' | '-' | '_'))
    {
        return None;
    }
    Package::new("PyPI", &pypi_name(name), version)
}

/// `poetry.lock` and `uv.lock` share the `[[package]]` layout. Only packages
/// from a package index are kept: the project itself and git, path,
/// directory, editable and direct-URL dependencies are skipped.
fn python_toml_lock(text: &str) -> Vec<Package> {
    let Ok(lock) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    toml_packages(&lock)
        .filter(|package| python_index_source(package))
        .filter_map(|package| pypi_package(package.get("name")?.as_str()?, package.get("version")?.as_str()?))
        .collect()
}

/// Whether a `[[package]]` table of `poetry.lock` or `uv.lock` comes from a
/// package index.
fn python_index_source(package: &toml::Table) -> bool {
    match package.get("source") {
        // Poetry writes no source for packages from PyPI.
        None => true,
        Some(toml::Value::Table(source)) => match source.get("type").and_then(toml::Value::as_str) {
            // Poetry: `type` is `legacy` for another index, otherwise `git`,
            // `directory`, `file` or `url`.
            Some(kind) => matches!(kind, "legacy" | "pypi"),
            // uv: `{ registry = "https://…" }`, otherwise `git`, `path`,
            // `directory`, `editable`, `virtual` or `url`. A registry that
            // is a local directory of wheels is not an index either.
            None => source
                .get("registry")
                .and_then(toml::Value::as_str)
                .is_some_and(|url| url.starts_with("http")),
        },
        Some(_) => false,
    }
}

/// `requirements*.txt`: only exact pins (`name==1.2.3`, `name===1.2.3`)
/// identify a version.
fn requirements_txt(text: &str) -> Vec<Package> {
    logical_lines(text)
        .iter()
        .filter_map(|line| requirement(line))
        .collect()
}

/// The logical lines of a requirements file: a trailing backslash continues
/// a line on the next one, which is how `--hash` options are usually attached.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut logical = String::new();
    for line in text.lines() {
        let is_comment = line.trim_start().starts_with('#');
        if let Some(head) = line.trim_end().strip_suffix('\\').filter(|_| !is_comment) {
            logical.push_str(head);
            logical.push(' ');
            continue;
        }
        logical.push_str(line);
        lines.push(std::mem::take(&mut logical));
    }
    lines.push(logical);
    lines
}

/// A logical line without its comment. A comment starts at a `#` that begins
/// the line or follows whitespace; a `#` inside a URL fragment is not one.
fn without_comment(line: &str) -> &str {
    let comment = line
        .char_indices()
        .find(|&(at, c)| c == '#' && (at == 0 || line[..at].ends_with(char::is_whitespace)))
        .map_or(line.len(), |(at, _)| at);
    &line[..comment]
}

/// The files a requirements file pulls in with `-r FILE`, `-rFILE` or
/// `--requirement[=]FILE`, resolved against its folder as pip does. Only
/// relative `.txt` paths are followed, so an include can only lead the scan
/// to another requirements file of the project; URLs are never fetched.
fn requirement_includes(text: &str, path: &Path) -> Vec<PathBuf> {
    let folder = path.parent().unwrap_or(Path::new(""));
    logical_lines(text)
        .iter()
        .filter_map(|line| {
            let line = without_comment(line).trim();
            let target = match line.strip_prefix("--requirement") {
                Some(rest) if rest.starts_with(|c: char| c == '=' || c.is_whitespace()) => rest,
                Some(_) => return None,
                None => line.strip_prefix("-r")?,
            };
            let target = target.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
            // pip splits the options part like a shell, so a path may be quoted.
            let target = target.trim_matches(['"', '\'']);
            let relative = !target.contains("://") && !Path::new(target).is_absolute();
            (relative && target.ends_with(".txt")).then(|| folder.join(target))
        })
        .collect()
}

/// Parses one logical line of a requirements file.
fn requirement(line: &str) -> Option<Package> {
    // Environment markers follow a `;`.
    let line = without_comment(line).split(';').next()?.trim();
    // Options: `-r other.txt`, `-e .`, `--index-url …`.
    if line.starts_with('-') {
        return None;
    }
    let (name, version) = line.split_once("==")?;
    // `===` is an exact pin too (arbitrary equality).
    let version = version.strip_prefix('=').unwrap_or(version);
    // Per-requirement options such as `--hash=…` follow the version.
    let version = version.split_whitespace().next()?;
    // `requests[socks]` → `requests`.
    let name = name.trim();
    let name = match name.split_once('[') {
        Some((name, extras)) if extras.ends_with(']') => name.trim_end(),
        Some(_) => return None,
        None => name,
    };
    // Anything else before the `==` means it was not the only specifier
    // (`foo>=1,==1.5`) or not a name at all (`foo @ https://…`).
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    // `pypi_package` rejects wildcards (`==1.*`) and further clauses (`==1.0,!=1.1`).
    pypi_package(name, version)
}

/// `Pipfile.lock`: `{"default": {"name": {"version": "==1.2.3"}}, "develop": …}`.
fn pipfile_lock(text: &str) -> Vec<Package> {
    let Ok(lock) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    ["default", "develop"]
        .iter()
        .filter_map(|section| lock.get(section)?.as_object())
        .flatten()
        .filter_map(|(name, entry)| {
            // Git, local and direct-URL dependencies are not index packages.
            if ["git", "hg", "svn", "path", "file"]
                .iter()
                .any(|key| entry.get(key).is_some())
            {
                return None;
            }
            let version = entry.get("version")?.as_str()?.strip_prefix("==")?;
            pypi_package(name, version.strip_prefix('=').unwrap_or(version))
        })
        .collect()
}

// ---- PHP, Ruby, Go ----

/// `composer.lock`: `packages` and `packages-dev` arrays.
fn composer_lock(text: &str) -> Vec<Package> {
    let Ok(lock) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    ["packages", "packages-dev"]
        .iter()
        .filter_map(|section| lock.get(section)?.as_array())
        .flatten()
        .filter_map(|entry| {
            // A `path` repository is a local directory, not a Packagist package.
            let kind = |key: &str| entry.get(key).and_then(|v| v.get("type")).and_then(Value::as_str);
            if kind("dist") == Some("path") || kind("source") == Some("path") {
                return None;
            }
            let version = entry.get("version")?.as_str()?;
            // Branches such as `dev-main` and `2.x-dev` are not released versions.
            let version = version.strip_prefix('v').unwrap_or(version);
            if !version.starts_with(|c: char| c.is_ascii_digit()) || version.ends_with("-dev") {
                return None;
            }
            Package::new("Packagist", entry.get("name")?.as_str()?, version)
        })
        .collect()
}

/// `Gemfile.lock`: resolved gems are the four-space-indented `name (1.2.3)`
/// lines of a `GEM` section that has a gem server as its `remote:`; deeper
/// lines are their dependency constraints. `PATH` and `GIT` sections (local
/// and git gems) use the same layout and are skipped.
fn gemfile_lock(text: &str) -> Vec<Package> {
    let mut found = Vec::new();
    let mut in_gem = false;
    let mut has_remote = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            // Section header: GEM, PATH, GIT, PLATFORMS, DEPENDENCIES, CHECKSUMS…
            in_gem = line.trim_end() == "GEM";
            has_remote = false;
            continue;
        }
        if !in_gem {
            continue;
        }
        if let Some(remote) = line.trim().strip_prefix("remote:") {
            has_remote |= remote.trim().starts_with("http");
            continue;
        }
        if has_remote {
            found.extend(gem(line));
        }
    }
    found
}

fn gem(line: &str) -> Option<Package> {
    let entry = line.strip_prefix("    ").filter(|rest| !rest.starts_with(' '))?;
    let (name, version) = entry.split_once(" (")?;
    let version = version.strip_suffix(')')?;
    // Platform suffix: `1.16.0-arm64-darwin` → `1.16.0`.
    let version = version.split('-').next()?;
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Package::new("RubyGems", name, version)
}

#[derive(Clone, Copy)]
enum GoDirective {
    Require,
    Replace,
    Other,
}

/// One `replace` directive of a `go.mod`.
struct GoReplace {
    module: String,
    /// `None` replaces every version of the module.
    version: Option<String>,
    /// The replacement module and version; `None` for a local directory.
    target: Option<(String, String)>,
}

/// `go.mod`: `require` directives with the `replace` directives applied,
/// each single-line or in a block.
fn go_mod(text: &str) -> Vec<Package> {
    let mut required: Vec<(String, String)> = Vec::new();
    let mut replaces: Vec<GoReplace> = Vec::new();
    let mut block: Option<GoDirective> = None;

    // Module paths and versions may be quoted.
    fn words(text: &str) -> Vec<String> {
        text.split_whitespace()
            .map(|word| word.trim_matches(['"', '`']).to_string())
            .collect()
    }

    for line in text.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (directive, entry) = match block {
            Some(_) if line.starts_with(')') => {
                block = None;
                continue;
            }
            Some(directive) => (directive, line),
            None => {
                // `require x v1`, `require (` and `require(` are all valid.
                let end = line.find(|c: char| c.is_whitespace() || c == '(').unwrap_or(line.len());
                let directive = match &line[..end] {
                    "require" => GoDirective::Require,
                    "replace" => GoDirective::Replace,
                    _ => GoDirective::Other,
                };
                let rest = line[end..].trim();
                if rest.starts_with('(') {
                    block = Some(directive);
                    continue;
                }
                (directive, rest)
            }
        };
        match directive {
            GoDirective::Require => {
                if let [module, version, ..] = words(entry).as_slice() {
                    required.push((module.clone(), version.clone()));
                }
            }
            GoDirective::Replace => {
                // `old [version] => new version` or `old [version] => ../local/path`.
                let Some((old, new)) = entry.split_once("=>") else {
                    continue;
                };
                let (old, new) = (words(old), words(new));
                let Some(module) = old.first() else {
                    continue;
                };
                let target = match new.as_slice() {
                    [path, version] if !path.starts_with(['.', '/']) => Some((path.clone(), version.clone())),
                    _ => None,
                };
                replaces.push(GoReplace {
                    module: module.clone(),
                    version: old.get(1).cloned(),
                    target,
                });
            }
            GoDirective::Other => {}
        }
    }

    required
        .into_iter()
        .filter_map(|(module, version)| {
            // A replacement for one version takes precedence over one for all.
            let replace = replaces
                .iter()
                .find(|r| r.module == module && r.version.as_deref() == Some(version.as_str()))
                .or_else(|| replaces.iter().find(|r| r.module == module && r.version.is_none()));
            let (module, version) = match replace {
                // Replaced by a local directory: not a published module.
                Some(GoReplace { target: None, .. }) => return None,
                Some(GoReplace {
                    target: Some(target), ..
                }) => target.clone(),
                None => (module, version),
            };
            // OSV stores Go versions without the leading `v`.
            Package::new("Go", &module, version.strip_prefix('v').unwrap_or(&version))
        })
        .collect()
}

// ---- Discovery ----

/// Directories that are never entered: dependencies and build output. Their
/// lockfiles belong to other people's packages, not to the user's projects.
const SKIP_DIRS: [&str; 16] = [
    "node_modules",
    "target",
    "vendor",
    "Pods",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    "DerivedData",
    "site-packages",
    "bower_components",
    "Carthage",
    "testdata",
    "fixtures",
    "tmp",
];

/// Finds lockfiles under the home directory, skipping large folders that
/// hold no projects.
pub fn default_files() -> Vec<PathBuf> {
    let Some(home) = crate::home::dir() else {
        return Vec::new();
    };
    const SKIP_TOP: [&str; 7] = ["Library", "Applications", "Music", "Movies", "Pictures", "Public", "go"];
    find(&home, &SKIP_TOP)
}

/// A user-supplied path: the file itself, or the lockfiles below a directory.
pub fn files_under(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    find(path, &[])
}

fn find(base: &Path, skip_top: &[&str]) -> Vec<PathBuf> {
    /// Deep enough to reach monorepo sub-packages when starting from the home directory.
    const MAX_DEPTH: usize = 9;

    fn visit(dir: &Path, depth: usize, skip: &[&str], found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            // `file_type` does not follow symbolic links, so they are skipped.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if kind.is_file() {
                if is_lockfile(&name) {
                    found.push(entry.path());
                }
            } else if kind.is_dir()
                && depth < MAX_DEPTH
                && !name.starts_with('.')
                && !SKIP_DIRS.contains(&name.as_ref())
                && !skip.contains(&name.as_ref())
            {
                // The skip list only applies to the top level.
                visit(&entry.path(), depth + 1, &[], found);
            }
        }
    }

    let mut found = Vec::new();
    visit(base, 0, skip_top, &mut found);
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(packages: &[Package]) -> Vec<String> {
        let mut names: Vec<String> = packages
            .iter()
            .map(|p| format!("{}:{}@{}", p.ecosystem, p.name, p.version))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn cargo_lock_keeps_only_registry_crates() {
        let text = r#"
            [[package]]
            name = "serde"
            version = "1.0.200"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "my-app"
            version = "0.1.0"

            [[package]]
            name = "forked"
            version = "0.3.0"
            source = "git+https://github.com/someone/forked#abc"

            [[package]]
            name = "company-internal"
            version = "2.0.0"
            source = "registry+https://cargo.example.com/index"

            [[package]]
            name = "company-sparse"
            version = "2.0.0"
            source = "sparse+https://cargo.example.com/index/"
        "#;
        assert_eq!(names(&cargo_lock(text)), ["crates.io:serde@1.0.200"]);
        assert!(cargo_lock("not toml [").is_empty());
    }

    #[test]
    fn package_lock_v3_uses_install_paths() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
                "node_modules/@scope/pkg": {"version": "2.0.0", "resolved": "https://npm.example.com/api/npm/repo/@scope/pkg/-/pkg-2.0.0.tgz"},
                "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
                "node_modules/alias": {"name": "real-name", "version": "1.1.0"},
                "node_modules/bundled": {"version": "1.0.0", "inBundle": true},
                "node_modules/workspace-pkg": {"resolved": "packages/x", "link": true},
                "packages/x": {"name": "workspace-pkg", "version": "0.0.1"}
            }
        }"#;
        assert_eq!(
            names(&package_lock(text)),
            [
                "npm:@scope/pkg@2.0.0",
                "npm:bundled@1.0.0",
                "npm:lodash@3.10.1",
                "npm:lodash@4.17.15",
                "npm:real-name@1.1.0"
            ]
        );
    }

    #[test]
    fn package_lock_v3_skips_non_registry_packages() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/ok": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz"},
                "node_modules/from-git": {"version": "1.2.3", "resolved": "git+ssh://git@github.com/acme/private.git#0123abc"},
                "node_modules/from-github-tarball": {"version": "1.2.3", "resolved": "https://codeload.github.com/acme/private/tar.gz/0123abc"},
                "node_modules/from-file": {"version": "1.2.3", "resolved": "file:../vendor/from-file-1.2.3.tgz"},
                "node_modules/from-url": {"version": "1.2.3", "resolved": "https://example.com/builds/from-url.tgz"},
                "node_modules/linked": {"resolved": "packages/linked", "link": true},
                "node_modules/local-dir": {"version": "1.2.3", "resolved": "../local-dir"},
                "node_modules/git-version": {"version": "git+https://github.com/acme/private.git#0123abc"},
                "packages/linked": {"name": "linked", "version": "0.0.1"}
            }
        }"#;
        assert_eq!(names(&package_lock(text)), ["npm:ok@1.0.0"]);
    }

    #[test]
    fn package_lock_v1_walks_nested_dependencies() {
        let text = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
                "from-git": {"version": "github:someone/repo#abc"}
            }
        }"#;
        assert_eq!(names(&package_lock(text)), ["npm:a@1.0.0", "npm:b@2.0.0"]);
    }

    #[test]
    fn package_lock_v1_skips_non_registry_versions_and_follows_aliases() {
        let text = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "ok": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz"},
                "alias": {"version": "npm:@scope/real@3.2.1", "resolved": "https://registry.npmjs.org/@scope/real/-/real-3.2.1.tgz"},
                "git-ssh": {"version": "git+ssh://git@github.com/acme/private.git#0123abc"},
                "git-https": {"version": "git+https://github.com/acme/private.git#0123abc"},
                "url": {"version": "https://example.com/builds/url-1.0.0.tgz"},
                "file": {"version": "file:../file"},
                "git-resolved": {"version": "1.0.0", "resolved": "git+https://github.com/acme/private.git#0123abc"}
            }
        }"#;
        assert_eq!(names(&package_lock(text)), ["npm:@scope/real@3.2.1", "npm:ok@1.0.0"]);
    }

    #[test]
    fn registry_tarballs_are_told_apart_from_other_urls() {
        for url in [
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz#abcdef",
            "https://example.jfrog.io/artifactory/api/npm/npm/lodash/-/lodash-4.17.21.tgz",
            "http://localhost:4873/lodash/-/lodash-4.17.21.tgz",
            "https://registry.npm.taobao.org/lodash/download/lodash-4.17.21.tgz?cache=0",
            "https://npm.pkg.github.com/download/@acme/pkg/1.0.0/0123abc",
        ] {
            assert!(is_registry_tarball(url), "{url}");
        }
        for url in [
            "git+ssh://git@github.com/acme/repo.git#0123abc",
            "git+https://github.com/acme/repo.git#0123abc",
            "https://codeload.github.com/acme/repo/tar.gz/0123abc",
            "https://github.com/acme/repo/releases/download/v1/repo.tgz",
            "https://gitlab.com/acme/repo/-/archive/main/repo-main.tar.gz",
            "https://example.com/repo.tgz",
            "file:../repo-1.0.0.tgz",
            "../repo",
            "",
        ] {
            assert!(!is_registry_tarball(url), "{url}");
        }
    }

    #[test]
    fn yarn_lock_classic_and_berry() {
        let classic = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.24.0\"\n  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz#abc\"\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n";
        assert_eq!(
            names(&yarn_lock(classic)),
            ["npm:@babel/core@7.24.0", "npm:lodash@4.17.21"]
        );

        let berry = "__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n";
        assert_eq!(names(&yarn_lock(berry)), ["npm:lodash@4.17.21"]);
    }

    #[test]
    fn yarn_berry_aliases_patches_and_workspaces() {
        let berry = concat!(
            "__metadata:\n  version: 8\n  cacheKey: 10\n\n",
            "\"string-width-cjs@npm:string-width@^4.2.0\":\n  version: 4.2.3\n  resolution: \"string-width@npm:4.2.3\"\n",
            "  dependencies:\n    version: \"npm:^9.9.9\"\n    emoji-regex: \"npm:^8.0.0\"\n  checksum: abc\n  languageName: node\n  linkType: hard\n\n",
            "\"scoped-alias@npm:@scope/real@^1.0.0, scoped-alias@npm:@scope/real@^1.1.0\":\n  version: 1.2.0\n  resolution: \"@scope/real@npm:1.2.0\"\n\n",
            "\"resolve@patch:resolve@npm%3A^1.22.4#optional!builtin<compat/resolve>\":\n  version: 1.22.8\n",
            "  resolution: \"resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d\"\n\n",
            "\"resolve@npm:^1.22.4\":\n  version: 1.22.8\n  resolution: \"resolve@npm:1.22.8\"\n\n",
            "\"my-app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"my-app@workspace:.\"\n\n",
            "\"@acme/ui@workspace:packages/ui\":\n  version: 0.0.0-use.local\n  resolution: \"@acme/ui@workspace:packages/ui\"\n\n",
            "\"linked@link:../linked::locator=my-app%40workspace%3A.\":\n  version: 0.0.0-use.local\n  resolution: \"linked@link:../linked::locator=my-app%40workspace%3A.\"\n\n",
            "\"portal@portal:../portal::locator=my-app%40workspace%3A.\":\n  version: 1.0.0\n  resolution: \"portal@portal:../portal::locator=my-app%40workspace%3A.\"\n\n",
            "\"tarball@file:./tarball.tgz::locator=my-app%40workspace%3A.\":\n  version: 1.0.0\n  resolution: \"tarball@file:./tarball.tgz::locator=my-app%40workspace%3A.\"\n\n",
            "\"private@git@github.com:acme/private.git#commit=0123abc\":\n  version: 2.0.0\n  resolution: \"private@git@github.com:acme/private.git#commit=0123abc\"\n\n",
            "\"private-https@https://github.com/acme/private.git#commit=0123abc\":\n  version: 2.0.0\n  resolution: \"private-https@https://github.com/acme/private.git#commit=0123abc\"\n",
        );
        assert_eq!(
            names(&yarn_lock(berry)),
            ["npm:@scope/real@1.2.0", "npm:resolve@1.22.8", "npm:string-width@4.2.3"]
        );
    }

    #[test]
    fn yarn_classic_aliases_and_non_registry_entries() {
        let classic = concat!(
            "# yarn lockfile v1\n\n",
            "\"string-width-cjs@npm:string-width@^4.2.0\":\n  version \"4.2.3\"\n  resolved \"https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz#269c\"\n",
            "  dependencies:\n    version \"^9.9.9\"\n\n",
            "\"scoped-alias@npm:@scope/real@^1.0.0\":\n  version \"1.2.0\"\n  resolved \"https://registry.yarnpkg.com/@scope/real/-/real-1.2.0.tgz#abc\"\n\n",
            "bare-alias@npm:real-bare:\n  version \"3.0.0\"\n  resolved \"https://registry.yarnpkg.com/real-bare/-/real-bare-3.0.0.tgz#abc\"\n\n",
            "\"from-git@git+ssh://git@github.com/acme/private.git\":\n  version \"1.0.0\"\n  resolved \"git+ssh://git@github.com/acme/private.git#0123abc\"\n\n",
            "\"from-github@acme/private\":\n  version \"1.0.0\"\n  resolved \"https://codeload.github.com/acme/private/tar.gz/0123abc\"\n\n",
            "\"from-file@file:../from-file\":\n  version \"1.0.0\"\n\n",
            "\"from-link@link:../from-link\":\n  version \"0.0.0\"\n\n",
            "\"from-url@https://example.com/from-url.tgz\":\n  version \"1.0.0\"\n  resolved \"https://example.com/from-url.tgz#abc\"\n\n",
            "\"@scope/plain@>=1.0.0 <2.0.0\":\n  version \"1.5.0\"\n  resolved \"https://registry.yarnpkg.com/@scope/plain/-/plain-1.5.0.tgz#abc\"\n",
        );
        assert_eq!(
            names(&yarn_lock(classic)),
            [
                "npm:@scope/plain@1.5.0",
                "npm:@scope/real@1.2.0",
                "npm:real-bare@3.0.0",
                "npm:string-width@4.2.3"
            ]
        );
    }

    #[test]
    fn split_spec_cuts_after_the_name() {
        assert_eq!(split_spec("lodash@^4.17.0"), Some(("lodash", "^4.17.0")));
        assert_eq!(split_spec("@babel/core@^7.0.0"), Some(("@babel/core", "^7.0.0")));
        assert_eq!(
            split_spec("string-width-cjs@npm:string-width@^4.2.0"),
            Some(("string-width-cjs", "npm:string-width@^4.2.0"))
        );
        assert_eq!(
            split_spec("resolve@patch:resolve@npm%3A^1.22.4#builtin"),
            Some(("resolve", "patch:resolve@npm%3A^1.22.4#builtin"))
        );
        assert_eq!(split_spec("@scope/only"), None);
        assert_eq!(split_spec("__metadata"), None);
    }

    #[test]
    fn pnpm_lock_handles_all_key_styles() {
        let text = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies: {}\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: x}\n\n  '@scope/pkg@2.0.0':\n    resolution: {integrity: x}\n\n  /old-style/1.2.3:\n    dev: false\n\n  /mid-style@3.0.0(react@18.2.0):\n    dev: false\n\nsnapshots:\n\n  ignored@9.9.9: {}\n";
        assert_eq!(
            names(&pnpm_lock(text)),
            [
                "npm:@scope/pkg@2.0.0",
                "npm:lodash@4.17.21",
                "npm:mid-style@3.0.0",
                "npm:old-style@1.2.3"
            ]
        );
    }

    #[test]
    fn pnpm_keys_of_every_lockfile_version() {
        let key = |key: &str| pnpm_key(key).map(|p| format!("{}@{}", p.name, p.version));
        // v5: `/name/version`, peers after an underscore.
        assert_eq!(key("/foo/1.2.3").as_deref(), Some("foo@1.2.3"));
        assert_eq!(key("/@scope/foo/1.2.3").as_deref(), Some("@scope/foo@1.2.3"));
        assert_eq!(key("/foo/1.2.3_react@17.0.2").as_deref(), Some("foo@1.2.3"));
        assert_eq!(
            key("/foo/1.2.3_react-dom@17.0.2+react@17.0.2").as_deref(),
            Some("foo@1.2.3")
        );
        assert_eq!(key("/foo/1.2.3_a1b2c3d4e5").as_deref(), Some("foo@1.2.3"));
        assert_eq!(
            key("/@emotion/styled/11.3.0_@emotion+react@11.4.0").as_deref(),
            Some("@emotion/styled@11.3.0")
        );
        assert_eq!(
            key("/foo/1.0.0-beta.1_react@17.0.2").as_deref(),
            Some("foo@1.0.0-beta.1")
        );
        // v6: `/name@version`, peers in parentheses.
        assert_eq!(key("/foo@1.2.3").as_deref(), Some("foo@1.2.3"));
        assert_eq!(key("/foo@1.2.3(react@18.0.0)").as_deref(), Some("foo@1.2.3"));
        assert_eq!(
            key("/@scope/foo@1.2.3(@types/react@18.0.0)(react@18.0.0)").as_deref(),
            Some("@scope/foo@1.2.3")
        );
        // v9: no leading slash.
        assert_eq!(key("foo@1.2.3").as_deref(), Some("foo@1.2.3"));
        assert_eq!(key("@scope/foo@1.2.3").as_deref(), Some("@scope/foo@1.2.3"));
        assert_eq!(key("foo@1.2.3(react@18.0.0)").as_deref(), Some("foo@1.2.3"));
        // Not from a registry.
        for other in [
            "github.com/acme/private/0123abc",
            "github.com/acme/private/1a2b3c4d",
            "file:packages/local",
            "local@file:packages/local",
            "local@link:../local",
            "private@https://codeload.github.com/acme/private/tar.gz/0123abc",
            "private@git+https://github.com/acme/private.git#0123abc",
            "@scope",
            "foo",
        ] {
            assert_eq!(key(other), None, "{other}");
        }

        let v5 = "lockfileVersion: 5.4\n\npackages:\n\n  /foo/1.2.3_react@17.0.2:\n    dev: false\n\n  /@emotion/styled/11.3.0_@emotion+react@11.4.0:\n    dev: false\n\n  github.com/acme/private/1a2b3c4d:\n    dev: false\n";
        assert_eq!(names(&pnpm_lock(v5)), ["npm:@emotion/styled@11.3.0", "npm:foo@1.2.3"]);
    }

    #[test]
    fn python_lockfiles() {
        let requirements = "# comment\nrequests[socks]==2.31.0 ; python_version >= '3.8' \\\n    --hash=sha256:abc\nflask>=2.0\n-r other.txt\nDjango==4.2.1  # pinned\n";
        assert_eq!(
            names(&requirements_txt(requirements)),
            ["PyPI:django@4.2.1", "PyPI:requests@2.31.0"]
        );

        let uv = r#"
            [[package]]
            name = "my-project"
            version = "0.1.0"
            source = { virtual = "." }

            [[package]]
            name = "idna"
            version = "3.6"
            source = { registry = "https://pypi.org/simple" }
        "#;
        assert_eq!(names(&python_toml_lock(uv)), ["PyPI:idna@3.6"]);

        let pipfile = r#"{"default": {"jinja2": {"version": "==3.1.2"}}, "develop": {"pytest": {"version": "==8.0.0"}, "local": {"path": "."}}}"#;
        assert_eq!(
            names(&pipfile_lock(pipfile)),
            ["PyPI:jinja2@3.1.2", "PyPI:pytest@8.0.0"]
        );
    }

    #[test]
    fn requirements_name_the_files_they_include() {
        let text = "\
-r base.txt
-rcompact.txt
--requirement spaced.txt  # a comment
--requirement=equals.txt
-r \"quoted name.txt\"
-r ../up.txt
-r \\
    continued.txt
--requirements wrong-option.txt
-r https://example.com/remote.txt
-r /etc/absolute.txt
-r requirements.in
-c constraints.txt
-e .
# -r commented.txt
django==3.2.0
";
        let includes = requirement_includes(text, Path::new("/p/app/requirements.txt"));
        let expected: Vec<PathBuf> = [
            "base.txt",
            "compact.txt",
            "spaced.txt",
            "equals.txt",
            "quoted name.txt",
            "../up.txt",
            "continued.txt",
        ]
        .iter()
        .map(|name| Path::new("/p/app").join(name))
        .collect();
        assert_eq!(includes, expected);
        // The pins of the same file are unaffected.
        assert_eq!(names(&requirements_txt(text)), ["PyPI:django@3.2.0"]);
        assert!(requirement_includes("-r base.txt\n", Path::new("requirements.txt")) == [PathBuf::from("base.txt")]);
    }

    #[test]
    fn included_requirements_are_read_whatever_their_name() {
        let dir = std::env::temp_dir().join(format!("swordcheck-included-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("requirements")).unwrap();
        let base = dir.join("requirements/base.txt");
        std::fs::write(&base, "-r common.txt\ndjango==3.2.0\n").unwrap();
        let top = dir.join("requirements.txt");
        std::fs::write(&top, "-r requirements/base.txt\n").unwrap();
        let lock = dir.join("package-lock.json");
        std::fs::write(&lock, r#"{"lockfileVersion":3,"packages":{}}"#).unwrap();

        let included = parse_included(&base);
        let top = parse_file(&top);
        let lock = parse_file(&lock);
        let missing = parse_included(&dir.join("requirements/missing.txt"));
        let _ = std::fs::remove_dir_all(&dir);

        // `base.txt` is no lockfile name, but a file pulled in with `-r` is read.
        assert_eq!(parse_file(&base).ok().flatten().map(|_| ()), None);
        let included = included.unwrap();
        assert_eq!(
            names(&included.packages.into_iter().collect::<Vec<_>>()),
            ["PyPI:django@3.2.0"]
        );
        assert_eq!(included.includes, [dir.join("requirements/common.txt")]);
        let top = top.unwrap().unwrap();
        assert!(top.packages.is_empty());
        assert_eq!(top.includes, [dir.join("requirements/base.txt")]);
        assert!(
            lock.unwrap().unwrap().includes.is_empty(),
            "only requirements files include others"
        );
        assert_eq!(missing.err(), Some("could not be read"));
    }

    #[test]
    fn requirements_accept_exact_pins_only() {
        let text = concat!(
            "foo===1.2.3\n",
            "bar==1.*\n",
            "baz == 2.0.0\n",
            "extras[one, two]==1.0\n",
            "spaced [one] == 1.1\n",
            "marker==3.0; python_version < \"3.9\" and sys_platform == \"darwin\"\n",
            "commented==4.0 # why\n",
            "#disabled==9.9.9\n",
            "hashed==5.0 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\n",
            "inline-hash==5.1 --hash=sha256:ccc\n",
            "epoch==1!2.0+local.1\n",
            "ranged>=1.0,==1.5\n",
            "two-clauses==1.0,!=1.1\n",
            "compatible~=1.4\n",
            "not-equal!=1.4\n",
            "at-least>=1.4\n",
            "at-most<=1.4\n",
            "unpinned\n",
            "direct @ https://example.com/direct-1.0.tar.gz#sha256=abc==\n",
            "-e git+https://github.com/acme/private.git@v1.0#egg=private==1.0\n",
            "--index-url https://pypi.example.com/simple\n",
            "git+https://github.com/acme/private.git@main#egg=private\n",
            "./local/pkg==1.0\n",
            "last==6.0 \\",
        );
        assert_eq!(
            names(&requirements_txt(text)),
            [
                "PyPI:baz@2.0.0",
                "PyPI:commented@4.0",
                "PyPI:epoch@1!2.0+local.1",
                "PyPI:extras@1.0",
                "PyPI:foo@1.2.3",
                "PyPI:hashed@5.0",
                "PyPI:inline-hash@5.1",
                "PyPI:last@6.0",
                "PyPI:marker@3.0",
                "PyPI:spaced@1.1",
            ]
        );
    }

    #[test]
    fn pypi_names_are_normalised_in_every_python_parser() {
        assert_eq!(pypi_name("Flask_SQLAlchemy"), "flask-sqlalchemy");
        assert_eq!(pypi_name("zope.interface"), "zope-interface");
        assert_eq!(pypi_name("A-_.b__C"), "a-b-c");
        assert_eq!(pypi_name("requests"), "requests");

        let expected = ["PyPI:flask-sqlalchemy@3.1.1", "PyPI:zope-interface@6.1"];
        assert_eq!(
            names(&requirements_txt("Flask_SQLAlchemy==3.1.1\nzope.interface==6.1\n")),
            expected
        );
        let toml = "[[package]]\nname = \"Flask-SQLAlchemy\"\nversion = \"3.1.1\"\n\n[[package]]\nname = \"zope.interface\"\nversion = \"6.1\"\n";
        assert_eq!(names(&python_toml_lock(toml)), expected);
        let pipfile =
            r#"{"default": {"flask_sqlalchemy": {"version": "==3.1.1"}, "Zope.Interface": {"version": "==6.1"}}}"#;
        assert_eq!(names(&pipfile_lock(pipfile)), expected);

        // The same project from two lockfiles is one entry.
        let mut all = BTreeSet::new();
        all.extend(requirements_txt("Flask_SQLAlchemy==3.1.1\n"));
        all.extend(python_toml_lock(
            "[[package]]\nname = \"flask-sqlalchemy\"\nversion = \"3.1.1\"\n",
        ));
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn poetry_lock_skips_git_path_and_url_sources() {
        let text = r#"
            [[package]]
            name = "requests"
            version = "2.31.0"
            description = "Python HTTP for Humans."

            [[package]]
            name = "from-mirror"
            version = "1.0.0"

            [package.source]
            type = "legacy"
            url = "https://pypi.example.com/simple"
            reference = "mirror"

            [[package]]
            name = "from-git"
            version = "0.1.0"

            [package.source]
            type = "git"
            url = "https://github.com/acme/private.git"
            reference = "main"
            resolved_reference = "0123abc"

            [[package]]
            name = "from-directory"
            version = "0.1.0"

            [package.source]
            type = "directory"
            url = "../from-directory"

            [[package]]
            name = "from-file"
            version = "0.1.0"

            [package.source]
            type = "file"
            url = "vendor/from_file-0.1.0-py3-none-any.whl"

            [[package]]
            name = "from-url"
            version = "0.1.0"

            [package.source]
            type = "url"
            url = "https://example.com/from_url-0.1.0.tar.gz"
        "#;
        assert_eq!(
            names(&python_toml_lock(text)),
            ["PyPI:from-mirror@1.0.0", "PyPI:requests@2.31.0"]
        );
    }

    #[test]
    fn uv_lock_keeps_only_registry_sources() {
        let text = r#"
            version = 1

            [[package]]
            name = "idna"
            version = "3.6"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "my-project"
            version = "0.1.0"
            source = { editable = "." }

            [[package]]
            name = "from-git"
            version = "0.1.0"
            source = { git = "https://github.com/acme/private.git?rev=main#0123abc" }

            [[package]]
            name = "from-path"
            version = "0.1.0"
            source = { path = "vendor/from_path-0.1.0.tar.gz" }

            [[package]]
            name = "from-directory"
            version = "0.1.0"
            source = { directory = "../from-directory" }

            [[package]]
            name = "from-url"
            version = "0.1.0"
            source = { url = "https://example.com/from_url-0.1.0.tar.gz" }

            [[package]]
            name = "from-flat-index"
            version = "0.1.0"
            source = { registry = "../wheels" }
        "#;
        assert_eq!(names(&python_toml_lock(text)), ["PyPI:idna@3.6"]);
    }

    #[test]
    fn pipfile_lock_skips_git_and_local_entries() {
        let text = r#"{"default": {
            "jinja2": {"version": "==3.1.2"},
            "from-git": {"git": "https://github.com/acme/private.git", "ref": "0123abc", "version": "==1.0.0"},
            "from-file": {"file": "https://example.com/from_file-1.0.tar.gz", "version": "==1.0.0"},
            "from-path": {"path": "./vendor/from-path", "version": "==1.0.0"},
            "wildcard": {"version": "==1.*"},
            "unpinned": {"version": "*"}
        }}"#;
        assert_eq!(names(&pipfile_lock(text)), ["PyPI:jinja2@3.1.2"]);
    }

    #[test]
    fn php_ruby_and_go_lockfiles() {
        let composer = r#"{"packages": [{"name": "laravel/framework", "version": "v10.0.0"}, {"name": "x/dev", "version": "dev-main"}, {"name": "x/branch", "version": "2.x-dev"}, {"name": "acme/local", "version": "1.0.0", "dist": {"type": "path", "url": "../local"}}], "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.1", "dist": {"type": "zip", "url": "https://api.github.com/repos/sebastianbergmann/phpunit/zipball/abc"}}]}"#;
        assert_eq!(
            names(&composer_lock(composer)),
            ["Packagist:laravel/framework@10.0.0", "Packagist:phpunit/phpunit@10.5.1"]
        );

        let gemfile = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n    nokogiri (1.16.0-arm64-darwin)\n\nPLATFORMS\n  ruby\n";
        assert_eq!(
            names(&gemfile_lock(gemfile)),
            ["RubyGems:nokogiri@1.16.0", "RubyGems:rails@7.0.4"]
        );

        let go = "module example.com/app\n\ngo 1.22\n\nrequire github.com/a/b v1.2.3\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/c/d v0.0.0-20230101000000-abcdef123456\n)\n";
        assert_eq!(
            names(&go_mod(go)),
            [
                "Go:github.com/a/b@1.2.3",
                "Go:github.com/c/d@0.0.0-20230101000000-abcdef123456",
                "Go:golang.org/x/net@0.17.0"
            ]
        );
    }

    #[test]
    fn gemfile_lock_counts_only_gem_sections() {
        let text = concat!(
            "GIT\n  remote: https://github.com/acme/private-gem.git\n  revision: 0123abc\n  branch: main\n  specs:\n",
            "    private-gem (1.0.0)\n      rack (>= 2.0)\n\n",
            "PATH\n  remote: engines/billing\n  specs:\n    billing (0.1.0)\n      rails (>= 7.0)\n\n",
            "PATH\n  remote: .\n  specs:\n    my-app (2.0.0)\n\n",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.8)\n    rails (7.0.4)\n      rack (>= 2.0)\n\n",
            "GEM\n  specs:\n    no-remote (1.0.0)\n\n",
            "PLATFORMS\n  arm64-darwin-23\n\n",
            "DEPENDENCIES\n  billing!\n  private-gem!\n  rails (~> 7.0)\n\n",
            "CHECKSUMS\n  rack (3.0.8) sha256=abc\n\n",
            "BUNDLED WITH\n   2.5.6\n",
        );
        assert_eq!(
            names(&gemfile_lock(text)),
            ["RubyGems:rack@3.0.8", "RubyGems:rails@7.0.4"]
        );
    }

    #[test]
    fn go_mod_applies_replace_directives() {
        let text = concat!(
            "module example.com/app\n\ngo 1.22\n\n",
            "require(\n",
            "\tgithub.com/kept/mod v1.0.0\n",
            "\tgithub.com/old/all v1.1.0 // indirect\n",
            "\tgithub.com/old/pinned v1.2.0\n",
            "\tgithub.com/old/other-version v1.3.0\n",
            "\tgithub.com/local/dir v1.4.0\n",
            "\tgithub.com/local/abs v1.5.0\n",
            "\tgithub.com/single/line v1.6.0\n",
            "\tgithub.com/both/kinds v1.7.0\n",
            ")\n\n",
            "require \"github.com/quoted/mod\" v1.8.0\n\n",
            "exclude github.com/kept/mod v0.9.0\n",
            "retract (\n\tv0.1.0 // broken\n)\n\n",
            "replace github.com/single/line => github.com/fork/line v1.6.1\n\n",
            "replace(\n",
            "\tgithub.com/old/all => github.com/new/all v2.0.0+incompatible\n",
            "\tgithub.com/old/pinned v1.2.0 => github.com/new/pinned v1.2.1 // security fix\n",
            "\tgithub.com/old/other-version v0.0.1 => github.com/new/unused v9.9.9\n",
            "\tgithub.com/local/dir => ../dir\n",
            "\tgithub.com/local/abs v1.5.0 => /src/abs\n",
            "\tgithub.com/both/kinds => ./kinds\n",
            "\tgithub.com/both/kinds v1.7.0 => github.com/fork/kinds v1.7.5\n",
            "\tgithub.com/not/required => github.com/new/not-required v1.0.0\n",
            ")\n",
        );
        assert_eq!(
            names(&go_mod(text)),
            [
                "Go:github.com/fork/kinds@1.7.5",
                "Go:github.com/fork/line@1.6.1",
                "Go:github.com/kept/mod@1.0.0",
                "Go:github.com/new/all@2.0.0+incompatible",
                "Go:github.com/new/pinned@1.2.1",
                "Go:github.com/old/other-version@1.3.0",
                "Go:github.com/quoted/mod@1.8.0",
            ]
        );

        // A replacement can pin the same module to another version.
        let same = "require example.com/m v1.0.0\nreplace example.com/m => example.com/m v1.0.1\n";
        assert_eq!(names(&go_mod(same)), ["Go:example.com/m@1.0.1"]);
        // A single-line local replacement drops the module.
        let local = "require (\n\texample.com/m v1.0.0\n)\nreplace example.com/m v1.0.0 => ../m\n";
        assert!(go_mod(local).is_empty());
    }

    #[test]
    fn lockfile_names_are_recognized() {
        for name in [
            "Cargo.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "requirements-dev.txt",
            "go.mod",
        ] {
            assert!(is_lockfile(name), "{name}");
        }
        for name in ["Cargo.toml", "package.json", "notes.txt", "requirements.in"] {
            assert!(!is_lockfile(name), "{name}");
        }
    }

    #[test]
    fn byte_order_marks_lose_no_packages() {
        let text = "requests==2.19.0\r\nDjango==3.2.0\r\n";
        let expected = ["PyPI:django@3.2.0", "PyPI:requests@2.19.0"];
        let utf16 = |unit: fn(u16) -> [u8; 2], bom: [u8; 2]| {
            let mut bytes = bom.to_vec();
            bytes.extend(text.encode_utf16().flat_map(unit));
            bytes
        };
        for bytes in [
            text.as_bytes().to_vec(),
            [b"\xEF\xBB\xBF".as_slice(), text.as_bytes()].concat(),
            utf16(u16::to_le_bytes, [0xFF, 0xFE]),
            utf16(u16::to_be_bytes, [0xFE, 0xFF]),
        ] {
            let decoded = decode(bytes).expect("decodes");
            assert_eq!(names(&requirements_txt(&decoded)), expected);
        }
        let lock = "\u{feff}{\"packages\": {\"node_modules/lodash\": {\"version\": \"4.17.15\"}}}";
        let decoded = decode(lock.as_bytes().to_vec()).expect("decodes");
        assert_eq!(names(&package_lock(&decoded)), ["npm:lodash@4.17.15"]);
        // Odd-length UTF-16 and invalid UTF-8 still yield nothing.
        assert_eq!(decode(vec![0xFF, 0xFE, b'a']), None);
        assert_eq!(decode(vec![b'a', 0xFF]), None);
    }

    #[test]
    fn parse_file_reads_a_file_with_a_byte_order_mark() {
        let dir = std::env::temp_dir().join(format!("swordcheck-lockfiles-bom-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requirements.txt");
        std::fs::write(&path, "\u{feff}requests==2.19.0\n").unwrap();
        let lockfile = parse_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
        let packages: Vec<Package> = lockfile
            .expect("readable")
            .expect("a lockfile")
            .packages
            .into_iter()
            .collect();
        assert_eq!(names(&packages), ["PyPI:requests@2.19.0"]);
    }

    #[test]
    fn parse_file_says_why_a_lockfile_could_not_be_used() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("swordcheck-lockfiles-unreadable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("folder/package-lock.json")).unwrap();
        let file = |name: &str, contents: &[u8]| {
            let path = dir.join(name);
            std::fs::write(&path, contents).unwrap();
            path
        };
        let locked = file("Gemfile.lock", b"GEM\n");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let big = file("requirements.txt", b"");
        std::fs::File::options()
            .write(true)
            .open(&big)
            .unwrap()
            .set_len(MAX_BYTES + 1)
            .unwrap();
        let latin1 = file("poetry.lock", b"# caf\xe9\n");
        let notes = file("notes.txt", b"not a lockfile");

        let reason = |path: &Path| parse_file(path).err();
        let results = [
            reason(&locked),
            reason(&big),
            reason(&latin1),
            reason(&dir.join("folder/package-lock.json")),
            reason(&dir.join("missing/yarn.lock")),
        ];
        let not_a_lockfile = parse_file(&notes);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            results,
            [
                Some("permission denied"),
                Some("over 64 MB"),
                Some("not UTF-8 or UTF-16 text"),
                Some("could not be read"),
                Some("could not be read"),
            ]
        );
        assert!(
            matches!(not_a_lockfile, Ok(None)),
            "an unknown file name is not a lockfile"
        );
    }
}
