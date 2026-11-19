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
        Some(Self { ecosystem, name: name.to_string(), version: version.to_string() })
    }
}

/// A parsed lockfile.
#[derive(Debug)]
pub struct Lockfile {
    pub path: PathBuf,
    pub packages: BTreeSet<Package>,
}

/// Lockfiles larger than this are not read.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Reads and parses a lockfile. Returns `None` if the file name is not a
/// known lockfile or the file cannot be read.
pub fn parse_file(path: &Path) -> Option<Lockfile> {
    let name = path.file_name()?.to_str()?;
    let parser = parser_for(name)?;
    if std::fs::metadata(path).ok()?.len() > MAX_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    Some(Lockfile { path: path.to_path_buf(), packages: parser(&text).into_iter().collect() })
}

/// Picks the parser for a file name. Function pointers (`fn(&str) -> …`) let
/// us return "which function to call" as a plain value.
fn parser_for(file_name: &str) -> Option<fn(&str) -> Vec<Package>> {
    Some(match file_name {
        "Cargo.lock" => cargo_lock,
        "package-lock.json" | "npm-shrinkwrap.json" => package_lock,
        "yarn.lock" => yarn_lock,
        "pnpm-lock.yaml" => pnpm_lock,
        "poetry.lock" => |text| python_toml_lock(text, false),
        "uv.lock" => |text| python_toml_lock(text, true),
        "Pipfile.lock" => pipfile_lock,
        "composer.lock" => composer_lock,
        "Gemfile.lock" => gemfile_lock,
        "go.mod" => go_mod,
        name if name.starts_with("requirements") && name.ends_with(".txt") => requirements_txt,
        _ => return None,
    })
}

pub fn is_lockfile(file_name: &str) -> bool {
    parser_for(file_name).is_some()
}

// ---- Rust ----

/// `Cargo.lock`: only crates from a registry; path and git dependencies have
/// no entry in a vulnerability database.
fn cargo_lock(text: &str) -> Vec<Package> {
    let Ok(lock) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    toml_packages(&lock)
        .filter(|package| {
            package.get("source").and_then(toml::Value::as_str).is_some_and(|s| s.starts_with("registry+"))
        })
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
    Package::new(ecosystem, package.get("name")?.as_str()?, package.get("version")?.as_str()?)
}

// ---- JavaScript ----

/// `package-lock.json`: lockfile v2/v3 keeps a flat `packages` map keyed by
/// install path; v1 keeps a nested `dependencies` tree.
fn package_lock(text: &str) -> Vec<Package> {
    let Ok(lock) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut found = Vec::new();

    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (path, entry) in packages {
            // The "" key is the project itself; links point at workspace
            // packages that are listed again under their real path.
            let Some((_, name)) = path.rsplit_once("node_modules/") else {
                continue;
            };
            if entry.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let name = entry.get("name").and_then(Value::as_str).unwrap_or(name);
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                found.extend(Package::new("npm", name, version));
            }
        }
        return found;
    }

    fn walk(dependencies: &Value, found: &mut Vec<Package>) {
        let Some(dependencies) = dependencies.as_object() else {
            return;
        };
        for (name, entry) in dependencies {
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                found.extend(npm_package(name, version));
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

/// Versions that are URLs, git refs or local paths are not registry packages.
fn npm_package(name: &str, version: &str) -> Option<Package> {
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Package::new("npm", name, version)
}

/// Splits `name@range` at the last `@`, keeping the leading `@` of a scope.
fn split_spec(spec: &str) -> Option<(&str, &str)> {
    let at = spec.char_indices().skip(1).filter(|&(_, c)| c == '@').map(|(i, _)| i).last()?;
    Some((&spec[..at], &spec[at + 1..]))
}

/// `yarn.lock`, both classic (`version "1.2.3"`) and Berry (`version: 1.2.3`).
fn yarn_lock(text: &str) -> Vec<Package> {
    let mut found = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            // Header: `"a@^1", "a@^2":` — every spec names the same package.
            let first = line.trim_end_matches(':').split(',').next().unwrap_or_default();
            let first = first.trim().trim_matches('"');
            current = split_spec(first).map(|(name, _)| name.to_string());
        } else if let Some(name) = &current
            && let Some(rest) = line.trim().strip_prefix("version")
        {
            let version = rest.trim_start_matches(':').trim().trim_matches('"');
            found.extend(npm_package(name, version));
            current = None;
        }
    }
    found
}

/// `pnpm-lock.yaml`: the keys of the top-level `packages:` map. The format
/// changed across versions: `/name/1.2.3`, `/name@1.2.3`, `name@1.2.3`, each
/// optionally followed by a peer-dependency suffix.
fn pnpm_lock(text: &str) -> Vec<Package> {
    let mut found = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        // Package keys sit exactly two spaces deep.
        let Some(key) = line.strip_prefix("  ").filter(|rest| in_packages && !rest.starts_with(' ')) else {
            continue;
        };
        let key = key.trim_end().trim_end_matches(':').trim_matches(['\'', '"']).trim_start_matches('/');
        // Drop peer suffixes: `(react@18.0.0)` or `_react@18.0.0`.
        let key = key.split('(').next().unwrap_or(key);
        let (name, version) = match split_spec(key) {
            Some(parts) => parts,
            None => match key.rsplit_once('/') {
                Some(parts) => parts,
                None => continue,
            },
        };
        let version = version.split('_').next().unwrap_or(version);
        found.extend(npm_package(name, version));
    }
    found
}

// ---- Python ----

/// `poetry.lock` and `uv.lock` share the `[[package]]` layout. uv also lists
/// the project itself and local packages, which have no registry source.
fn python_toml_lock(text: &str, require_registry: bool) -> Vec<Package> {
    let Ok(lock) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    toml_packages(&lock)
        .filter(|package| {
            !require_registry
                || package.get("source").and_then(toml::Value::as_table).is_some_and(|s| s.contains_key("registry"))
        })
        .filter_map(|package| toml_package("PyPI", package))
        .collect()
}

/// `requirements*.txt`: only exact pins (`name==1.2.3`) identify a version.
fn requirements_txt(text: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|line| {
            // Strip comments, environment markers and hash continuations.
            let line = line.split('#').next()?.split(';').next()?.trim().trim_end_matches('\\');
            if line.starts_with('-') {
                return None;
            }
            let (name, version) = line.split_once("==")?;
            // `requests[socks]` → `requests`.
            let name = name.split('[').next()?;
            let version = version.split_whitespace().next()?;
            Package::new("PyPI", name, version)
        })
        .collect()
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
            let version = entry.get("version")?.as_str()?.strip_prefix("==")?;
            Package::new("PyPI", name, version)
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
            let version = entry.get("version")?.as_str()?;
            // Branch aliases such as `dev-main` are not released versions.
            let version = version.strip_prefix('v').unwrap_or(version);
            if !version.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            Package::new("Packagist", entry.get("name")?.as_str()?, version)
        })
        .collect()
}

/// `Gemfile.lock`: resolved gems are the four-space-indented `name (1.2.3)`
/// lines; deeper lines are their dependency constraints.
fn gemfile_lock(text: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|line| {
            let entry = line.strip_prefix("    ").filter(|rest| !rest.starts_with(' '))?;
            let (name, version) = entry.split_once(" (")?;
            let version = version.strip_suffix(')')?;
            // Platform suffix: `1.16.0-arm64-darwin` → `1.16.0`.
            let version = version.split('-').next()?;
            if !version.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            Package::new("RubyGems", name, version)
        })
        .collect()
}

/// `go.mod`: `require` directives, single-line or in a block.
fn go_mod(text: &str) -> Vec<Package> {
    let mut found = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        let entry = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if line == "require (" {
            in_block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest.trim()
        } else {
            continue;
        };
        let mut parts = entry.split_whitespace();
        if let (Some(module), Some(version)) = (parts.next(), parts.next()) {
            // OSV stores Go versions without the leading `v`.
            let version = version.strip_prefix('v').unwrap_or(version);
            found.extend(Package::new("Go", module, version));
        }
    }
    found
}

// ---- Discovery ----

/// Directories that are never entered: dependencies and build output. Their
/// lockfiles belong to other people's packages, not to the user's projects.
const SKIP_DIRS: [&str; 16] = [
    "node_modules", "target", "vendor", "Pods", "venv", "env", "__pycache__", "dist", "build",
    "DerivedData", "site-packages", "bower_components", "Carthage", "testdata", "fixtures", "tmp",
];

/// Finds lockfiles under the home directory, skipping large folders that
/// hold no projects.
pub fn default_files() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
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
        let mut names: Vec<String> =
            packages.iter().map(|p| format!("{}:{}@{}", p.ecosystem, p.name, p.version)).collect();
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
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/@scope/pkg": {"version": "2.0.0"},
                "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
                "node_modules/alias": {"name": "real-name", "version": "1.1.0"},
                "node_modules/workspace-pkg": {"resolved": "packages/x", "link": true},
                "packages/x": {"name": "workspace-pkg", "version": "0.0.1"}
            }
        }"#;
        assert_eq!(
            names(&package_lock(text)),
            ["npm:@scope/pkg@2.0.0", "npm:lodash@3.10.1", "npm:lodash@4.17.15", "npm:real-name@1.1.0"]
        );
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
    fn yarn_lock_classic_and_berry() {
        let classic = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.24.0\"\n  resolved \"https://x\"\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n";
        assert_eq!(names(&yarn_lock(classic)), ["npm:@babel/core@7.24.0", "npm:lodash@4.17.21"]);

        let berry = "__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n";
        assert_eq!(names(&yarn_lock(berry)), ["npm:lodash@4.17.21"]);
    }

    #[test]
    fn pnpm_lock_handles_all_key_styles() {
        let text = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies: {}\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: x}\n\n  '@scope/pkg@2.0.0':\n    resolution: {integrity: x}\n\n  /old-style/1.2.3:\n    dev: false\n\n  /mid-style@3.0.0(react@18.2.0):\n    dev: false\n\nsnapshots:\n\n  ignored@9.9.9: {}\n";
        assert_eq!(
            names(&pnpm_lock(text)),
            ["npm:@scope/pkg@2.0.0", "npm:lodash@4.17.21", "npm:mid-style@3.0.0", "npm:old-style@1.2.3"]
        );
    }

    #[test]
    fn python_lockfiles() {
        let requirements = "# comment\nrequests[socks]==2.31.0 ; python_version >= '3.8' \\\n    --hash=sha256:abc\nflask>=2.0\n-r other.txt\nDjango==4.2.1  # pinned\n";
        assert_eq!(names(&requirements_txt(requirements)), ["PyPI:Django@4.2.1", "PyPI:requests@2.31.0"]);

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
        assert_eq!(names(&python_toml_lock(uv, true)), ["PyPI:idna@3.6"]);
        assert_eq!(names(&python_toml_lock(uv, false)).len(), 2);

        let pipfile = r#"{"default": {"jinja2": {"version": "==3.1.2"}}, "develop": {"pytest": {"version": "==8.0.0"}, "local": {"path": "."}}}"#;
        assert_eq!(names(&pipfile_lock(pipfile)), ["PyPI:jinja2@3.1.2", "PyPI:pytest@8.0.0"]);
    }

    #[test]
    fn php_ruby_and_go_lockfiles() {
        let composer = r#"{"packages": [{"name": "laravel/framework", "version": "v10.0.0"}, {"name": "x/dev", "version": "dev-main"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.1"}]}"#;
        assert_eq!(
            names(&composer_lock(composer)),
            ["Packagist:laravel/framework@10.0.0", "Packagist:phpunit/phpunit@10.5.1"]
        );

        let gemfile = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n    nokogiri (1.16.0-arm64-darwin)\n\nPLATFORMS\n  ruby\n";
        assert_eq!(names(&gemfile_lock(gemfile)), ["RubyGems:nokogiri@1.16.0", "RubyGems:rails@7.0.4"]);

        let go = "module example.com/app\n\ngo 1.22\n\nrequire github.com/a/b v1.2.3\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/c/d v0.0.0-20230101000000-abcdef123456\n)\n";
        assert_eq!(
            names(&go_mod(go)),
            ["Go:github.com/a/b@1.2.3", "Go:github.com/c/d@0.0.0-20230101000000-abcdef123456", "Go:golang.org/x/net@0.17.0"]
        );
    }

    #[test]
    fn lockfile_names_are_recognized() {
        for name in ["Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements-dev.txt", "go.mod"] {
            assert!(is_lockfile(name), "{name}");
        }
        for name in ["Cargo.toml", "package.json", "notes.txt", "requirements.in"] {
            assert!(!is_lockfile(name), "{name}");
        }
    }
}
