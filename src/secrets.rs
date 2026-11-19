//! Secret scan (`--secrets`): which API key lives where on this machine?
//!
//! On developer machines, secrets end up scattered across `.env` files, shell
//! history and tool configurations. This module finds those files, scans them
//! with provider-specific regular expressions (`RULES`) and produces a
//! "which provider → which files" summary.
//!
//! Three kinds of signals are searched for:
//! 1. **Provider patterns**: keys with a known prefix (`sk-ant-…`, `AKIA…`,
//!    `ghp_…`). These findings are close to certain.
//! 2. **Generic assignments**: variables whose name contains `SECRET`, `TOKEN`,
//!    `PASSWORD` or `API_KEY`. Reported if the value looks random enough
//!    (heuristic).
//! 3. **Unencrypted private keys**: PEM / OpenSSH keys without a passphrase.
//!
//! Safety rules:
//! - The scan is read-only and never touches the network.
//! - The raw secret value is never written to any output; reports contain only
//!   the masked form (`sk-ant-api0…a3F9`). The raw value is kept in memory only
//!   to match copies of the same secret across different files.

use colored::Colorize;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

// ---- Rules ----

/// A provider's key pattern. If the pattern has a capture group, the secret
/// is group 1; otherwise it is the whole match.
struct Rule {
    id: &'static str,
    provider: &'static str,
    pattern: &'static str,
    /// If set, the rule only runs on files whose name contains this fragment.
    file_hint: Option<&'static str>,
}

const fn rule(id: &'static str, provider: &'static str, pattern: &'static str) -> Rule {
    Rule { id, provider, pattern, file_hint: None }
}

const PRIVATE_KEY: &str = "private-key";
const GENERIC: &str = "generic";
const URL_PASSWORD: &str = "url-password";

/// Order matters: a piece of text is claimed by the first rule that matches it.
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
        "Private key (unencrypted)",
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
        provider: "netrc password",
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
        "Password in URL",
        r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\x22]{1,64}:([^\s@/'\x22]{4,})@[A-Za-z0-9\[]",
    ),
];

/// Generic assignment: group 1 is the variable name, group 2 is the value.
const GENERIC_PATTERN: &str = r#"(?i)\b([a-z0-9_.-]*(?:secret|token|passwd|password|api_?key|apikey|private_?key|access_?key)[a-z0-9_.-]*)["']?\s*[=:]\s*["']?([^\s"'`,;#]{8,})"#;

/// Extracts the name from the `NAME=` or `"name": "` fragment immediately left of a match.
const NAME_PATTERN: &str = r#"([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[=:]\s*["']?$"#;

struct Compiled {
    rules: Vec<(&'static Rule, Regex)>,
    generic: Regex,
    name: Regex,
}

/// Compiling regular expressions is expensive; they are compiled once on first use.
static COMPILED: LazyLock<Compiled> = LazyLock::new(|| Compiled {
    rules: RULES
        .iter()
        .map(|rule| (rule, Regex::new(rule.pattern).expect("rule pattern is valid")))
        .collect(),
    generic: Regex::new(GENERIC_PATTERN).expect("generic pattern is valid"),
    name: Regex::new(NAME_PATTERN).expect("name pattern is valid"),
});

// ---- Result types ----

/// A single secret found in a file.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub provider: &'static str,
    pub rule: &'static str,
    /// The masked form of the secret; the raw value is never serialized.
    pub masked: String,
    /// The name of the variable the secret is assigned to (if it could be found).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub path: PathBuf,
    pub line: usize,
    /// How many times the same secret occurs in this file.
    pub occurrences: usize,
    /// Same number = same secret (copies in different files).
    pub secret_id: usize,
    /// Is the file tracked in a git repository (has it been committed)?
    pub git_tracked: bool,
    /// File mode, octal (e.g. `644`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Can the group or other users read the file?
    pub others_can_read: bool,
    #[serde(skip)]
    secret: String,
}

/// Summary row per provider.
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

// ---- Text scanning ----

/// A raw match found in a file's contents.
struct Match {
    rule: &'static str,
    provider: &'static str,
    secret: String,
    name: Option<String>,
    offset: usize,
}

/// Finds all secrets in the text. `file_name` is used only for `file_hint`
/// rules.
fn scan_text(file_name: &str, text: &str) -> Vec<Match> {
    let compiled = &*COMPILED;
    let mut matches = Vec::new();
    // Claimed byte ranges: a second rule must not report the same fragment.
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let overlaps = |taken: &[(usize, usize)], start: usize, end: usize| {
        taken.iter().any(|&(s, e)| start < e && s < end)
    };

    // Templates such as `.env.example` are committed on purpose and contain
    // made-up passwords; only real key patterns are searched for there.
    let template = is_template(file_name);

    for (rule, regex) in &compiled.rules {
        if rule.file_hint.is_some_and(|hint| !file_name.contains(hint))
            || (template && rule.id == URL_PASSWORD)
        {
            continue;
        }
        for captures in regex.captures_iter(text) {
            let whole = captures.get(0).expect("group 0 always exists");
            let value = captures.get(1).unwrap_or(whole);
            if overlaps(&taken, value.start(), value.end()) {
                continue;
            }
            let secret = if rule.id == PRIVATE_KEY {
                if key_is_encrypted(&text[whole.end()..]) {
                    continue;
                }
                // Each private key counts separately; we do not compare the contents.
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
            provider: "Generic (by name)",
            secret: value.as_str().to_string(),
            name: Some(name.as_str().to_string()),
            offset: name.start(),
        });
    }

    matches
}

/// Returns the variable name immediately left of the match, on the same line.
fn name_before(text: &str, offset: usize) -> Option<String> {
    let line_start = text[..offset].rfind('\n').map_or(0, |index| index + 1);
    let prefix = &text[line_start..offset];
    let captures = COMPILED.name.captures(prefix)?;
    Some(captures.get(1)?.as_str().to_string())
}

/// Does the body after the PEM header belong to an encrypted (passphrase-protected) key?
fn key_is_encrypted(after_header: &str) -> bool {
    // The old PEM format declares encryption in the header.
    let head: String = after_header.chars().take(200).collect();
    if head.contains("ENCRYPTED") {
        return true;
    }
    // In the OpenSSH format the cipher name is at the start of the body. For
    // an unencrypted key that name is "none"; its base64 form always starts
    // with the same prefix.
    const OPENSSH_MAGIC: &str = "b3BlbnNzaC1rZXktdjEA";
    const OPENSSH_NONE: &str = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";
    // In keys embedded in JSON, a line break is written as the two characters `\n`.
    let body: String = head.replace("\\n", "").split_whitespace().collect();
    body.starts_with(OPENSSH_MAGIC) && !body.starts_with(OPENSSH_NONE)
}

/// Is the file a template (`.env.example`, `config.sample.json`)?
fn is_template(file_name: &str) -> bool {
    const MARKERS: [&str; 5] = ["example", "sample", "template", ".dist", ".defaults"];
    let lower = file_name.to_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Filters out example / placeholder values copied from documentation.
fn is_placeholder(value: &str) -> bool {
    const MARKERS: [&str; 20] = [
        "example", "sample", "placeholder", "changeme", "change_me", "change-me", "your_", "your-",
        "yourkey", "xxxx", "dummy", "redacted", "insert", "<", ">", "${", "$(", "{{", "***", "...",
    ];
    let lower = value.to_lowercase();
    let distinct: BTreeSet<char> = lower.chars().collect();
    distinct.len() <= 3 || MARKERS.iter().any(|marker| lower.contains(marker))
}

/// In generic assignments, does the value really look like a secret?
fn looks_secret(name: &str, value: &str) -> bool {
    const LITERALS: [&str; 6] = ["true", "false", "null", "none", "undefined", "required"];
    let lower = value.to_lowercase();
    if is_placeholder(value)
        || LITERALS.contains(&lower.as_str())
        // A variable, path, URL or code fragment: not a secret, but the address of one.
        || value.starts_with(['$', '/', '~', '.', '%', '@', '[', '{', '!'])
        || lower.starts_with("http")
        || value.contains(['(', ')', '\\'])
        || value.chars().all(|c| c.is_ascii_digit())
        // Dates such as `…TokenDate: 2026-01-31T…`.
        || is_date(value)
    {
        return false;
    }
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let mixed_case = value.chars().any(char::is_lowercase) && value.chars().any(char::is_uppercase);
    let is_password = name.to_lowercase().contains("pass");
    entropy(value) >= 3.0 && (has_digit || mixed_case || is_password)
}

/// Does the value start with `YYYY-MM-DD`?
fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&index| bytes[index].is_ascii_digit())
}

/// Shannon entropy (bits per character). High for random keys, low for
/// words.
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

/// Makes the secret recognizable but unusable.
fn mask(rule: &str, secret: &str) -> String {
    if rule == PRIVATE_KEY {
        return "(private key)".to_string();
    }
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();
    // For short values, showing the head/tail would reveal most of the value.
    if len < 16 {
        return format!("•••• ({len} chars)");
    }
    let head: String = chars[..(len / 4).min(12)].iter().collect();
    let tail: String = chars[len - 4..].iter().collect();
    format!("{head}…{tail}")
}

// ---- File scanning ----

/// Files larger than this size are not read.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Scans a single file. Unreadable and binary files return `None`.
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

    // The same secret may occur many times in a file (e.g. shell history);
    // we keep the first location and count the repeats.
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
            // Private keys are specific to a file; with the path added they do not count as copies.
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

/// Is the file tracked in a git repository? `false` if `git` is missing or
/// the file is outside a repository.
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

/// Scans the files by spreading them across threads and summarizes the result.
pub fn scan(files: &[PathBuf]) -> Scan {
    let next = AtomicUsize::new(0);
    let scanned = AtomicUsize::new(0);
    let collected: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(4, usize::from).min(files.len().max(1));

    // `scope` lets the threads borrow local variables: all of them are
    // guaranteed to finish before the scope ends.
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                // The shared counter acts as a work queue: each thread
                // takes the index of the next file.
                while let Some(path) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                    if let Some(findings) = scan_file(path) {
                        scanned.fetch_add(1, Ordering::Relaxed);
                        if !findings.is_empty() {
                            collected.lock().expect("lock is not poisoned").extend(findings);
                        }
                    }
                }
            });
        }
    });

    let mut findings = collected.into_inner().expect("lock is not poisoned");
    // Thread order is arbitrary; make the output identical on every run.
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

// ---- Finding the files to scan ----

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Files in the home directory that are known to hold secrets.
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

/// Files looked at inside a project's hidden directories (the rest of the
/// hidden directories is not walked).
const HIDDEN_PROJECT_FILES: [&str; 7] = [
    ".git/config",
    ".vscode/settings.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".aws/credentials",
];

/// Directories that are not descended into: dependencies and build outputs.
const SKIP_DIRS: [&str; 19] = [
    "testdata", "_testfiles", "fixtures",
    "node_modules", "target", "vendor", "Pods", "venv", "env", "__pycache__", "dist", "build",
    "DerivedData", "site-packages", "bower_components", "Carthage", "coverage", "out", "tmp",
];

/// Default targets: the known files in the home directory, `~/.ssh` and
/// the projects under the home directory.
pub fn default_files() -> Vec<PathBuf> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = HOME_FILES.iter().map(|relative| home.join(relative)).collect();

    // Any file inside `~/.ssh` may be a private key; the names are arbitrary.
    if let Ok(entries) = std::fs::read_dir(home.join(".ssh")) {
        files.extend(entries.flatten().map(|entry| entry.path()).filter(|path| {
            path.extension().is_none_or(|extension| extension != "pub")
        }));
    }

    // Large top-level folders that contain no projects are skipped.
    const SKIP_TOP: [&str; 6] = ["Library", "Applications", "Music", "Movies", "Pictures", "Public"];
    files.extend(walk(&home, &SKIP_TOP));
    unique_files(files)
}

/// A user-supplied path: the file itself if it is a file, the candidates under it if a directory.
pub fn files_under(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    unique_files(walk(path, &[]))
}

/// Searches under `base` for files that may hold secrets. Hidden directories,
/// dependency directories and symbolic links are skipped.
fn walk(base: &Path, skip_top: &[&str]) -> Vec<PathBuf> {
    /// Deep enough to reach monorepo sub-packages when starting from the home directory.
    const MAX_DEPTH: usize = 9;

    fn visit(dir: &Path, depth: usize, skip: &[&str], found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        found.extend(HIDDEN_PROJECT_FILES.iter().map(|relative| dir.join(relative)).filter(|p| p.is_file()));

        for entry in entries.flatten() {
            // `file_type` does not follow links; symbolic links count as neither
            // file nor directory and are skipped (to avoid loops and duplicates).
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
                // Go module cache (`~/go/pkg`): other people's code and test keys.
                && !(name == "pkg" && dir.file_name().is_some_and(|parent| parent == "go"))
            {
                // The skip list only applies to the top level.
                visit(&entry.path(), depth + 1, &[], found);
            }
        }
    }

    let mut found = Vec::new();
    visit(base, 0, skip_top, &mut found);
    found
}

/// Is the file name a candidate for holding secrets?
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

/// Resolves existing files to their real paths and removes duplicates.
fn unique_files(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let unique: BTreeSet<PathBuf> = candidates
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.is_file())
        .collect();
    unique.into_iter().collect()
}

// ---- Report (--secrets) ----

/// The output of `--secrets` mode.
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
        serde_json::to_string_pretty(self).expect("report can be converted to JSON")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let rule = "─".repeat(78).dimmed();
        let scan = &self.scan;
        let home = home();
        let short = |path: &Path| display_path(path, home.as_deref());

        let _ = writeln!(out);
        let _ = writeln!(out, "{}", " Secret / API Key Scan ".on_blue().white().bold());
        let _ = writeln!(
            out,
            " {} files scanned · {} secrets · {} locations",
            scan.files_scanned,
            scan.unique_secrets(),
            scan.findings.len()
        );
        let _ = writeln!(out, "{rule}");

        if scan.findings.is_empty() {
            let _ = writeln!(out, "{}", "No secrets found.".green().bold());
            return out.trim_end().to_string();
        }

        let _ = writeln!(out, "{}", "SUMMARY".bold());
        for row in &scan.summary {
            let tracked = if row.git_tracked > 0 {
                format!("  {} locations tracked in git", row.git_tracked).red().bold().to_string()
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "  {:<26} {:>3} secrets {:>4} locations{tracked}",
                row.provider, row.secrets, row.locations
            );
        }
        let _ = writeln!(out, "{rule}");

        // Provider → secret → locations. The findings are already in this order.
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
                    format!("  (in {copies} places)").yellow().to_string()
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
                flags.push("TRACKED IN GIT".red().bold().to_string());
            }
            if finding.others_can_read && let Some(mode) = &finding.mode {
                flags.push(format!("mode {mode}").yellow().to_string());
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
                format!("Secrets found in git-tracked files: {tracked}.").red().bold()
            );
            let _ = writeln!(
                out,
                "If the repository has been shared, treat the secret as leaked: revoke and rotate it at the provider,\n\
                 add the file to `.gitignore` and untrack it with `git rm --cached`."
            );
        }
        let loose = scan.findings.iter().filter(|f| f.others_can_read).count();
        if loose > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!("Locations where the file is readable by other users: {loose}. Fix with `chmod 600 FILE`.").yellow()
            );
        }
        let _ = writeln!(
            out,
            "{}",
            "Values are masked. \"Generic\" findings are heuristic and may be false positives.".dimmed()
        );
        out.trim_end().to_string()
    }
}

/// Abbreviates the home directory as `~`.
fn display_path(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|home| path.strip_prefix(home).ok()) {
        Some(relative) => format!("~/{}", relative.display()),
        None => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory that is deleted when the test ends (via `Drop`).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("macos-audit-secrets-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // On macOS the temporary directory lives under a symbolic link.
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

    /// Produces a deterministic, random-looking string. Fake keys are not
    /// written into the source code so that repository scanners (and this
    /// tool) do not raise an alarm.
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
    fn provider_patterns_are_recognized() {
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
            assert_eq!(rules_hit(".env", &text), [expected], "{expected} should be recognized");
        }
    }

    #[test]
    fn aws_secret_key_is_recognized_by_name() {
        let text = format!(
            "[default]\naws_access_key_id = AKIA{}\naws_secret_access_key = {}\n",
            random(UPPER, 16, 1),
            random(ALNUM, 40, 2)
        );
        assert_eq!(rules_hit("credentials", &text), ["aws-access-key", "aws-secret-key"]);
    }

    #[test]
    fn variable_name_and_line_are_found() {
        let text = format!("# comment\nexport ANTHROPIC_API_KEY=\"{}\"\n", anthropic_key(1));
        let found = scan_text(".zshrc", &text);
        assert_eq!(found.len(), 1, "the generic rule must not report the same value a second time");
        assert_eq!(found[0].name.as_deref(), Some("ANTHROPIC_API_KEY"));

        let text = format!("{{\n  \"apiKey\": \"{}\"\n}}", anthropic_key(1));
        assert_eq!(scan_text("a.json", &text)[0].name.as_deref(), Some("apiKey"));
    }

    #[test]
    fn placeholders_are_filtered() {
        let text = "\
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
            API_KEY=your_api_key_here\n\
            SECRET_KEY=${SECRET_KEY}\n\
            DB_PASSWORD=changeme123\n\
            AUTH_TOKEN=$(gh auth token)\n\
            PRIVATE_KEY_PATH=/Users/someone/.ssh/id_ed25519\n\
            TOKEN_TTL=86400000\n\
            API_KEY_HEADER=x-api-key-name\n\
            ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n";
        assert!(rules_hit(".env", text).is_empty(), "{:?}", rules_hit(".env", text));
    }

    #[test]
    fn generic_assignment_with_random_value_is_caught() {
        let text = format!("MY_SERVICE_TOKEN={}\nDB_PASSWORD='{}'\n", random(ALNUM, 32, 1), random(ALNUM, 14, 2));
        let found = scan_text(".env", &text);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.rule == GENERIC));
        assert_eq!(found[0].name.as_deref(), Some("MY_SERVICE_TOKEN"));
    }

    #[test]
    fn template_files_are_only_searched_for_real_patterns() {
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
    fn date_values_do_not_count_as_secrets() {
        assert!(rules_hit("a.json", "\"firstTokenDate\": \"2026-01-31T10:20:30.000Z\"").is_empty());
    }

    #[test]
    fn password_in_url_is_caught() {
        let password = random(ALNUM, 16, 1);
        let text = format!("DATABASE_URL=postgres://app:{password}@db.internal:5432/app\n");
        let found = scan_text(".env", &text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "url-password");
        assert_eq!(found[0].secret, password);
        assert!(rules_hit(".env", "URL=https://example.com:8080/a@b\n").is_empty());
    }

    #[test]
    fn rules_with_a_file_hint_do_not_run_on_other_files() {
        let text = format!("machine api.github.com login me password {}\n", random(ALNUM, 20, 1));
        assert_eq!(rules_hit(".netrc", &text), ["netrc"]);
        assert!(rules_hit("notes.txt", &text).is_empty());
    }

    #[test]
    fn only_unencrypted_private_keys_are_reported() {
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

        // In a service account JSON the key is embedded on a single line.
        let json = format!("\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n\"", random(ALNUM, 40, 2));
        assert_eq!(rules_hit("sa.json", &json), [PRIVATE_KEY]);
    }

    #[test]
    fn mask_hides_the_value() {
        let key = anthropic_key(1);
        let masked = mask("anthropic", &key);
        assert!(masked.starts_with("sk-ant-api03"));
        assert!(masked.chars().count() < 20);
        assert!(!mask(GENERIC, "shortpass1").contains("short"));
        assert_eq!(mask(PRIVATE_KEY, "pem@0"), "(private key)");
    }

    #[test]
    fn candidate_files_are_found_and_dependencies_skipped() {
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
    fn same_secret_is_matched_across_files() {
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
        assert_eq!(ids.len(), 1, "the same secret gets the same number");
    }

    #[test]
    fn raw_value_does_not_leak_into_reports() {
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
    fn file_tracked_in_git_is_flagged() {
        let dir = TempDir::new("git");
        dir.write("tracked.env", &format!("K={}\n", anthropic_key(1)));
        dir.write("untracked.env", &format!("K={}\n", anthropic_key(2)));
        let git = |args: &[&str]| {
            Command::new("git").arg("-C").arg(&dir.0).args(args).output().is_ok_and(|o| o.status.success())
        };
        if !git(&["init", "-q"]) || !git(&["add", "tracked.env"]) {
            return; // without git this test is meaningless
        }

        let scan = scan(&files_under(&dir.0));
        let tracked: Vec<_> = scan.tracked().map(|f| f.path.file_name().unwrap().to_owned()).collect();
        assert_eq!(tracked, ["tracked.env"]);
    }

    #[test]
    fn entropy_separates_words_from_random() {
        assert!(entropy("aaaaaaaa") < 0.1);
        assert!(entropy("password") < 3.0);
        assert!(entropy(&random(ALNUM, 32, 1)) > 4.0);
    }
}
