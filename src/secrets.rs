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
//! 3. **Private keys**: PEM / OpenSSH keys without a passphrase, and armored
//!    PGP private key blocks (whose protection is not checked).
//!
//! Safety rules:
//! - The scan is read-only and never touches the network.
//! - The raw secret value is never written to any output; reports contain only
//!   the masked form (`sk-ant-…a3F9 (93 chars)`, see `mask`). The raw value is
//!   kept in memory only to match copies of the same secret across different
//!   files; copies are linked in the output through `secret_id`, a plain
//!   counter that carries no information about the value.

use crate::progress::Progress;
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
    Rule {
        id,
        provider,
        pattern,
        file_hint: None,
    }
}

const PRIVATE_KEY: &str = "private-key";
const PGP_KEY: &str = "pgp-private-key";
const GENERIC: &str = "generic";
const URL_PASSWORD: &str = "url-password";
const DOCKER_AUTH: &str = "docker-auth";
const KUBE_CLIENT_KEY: &str = "kube-client-key";
const NETRC: &str = "netrc";

/// Order matters: a piece of text is claimed by the first rule that matches it.
const RULES: &[Rule] = &[
    rule("anthropic", "Anthropic", r"\bsk-ant-[A-Za-z0-9_-]{24,}"),
    rule("openrouter", "OpenRouter", r"\bsk-or-v1-[a-f0-9]{64}\b"),
    rule("openai", "OpenAI", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{24,}"),
    rule(
        "openai-legacy",
        "OpenAI",
        r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b",
    ),
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
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    // Whether a PGP key is passphrase-protected is recorded inside its binary
    // packets (the S2K usage byte), not in the armor, so it is reported
    // without any claim about encryption.
    rule(PGP_KEY, "PGP private key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    Rule {
        id: DOCKER_AUTH,
        provider: "Docker registry",
        pattern: r#""auth"\s*:\s*"([A-Za-z0-9+/=]{16,})""#,
        file_hint: Some("config.json"),
    },
    Rule {
        id: KUBE_CLIENT_KEY,
        provider: "Kubernetes",
        pattern: r"client-key-data:\s*([A-Za-z0-9+/=]{40,})",
        file_hint: None,
    },
    Rule {
        id: NETRC,
        provider: "netrc password",
        pattern: r"\bpassword\s+(\S{4,})",
        file_hint: Some("netrc"),
    },
    rule(
        "jwt",
        "JWT",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    // Group 1 is the user name (may be empty, as in `redis://:pw@host`), group 2
    // is everything after the colon; `url_password` finds where the password ends.
    rule(
        URL_PASSWORD,
        "Password in URL",
        r"\b[a-z][a-z0-9+.-]{1,20}://([^\s:/@'\x22]{0,64}):([^\s'\x22]+)",
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

/// A raw secret value. It is only ever compared; `Debug` output is redacted so
/// that the value cannot leak through `{:?}` formatting of a `Finding`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Raw(String);

impl std::fmt::Debug for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

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
    /// Same number = same secret (copies in different files). A counter
    /// assigned in report order; it is not derived from the secret's value.
    pub secret_id: usize,
    /// Is the file tracked in a git repository (has it been committed)?
    pub git_tracked: bool,
    /// File mode, octal (e.g. `644`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Can the group or other users read the file?
    pub others_can_read: bool,
    /// Byte offset in the (decoded) file; orders several secrets on one line.
    #[serde(skip)]
    offset: usize,
    #[serde(skip)]
    secret: Raw,
}

/// Files that could not be scanned, by reason.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SkippedFiles {
    /// Larger than the size limit (8 MB).
    pub too_large: usize,
    /// Binary, or text in an encoding that is not understood.
    pub binary: usize,
    /// Could not be read (permissions, vanished, not a regular file).
    pub unreadable: usize,
}

impl SkippedFiles {
    pub fn total(&self) -> usize {
        self.too_large + self.binary + self.unreadable
    }

    /// E.g. `2 over 8 MB, 1 binary or not text`; empty if nothing was skipped.
    pub fn reasons(&self) -> String {
        let parts = [
            (self.too_large, format!("over {} MB", MAX_FILE_BYTES / (1024 * 1024))),
            (self.binary, "binary or not text".to_string()),
            (self.unreadable, "unreadable".to_string()),
        ];
        let parts: Vec<String> = parts
            .into_iter()
            .filter(|(count, _)| *count > 0)
            .map(|(count, why)| format!("{count} {why}"))
            .collect();
        parts.join(", ")
    }
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
    /// Files that were candidates but could not be scanned (`skipped` says why).
    pub files_skipped: usize,
    pub skipped: SkippedFiles,
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
    let overlaps =
        |taken: &[(usize, usize)], start: usize, end: usize| taken.iter().any(|&(s, e)| start < e && s < end);

    // Templates such as `.env.example` are committed on purpose and contain
    // made-up passwords; only real key patterns are searched for there.
    let template = is_template(file_name);

    for (rule, regex) in &compiled.rules {
        if rule.file_hint.is_some_and(|hint| !file_name.contains(hint)) || (template && rule.id == URL_PASSWORD) {
            continue;
        }
        for captures in regex.captures_iter(text) {
            let whole = captures.get(0).expect("group 0 always exists");
            let (start, end, secret) = match rule.id {
                PRIVATE_KEY | PGP_KEY => {
                    if rule.id == PRIVATE_KEY && key_is_encrypted(&text[whole.end()..]) {
                        continue;
                    }
                    // Each private key counts separately; we do not compare the contents.
                    (whole.start(), whole.end(), format!("pem@{}", whole.start()))
                }
                URL_PASSWORD => {
                    let (Some(user), Some(rest)) = (captures.get(1), captures.get(2)) else {
                        continue;
                    };
                    let Some((len, host)) = url_password(user.as_str(), rest.as_str()) else {
                        continue;
                    };
                    let password = percent_decode(&rest.as_str()[..len]);
                    if password.chars().count() < MIN_URL_PASSWORD_LEN
                        || is_placeholder(&password)
                        || is_documentation_host(host)
                        || is_dev_default(user.as_str(), &password, host)
                    {
                        continue;
                    }
                    (rest.start(), rest.start() + len, password)
                }
                _ => {
                    let value = captures.get(1).unwrap_or(whole);
                    if is_placeholder(value.as_str()) {
                        continue;
                    }
                    (value.start(), value.end(), value.as_str().to_string())
                }
            };
            if overlaps(&taken, start, end) {
                continue;
            }
            taken.push((start, end));
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
        if overlaps(&taken, value.start(), value.end()) || !looks_secret(name.as_str(), value.as_str()) {
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
///
/// Only the shape of the *whole* value counts (`<your-key>`, `${VAR}`,
/// `xxxxxxxx`, `your_api_key_here`, `changeme`, `...`). A marker that merely
/// occurs somewhere inside the value (`p4ssw0rd<Zq9!x`, `Ab...Zq***9`) does not
/// make it a placeholder: real passwords contain such characters.
fn is_placeholder(value: &str) -> bool {
    let lower = value.trim().to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let distinct: BTreeSet<char> = chars.iter().copied().collect();
    // `xxxxxxxx`, `********`, `...`, `abcabc`.
    if distinct.len() <= 3 {
        return true;
    }

    // Something to fill in or to be substituted: `<token>`, `${VAR}`, `$(cmd)`, `{{ var }}`.
    const WRAPPERS: [(&str, &str); 4] = [("<", ">"), ("${", "}"), ("$(", ")"), ("{{", "}}")];
    if WRAPPERS
        .iter()
        .any(|(open, close)| lower.starts_with(open) && lower.ends_with(close))
    {
        return true;
    }
    let identifier = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    // `$VAR` and `%VAR%`.
    if lower.strip_prefix('$').is_some_and(identifier)
        || lower
            .strip_prefix('%')
            .and_then(|rest| rest.strip_suffix('%'))
            .is_some_and(identifier)
    {
        return true;
    }

    // A value that is mostly one run of a masking character: `sk-ant-xxxxxxxxxxxx`.
    let mut longest = 0;
    let mut run = 0;
    let mut previous = None;
    for &c in &chars {
        run = if Some(c) == previous { run + 1 } else { 1 };
        previous = Some(c);
        if matches!(c, 'x' | '*' | '.' | '•' | '#') {
            longest = longest.max(run);
        }
    }
    if longest >= 8 && longest * 2 >= chars.len() {
        return true;
    }

    // Elided in documentation (`sk-proj-...`), or one of the documented example
    // keys, which end in `EXAMPLE` / `EXAMPLEKEY` (`AKIAIOSFODNN7EXAMPLE`).
    if lower.ends_with("...") || lower.ends_with('…') || lower.ends_with("example") || lower.ends_with("examplekey") {
        return true;
    }

    // Made of placeholder words only, e.g. `your_api_key_here`, `changeme123`,
    // `replace-with-token`. At least one word must be a real marker, so that
    // a weak but real value such as `secret-password` is still reported.
    const MARKERS: [&str; 30] = [
        "your",
        "yours",
        "yourkey",
        "here",
        "changeme",
        "change",
        "changeit",
        "changethis",
        "example",
        "sample",
        "placeholder",
        "dummy",
        "redacted",
        "insert",
        "replace",
        "replaceme",
        "todo",
        "fixme",
        "tbd",
        "fake",
        "foo",
        "bar",
        "baz",
        "foobar",
        "hidden",
        "masked",
        "removed",
        "enter",
        "put",
        "add",
    ];
    const FILLER: [&str; 36] = [
        "api", "key", "apikey", "token", "secret", "password", "passwd", "pass", "pwd", "my", "me", "the", "a", "an",
        "of", "for", "is", "this", "it", "value", "access", "private", "public", "client", "id", "user", "username",
        "name", "string", "auth", "app", "db", "new", "real", "goes", "with",
    ];
    let mut marker_seen = false;
    for word in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        // `changeme123` → `changeme`; a purely numeric word is empty here.
        let word = word.trim_end_matches(|c: char| c.is_ascii_digit());
        if word.is_empty() || FILLER.contains(&word) {
            continue;
        }
        if MARKERS.contains(&word) || (word.len() >= 2 && word.chars().all(|c| c == 'x')) {
            marker_seen = true;
        } else {
            return false;
        }
    }
    marker_seen
}

// ---- Passwords in URLs ----

/// Shorter passwords in URLs are not reported (too many false positives).
const MIN_URL_PASSWORD_LEN: usize = 4;

/// Splits what follows `scheme://user:` into password and host. Returns the
/// byte length of the password (it starts at offset 0 of `rest`) and the host.
///
/// The password may itself contain `@` or `/`, so the first `@` is not always
/// the separator. The separator is the first `@` that is followed by a
/// well-formed `host[:port]` and is the last `@` of its path segment. Where
/// the text is equally valid as `host:port/path@…` (no credentials at all),
/// nothing is reported.
fn url_password<'a>(user: &str, rest: &'a str) -> Option<(usize, &'a str)> {
    const STOPS: [char; 3] = ['/', '?', '#'];
    // `http://[::1]:8080/…` is an IPv6 host, not a user name.
    if user.starts_with('[') {
        return None;
    }
    let authority = &rest[..rest.find(STOPS).unwrap_or(rest.len())];
    if !authority.contains('@') {
        // No `@` before the first `/`: either `host:port/…@…` or a password
        // containing `/`. A port is numeric, so only a non-numeric start can
        // be a password.
        let digits = authority.chars().take_while(char::is_ascii_digit).count();
        let after_digits = authority[digits..].chars().next();
        if authority.is_empty() || (digits > 0 && after_digits.is_none_or(|c| !c.is_ascii_alphanumeric())) {
            return None;
        }
    }
    for (at, _) in rest.match_indices('@') {
        // `app:Zq9@K2m/x7@db.internal` can be read as password `Zq9` on host
        // `K2m`. A split that leaves a password too short to report is not
        // taken; the next `@` is tried, so the finding is not lost.
        if at < MIN_URL_PASSWORD_LEN {
            continue;
        }
        let after = &rest[at + 1..];
        let Some((host, consumed)) = parse_host(after) else {
            continue;
        };
        let tail = &after[consumed..];
        if tail[..tail.find(STOPS).unwrap_or(tail.len())].contains('@') {
            continue;
        }
        return Some((at, host));
    }
    None
}

/// Reads `host[:port]` from the start of the text: the host and the number of
/// bytes consumed (including the port).
fn parse_host(text: &str) -> Option<(&str, usize)> {
    let (host, mut consumed) = if let Some(inner) = text.strip_prefix('[') {
        let close = inner.find(']')?;
        (&inner[..close], close + 2)
    } else {
        let len = text
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
            .unwrap_or(text.len());
        (&text[..len], len)
    };
    if !host.starts_with(|c: char| c.is_ascii_alphanumeric() || c == ':') {
        return None;
    }
    if let Some(port) = text[consumed..].strip_prefix(':') {
        let digits = port.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 {
            consumed += 1 + digits;
        }
    }
    Some((host, consumed))
}

/// Decodes `%XX` escapes, so that `p%40ss` and `p@ss` count as the same secret.
/// Returns the text unchanged if the result would not be valid UTF-8.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |index: usize| {
        bytes
            .get(index)
            .and_then(|&byte| (byte as char).to_digit(16))
            .map(|digit| digit as u8)
    };
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (hex(index + 1), hex(index + 2))
        {
            decoded.push(high * 16 + low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| text.to_string())
}

/// Is the host this machine or a docker-compose style bare service name (`db`)?
fn is_local_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "host.docker.internal"
        || lower == "::1"
        || lower == "0.0.0.0"
        || (lower.starts_with("127.") && lower.split('.').count() == 4)
        // A name without dots (and not an IPv6 address) only resolves locally.
        || !lower.contains(['.', ':'])
}

/// Hosts reserved for documentation (RFC 2606 / 6761).
fn is_documentation_host(host: &str) -> bool {
    let lower = host.to_lowercase();
    // `sha256` is not a host: `image:tag@sha256:…` is a container image reference.
    [
        "example.com",
        "example.org",
        "example.net",
        "example",
        "invalid",
        "sha256",
        "sha512",
    ]
    .iter()
    .any(|reserved| lower == *reserved || lower.ends_with(&format!(".{reserved}")))
}

/// Development defaults such as `postgres:postgres@localhost`: a password
/// equal to the user name or a well-known default, on a local host. The same
/// password on a real host is reported.
fn is_dev_default(user: &str, password: &str, host: &str) -> bool {
    const DEFAULTS: [&str; 10] = [
        "postgres", "password", "root", "admin", "example", "secret", "changeme", "user", "pass", "test",
    ];
    let lower = password.to_lowercase();
    is_local_host(host) && (lower == user.to_lowercase() || DEFAULTS.contains(&lower.as_str()))
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
        || value.contains("://")
        || value.contains('\\')
        // A call such as `os.getenv(` or `get_token()`. Parentheses elsewhere
        // in the value are ordinary password characters.
        || value.ends_with(['(', ')'])
        || value.contains("()")
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
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|&index| bytes[index].is_ascii_digit())
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

/// The well-known, non-secret prefix that identifies the provider (`sk-ant-`,
/// `ghp_`, `AKIA`); empty if the rule has none.
fn public_prefix(rule: &str, secret: &str) -> &'static str {
    let candidates: &[&'static str] = match rule {
        "anthropic" => &["sk-ant-"],
        "openrouter" => &["sk-or-v1-"],
        "openai" => &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        "openai-legacy" => &["sk-"],
        "aws-access-key" => &["AKIA", "ASIA"],
        "google-api-key" => &["AIza"],
        "google-oauth-secret" => &["GOCSPX-"],
        "digitalocean" => &["dop_v1_", "doo_v1_", "dor_v1_"],
        "github" => &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        "github-pat" => &["github_pat_"],
        "gitlab" => &["glpat-"],
        "slack" => &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
        "slack-webhook" => &["https://hooks.slack.com/services/"],
        "stripe" => &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        "sendgrid" => &["SG."],
        "twilio" => &["SK"],
        "npm" => &["npm_"],
        "huggingface" => &["hf_"],
        "groq" => &["gsk_"],
        "jwt" => &["eyJ"],
        _ => &[],
    };
    candidates
        .iter()
        .copied()
        .find(|prefix| secret.starts_with(prefix))
        .unwrap_or("")
}

/// Values shorter than this are never shown, not even partially.
const MIN_REVEAL_LEN: usize = 20;

/// Makes the secret recognizable but unusable.
///
/// At most the provider's public prefix and the last 2–4 characters are
/// shown; the tail is never more than an eighth of the part after the prefix.
/// Nothing at all is shown (only the length) for values under
/// `MIN_REVEAL_LEN` characters and for everything that is not a provider key
/// with a fixed format: generic matches, passwords, and base64 blobs such as
/// a docker `auth`, whose first characters decode to the user name.
/// Copies of a secret are recognized through `secret_id`, not through the mask.
fn mask(rule: &str, secret: &str) -> String {
    match rule {
        PRIVATE_KEY => return "(private key)".to_string(),
        PGP_KEY => return "(PGP private key, passphrase protection not checked)".to_string(),
        _ => {}
    }
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();
    let hidden = format!("•••• ({len} chars)");
    if len < MIN_REVEAL_LEN || matches!(rule, GENERIC | URL_PASSWORD | DOCKER_AUTH | KUBE_CLIENT_KEY | NETRC) {
        return hidden;
    }
    let prefix = public_prefix(rule, secret);
    let body = len - prefix.chars().count();
    let tail_len = match (body / 8).min(4) {
        0 | 1 => 0,
        n => n,
    };
    if prefix.is_empty() && tail_len == 0 {
        return hidden;
    }
    let tail: String = chars[len - tail_len..].iter().collect();
    format!("{prefix}…{tail} ({len} chars)")
}

// ---- File scanning ----

/// Files larger than this size are not read.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Why a file was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skip {
    TooLarge,
    Binary,
    Unreadable,
}

/// Turns file contents into text: UTF-8 (invalid sequences are replaced), or
/// UTF-16 when it starts with a byte order mark. `None` for binary data.
fn decode(bytes: &[u8]) -> Option<String> {
    let text = match bytes {
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    };
    // A NUL near the start means binary (or UTF-16/32 without a usable mark).
    (!text.chars().take(1024).any(|c| c == '\0')).then_some(text)
}

fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| unit([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Scans a single file. Files that are too large, binary or unreadable are
/// not scanned; the reason is returned so that they can be counted.
fn scan_file(path: &Path) -> Result<Vec<Finding>, Skip> {
    let metadata = std::fs::metadata(path).map_err(|_| Skip::Unreadable)?;
    if !metadata.is_file() {
        return Err(Skip::Unreadable);
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(Skip::TooLarge);
    }
    let bytes = std::fs::read(path).map_err(|_| Skip::Unreadable)?;
    let text = decode(&bytes).ok_or(Skip::Binary)?;
    let file_name = path.file_name().ok_or(Skip::Unreadable)?.to_string_lossy();

    // The same secret may occur many times in a file (e.g. shell history);
    // we keep the first location and count the repeats.
    let mut findings: Vec<Finding> = Vec::new();
    for found in scan_text(&file_name, &text) {
        // Private keys are specific to a file; with the path added they do not count as copies.
        let secret = Raw(if matches!(found.rule, PRIVATE_KEY | PGP_KEY) {
            format!("{}:{}", path.display(), found.secret)
        } else {
            found.secret
        });
        if let Some(existing) = findings.iter_mut().find(|f| f.secret == secret) {
            existing.occurrences += 1;
            continue;
        }
        findings.push(Finding {
            provider: found.provider,
            rule: found.rule,
            masked: mask(found.rule, &secret.0),
            name: found.name,
            path: path.to_path_buf(),
            line: text[..found.offset].matches('\n').count() + 1,
            occurrences: 1,
            secret_id: 0,
            git_tracked: false,
            mode: None,
            others_can_read: false,
            offset: found.offset,
            secret,
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
    Ok(findings)
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
    scan_with(files, &Progress::none())
}

/// Like `scan`, reporting how many files have been processed.
pub fn scan_with(files: &[PathBuf], progress: &Progress) -> Scan {
    progress.stage(format!("Scanning {} files for secrets", files.len()));
    let processed = AtomicUsize::new(0);
    let next = AtomicUsize::new(0);
    let scanned = AtomicUsize::new(0);
    let (too_large, binary, unreadable) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let collected: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism()
        .map_or(4, usize::from)
        .min(files.len().max(1));

    // `scope` lets the threads borrow local variables: all of them are
    // guaranteed to finish before the scope ends.
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                // The shared counter acts as a work queue: each thread
                // takes the index of the next file.
                while let Some(path) = files.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let skipped = match scan_file(path) {
                        Ok(findings) => {
                            if !findings.is_empty() {
                                collected.lock().expect("lock is not poisoned").extend(findings);
                            }
                            &scanned
                        }
                        Err(Skip::TooLarge) => &too_large,
                        Err(Skip::Binary) => &binary,
                        Err(Skip::Unreadable) => &unreadable,
                    };
                    skipped.fetch_add(1, Ordering::Relaxed);
                    // Reporting every file would cost more than scanning it.
                    let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
                    if count.is_multiple_of(8) || count == files.len() {
                        progress.step(count, files.len());
                        progress.note(display_path(path, home().as_deref()));
                    }
                }
            });
        }
    });

    let findings = order_and_number(collected.into_inner().expect("lock is not poisoned"));
    let skipped = SkippedFiles {
        too_large: too_large.into_inner(),
        binary: binary.into_inner(),
        unreadable: unreadable.into_inner(),
    };

    Scan {
        files_scanned: scanned.into_inner(),
        files_skipped: skipped.total(),
        skipped,
        summary: summarize(&findings),
        findings,
    }
}

/// Puts the findings in report order and numbers the secrets.
///
/// Order: provider → secret → location, so that all copies of a secret are
/// adjacent within their provider. Secrets are ordered by where they first
/// occur, never by their value or their mask: two different secrets may have
/// the same mask, and ordering by value would leak information about it.
/// `secret_id` is then a counter in that order (1, 2, 3, …).
fn order_and_number(mut findings: Vec<Finding>) -> Vec<Finding> {
    // Thread order is arbitrary; make the output identical on every run.
    findings.sort_by(|a, b| (&a.path, a.line, a.offset).cmp(&(&b.path, b.line, b.offset)));

    // The position of the first location of each secret (per provider).
    let ranks: Vec<usize> = {
        let mut first_seen: BTreeMap<(&'static str, &Raw), usize> = BTreeMap::new();
        findings
            .iter()
            .enumerate()
            .map(|(index, finding)| *first_seen.entry((finding.provider, &finding.secret)).or_insert(index))
            .collect()
    };
    let mut ranked: Vec<(usize, Finding)> = ranks.into_iter().zip(findings).collect();
    // The sort is stable: copies of one secret stay in location order.
    ranked.sort_by(|a, b| (a.1.provider, a.0).cmp(&(b.1.provider, b.0)));

    let mut ids: BTreeMap<Raw, usize> = BTreeMap::new();
    ranked
        .into_iter()
        .map(|(_, mut finding)| {
            let next_id = ids.len() + 1;
            finding.secret_id = *ids.entry(finding.secret.clone()).or_insert(next_id);
            finding
        })
        .collect()
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
    "testdata",
    "_testfiles",
    "fixtures",
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
    "coverage",
    "out",
    "tmp",
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
        files.extend(
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_none_or(|extension| extension != "pub")),
        );
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
        found.extend(
            HIDDEN_PROJECT_FILES
                .iter()
                .map(|relative| dir.join(relative))
                .filter(|p| p.is_file()),
        );

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
        ".npmrc",
        ".netrc",
        ".pypirc",
        ".mcp.json",
        ".envrc",
        "credentials.json",
        "credentials",
        "secrets.json",
        "secrets.yml",
        "secrets.yaml",
        "secrets.toml",
        "local.settings.json",
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
        if scan.files_skipped > 0 {
            let _ = writeln!(
                out,
                "{}",
                format!(
                    " {} files skipped, not scanned: {}",
                    scan.files_skipped,
                    scan.skipped.reasons()
                )
                .yellow()
            );
        }
        let _ = writeln!(out, "{rule}");

        if scan.findings.is_empty() {
            let _ = writeln!(out, "{}", "No secrets found.".green().bold());
            return out.trim_end().to_string();
        }

        let _ = writeln!(out, "{}", "SUMMARY".bold());
        for row in &scan.summary {
            let tracked = if row.git_tracked > 0 {
                format!("  {} locations tracked in git", row.git_tracked)
                    .red()
                    .bold()
                    .to_string()
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

        // Provider → secret → locations. `order_and_number` sorted the findings
        // this way, so the copies of a secret are adjacent within a provider.
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
            if finding.others_can_read
                && let Some(mode) = &finding.mode
            {
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
                format!("Locations where the file is readable by other users: {loose}. Fix with `chmod 600 FILE`.")
                    .yellow()
            );
        }
        let _ = writeln!(
            out,
            "{}",
            "Values are masked. \"Generic\" findings are heuristic and may be false positives. PGP keys are listed without checking for a passphrase.".dimmed()
        );
        out.trim_end().to_string()
    }
}

/// Abbreviates the home directory as `~`.
pub(crate) fn display_path(path: &Path, home: Option<&Path>) -> String {
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
            let dir = std::env::temp_dir().join(format!("swordcheck-secrets-{label}-{}", std::process::id()));
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
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
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
        assert_eq!(
            found.len(),
            1,
            "the generic rule must not report the same value a second time"
        );
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
        let text = format!(
            "MY_SERVICE_TOKEN={}\nDB_PASSWORD='{}'\n",
            random(ALNUM, 32, 1),
            random(ALNUM, 14, 2)
        );
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
        let json = format!(
            "\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n\"",
            random(ALNUM, 40, 2)
        );
        assert_eq!(rules_hit("sa.json", &json), [PRIVATE_KEY]);
    }

    #[test]
    fn mask_hides_the_value() {
        let key = anthropic_key(1);
        let masked = mask("anthropic", &key);
        assert!(masked.starts_with("sk-ant-…"));
        assert!(!masked.contains("api03"));
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
            [
                "app/.env",
                "app/.env.production",
                "app/.git/config",
                "app/config/prod.env",
                "app/infra/terraform.tfstate"
            ]
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
            [ProviderSummary {
                provider: "Anthropic",
                secrets: 2,
                locations: 3,
                git_tracked: 0
            }]
        );

        let in_a = scan.findings.iter().find(|f| f.path.ends_with("a/.env")).unwrap();
        assert_eq!(in_a.occurrences, 2);
        assert_eq!(in_a.line, 1);
        let ids: BTreeSet<usize> = scan
            .findings
            .iter()
            .filter(|f| f.secret.0 == shared)
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
            Command::new("git")
                .arg("-C")
                .arg(&dir.0)
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
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

    /// The part of a mask that could show characters of the secret: the
    /// mask without its ` (N chars)` suffix.
    fn shown(masked: &str, secret: &str) -> String {
        let suffix = format!(" ({} chars)", secret.chars().count());
        masked
            .strip_suffix(&suffix)
            .unwrap_or_else(|| panic!("no length suffix in {masked:?}"))
            .to_string()
    }

    #[test]
    fn mask_shows_nothing_of_passwords_and_blobs() {
        let password = random(ALNUM, 16, 1);
        for rule in [GENERIC, URL_PASSWORD, NETRC] {
            assert_eq!(shown(&mask(rule, &password), &password), "••••", "{rule}");
        }
        // Long values of the same kinds are hidden just the same.
        let long = random(ALNUM, 64, 2);
        for rule in [GENERIC, URL_PASSWORD, NETRC, DOCKER_AUTH, KUBE_CLIENT_KEY] {
            assert_eq!(shown(&mask(rule, &long), &long), "••••", "{rule}");
        }

        // A docker `auth` is base64 of `user:password`; its start is the user name.
        let auth = format!("{}==", random(ALNUM, 42, 3));
        let text = format!("{{\"auths\":{{\"ghcr.io\":{{\"auth\": \"{auth}\"}}}}}}");
        let found = scan_text("config.json", &text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, DOCKER_AUTH);
        let masked = mask(found[0].rule, &found[0].secret);
        assert_eq!(masked, "•••• (44 chars)");
        let windows: Vec<String> = auth
            .as_bytes()
            .windows(3)
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect();
        assert!(windows.iter().all(|window| !masked.contains(window.as_str())));

        // Short provider keys are hidden too: a prefix plus a tail would be most of the value.
        let short = format!("glpat-{}", random(ALNUM, 12, 4));
        assert_eq!(shown(&mask("gitlab", &short), &short), "••••");
    }

    #[test]
    fn mask_shows_at_most_the_public_prefix_and_a_short_tail() {
        // 40-character AWS secret: no public prefix, only the last four characters.
        let aws_secret = random(ALNUM, 40, 1);
        assert_eq!(
            shown(&mask("aws-secret-key", &aws_secret), &aws_secret),
            format!("…{}", &aws_secret[36..])
        );

        // 20-character access key id: the prefix and two characters.
        let access_key = format!("AKIA{}", random(UPPER, 16, 2));
        assert_eq!(
            shown(&mask("aws-access-key", &access_key), &access_key),
            format!("AKIA…{}", &access_key[18..])
        );

        let cases = [
            ("anthropic", "sk-ant-", anthropic_key(3)),
            ("github", "ghp_", format!("ghp_{}", random(ALNUM, 36, 4))),
            ("slack", "xoxb-", format!("xoxb-{}", random(ALNUM, 40, 5))),
            ("stripe", "sk_live_", format!("sk_live_{}", random(ALNUM, 24, 6))),
            ("openai", "sk-proj-", format!("sk-proj-{}", random(ALNUM, 48, 7))),
            ("telegram", "", format!("12345678:AA{}", random(ALNUM, 33, 8))),
        ];
        for (rule, prefix, key) in cases {
            let masked = mask(rule, &key);
            let visible = shown(&masked, &key);
            let (head, tail) = visible.split_once('…').expect("prefix…tail");
            assert_eq!(head, prefix, "{rule}: only the public prefix is shown");
            assert!((2..=4).contains(&tail.len()), "{rule}: tail is {tail:?}");
            assert!(key.ends_with(tail));
            let secret_part = key.len() - prefix.len();
            assert!(
                tail.len() * 8 <= secret_part,
                "{rule}: at most an eighth of the secret part"
            );
            // Nothing else: no five consecutive characters of the secret part appear.
            let hidden = &key[prefix.len()..key.len() - tail.len()];
            for window in hidden.as_bytes().windows(5) {
                assert!(
                    !masked.contains(std::str::from_utf8(window).unwrap()),
                    "{rule} leaks {masked}"
                );
            }
        }
    }

    #[test]
    fn debug_output_of_a_finding_is_redacted() {
        let dir = TempDir::new("debug");
        let key = anthropic_key(1);
        dir.write(".env", &format!("ANTHROPIC_API_KEY={key}\n"));
        let scan = scan(&files_under(&dir.0));
        assert_eq!(scan.findings.len(), 1);
        let debug = format!("{scan:?}");
        assert!(!debug.contains(&key) && !debug.contains(&key[20..40]), "{debug}");
    }

    #[test]
    fn secrets_that_merely_contain_a_placeholder_marker_are_reported() {
        let cases = [
            "DB_PASSWORD=p4ssw0rd<Zq9!x",
            "DB_PASSWORD=Zq9>k2M<x7Lw",
            "API_TOKEN=aB3insertK9sampleQ2dummyZ7",
            "SECRET_KEY=Zq9...Ab3***Xy7xxxxK2",
            "ADMIN_PASSWORD=Tr0ub4dor${x}Zq",
            "SERVICE_PASSWORD=p4ss(w0rd)Zq9",
        ];
        for line in cases {
            assert_eq!(rules_hit(".env", &format!("{line}\n")), [GENERIC], "{line}");
        }
        // A real key is not dropped because of the letters it happens to contain.
        let key = format!("ghp_{}dummyxxxxsample{}", random(ALNUM, 12, 1), random(ALNUM, 12, 2));
        assert_eq!(rules_hit(".env", &format!("GH={key}\n")), ["github"]);
    }

    #[test]
    fn placeholders_are_whole_value_shapes() {
        for value in [
            "<your-key>",
            "<token>",
            "xxxxxxxx",
            "XXXXXXXXXXXXXXXX",
            "********",
            "...",
            "changeme",
            "changeme123",
            "CHANGE_ME",
            "your_api_key_here",
            "your-token",
            "${VAR}",
            "${DB_PASSWORD:-}",
            "$DB_PASSWORD",
            "%API_KEY%",
            "{{ secrets.token }}",
            "$(gh auth token)",
            "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx",
            "sk-proj-...",
            "AKIAIOSFODNN7EXAMPLE",
            "replace-with-your-token",
            "dummy",
            "REDACTED",
        ] {
            assert!(is_placeholder(value), "{value} is a placeholder");
        }
        for value in [
            "p4ssw0rd<Zq9!x",
            "secret-password",
            "hunter2Zq9",
            "Zq9...Ab3",
            "a<b>c9Zq",
            "insertK9sampleQ2",
        ] {
            assert!(!is_placeholder(value), "{value} is not a placeholder");
        }
        assert!(rules_hit(".env", "API_TOKEN=os.getenv(\nAPI_TOKEN=get_token()\n").is_empty());
    }

    #[test]
    fn pgp_key_is_reported_without_claiming_it_is_unencrypted() {
        let text = format!(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{}\n-----END PGP PRIVATE KEY BLOCK-----\n",
            random(ALNUM, 60, 1)
        );
        let found = scan_text("backup.key", &text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, PGP_KEY);
        assert_eq!(found[0].provider, "PGP private key");
        let masked = mask(found[0].rule, &found[0].secret);
        assert!(masked.contains("not checked"), "{masked}");
        for wording in [found[0].provider, masked.as_str()] {
            assert!(!wording.to_lowercase().contains("unencrypted"), "{wording}");
        }
        // PEM keys keep their own rule and wording.
        let pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n", random(ALNUM, 40, 2));
        assert_eq!(rules_hit("id_rsa", &pem), [PRIVATE_KEY]);
    }

    #[test]
    fn findings_are_grouped_by_secret_even_when_the_masks_are_equal() {
        let dir = TempDir::new("group");
        let first = random(ALNUM, 12, 1);
        let second = random(ALNUM, 12, 2);
        assert_eq!(mask(GENERIC, &first), mask(GENERIC, &second), "the masks are identical");
        dir.write("a/.env", &format!("DB_PASSWORD={first}\nREDIS_PASSWORD={second}\n"));
        dir.write("b/.env", &format!("DB_PASSWORD={first}\nREDIS_PASSWORD={second}\n"));

        let scan = scan(&files_under(&dir.0));
        let order: Vec<(usize, &str, bool)> = scan
            .findings
            .iter()
            .map(|f| (f.secret_id, f.name.as_deref().unwrap(), f.path.ends_with("a/.env")))
            .collect();
        assert_eq!(
            order,
            [
                (1, "DB_PASSWORD", true),
                (1, "DB_PASSWORD", false),
                (2, "REDIS_PASSWORD", true),
                (2, "REDIS_PASSWORD", false)
            ]
        );

        let text = SecretsReport::new("2026-01-01T00:00:00+00:00".to_string(), scan).to_text();
        assert_eq!(text.matches("(in 2 places)").count(), 2, "{text}");
        assert_eq!(
            text.matches("•••• (12 chars)").count(),
            2,
            "one header per secret:\n{text}"
        );
        assert_eq!(
            text.matches("Generic (by name)").count(),
            2,
            "summary row and one section:\n{text}"
        );
    }

    #[test]
    fn secret_ids_do_not_depend_on_the_values() {
        // Swapping the two values must not change the numbering: ids follow
        // the location, so they say nothing about the secrets themselves.
        let number = |first: &str, second: &str| {
            let dir = TempDir::new("ids");
            dir.write(".env", &format!("A_TOKEN={first}\nB_TOKEN={second}\n"));
            let scan = scan(&files_under(&dir.0));
            scan.findings
                .iter()
                .map(|f| (f.name.clone().unwrap(), f.secret_id))
                .collect::<Vec<_>>()
        };
        let (low, high) = (
            format!("aaaa{}", random(ALNUM, 28, 1)),
            format!("zzzz{}", random(ALNUM, 28, 2)),
        );
        assert_eq!(number(&low, &high), number(&high, &low));
        assert_eq!(
            number(&low, &high),
            [("A_TOKEN".to_string(), 1), ("B_TOKEN".to_string(), 2)]
        );
    }

    #[test]
    fn skipped_files_are_counted_and_utf16_is_decoded() {
        let dir = TempDir::new("skip");
        let key = anthropic_key(1);

        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend(
            format!("# note\r\nANTHROPIC_API_KEY={key}\r\n")
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let utf16_path = dir.0.join("utf16.env");
        std::fs::write(&utf16_path, utf16).unwrap();

        let mut utf16_be = vec![0xFE, 0xFF];
        utf16_be.extend(
            format!("OTHER={}\n", anthropic_key(2))
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        );
        let utf16_be_path = dir.0.join("utf16be.env");
        std::fs::write(&utf16_be_path, utf16_be).unwrap();

        let binary = dir.0.join("binary.env");
        std::fs::write(&binary, [b'K', 0, 1, 2, b'=', 0]).unwrap();
        // UTF-16 without a byte order mark cannot be told from binary data.
        let no_bom = dir.0.join("nobom.env");
        std::fs::write(
            &no_bom,
            format!("K={key}")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        )
        .unwrap();
        let large = dir.0.join("large.env");
        std::fs::File::create(&large)
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        let missing = dir.0.join("missing.env");

        let scan = scan(&[utf16_path, utf16_be_path, binary, no_bom, large, missing]);
        assert_eq!(scan.files_scanned, 2);
        assert_eq!(
            scan.skipped,
            SkippedFiles {
                too_large: 1,
                binary: 2,
                unreadable: 1
            }
        );
        assert_eq!(scan.files_skipped, 4);
        assert_eq!(scan.findings.len(), 2);
        let found = scan.findings.iter().find(|f| f.path.ends_with("utf16.env")).unwrap();
        assert_eq!(
            (found.rule, found.line, found.name.as_deref()),
            ("anthropic", 2, Some("ANTHROPIC_API_KEY"))
        );

        let report = SecretsReport::new("2026-01-01T00:00:00+00:00".to_string(), scan);
        let json: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(json["files_skipped"], 4);
        assert_eq!(json["skipped"]["too_large"], 1);
        assert_eq!(json["skipped"]["binary"], 2);
        let text = report.to_text();
        assert!(
            text.contains("4 files skipped, not scanned: 1 over 8 MB, 2 binary or not text, 1 unreadable"),
            "{text}"
        );
    }

    #[test]
    fn skipped_files_are_reported_even_without_findings() {
        let dir = TempDir::new("skip-empty");
        let binary = dir.0.join("binary.env");
        std::fs::write(&binary, [0u8, 1, 2]).unwrap();
        let text = SecretsReport::new("2026-01-01T00:00:00+00:00".to_string(), scan(&[binary])).to_text();
        assert!(
            text.contains("1 files skipped, not scanned: 1 binary or not text"),
            "{text}"
        );
        assert!(text.contains("No secrets found."));

        let clean = dir.write("clean.env", "DEBUG=true\n");
        let text = SecretsReport::new("2026-01-01T00:00:00+00:00".to_string(), scan(&[clean])).to_text();
        assert!(!text.contains("skipped"), "{text}");
    }

    fn url_secrets(line: &str) -> Vec<String> {
        scan_text(".env", &format!("{line}\n"))
            .into_iter()
            .map(|found| {
                assert_eq!(found.rule, URL_PASSWORD, "{line}");
                found.secret
            })
            .collect()
    }

    #[test]
    fn url_password_may_contain_at_and_slash() {
        let cases = [
            (
                "DATABASE_URL=postgres://app:Zq9@K2m!x7@db.prod.internal:5432/app",
                "Zq9@K2m!x7",
            ),
            (
                "DATABASE_URL=postgres://app:Zq9/K2mx7@db.prod.internal/app",
                "Zq9/K2mx7",
            ),
            (
                "DATABASE_URL=postgres://app:Zq9/K2@mx7@db.prod.internal:5432/app?sslmode=require",
                "Zq9/K2@mx7",
            ),
            (
                "DATABASE_URL=postgres://app:Zq9%40K2%2Fx7@db.prod.internal/app",
                "Zq9@K2/x7",
            ),
            (
                "DATABASE_URL=postgres://app:Zq9@K2m/x7@db.prod.internal/app",
                "Zq9@K2m/x7",
            ),
            ("REDIS_URL=redis://:Zq9K2mx7Lw@cache.prod.internal:6379/0", "Zq9K2mx7Lw"),
            ("AMQP=\"amqps://svc:Zq9K2mx7Lw@[2001:db8::1]:5671/vhost\"", "Zq9K2mx7Lw"),
            (
                "NPM=https://ci:Zq9K2mx7Lw@registry.corp.io/path/@scope/pkg",
                "Zq9K2mx7Lw",
            ),
        ];
        for (line, password) in cases {
            assert_eq!(url_secrets(line), [password], "{line}");
        }
        // The encoded and the plain spelling are the same secret.
        assert_eq!(percent_decode("a%40b%2Fc%zz%4"), "a@b/c%zz%4");
    }

    #[test]
    fn url_without_credentials_is_not_reported() {
        for line in [
            "URL=https://example.com:8080/a@b",
            "URL=http://localhost:3000/users/@me",
            "URL=http://[::1]:8080/a@b",
            "URL=mongodb://host1:27017,host2:27017/db?owner=a@b",
            "URL=https://registry.npmjs.org/@scope/pkg",
            "IMAGE=docker://nginx:latest@sha256:0123456789abcdef",
            "URL=https://user:${DB_PASSWORD}@db.prod.internal/app",
            "URL=https://user:<password>@db.prod.internal/app",
            "URL=https://user:hunter2Zq9@example.com/docs",
        ] {
            assert!(
                rules_hit(".env", &format!("{line}\n")).is_empty(),
                "{line}: {:?}",
                rules_hit(".env", line)
            );
        }
    }

    #[test]
    fn development_defaults_on_local_hosts_are_not_reported() {
        for line in [
            "DATABASE_URL=postgres://postgres:postgres@localhost:5432/app",
            "DATABASE_URL=postgres://app:app@db:5432/app",
            "DATABASE_URL=mysql://root:password@127.0.0.1:3306/app",
            "DATABASE_URL=mysql://root:ROOT@[::1]/app",
            "REDIS_URL=redis://:secret@redis:6379",
            "AMQP_URL=amqp://guest:guest@rabbitmq",
            "MONGO_URL=mongodb://admin:changeme@mongo.localhost/app",
        ] {
            assert!(url_secrets(line).is_empty(), "{line}");
        }
        // The same weak password on a real host is a finding, and so is a
        // real-looking password on a local one.
        assert_eq!(
            url_secrets("DATABASE_URL=postgres://postgres:postgres@db.prod.internal/app"),
            ["postgres"]
        );
        assert_eq!(url_secrets("DATABASE_URL=postgres://app:app12@10.0.0.5/app"), ["app12"]);
        assert_eq!(
            url_secrets("DATABASE_URL=postgres://postgres:Zq9K2mx7Lw@localhost/app"),
            ["Zq9K2mx7Lw"]
        );
        assert_eq!(
            url_secrets("DATABASE_URL=postgres://app:Zq9K2mx7Lw@db/app"),
            ["Zq9K2mx7Lw"]
        );
    }
}
