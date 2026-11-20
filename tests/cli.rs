//! End-to-end runs of the `swordcheck` binary.
//!
//! Every run gets its own home directory (`HOME` and `SWORDCHECK_HOME`), so
//! the scans see only the fixtures written here and never the real home.
//! The audit itself reads this Mac's settings: it is read-only, like in CI.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_swordcheck");

/// A closed local port: with it as the proxy, every online lookup fails at
/// once instead of reaching the network.
const DEAD_PROXY: &str = "http://127.0.0.1:9";

/// A temporary home directory that is deleted when the test ends.
struct Home(PathBuf);

impl Home {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("swordcheck-cli-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The scans report resolved paths (/private/var/… for /var/…).
        Self(std::fs::canonicalize(&dir).unwrap())
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.path(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// A project with a lockfile and one installed npm package, plus a
    /// known malicious one when `malware` is set.
    fn project(&self, relative: &str, malware: bool) -> PathBuf {
        self.write(
            &format!("{relative}/package-lock.json"),
            r#"{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.15"}}}"#,
        );
        self.write(
            &format!("{relative}/node_modules/left-pad/package.json"),
            r#"{"name":"left-pad","version":"1.3.0"}"#,
        );
        if malware {
            self.write(
                &format!("{relative}/node_modules/event-stream/package.json"),
                r#"{"name":"event-stream","version":"3.3.6"}"#,
            );
        }
        self.path(relative)
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(args)
            .env("HOME", &self.0)
            .env("SWORDCHECK_HOME", self.path(".swordcheck"))
            .env("NO_COLOR", "1")
            .env_remove("NVD_API_KEY");
        command
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A password-like value that is not written out in the source.
fn password(seed: u64) -> String {
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..20)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            alphabet[(state >> 33) as usize % alphabet.len()] as char
        })
        .collect()
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(["-c", "user.name=test", "-c", "user.email=test@example.invalid"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
        .status;
    assert!(status.success(), "git {args:?}");
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn str(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn report_scans_the_home_directory() {
    let home = Home::new("report");
    let app = home.project("projects/app", true);
    let tracked = password(1);
    let pgpass = password(2);
    home.write(
        "projects/app/.env",
        &format!("DATABASE_URL=postgres://app:{tracked}@db.prod.internal/app\n"),
    );
    git(&app, &["init", "-q"]);
    git(&app, &["add", ".env"]);
    git(&app, &["commit", "-qm", "fixture"]);
    home.write(".pgpass", &format!("db.prod.internal:5432:app:appuser:{pgpass}\n"));
    let out = home.path("report.html");

    let first = home.run(&["--report", str(&out)]);
    assert_eq!(
        first.status.code(),
        Some(1),
        "malware and a leaked secret: {}",
        stderr(&first)
    );
    assert!(stderr(&first).contains("Report written:"));
    let html = std::fs::read_to_string(&out).unwrap();
    for text in [
        "Security check-up of this Mac",
        "event-stream@3.3.6",
        "~/projects/app/node_modules/event-stream",
        "Revoke <strong>DATABASE_URL</strong> in app/.env.",
        "~/.pgpass",
        "1 lockfile · 1 package",
        "Online lookups off: nothing left this Mac",
    ] {
        assert!(html.contains(text), "{text}");
    }
    assert!(
        !html.contains(&tracked) && !html.contains(&pgpass),
        "raw secrets never reach the page"
    );

    // The audit was saved, so the next report compares with it.
    let history = std::fs::read_to_string(home.path(".swordcheck/history.json")).unwrap();
    assert_eq!(history.matches("\"timestamp\"").count(), 1);
    home.run(&["--report", str(&out)]);
    assert!(std::fs::read_to_string(&out).unwrap().contains(" since "));
}

#[test]
fn report_with_failed_online_lookups_is_incomplete() {
    let home = Home::new("online");
    let app = home.project("app", false);
    // An exception keeps the audit out of the exit code, whatever this Mac's setting.
    let config = home.write("audit.toml", "[exceptions]\nsip = \"not under test\"\n");
    let out = home.path("report.html");
    // Offline, a clean project and an exempted check: nothing to report.
    let mut offline = vec!["--report", str(&out), "--only", "sip", "--config", str(&config)];
    for flag in ["--vulns-path", "--npm-path", "--secrets-path"] {
        offline.extend([flag, str(&app)]);
    }
    let output = home.run(&offline);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let output = home
        .command(&[
            "--report",
            str(&out),
            "--online",
            "--only",
            "sip",
            "--config",
            str(&config),
            "--vulns-path",
            str(&app),
            "--npm-path",
            str(&app),
            "--secrets-path",
            str(&app),
        ])
        .env("https_proxy", DEAD_PROXY)
        .env("HTTPS_PROXY", DEAD_PROXY)
        .env("http_proxy", DEAD_PROXY)
        .env("ALL_PROXY", DEAD_PROXY)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let html = std::fs::read_to_string(&out).unwrap();
    for text in [
        "Online lookups on",
        "OSV lookup failed",
        "The OSV lookup failed, so the packages it did not answer for were checked against the built-in list only",
        "0 apps and formulae",
    ] {
        assert!(html.contains(text), "{text}");
    }
    assert!(
        !home.path(".swordcheck/history.json").exists(),
        "--only is a partial run"
    );
}

#[test]
fn report_rejects_bad_paths_before_scanning() {
    let home = Home::new("paths");
    let app = home.project("app", false);
    let readme = home.write("README.md", "hello\n");
    let missing = home.path("missing");
    let out = home.path("report.html");
    let cases: [(&[&str], &str); 4] = [
        (&["--vulns-path", str(&readme)], "is not a lockfile this tool can read"),
        (&["--vulns-path", str(&missing)], "not found"),
        (
            &["--vulns-path", str(&app), "--npm-path", str(&missing)],
            "is not a directory",
        ),
        (
            &[
                "--vulns-path",
                str(&app),
                "--npm-path",
                str(&app),
                "--secrets-path",
                str(&missing),
            ],
            "not found",
        ),
    ];
    for (paths, message) in cases {
        let mut args = vec!["--report", str(&out)];
        args.extend_from_slice(paths);
        let output = home.run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains(message), "{args:?}: {}", stderr(&output));
        assert!(!out.exists());
    }

    // An output file that cannot be written is rejected before any scan runs,
    // not after minutes of online lookups.
    let scope = [
        "--vulns-path",
        str(&app),
        "--npm-path",
        str(&app),
        "--secrets-path",
        str(&app),
    ];
    let missing_folder = home.path("missing/r.html");
    for (target, message) in [(str(&missing_folder), "does not exist"), (str(&app), "is a directory")] {
        let mut args = vec!["--report", target, "--no-history"];
        args.extend(scope);
        let output = home.run(&args);
        assert_eq!(output.status.code(), Some(2), "{target}");
        assert!(stderr(&output).contains(message), "{target}: {}", stderr(&output));
        assert!(
            !stderr(&output).contains('›'),
            "nothing was scanned: {}",
            stderr(&output)
        );
    }
    let output = home.run(&["--only", "sip", "-o", str(&missing_folder)]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));

    // A bare file name goes to the current folder.
    let mut args = vec!["--report", "relative.html", "--only", "sip", "--no-history"];
    args.extend(scope);
    home.command(&args).current_dir(&home.0).output().unwrap();
    assert!(home.path("relative.html").is_file());
}

#[test]
fn a_closed_stderr_does_not_lose_the_report() {
    // `swordcheck --report r.html 2>&1 | head` once head has exited: every
    // write to stderr fails, which must not stop the report or change the exit code.
    let home = Home::new("stderr");
    let app = home.project("app", false);
    let app = str(&app);
    let report = home.path("report.html");
    let json = home.path("audit.json");
    let runs: [Vec<&str>; 2] = [
        vec![
            "--report",
            str(&report),
            "--no-history",
            "--vulns-path",
            app,
            "--npm-path",
            app,
            "--secrets-path",
            app,
        ],
        vec!["--only", "sip", "--no-history", "--format", "json", "-o", str(&json)],
    ];
    for args in runs {
        let normal = home.run(&args).status.code();
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let closed = home
            .command(&args)
            .stdout(std::process::Stdio::null())
            .stderr(writer)
            .status()
            .unwrap()
            .code();
        assert_eq!(closed, normal, "{args:?}");
    }
    assert!(std::fs::read_to_string(&report).unwrap().contains("Security check-up"));
    assert!(std::fs::read_to_string(&json).unwrap().starts_with('{'));
}

#[test]
fn scan_modes_accept_paths() {
    let home = Home::new("modes");
    let app = home.project("app", false);
    let app = str(&app);
    for args in [
        ["--npm", "--json", "--npm-path", app],
        ["--secrets", "--json", "--secrets-path", app],
        ["--vulns", "--json", "--vulns-path", app],
    ] {
        let output = home.run(&args);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {}", stderr(&output));
        assert!(String::from_utf8_lossy(&output.stdout).starts_with('{'), "{args:?}");
    }
    let output = home
        .command(&["--vulns", "--online", "--quiet", "--vulns-path", app])
        .env("https_proxy", DEAD_PROXY)
        .env("HTTPS_PROXY", DEAD_PROXY)
        .env("ALL_PROXY", DEAD_PROXY)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn audit_keeps_going_when_the_history_is_unusable() {
    // A corrupt history is reported and left alone.
    let home = Home::new("corrupt");
    let history = home.write(".swordcheck/history.json", "{not json");
    let output = home.run(&["--format", "json"]);
    assert_ne!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("history unavailable"), "{}", stderr(&output));
    assert_eq!(std::fs::read_to_string(&history).unwrap(), "{not json");

    // A history folder that cannot be written to: the audit still reports.
    let home = Home::new("readonly");
    let folder = home.path(".swordcheck");
    std::fs::create_dir_all(&folder).unwrap();
    let mode = |mode| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(0o500);
    let output = home.run(&["--format", "json"]);
    mode(0o700);
    assert_ne!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("could not save history"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_closed_stdout_keeps_the_exit_code() {
    // `swordcheck --list | head -1` once head has exited: a write to stdout
    // fails, which must not turn into a panic and exit code 101.
    let home = Home::new("stdout");
    for args in [&["--list"][..], &["--history"][..]] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = home
            .command(args)
            .stdout(writer)
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{args:?}: {}", stderr(&output));
        assert!(!stderr(&output).contains("panicked"), "{args:?}: {}", stderr(&output));
    }
}

#[test]
fn notes_and_warnings_reach_stderr() {
    // An audit.toml in the current directory is announced.
    let home = Home::new("notes");
    home.write("audit.toml", "[exceptions]\nsip = \"not under test\"\n");
    let output = home
        .command(&["--only", "sip", "--no-history", "--json"])
        .current_dir(&home.0)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).contains("using ./audit.toml"), "{}", stderr(&output));

    // A failed OSV query for npm says so, and the scan is incomplete.
    let app = home.project("app", false);
    let output = home
        .command(&["--npm", "--online", "--npm-path", str(&app)])
        .env("https_proxy", DEAD_PROXY)
        .env("HTTPS_PROXY", DEAD_PROXY)
        .env("ALL_PROXY", DEAD_PROXY)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("OSV query failed"), "{}", stderr(&output));
}

#[test]
fn secrets_say_when_git_cannot_tell_whether_a_file_is_tracked() {
    let home = Home::new("gitshim");
    let app = home.path("app");
    let secret = password(303);
    home.write(
        "app/.env",
        &format!("DATABASE_URL=postgres://app:{secret}@db.prod.internal/app\n"),
    );
    git(&app, &["init", "-q"]);
    git(&app, &["add", ".env"]);
    git(&app, &["commit", "-qm", "fixture"]);

    // With a working git the leak is reported, and the run fails.
    let output = home.run(&["--secrets", "--secrets-path", str(&app)]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("TRACKED IN GIT"), "{text}");

    // The git of a Mac without the Command Line Tools: an error, exit 1.
    let shim = home.write(
        "shim/git",
        "#!/bin/sh\necho 'xcrun: error: invalid active developer path' >&2\nexit 1\n",
    );
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:/usr/bin:/bin", str(&home.path("shim")));
    for json in [false, true] {
        let mut args = vec!["--secrets", "--secrets-path", str(&app)];
        if json {
            args.push("--json");
        }
        let output = home.command(&args).env("PATH", &path).output().unwrap();
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        assert_eq!(output.status.code(), Some(3), "unknown is not clean: {out}");
        assert!(!out.contains(&secret), "the raw secret is never printed");
        if json {
            assert!(out.contains("\"git_unknown\": true"), "{out}");
        } else {
            assert!(out.contains("GIT STATUS UNKNOWN"), "{out}");
            assert!(
                out.contains("git could not tell whether the file is tracked: 1"),
                "{out}"
            );
            assert!(!out.contains("TRACKED IN GIT"), "{out}");
        }
    }
}

#[test]
fn a_lockfile_that_cannot_be_read_makes_the_scan_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new("unread");
    let app = home.project("app", false);
    let locked = home.write(
        "other/package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"0.21.0"}}}"#,
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let config = home.write("audit.toml", "[exceptions]\nsip = \"not under test\"\n");
    let out = home.path("report.html");

    let vulns = home.run(&["--vulns", "--json", "--vulns-path", str(&home.0)]);
    let report = home.run(&[
        "--report",
        str(&out),
        "--only",
        "sip",
        "--config",
        str(&config),
        "--vulns-path",
        str(&home.0),
        "--npm-path",
        str(&app),
        "--secrets-path",
        str(&app),
    ]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();

    let json = String::from_utf8_lossy(&vulns.stdout);
    assert_eq!(
        vulns.status.code(),
        Some(3),
        "an unread lockfile is not a clean scan: {json}"
    );
    assert!(json.contains("\"reason\": \"permission denied\""), "{json}");
    assert!(json.contains("other/package-lock.json"), "{json}");
    assert_eq!(report.status.code(), Some(3), "{}", stderr(&report));
    let html = std::fs::read_to_string(&out).unwrap();
    assert!(html.contains("1 lockfile could not be read"), "the report says so");
}

#[test]
fn quiet_summaries_say_when_a_scan_is_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new("quiet");
    let clean = home.project("clean", false);
    let unread = home.project("unread", false);
    std::fs::set_permissions(unread.join("package-lock.json"), std::fs::Permissions::from_mode(0o000)).unwrap();
    home.write(
        "loose/.env",
        &format!("DATABASE_URL=postgres://app:{}@db.prod.internal/app\n", password(1005)),
    );
    let loose = home.path("loose");
    // The git of a Mac without the Command Line Tools: an error, exit 1.
    let shim = home.write("shim/git", "#!/bin/sh\necho 'xcrun: error' >&2\nexit 1\n");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let shim_path = format!("{}:/usr/bin:/bin", str(&home.path("shim")));
    let quiet = |output: Output| {
        let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (output.status.code(), line)
    };
    let offline = |args: &[&str]| {
        home.command(args)
            .env("https_proxy", DEAD_PROXY)
            .env("HTTPS_PROXY", DEAD_PROXY)
            .env("ALL_PROXY", DEAD_PROXY)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .unwrap()
    };

    // Clean scans keep their summary exactly as before.
    assert_eq!(
        quiet(home.run(&["--vulns", "-q", "--vulns-path", str(&clean)])),
        (Some(0), "0 findings, 0 known-exploited".to_string())
    );
    assert_eq!(
        quiet(home.run(&["--npm", "-q", "--npm-path", str(&clean)])),
        (Some(0), "0 malicious, 0 suspicious".to_string())
    );

    // Incomplete scans (exit 3) say so and why.
    assert_eq!(
        quiet(home.run(&["--vulns", "-q", "--vulns-path", str(&unread)])),
        (
            Some(3),
            "0 findings, 0 known-exploited; incomplete: 1 lockfile not read".to_string()
        )
    );
    std::fs::set_permissions(unread.join("package-lock.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, line) = quiet(offline(&["--vulns", "-q", "--online", "--vulns-path", str(&clean)]));
    assert_eq!(code, Some(3), "{line}");
    assert!(
        line.starts_with("0 findings, 0 known-exploited; incomplete: "),
        "{line}"
    );
    assert!(line.ends_with("lookups failed"), "{line}");
    assert_eq!(
        quiet(offline(&["--npm", "-q", "--online", "--npm-path", str(&clean)])),
        (
            Some(3),
            "0 malicious, 0 suspicious; incomplete: 1 OSV lookup failed".to_string()
        )
    );
    let output = home
        .command(&["--secrets", "-q", "--secrets-path", str(&loose)])
        .env("PATH", &shim_path)
        .output()
        .unwrap();
    assert_eq!(
        quiet(output),
        (
            Some(3),
            "1 secrets, 1 locations, 0 tracked in git; incomplete: 1 location with unknown git status".to_string()
        )
    );
}

/// A `curl` that answers OSV, CISA KEV and EPSS from the files in `$FAKE`
/// and fails for anything else, so the online scan runs without a network.
const FAKE_CURL: &str = r#"#!/bin/sh
input=$(cat)
case "$*" in *querybatch*) cat "$FAKE/batch.json"; exit 0;; esac
case "$input" in
  *"output = "*)
    printf '%s\n' "$input" | while IFS= read -r line; do
      case "$line" in
        "url = "*) id=${line##*/}; id=${id%\"};;
        "output = "*) out=${line#output = \"}; cp "$FAKE/$id.json" "${out%\"}";;
      esac
    done
    exit 0;;
  *cisa.gov*) [ -f "$FAKE/kev.json" ] && cat "$FAKE/kev.json" && exit 0;;
  *api.first.org*) echo '{"data": []}'; exit 0;;
esac
echo "curl: (7) Failed to connect to fake host" >&2
exit 7
"#;

#[test]
fn online_scan_joins_the_kev_catalog_and_says_when_it_is_stale() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new("kev");
    let app = home.project("app", false);
    let shim = home.write("shim/curl", FAKE_CURL);
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let shim_path = format!("{}:/usr/bin:/bin", str(&home.path("shim")));
    home.write(
        "fake/batch.json",
        r#"{"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2024-01-01T00:00:00Z"}]}]}"#,
    );
    // One advisory, two CVEs in the catalog; only the second is used in ransomware.
    home.write(
        "fake/GHSA-aaaa-bbbb-cccc.json",
        r#"{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2024-1", "CVE-2024-2"], "summary": "Test",
            "database_specific": {"severity": "HIGH"}}"#,
    );
    home.write(
        "fake/kev.json",
        r#"{"vulnerabilities": [
            {"cveID": "CVE-2024-1", "dateAdded": "2024-02-01", "knownRansomwareCampaignUse": "Unknown"},
            {"cveID": "CVE-2024-2", "dateAdded": "2024-03-01", "knownRansomwareCampaignUse": "Known"}
        ]}"#,
    );
    let scan = || {
        let output = home
            .command(&["--vulns", "--online", "--json", "--vulns-path", str(&app)])
            .env("PATH", &shim_path)
            .env("FAKE", home.path("fake"))
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("a JSON report");
        (output.status.code(), report)
    };

    // The downloaded catalog, then the cached copy of the same day.
    for run in ["downloaded", "cached"] {
        let (code, report) = scan();
        assert_eq!(code, Some(1), "{run}: {report}");
        assert_eq!(report["warnings"], serde_json::json!([]), "{run}");
        assert_eq!(
            report["findings"][0]["kev"],
            serde_json::json!({"date_added": "2024-03-01", "ransomware": true}),
            "{run}"
        );
        // From now on the download fails.
        let _ = std::fs::remove_file(home.path("fake/kev.json"));
    }

    // Older than a day and the download fails: the old copy is still used,
    // but the report says the catalog may be out of date.
    let ninety_days_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(90 * 24 * 60 * 60);
    std::fs::File::options()
        .write(true)
        .open(home.path(".swordcheck/cache/kev.json"))
        .unwrap()
        .set_modified(ninety_days_ago)
        .unwrap();
    let (code, report) = scan();
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["findings"][0]["kev"]["ransomware"], true);
    let warning = report["warnings"][0].as_str().unwrap();
    assert!(
        warning.starts_with(
            "CISA KEV download failed: curl: (7) Failed to connect to fake host; used the cached catalog of "
        ),
        "{warning}"
    );
    assert!(
        warning.ends_with(", which may miss recently added vulnerabilities."),
        "{warning}"
    );
}

/// A `curl` that answers OSV batch request N from `$FAKE/batchN.json` and
/// times out when that file is missing.
const NUMBERED_CURL: &str = r#"#!/bin/sh
cat > /dev/null
n=$(($(cat "$FAKE/count" 2>/dev/null || echo 0) + 1))
echo "$n" > "$FAKE/count"
[ -f "$FAKE/batch$n.json" ] && cat "$FAKE/batch$n.json" && exit 0
echo "curl: (28) Operation timed out" >&2
exit 28
"#;

#[test]
fn a_failed_osv_request_keeps_the_malware_found_before_it() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new("osv-partial");
    // 1001 packages take two OSV requests; the malicious one is in the first.
    for name in std::iter::once("aaa-evil".to_string()).chain((0..1000).map(|index| format!("pkg-{index:04}"))) {
        home.write(
            &format!("app/node_modules/{name}/package.json"),
            &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        );
    }
    let shim = home.write("shim/curl", NUMBERED_CURL);
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut first = vec![serde_json::json!({}); 1000];
    first[0] = serde_json::json!({"vulns": [{"id": "MAL-2025-1", "modified": "2025-01-01T00:00:00Z"}]});
    home.write("fake/batch1.json", &serde_json::json!({ "results": first }).to_string());
    home.write("fake/batch2.json", r#"{"results": [{}]}"#);
    let scan = || {
        let _ = std::fs::remove_file(home.path("fake/count"));
        let output = home
            .command(&["--npm", "--online", "--json", "--npm-path", str(&home.path("app"))])
            .env("PATH", format!("{}:/usr/bin:/bin", str(&home.path("shim"))))
            .env("FAKE", home.path("fake"))
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("a JSON report");
        let malware: Vec<String> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["reason"].as_str().unwrap().contains("MAL-2025-1"))
            .map(|finding| finding["package"].as_str().unwrap().to_string())
            .collect();
        (output.status.code(), report["online"].clone(), malware, stderr(&output))
    };

    // Both requests answered.
    let (code, online, malware, err) = scan();
    assert_eq!(
        (code, online, malware),
        (Some(1), serde_json::json!(true), vec!["aaa-evil".to_string()])
    );
    assert!(!err.contains("OSV"), "{err}");

    // The second request times out: the record from the first is still reported.
    std::fs::remove_file(home.path("fake/batch2.json")).unwrap();
    let (code, online, malware, err) = scan();
    assert_eq!(
        (code, online, malware),
        (Some(1), serde_json::json!(false), vec!["aaa-evil".to_string()])
    );
    assert!(
        err.contains(
            "OSV query failed: curl: (28) Operation timed out. \
             The packages it did not answer for were checked against the built-in list only."
        ),
        "{err}"
    );
}

#[test]
fn an_empty_or_relative_home_never_puts_the_history_in_the_current_folder() {
    let home = Home::new("relative-home");
    let work = home.path("project");
    std::fs::create_dir_all(&work).unwrap();
    for value in ["", "relative"] {
        let run = |args: &[&str]| {
            home.command(args)
                .env("HOME", value)
                .env_remove("SWORDCHECK_HOME")
                .current_dir(&work)
                .output()
                .unwrap()
        };
        let history = run(&["--history"]);
        assert_eq!(history.status.code(), Some(2), "HOME={value:?}");
        assert!(
            stderr(&history).contains("history directory (HOME is not set to an absolute path)"),
            "{}",
            stderr(&history)
        );
        let vulns = run(&["--vulns", "--online", "--vulns-path", str(&work)]);
        assert_eq!(vulns.status.code(), Some(2), "HOME={value:?}");
        assert!(stderr(&vulns).contains("cache directory (HOME is not set to an absolute path)"));
        let audit = run(&[]);
        assert!(matches!(audit.status.code(), Some(0 | 1)), "HOME={value:?}");
        // (npm, run by the supply-chain check, may still log under $HOME.)
        let history = work.join(value).join(".swordcheck");
        assert!(!history.exists(), "{} was created", history.display());
    }
}

/// A fake `npm`: `npm root -g` prints `$NPM_ROOT`, or fails when it is empty.
const ROOT_NPM: &str = r#"#!/bin/sh
[ "$1 $2" = "root -g" ] || exit 2
[ -n "$NPM_ROOT" ] && echo "$NPM_ROOT" && exit 0
echo "npm error code EACCES" >&2
exit 1
"#;

#[test]
fn npm_scan_says_when_npm_cannot_name_its_global_directory() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new("npm-root");
    // A custom prefix is found only through `npm root -g`.
    home.write(
        ".npm-packages/lib/node_modules/chalk/package.json",
        r#"{"name":"chalk","version":"5.6.1"}"#,
    );
    let root = home.path(".npm-packages/lib/node_modules");
    let shim = home.write("shim/npm", ROOT_NPM);
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str], npm_root: &str| {
        home.command(args)
            .env("PATH", format!("{}:/usr/bin:/bin", str(&home.path("shim"))))
            .env("NPM_ROOT", npm_root)
            .output()
            .unwrap()
    };

    // npm answers: the prefix is scanned and the malicious version found.
    let found = run(&["--npm", "--json"], str(&root));
    assert_eq!(found.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&found.stdout).unwrap();
    assert!(report.get("global_dir_problem").is_none());

    // npm fails: no all-clear, the reason is named and the scan is incomplete.
    let json = run(&["--npm", "--json"], "");
    assert_eq!(json.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        report["global_dir_problem"],
        "`npm root -g` failed: npm error code EACCES"
    );
    let text = run(&["--npm"], "");
    assert_eq!(text.status.code(), Some(3));
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(
        text.contains(
            "npm's own global directory could not be located, so it may not have been scanned: \
             `npm root -g` failed: npm error code EACCES."
        ),
        "{text}"
    );
    assert!(!text.contains("No known malicious packages found."), "{text}");
    let quiet = run(&["--npm", "-q"], "");
    assert_eq!(quiet.status.code(), Some(3));
    let quiet = String::from_utf8_lossy(&quiet.stdout);
    assert!(
        quiet.ends_with("; incomplete: 1 npm global directory not located\n"),
        "{quiet}"
    );
}

/// With `HOME` unset, empty or relative there is no home folder: the scans
/// that search it say so instead of reporting an empty, clean result, and
/// the audit never takes the current folder's files for the user's.
#[test]
fn without_a_home_folder_nothing_is_scanned_as_if_it_were_one() {
    let home = Home::new("no-home");
    let work = home.path("project");
    home.write(
        "project/.env",
        "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
    );
    home.write("project/.config/swordcheck/audit.toml", "skip = [\"sip\"]\n");
    let report = home.path("report.html");
    for value in [None, Some(""), Some("relative")] {
        let run = |args: &[&str]| {
            let mut command = home.command(args);
            match value {
                Some(value) => command.env("HOME", value),
                None => command.env_remove("HOME"),
            };
            command.current_dir(&work).output().unwrap()
        };
        let (report, work) = (str(&report), str(&work));
        for (args, flag) in [
            (vec!["--secrets"], "--secrets-path"),
            (vec!["--vulns"], "--vulns-path"),
            (vec!["--npm"], "--npm-path"),
            (
                vec!["--report", report, "--npm-path", work, "--secrets-path", work],
                "--vulns-path",
            ),
            (
                vec!["--report", report, "--vulns-path", work, "--secrets-path", work],
                "--npm-path",
            ),
            (
                vec!["--report", report, "--vulns-path", work, "--npm-path", work],
                "--secrets-path",
            ),
        ] {
            let output = run(&args);
            assert_eq!(output.status.code(), Some(2), "HOME={value:?} {args:?}");
            let message = stderr(&output);
            assert!(
                message.contains("HOME is not set to an absolute path, so there is no home folder to scan")
                    && message.contains(flag),
                "HOME={value:?} {args:?}: {message}"
            );
        }
        assert!(!Path::new(report).exists(), "no report is written");
        // An explicit path needs no home.
        let secrets = run(&["--secrets", "--secrets-path", work, "--json"]);
        assert_eq!(secrets.status.code(), Some(0), "HOME={value:?}");
        assert!(String::from_utf8_lossy(&secrets.stdout).contains("\"provider\": \"GitHub\""));

        let audit = run(&["--json", "--no-history", "--only", "sip,launch-items,npm-packages"]);
        let json: serde_json::Value = serde_json::from_slice(&audit.stdout).expect("a JSON report");
        let checks = json["checks"].as_array().unwrap();
        let result = |id: &str| {
            let check = checks.iter().find(|check| check["id"] == id).unwrap();
            (
                check["status"].as_str().unwrap().to_string(),
                check["detail"].as_str().unwrap().to_string(),
            )
        };
        // The current folder's .config/swordcheck/audit.toml is not the user's config.
        assert!(checks.iter().any(|check| check["id"] == "sip"), "HOME={value:?}");
        let (status, detail) = result("launch-items");
        assert!(
            status != "pass" && detail.contains("~/Library/LaunchAgents was not examined"),
            "{status}: {detail}"
        );
        let (status, detail) = result("npm-packages");
        assert!(
            status != "pass" && detail.contains("npm directories in the home folder were not located"),
            "{status}: {detail}"
        );
    }
}
