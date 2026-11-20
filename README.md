# SwordCheck

[![CI](https://github.com/SwordSec/SwordCheck/actions/workflows/ci.yml/badge.svg)](https://github.com/SwordSec/SwordCheck/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

A security check-up for your computer, by [SwordSec](https://swordsec.com).
It runs on macOS today; Linux and Windows are planned.

A small, fast Rust CLI that audits the security settings of your Mac, scores
them out of 100 and reports what to fix. It also finds known vulnerabilities
in your project dependencies, macOS, common apps and Homebrew formulae, scans
for malicious npm packages, and locates API keys scattered across `.env` and
config files.

https://github.com/user-attachments/assets/aeada071-fcdb-4b30-ab3d-1807fb02b6b2

The tool is **read-only**: it never changes a setting on your Mac. For every
problem it explains what to do, and where a single command does the job it
shows that command for you to run yourself.

## Install

SwordCheck runs on macOS (Apple silicon and Intel). Install the latest
release with:

```sh
curl -fsSL https://raw.githubusercontent.com/SwordSec/SwordCheck/main/install.sh | sh
```

The script downloads the release archive from GitHub, checks it against its
published SHA-256 and puts `swordcheck` in `~/.local/bin`. It never uses
`sudo`. Set `SWORDCHECK_VERSION=v0.1.0` to pick a release, or
`SWORDCHECK_INSTALL_DIR` to install elsewhere. You can also download the
archive yourself from the
[releases page](https://github.com/SwordSec/SwordCheck/releases). The binary
is not notarized: a copy downloaded with a browser has to be allowed once
under System Settings > Privacy & Security.

To build from source instead, you need a Rust toolchain (1.88 or newer, from
[rustup.rs](https://rustup.rs)):

```sh
git clone https://github.com/SwordSec/SwordCheck.git
cd SwordCheck
cargo install --path .
```

That puts `swordcheck` in `~/.cargo/bin`. The examples below use
`cargo run --`, which works straight from the checkout; with the installed
binary, write `swordcheck` instead.

## Usage

Run it without arguments to open the dashboard, pick a module and watch it
work:

```sh
cargo run
```

Every module is also available as a flag, for scripts and CI:

```sh
cargo run -- --format text        # colored text report of the audit
cargo run -- --json               # JSON output (scripts / CI)
cargo run -- --format html -o report.html
cargo run -- --report report.html # one HTML page with every module (see below)
cargo run -- --only filevault,sip # run selected checks only
cargo run -- --min-score 80 -q    # CI: exit code 1 if the score is below 80
cargo run -- --npm                # malicious npm package scan (global + projects)
cargo run -- --npm --online       # also query the OSV.dev malicious package database
cargo run -- --secrets            # find API keys in .env and config files
cargo run -- --secrets --secrets-path ~/project   # scan a single directory / file
cargo run -- --vulns              # inventory of lockfiles, macOS, known apps and Homebrew (offline)
cargo run -- --vulns --online     # look them up in OSV.dev, NVD, CISA KEV and EPSS
cargo run -- --help
```

Tests: `cargo test` (the end-to-end tests in `tests/cli.rs` run the binary
against a temporary home directory)

## Checks

`cargo run -- --list` prints the current list with id, weight and CIS section.

| Id | Check | Weight | Severity | Remedy |
| --- | --- | --- | --- | --- |
| `filevault` | FileVault (disk encryption) | 25 | critical | settings |
| `sip` | System Integrity Protection (SIP) | 20 | critical | settings |
| `gatekeeper` | Gatekeeper | 15 | high | settings |
| `auto-update` | Automatic updates | 10 | high | settings |
| `pending-updates` | Pending updates | 10 | medium | settings |
| `xprotect` | XProtect signatures | 5 | medium | settings |
| `firewall` | Firewall | 20 | high | command |
| `stealth` | Firewall stealth mode | 5 | low | command |
| `ssh` | Remote Login (SSH) | 10 | medium | settings |
| `sharing` | Sharing services | 10 | medium | settings |
| `airdrop` | AirDrop visibility | 5 | low | settings |
| `auto-login` | Automatic login | 10 | high | settings |
| `guest` | Guest account | 5 | medium | command |
| `screen-lock` | Screen lock password | 10 | medium | settings |
| `sudo` | Passwordless sudo | 10 | high | settings |
| `launch-items` | Launch items | 10 | medium | settings |
| `npm-packages` | Malicious npm packages | 15 | critical | settings |

`command` means the report prints a command you can run yourself; `settings`
means the advice points to the place in System Settings (or Recovery).

### Scoring

- `Pass` earns full weight, `Warn` half, `Fail` none.
- Checks whose state cannot be determined (`Unknown`) and checks with an
  exception are left out of the denominator. If that leaves nothing to
  score, the score is shown as `n/a`.
- A check never passes on a guess: a command that fails, times out (20 s)
  or prints something unexpected gives `Unknown` with the raw output.
- Grades: 90+ A, 75+ B, 60+ C, 40+ D, below that F.

### Exit code

| Code | Meaning |
| --- | --- |
| 0 | No failed check and the score is above the threshold |
| 1 | At least one check failed, or the score is below `--min-score` |
| 2 | Usage or configuration error |
| 3 | The scan is incomplete: `--npm` / `--vulns` / `--report` with `--online`: a lookup failed; `--vulns` / `--report`: a lockfile could not be read (no permission, over 64 MB, not UTF-8/UTF-16 text); `--secrets` / `--report`: git could not tell whether a file with a secret is tracked |

The scan modes use 1 for their own "found something" condition (described in
each section) and 3 when part of the scan could not be done and nothing was
found in the part that did work: a script must not read an incomplete scan as
a clean one. Lockfiles that could not be read are named in the report and
listed under `skipped` in the JSON output.
The dashboard is interactive and always exits with 0.

## Secret scan (`--secrets`)

Summarizes which API keys live in which files on this machine. Read-only, and
it never touches the network.

- **Where it looks:** in projects under your home directory: `.env*`, `*.env`,
  `*.tfstate`, `*.tfvars`, `*.pem`, `*.key`, `credentials.json`, `secrets.*`,
  `.mcp.json`, `.git/config`. In addition: `~/.aws/credentials`, `~/.npmrc`,
  `~/.netrc`, `~/.docker/config.json`, `~/.kube/config`, shell history and rc
  files, `~/.ssh`, and Claude / Cursor / VS Code settings.
- **What it skips:** dependency and build directories such as `node_modules`,
  `target`, `vendor` and `testdata`, hidden directories, `~/Library`,
  `~/go/pkg`.
- **Patterns:** Anthropic, OpenAI, OpenRouter, AWS, Google, DigitalOcean,
  GitHub, GitLab, Slack, Stripe, SendGrid, Twilio, npm, Hugging Face, Groq,
  Telegram, JWTs, passwords embedded in URLs and unencrypted private keys. On
  top of that, assignments whose name contains `SECRET` / `TOKEN` / `PASSWORD`
  / `API_KEY` and whose value looks random are reported under "Generic"
  (heuristic).
- **Template files** (`.env.example` etc.): only real key patterns are
  matched; made-up passwords are not reported.
- **Masking:** raw values are never written to any output. A finding shows
  at most the provider's public prefix (`sk-ant-`, `ghp_`, `AKIA`…) and the
  last 2–4 characters of long keys; passwords, generic matches and anything
  under 20 characters show only their length. Copies of the same key in
  different files are linked through `secret_id`, a running number that says
  nothing about the value.
- **Skipped files:** files over 8 MB, binary files and unreadable files are
  counted and reported, not dropped silently. PGP private key blocks are
  reported without a claim about passphrase protection.
- **Flags:** `TRACKED IN GIT` when the file is tracked by a git repository,
  `mode 644` when group / other users can read it.
- **Exit code:** 1 if a secret sits in a git-tracked file; otherwise 3 if git
  could not tell whether a file with a secret is tracked, 0 if not.
- Only the `text` and `json` formats are supported.

Limits: secrets that only exist in git history (committed, then deleted) are
not found, and keys are not checked for validity against the provider.

## Vulnerability scan (`--vulns`)

Lists the known vulnerabilities that affect the software on this machine and
ranks them by how likely they are to be exploited.

| What | Source | How it is matched |
| --- | --- | --- |
| Project dependencies | [OSV.dev](https://osv.dev) | Exact name + version from lockfiles |
| macOS, common apps and Homebrew formulae | [NVD](https://nvd.nist.gov) | Product name + installed version; only known-exploited CVEs are reported |
| "Is it exploited in the wild?" | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE id |
| "How likely is exploitation?" | [EPSS](https://www.first.org/epss/) | CVE id |

- **Lockfiles:** `Cargo.lock`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `requirements*.txt` (pinned lines), `poetry.lock`,
  `uv.lock`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`, `go.mod`, found
  under your home directory. Dependency and build directories are skipped.
- **Homebrew:** installed formulae are read from the Cellar (`/opt/homebrew`,
  `/usr/local` or `HOMEBREW_PREFIX`); `brew` itself is never run. Well-known
  formulae (`openssl`, `curl`, `git`, `node`, `python`, `php`, …) are looked
  up; the report says how many others were left out. Casks are covered when
  the installed app is in the application table.
- **Ranking:** known-exploited (KEV) and malware first, then EPSS probability,
  then severity. The text report shows the top 25; `--json` has everything.
- **Offline by default:** without `--online` only the inventory is printed.
  With `--online`, package names and versions are sent to the services above;
  file paths and contents never are.
- **Cache:** responses are kept under `~/.swordcheck/cache` (advisories until
  they change, KEV and NVD answers for a day).
- **NVD rate limit:** without an API key the NVD allows 5 requests per 30
  seconds, so the first run takes a few seconds per product. A free
  [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) makes it
  about ten times faster; see [API keys](#api-keys).
- **Options:** `--vulns-path PATH` scans only the lockfiles under a path (and
  skips macOS, apps and Homebrew); `--json`, `-o FILE` and `-q` work as usual.
- **Exit code:** 1 if a known-exploited vulnerability or malware is found;
  otherwise 3 if an online lookup failed or a lockfile could not be read,
  0 if not.

Limits: applications and Homebrew formulae are matched through built-in
tables (bundle ids and formula names), so anything that is not in a table is
not checked; for these products only known-exploited CVEs are reported, not
every CVE; NVD matching depends on the vendor publishing version data and can
miss or over-report; unpinned requirements (`flask>=2.0`) and git / path /
workspace dependencies are ignored and never sent anywhere, but a private
registry that looks like a public one cannot be told apart from the lockfile,
so its package names are looked up too.

## API keys

Everything works without a key. The only service that offers one is the NVD,
where it lifts the rate limit from 5 to 50 requests per 30 seconds. OSV.dev,
CISA KEV and EPSS have no keys.

```sh
cp .env.example .env && chmod 600 .env   # then fill in NVD_API_KEY
```

A key is looked up in the environment first, then in `./.env`, then in
`~/.swordcheck/.env`. Only the names listed in
[`.env.example`](.env.example) are read, the file is never loaded into the
environment of the commands the tool runs, and the key is sent to the NVD
only. `.env` is in `.gitignore`.

## npm malicious package scan (`--npm`)

Looks for npm packages that were hijacked or published as malware in the first
place. Only `package.json` files are read; no package code is ever executed.

| Finding | Meaning | Confidence |
| --- | --- | --- |
| `MALICIOUS VERSION` | Name + version match the built-in incident list (event-stream, ua-parser-js, chalk/debug, Nx, Shai-Hulud, axios…) | certain |
| `OSV RECORD` | OSV.dev has a `MAL-` record (only with `--online`) | certain |
| `IOC FILE` | The package directory contains a file dropped by a known worm | certain |
| `SUSPICIOUS SCRIPT` | `preinstall` / `install` / `postinstall` contains patterns such as download-and-execute, reverse shells or credential reads | heuristic |

There are two scopes:

- **Every audit** runs the `npm-packages` check against global install
  directories (npm, pnpm, yarn, bun, nvm / fnm / volta / asdf / mise and the
  `npx` cache). It is fast and affects the score and exit code.
- **`--npm`** additionally scans the `node_modules` directories of every
  project under your home directory and lists each finding with its location.
  macOS may ask for permission to let the terminal access folders such as
  Documents and Desktop.

Options:

- `--npm-path DIR` : scan only this directory (or the `node_modules`
  directories below it); repeatable
- `--online` : sends the **names and versions** of installed packages to
  OSV.dev and looks up malicious package records. No file paths or contents
  are sent. The built-in list ages; up-to-date coverage comes from here.
- `--json`, `-o FILE` and `-q` work in this mode too (markdown / html are not
  supported)

The exit code is 1 when a confirmed malicious package is found; heuristic
script warnings do not affect it. Otherwise it is 3 when the `--online` OSV
lookup failed, so only the built-in list was checked. If something turns up: remove the package or
move to a clean version, delete and reinstall `node_modules`, and rotate the
npm / GitHub / cloud credentials on that machine.

Limits: lockfiles (`package-lock.json` etc.) are not scanned on their own,
only packages installed on disk; symlinks (`npm link`) are not followed; the
JavaScript inside packages is not analyzed.

## Output formats

`--format text|json|markdown|html` (or `--json` for short). `-o FILE` writes
the report to a file. The JSON output contains the score, the summary, the
details of every check, the previous run and the checks that changed.

## Full report (`--report`)

`--report FILE` runs the audit and every scan and writes one HTML page: a
"Fix these first" list ordered by risk across all modules (malware, then what
is exploited in the wild, then secrets in git-tracked files, then failing
settings by weight), the score with its grade bands and the change since the
previous audit, and one section per module with a row for every finding.
Rows open for details, commands to run have a copy button, and passing checks
are folded away.

The page is a single file: the styles and the small script are inline, the
fonts are the system's, and it loads nothing from the network, so it can be
attached to a ticket or opened offline. It follows the light or dark setting
and prints with every row expanded. Secret values stay masked.

```sh
cargo run -- --report report.html            # audit + every scan, offline
cargo run -- --report report.html --online   # also look versions up (OSV.dev, NVD, CISA, FIRST)
cargo run -- --report report.html --vulns-path ~/app --npm-path ~/app --secrets-path ~/app
```

The audit options (`--only`, `--skip`, `--config`, `--min-score`,
`--no-history`) apply to its audit part, and a full audit is saved to the
history as usual. The path options narrow the scans to one project; with
`--vulns-path`, macOS, apps and Homebrew are not scanned. The exit code is 1
when the audit fails or a scan finds malware, a known-exploited vulnerability
or a secret in a git-tracked file; otherwise 3 when part of a scan could not
be done (an online lookup failed, a lockfile could not be read, or git could
not tell whether a file with a secret is tracked).

## History and comparison

Every full audit, from the command line or the dashboard, is saved to
`~/.swordcheck/history.json` (last 100 runs). The next run shows the score
difference and the checks whose status changed.

- `--history` : list past audits
- `--no-history` : do not save or compare
- Partial runs with `--only` / `--skip` are not saved
- The `SWORDCHECK_HOME` environment variable changes the storage directory

## Configuration (`audit.toml`)

Looked up in this order: `--config FILE`, `./audit.toml`,
`~/.config/swordcheck/audit.toml`. See
[`audit.example.toml`](audit.example.toml) for an example:

```toml
min_score = 80
skip = ["airdrop"]

[weights]
filevault = 40

[exceptions]
ssh = "Development machine; SSH is enabled on purpose"
```

A check with an exception still runs and shows up in the report as
`EXCEPTION`, but it does not affect the score or the exit code. Unknown ids and
fields are errors.

## Recommendations

The tool never applies a fix. Every failed or warned check comes with advice,
and where one command is a correct and complete remedy the report prints it
under `Run:` (the dashboard shows it as "Command to run yourself"). Settings
such as FileVault, SIP and Gatekeeper can only be changed in System Settings
or Recovery; for those the advice names the place. Run the audit again
afterwards to confirm.

## Dashboard

`swordcheck` with no arguments (or `--tui`) opens the dashboard when it runs
in a terminal. When the output is piped or redirected, the plain audit report
is printed instead, so existing scripts keep working.

- **Home:** the four modules (security audit, vulnerability scan, npm malware
  scan, secret scan) with a description of what each one reads and sends.
  Online lookups are off until you press `o`.
- **Running:** the current phase, a progress bar with a percentage when the
  total is known (a moving bar when it is not), the step counter, elapsed
  time and the most recent items being processed. `Esc` goes back and stops
  the scan: no further network request is started (a request already in
  flight finishes, and what was downloaded stays cached).
- **Results:** findings on the left, the selected finding's details on the
  right, most urgent first.

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k` | Move the selection |
| `PgUp` `PgDn`, `g` / `G` | Jump; first / last row |
| `Enter`, `1`–`4` | Run the selected module / run a module directly |
| `o` | Turn online lookups on or off (home screen) |
| `r` | Re-run the current module |
| `Esc` | Back to the home screen (stops a running scan) |
| `q` | Quit |

On the command line, `--vulns --online` prints the same phases to stderr.

## Code layout

| File | Contents |
| --- | --- |
| `src/main.rs` | Command line (`clap`) and control flow |
| `src/checks/mod.rs` | The `Check` trait, the registry, parallel execution |
| `src/checks/{system,network,accounts,persistence,supply_chain}.rs` | The checks |
| `src/npm.rs` | npm package scan, incident list |
| `src/osv.rs` | OSV.dev batch queries (with paging), shared by both scans |
| `src/net.rs` | HTTP through the system `curl` |
| `src/envfile.rs` | API keys from the environment or `.env` |
| `src/vulns.rs` | Vulnerability scan: OSV / NVD / KEV / EPSS lookups, ranking, report |
| `src/lockfiles.rs` | Lockfile discovery and parsers |
| `src/secrets.rs` | Secret scan: rules, file discovery, masking |
| `src/runner.rs` | Command execution layer (`CommandRunner`) and its test mock |
| `src/config.rs` | `audit.toml` |
| `src/score.rs` | Score, grade, summary |
| `src/history.rs` | History records and diffing |
| `src/report.rs` | Text / JSON / Markdown / HTML |
| `src/full_report.rs` | The single-page HTML report of every module (`--report`) |
| `src/tui.rs` | `ratatui` dashboard: home, progress and result screens |
| `src/progress.rs` | Progress events shared by the dashboard and the command line |

To add a check: define a type, implement the `Check` trait and add it to
`checks::registry()`. Checks run commands through `CommandRunner`, so they can
be tested against canned output with `MockRunner`.

## Notes

- The CIS column refers to the matching section of the *CIS Apple macOS 26.0
  Tahoe Benchmark v1.1.0*, as mapped by NIST's
  [macOS Security Compliance Project](https://github.com/usnistgov/macos_security).
  `sharing` covers several subsections of 2.3.3 (screen sharing, file sharing,
  remote management). Section numbers change between benchmark versions;
  compare with the version you use before relying on them in a compliance
  report. SwordCheck is not a CIS-certified tool.
- `launch-items` uses simple heuristics (programs running from temporary or
  hidden directories, download-and-execute, etc.); a warning is not a verdict.
- This tool covers baseline configuration checks. It is not a replacement for
  a full security assessment.

## License

Copyright © 2026 SwordSec.

SwordCheck is free software: you can redistribute it and/or modify it under
the terms of the [GNU Affero General Public License, version 3](LICENSE), as
published by the Free Software Foundation. It is distributed in the hope
that it will be useful, but without any warranty; see the license for
details.

In short: you may use it, at home or at work, and you may change it. If you
distribute a changed version, or offer one to others over a network, you
must make its source available under the same license.

If the AGPL does not fit your use, contact SwordSec about a commercial
license.
