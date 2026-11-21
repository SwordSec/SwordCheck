# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-22

### Added

- **Dashboard export:** `e` on a result screen writes the audit (HTML,
  Markdown, text or JSON) or a scan (HTML, text or JSON) to
  `~/.swordcheck/reports/`. An exported npm report says when the OSV lookup
  failed (`lookup_error` in JSON).
- **Vulnerability scan:** `-r` includes in requirements files are followed;
  lockfiles that could not be read are reported (and listed under `skipped`
  in JSON) instead of being dropped; known products without a version to look
  up are named; CISA KEV ransomware flags are shown, and the report says when
  the cached KEV catalog is stale.
- **npm malware scan:** npm's linked store is scanned; download-and-run
  through command substitution in install scripts is flagged; packages whose
  manifest is too large to read are reported; `package.json` is read the way
  npm reads it.
- **Secret scan:** a project's `.yarnrc.yml` (Yarn's `npmAuthIdent`), npm
  `_auth`, quoted secrets with separators, symlinked `.env` files and `.env`
  files that start with a BOM are covered; folders that cannot be opened are
  counted.
- The dashboard says exactly what leaves the machine when online lookups are
  on.

### Changed

- A scan that could not be completed is never shown as clean. A failed
  online lookup, an unread lockfile, a failed `npm root -g` or an unknown git
  status gives exit code 3, a warning instead of a green all-clear in the
  text report, the dashboard and the HTML report, and a note in the `--quiet`
  summary. "Fix these first" names every such gap.
- Without an absolute `HOME` nothing is scanned as if it were the home
  folder, and the history is never written to the current folder.
- An audit in which checks are Unknown no longer reads as all clear;
  FileVault being turned off is not a Pass; a check that became Unknown is
  not shown as improved.

### Fixed

- `install.sh` no longer stops with "no published release yet" in the first
  minutes after a release: when GitHub's `/releases/latest` redirect still
  lags, it asks the GitHub API for the latest tag.
- What OSV.dev returned before a later request failed is kept.
- An audit saved by another run while `--report` was scanning is no longer
  erased from the history.
- Exit codes and the report survive a closed stdout or stderr
  (`| head`); output paths are checked before a long scan starts.
- A command that times out has its own child processes killed too.
- A sharing service that was found is kept when `launchd` fails.
- An unknown git status is not read as "untracked", and file names are not
  read as git patterns.
- Only fixed versions newer than the installed one are listed.
- Control characters are escaped in the text audit report; long warnings
  wrap in the dashboard instead of being cut off.
- `NVD_API_KEY` from the environment is trimmed like a value from `.env`.

## [0.1.0] - 2026-11-20

First public version.

### Features

- **Security audit:** 17 read-only checks of macOS settings (FileVault, SIP,
  Gatekeeper, updates, firewall, sharing services, login settings, launch
  items, global npm packages), a score out of 100, history with comparison,
  and text / JSON / Markdown / HTML reports. CIS section numbers follow the
  CIS Apple macOS 26.0 Tahoe Benchmark v1.1.0.
- **Vulnerability scan (`--vulns`):** dependencies from 11 lockfile formats
  (OSV.dev); macOS, well-known applications and Homebrew formulae (NVD);
  ranked by CISA KEV and EPSS.
- **npm malware scan (`--npm`):** installed packages checked against a
  built-in incident list and OSV malware records.
- **Secret scan (`--secrets`):** API keys, tokens and private keys in `.env`
  and configuration files, always masked.
- **Dashboard:** run every module from one terminal screen with live
  progress.
- Strictly read-only: recommendations and, where one command is a complete
  remedy, the command to run yourself.
- Optional `NVD_API_KEY` from the environment or a `.env` file.
- **Full report (`--report FILE`):** the audit and every scan on one
  self-contained HTML page, with a "Fix these first" list across modules.
- **Install script:** `install.sh` installs a release binary without a Rust
  toolchain, after checking the archive's SHA-256.

[Unreleased]: https://github.com/SwordSec/SwordCheck/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SwordSec/SwordCheck/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SwordSec/SwordCheck/releases/tag/v0.1.0
