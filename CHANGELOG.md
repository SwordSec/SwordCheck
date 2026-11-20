# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
