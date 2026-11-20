# Security policy

SwordCheck reads sensitive places on your Mac (configuration, `.env` files,
SSH keys, shell history), so we treat bugs in it seriously.

## Reporting a vulnerability

Please report it privately through GitHub:
**Security → Report a vulnerability** on this repository
(<https://github.com/SwordSec/SwordCheck/security/advisories/new>).

Do not open a public issue for a vulnerability. Include the version
(`swordcheck --version`), your macOS version and the steps to reproduce.
Remove real secrets from anything you send.

We aim to acknowledge a report within 3 working days and to tell you within
10 working days whether we can reproduce it and what we plan to do. We will
credit you in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives fixes.

## What counts

In scope, for example:

- A raw secret value ending up in any output (report, JSON, dashboard, logs).
- Data leaving the machine that the documentation says stays local: anything
  other than package names, ecosystems and versions sent to OSV.dev, product
  names and versions sent to the NVD, and CVE ids sent to FIRST (EPSS).
- SwordCheck changing a system setting, or running a command taken from the
  files it scans. It is meant to be strictly read-only.
- A crafted file (lockfile, plist, `.env`, `package.json`) that makes it
  crash, hang, or report a clean result for something it should flag.

Out of scope: a check that is missing, a false positive or negative of a
heuristic (please open a normal issue), and vulnerabilities in the services
SwordCheck queries.
