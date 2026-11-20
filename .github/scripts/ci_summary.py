"""Summaries for the CI job page, and the changed-lines coverage check.

usage:
  python3 .github/scripts/ci_summary.py tests <cargo test log>
      Writes a table of the test results to $GITHUB_STEP_SUMMARY (or stdout).
  python3 .github/scripts/ci_summary.py coverage <base commit> <lcov file>
      Checks that every instrumented line under src/ that differs from the
      base commit is covered, writes a table to $GITHUB_STEP_SUMMARY (or
      stdout) and exits with 1 when a line is not covered.
"""

import os
import re
import subprocess
import sys


def summary(markdown):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")
    else:
        print(markdown)


def tests(log_path):
    """`Running <target>` lines name the suite of the next `test result` line."""
    rows = []
    suite = "tests"
    with open(log_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            running = re.match(r"Running (unittests \S+|\S+)", line)
            if running:
                suite = running.group(1)
            result = re.match(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", line)
            if result:
                rows.append((suite,) + result.groups())
    lines = ["### Tests", "", "| Suite | Result | Passed | Failed | Ignored |", "| --- | --- | ---: | ---: | ---: |"]
    for suite, status, passed, failed, ignored in rows:
        mark = "✅" if status == "ok" else "❌"
        lines.append(f"| `{suite}` | {mark} {status} | {passed} | {failed} | {ignored} |")
    if not rows:
        lines.append("| (no test results found in the log) | ❌ | | | |")
    summary("\n".join(lines))
    return 0 if rows and all(row[1] == "ok" for row in rows) else 1


def changed_lines(base):
    """{absolute path: set of line numbers} added or changed since `base`."""
    diff = subprocess.run(
        ["git", "diff", "-U0", base, "--", "src"],
        capture_output=True, text=True, check=True,
    ).stdout
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    ).stdout.strip()
    changed, current = {}, None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            current = None if path == "/dev/null" else os.path.normpath(os.path.join(root, path[2:]))
            if current:
                changed.setdefault(current, set())
        elif line.startswith("@@") and current:
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            start, count = int(match.group(1)), int(match.group(2) or "1")
            changed[current].update(range(start, start + count))
    return root, changed


def hits(lcov_path):
    """{absolute path: {line: execution count}} from an lcov file."""
    found, current = {}, None
    with open(lcov_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line.startswith("SF:"):
                current = os.path.normpath(line[3:])
                found.setdefault(current, {})
            elif line.startswith("DA:") and current:
                number, count = line[3:].split(",")[:2]
                found[current][int(number)] = found[current].get(int(number), 0) + int(count)
    return found


def coverage(base, lcov_path):
    root, changed = changed_lines(base)
    counts = hits(lcov_path)
    rows, missing, total, covered = [], [], 0, 0
    for path in sorted(changed):
        file_hits = counts.get(path, {})
        lines = sorted(number for number in changed[path] if number in file_hits)
        if not lines:
            continue
        ok = [number for number in lines if file_hits[number] > 0]
        total += len(lines)
        covered += len(ok)
        relative = os.path.relpath(path, root)
        rows.append(f"| `{relative}` | {len(ok)}/{len(lines)} |")
        with open(path, encoding="utf-8") as source:
            text = source.read().splitlines()
        missing += [f"- `{relative}:{number}` `{text[number - 1].strip()}`" for number in lines if file_hits[number] == 0]

    percent = 100.0 * covered / total if total else 100.0
    lines = ["### Coverage of changed lines", ""]
    if total:
        lines += ["| File | Covered |", "| --- | ---: |", *rows, f"| **Total** | **{covered}/{total} = {percent:.2f}%** |"]
    else:
        lines.append("No instrumented line under `src/` changed.")
    if missing:
        lines += ["", "Not covered by any test:", "", *missing]
    summary("\n".join(lines))
    for entry in missing:
        print(entry.replace("`", ""), file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "tests" and len(sys.argv) == 3:
        sys.exit(tests(sys.argv[2]))
    if command == "coverage" and len(sys.argv) == 4:
        sys.exit(coverage(sys.argv[2], sys.argv[3]))
    sys.exit(__doc__)
