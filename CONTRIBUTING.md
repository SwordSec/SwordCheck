# Contributing

Thanks for your interest. Bug reports and ideas are welcome as issues; for a
vulnerability in SwordCheck itself, see [SECURITY.md](SECURITY.md).

## Before you send code

- Open an issue first for anything larger than a small fix, so we can agree
  on the approach.
- SwordCheck is licensed under the [AGPL-3.0](LICENSE). Contributions are
  accepted under the same license. SwordSec also offers the project under
  separate commercial terms, so we may ask you to sign a contributor
  agreement before a larger change is merged.

## Ground rules

- **Read-only.** A check runs commands that read state; nothing may change a
  setting. Remedies are shown to the user, never applied.
- **No guessing.** A command that fails, times out or prints something
  unexpected gives `Unknown`, not `Pass` and not `Fail`.
- **Nothing secret in output.** Raw secret values never reach a report.
- **Say what leaves the machine.** A new network request must be documented
  in the README, and must work behind `--online` only.

## Development

```sh
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

CI runs the same four commands on macOS. Checks talk to the system through
`CommandRunner`, so they are tested against canned output with `MockRunner`;
please add a test for every behaviour you change.
