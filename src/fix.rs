//! `--fix` mode: shows the command for each fixable issue and runs it if the
//! user confirms.
//!
//! The rest of the tool is read-only; this is the only place that changes
//! the system. That is why every command is shown explicitly and confirmed
//! one by one.

use crate::checks::{Check, CheckResult, Fix};
use crate::config::Config;
use crate::report;
use crate::runner::SystemRunner;
use colored::Colorize;
use std::io::{BufRead, IsTerminal, Write};
use std::process::Command;

pub struct FixOptions {
    /// Only show the commands, do not run them.
    pub dry_run: bool,
    /// Apply without asking for confirmation.
    pub yes: bool,
}

/// Summary of a fix pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FixSummary {
    pub applied: usize,
    pub failed: usize,
    pub skipped: usize,
}

/// Walks through the checks with issues and applies the fixes.
pub fn run_fixes(
    results: &[CheckResult],
    checks: &[Box<dyn Check>],
    config: &Config,
    options: &FixOptions,
) -> FixSummary {
    let mut summary = FixSummary::default();
    let (fixable, manual) = split_issues(results);

    println!();
    println!("{}", " Fix mode ".on_magenta().white().bold());

    if fixable.is_empty() {
        println!("There are no issues that can be fixed automatically.");
    }

    for (result, fix) in fixable {
        println!();
        println!("{} {}", "▸".cyan(), result.name.bold());
        println!("  Issue:   {}", result.detail);
        println!("  Command: {}", fix.command_line().cyan());

        if options.dry_run {
            println!("  {}", "[dry-run] command was not run.".dimmed());
            summary.skipped += 1;
            continue;
        }
        if !options.yes && !confirm("  Apply? [y/N] ") {
            println!("  {}", "Skipped.".dimmed());
            summary.skipped += 1;
            continue;
        }

        match apply(&fix) {
            Ok(()) => {
                // We do not assume the fix worked: we re-run the check and
                // show the result. New runner = empty cache.
                let check = checks.iter().find(|check| check.id() == result.id);
                let verified = check.map(|check| {
                    crate::checks::run_one(check.as_ref(), &SystemRunner::new(), config)
                });
                match verified {
                    Some(after) if !after.is_issue() => {
                        println!("  {}", report::text_line(&after));
                        summary.applied += 1;
                    }
                    Some(after) => {
                        println!("  {}", report::text_line(&after));
                        println!(
                            "  {}",
                            "The command ran but the issue persists; check it manually.".yellow()
                        );
                        summary.failed += 1;
                    }
                    None => summary.applied += 1,
                }
            }
            Err(err) => {
                println!("  {} {err}", "Failed:".red().bold());
                summary.failed += 1;
            }
        }
    }

    if !manual.is_empty() {
        println!();
        println!("{}", "Needs a manual fix".bold());
        for result in manual {
            println!("  {} {}: {}", "•".yellow(), result.name.bold(), result.advice);
        }
    }

    println!();
    if options.dry_run {
        println!(
            "{}",
            "Preview complete; no settings were changed.".dimmed()
        );
    } else {
        println!(
            "Fix summary: {} applied · {} failed · {} skipped",
            summary.applied, summary.failed, summary.skipped
        );
    }
    summary
}

/// Splits the issues into "automatically fixable" and "needs a manual fix".
/// Exempted checks are left alone (`is_issue` excludes them).
fn split_issues(results: &[CheckResult]) -> (Vec<(&CheckResult, Fix)>, Vec<&CheckResult>) {
    let mut fixable = Vec::new();
    let mut manual = Vec::new();
    for result in results.iter().filter(|result| result.is_issue()) {
        match result.fix {
            Some(fix) => fixable.push((result, fix)),
            None => manual.push(result),
        }
    }
    (fixable, manual)
}

/// Gets a yes/no answer from the user. If the input is not a terminal (e.g.
/// inside a script) we stay on the safe side and treat it as "no".
fn confirm(prompt: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        println!("{prompt}(no interactive terminal; confirm with `--yes` instead)");
        return false;
    }
    print!("{prompt}");
    let _ = std::io::stdout().flush();

    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }
    is_yes(&answer)
}

fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes"
    )
}

/// Runs the fix command. Input/output stay attached to the terminal, so
/// `sudo` can ask the user for the password directly.
fn apply(fix: &Fix) -> Result<(), String> {
    let mut command = if fix.sudo {
        let mut command = Command::new("sudo");
        command.arg(fix.program);
        command
    } else {
        Command::new(fix.program)
    };

    let status = command
        .args(fix.args)
        .status()
        .map_err(|err| format!("could not start the command: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("command exited with an error code ({status})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;
    use crate::score::tests::result;

    const FIX: Fix = Fix {
        program: "true",
        args: &[],
        sudo: false,
    };

    #[test]
    fn yes_answers() {
        for yes in ["y", "Y", "yes", "YES", " y\n"] {
            assert!(is_yes(yes), "{yes:?} should count as yes");
        }
        for no in ["", "\n", "n", "no", "maybe"] {
            assert!(!is_yes(no), "{no:?} should count as no");
        }
    }

    #[test]
    fn splits_issues_correctly() {
        let mut fixable = result("firewall", Status::Fail, 20);
        fixable.fix = Some(FIX);

        let manual = result("filevault", Status::Fail, 25);

        let mut passing = result("sip", Status::Pass, 20);
        passing.fix = Some(FIX);

        let mut exempt = result("ssh", Status::Warn, 10);
        exempt.fix = Some(FIX);
        exempt.exempt = Some("enabled on purpose".into());

        let results = [fixable, manual, passing, exempt];
        let (fixable, manual) = split_issues(&results);

        assert_eq!(fixable.len(), 1);
        assert_eq!(fixable[0].0.id, "firewall");
        assert_eq!(manual.len(), 1);
        assert_eq!(manual[0].id, "filevault");
    }

    #[test]
    fn dry_run_applies_nothing() {
        let mut fixable = result("firewall", Status::Fail, 20);
        // A command that would fail if run: it must never be called in a dry run.
        fixable.fix = Some(Fix {
            program: "false",
            args: &[],
            sudo: false,
        });

        let summary = run_fixes(
            &[fixable],
            &[],
            &Config::default(),
            &FixOptions {
                dry_run: true,
                yes: true,
            },
        );
        assert_eq!(
            summary,
            FixSummary {
                applied: 0,
                failed: 0,
                skipped: 1
            }
        );
    }

    #[test]
    fn command_success_and_failure() {
        assert!(apply(&FIX).is_ok());
        let failing = Fix {
            program: "false",
            args: &[],
            sudo: false,
        };
        assert!(apply(&failing).is_err());
    }
}
