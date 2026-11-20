//! Report generation: text, JSON, Markdown and HTML output from the same data.
//!
//! Every format first produces a `String`; `main.rs` decides where it is
//! written (terminal or file).

use crate::checks::{CheckResult, Status};
use crate::history::{Change, RunRecord};
use crate::score::{self, Summary};
use clap::ValueEnum;
use colored::{ColoredString, Colorize};
use serde::Serialize;
use std::fmt::Write as _; // to use the `write!`/`writeln!` macros on a String

/// Supported output formats. `ValueEnum` lets clap parse values such as
/// `--format json` automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Markdown,
    Html,
}

/// Short summary of the previous run.
#[derive(Debug, Serialize)]
pub struct Previous {
    pub timestamp: String,
    pub score: u32,
}

/// All the data of one audit. The JSON output is derived directly from this struct.
#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    pub os_version: String,
    pub score: u32,
    pub grade: &'static str,
    /// `false` when no check could be evaluated (all unknown or exempt):
    /// the score is then a placeholder, shown as "n/a".
    pub scorable: bool,
    pub summary: Summary,
    pub previous: Option<Previous>,
    pub changes: Vec<Change>,
    pub checks: Vec<CheckResult>,
}

impl Report {
    /// Builds a report from the results; if `previous` is given, the diff is computed too.
    pub fn new(
        timestamp: String,
        os_version: String,
        checks: Vec<CheckResult>,
        previous: Option<&RunRecord>,
    ) -> Self {
        let scored = score::score_if_scorable(&checks);
        let score = scored.unwrap_or(score::NOTHING_SCORABLE);
        Self {
            tool: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            timestamp,
            os_version,
            score,
            grade: if scored.is_some() { score::grade(score) } else { "n/a" },
            scorable: scored.is_some(),
            summary: Summary::from_results(&checks),
            previous: previous.map(|record| Previous {
                timestamp: record.timestamp.clone(),
                score: record.score,
            }),
            changes: previous
                .map(|record| crate::history::diff(record, &checks))
                .unwrap_or_default(),
            checks,
        }
    }

    /// "87/100", or "n/a" when no check could be evaluated.
    fn score_label(&self) -> String {
        if self.scorable { format!("{}/100", self.score) } else { "n/a".to_string() }
    }

    /// Fail/Warn checks that have no exception defined.
    fn issues(&self) -> impl Iterator<Item = &CheckResult> {
        self.checks.iter().filter(|check| check.is_issue())
    }

    pub fn render(&self, format: Format, quiet: bool) -> String {
        match format {
            Format::Text if quiet => self.to_text_quiet(),
            Format::Text => self.to_text(),
            Format::Json => self.to_json(),
            Format::Markdown => self.to_markdown(),
            Format::Html => self.to_html(),
        }
    }

    fn to_json(&self) -> String {
        // Every field in this struct is serializable, so no error is expected.
        serde_json::to_string_pretty(self).expect("report can be converted to JSON")
    }

    fn to_text_quiet(&self) -> String {
        format!("{} ({})", self.score_label(), self.grade)
    }

    fn to_text(&self) -> String {
        let mut out = String::new();
        let rule = "─".repeat(78).dimmed();

        // Writing to a String cannot fail; we deliberately ignore the result with `let _ =`.
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", " macOS Security Audit ".on_blue().white().bold());
        let _ = writeln!(
            out,
            " {} · {} · read-only audit",
            self.os_version.dimmed(),
            short_time(&self.timestamp).dimmed()
        );
        let _ = writeln!(out, "{rule}");
        let _ = writeln!(out);

        for check in &self.checks {
            let _ = writeln!(out, "{}", text_line(check));
        }

        let _ = writeln!(out);
        let _ = writeln!(out, "{rule}");

        let score_text = self.score_label();
        let score_text = match (self.scorable, self.score) {
            (false, _) => score_text.yellow().bold(),
            (true, 90..) => score_text.green().bold(),
            (true, 60..=89) => score_text.yellow().bold(),
            _ => score_text.red().bold(),
        };
        let summary = &self.summary;
        let _ = write!(
            out,
            "Score: {score_text}  (Grade: {})   {} pass · {} warn · {} fail",
            self.grade, summary.pass, summary.warn, summary.fail
        );
        if summary.unknown > 0 {
            let _ = write!(out, " · {} unknown", summary.unknown);
        }
        if summary.exempt > 0 {
            let _ = write!(out, " · {} exempt", summary.exempt);
        }
        let _ = writeln!(out);

        if let Some(previous) = &self.previous {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{} {}",
                "Since the previous audit".bold(),
                format!("({})", short_time(&previous.timestamp)).dimmed()
            );
            let delta = i64::from(self.score) - i64::from(previous.score);
            let trend = match delta {
                0 => "unchanged".dimmed(),
                1.. => format!("+{delta}").green(),
                _ => delta.to_string().red(),
            };
            let _ = writeln!(out, "  Score: {} → {} ({trend})", previous.score, self.score);
            for change in &self.changes {
                let arrow = if change.improved() {
                    "▲".green()
                } else {
                    "▼".red()
                };
                let _ = writeln!(
                    out,
                    "  {arrow} {}: {} → {}",
                    change.name,
                    change.from.label(),
                    change.to.label()
                );
            }
        }

        let _ = writeln!(out);
        let issues: Vec<&CheckResult> = self.issues().collect();
        if issues.is_empty() {
            let _ = writeln!(
                out,
                "{}",
                if self.scorable {
                    "Great! All audited safeguards are in place.".green()
                } else {
                    "No check could be evaluated, so there is nothing to score.".yellow()
                }
            );
        } else {
            let _ = writeln!(out, "{}", "Recommendations".bold());
            for issue in issues {
                let _ = writeln!(
                    out,
                    "  {} {} {}: {}",
                    "•".yellow(),
                    issue.name.bold(),
                    format!("[{}]", meta(issue)).dimmed(),
                    issue.advice
                );
                if let Some(fix) = &issue.fix {
                    let _ = writeln!(out, "      {} {}", "Run:".dimmed(), fix.command_line().cyan());
                }
            }
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{}",
                "This tool changes nothing on your Mac: apply the recommendations yourself, then run it again."
                    .dimmed()
            );
        }

        let _ = writeln!(out);
        let _ = write!(
            out,
            "{}",
            "Note: This tool only audits local configuration; it is not a comprehensive security scan."
                .dimmed()
        );
        out
    }

    fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# macOS Security Audit");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "**Score: {} (Grade: {})** · {} · {}",
            self.score_label(),
            self.grade,
            self.os_version,
            short_time(&self.timestamp)
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "| Status | Check | Severity | CIS | Detail |");
        let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
        for check in &self.checks {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                status_label(check),
                check.name,
                check.severity.label(),
                check.cis.unwrap_or("–"),
                markdown_cell(&detail_with_exemption(check))
            );
        }

        if let Some(previous) = &self.previous {
            let _ = writeln!(out);
            let _ = writeln!(out, "## Since the previous audit");
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "Score: {} → {} (previous: {})",
                previous.score,
                self.score,
                short_time(&previous.timestamp)
            );
            for change in &self.changes {
                let _ = writeln!(
                    out,
                    "- {}: {} → {}",
                    change.name,
                    change.from.label(),
                    change.to.label()
                );
            }
        }

        let issues: Vec<&CheckResult> = self.issues().collect();
        if !issues.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "## Recommendations");
            let _ = writeln!(out);
            for issue in issues {
                let _ = writeln!(out, "- **{}**: {}", issue.name, issue.advice);
                if let Some(fix) = &issue.fix {
                    let _ = writeln!(out, "  - Run: `{}`", fix.command_line());
                }
            }
        }
        out
    }

    fn to_html(&self) -> String {
        let mut rows = String::new();
        for check in &self.checks {
            let class = match (&check.exempt, check.status) {
                (Some(_), _) => "exempt",
                (None, Status::Pass) => "pass",
                (None, Status::Warn) => "warn",
                (None, Status::Fail) => "fail",
                (None, Status::Unknown) => "unknown",
            };
            let _ = writeln!(
                rows,
                "<tr><td><span class=\"badge {class}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                status_label(check),
                escape_html(check.name),
                check.severity.label(),
                check.cis.unwrap_or("–"),
                escape_html(&detail_with_exemption(check)),
            );
        }

        let mut advice = String::new();
        for issue in self.issues() {
            let _ = writeln!(
                advice,
                "<li><strong>{}</strong>: {}{}</li>",
                escape_html(issue.name),
                escape_html(issue.advice),
                issue.fix.map(|fix| format!("<br>Run: <code>{}</code>", escape_html(&fix.command_line()))).unwrap_or_default()
            );
        }
        let advice = if advice.is_empty() {
            "<p>All audited safeguards are in place.</p>".to_string()
        } else {
            format!("<ul>\n{advice}</ul>")
        };

        let mut trend = String::new();
        if let Some(previous) = &self.previous {
            let _ = writeln!(
                trend,
                "<h2>Since the previous audit</h2>\n<p>Score: {} → {} (previous: {})</p>\n<ul>",
                previous.score,
                self.score,
                escape_html(&short_time(&previous.timestamp))
            );
            for change in &self.changes {
                let _ = writeln!(
                    trend,
                    "<li>{}: {} → {}</li>",
                    escape_html(change.name),
                    change.from.label(),
                    change.to.label()
                );
            }
            trend.push_str("</ul>\n");
        }

        let score_class = match self.score {
            90.. => "pass",
            60..=89 => "warn",
            _ => "fail",
        };

        format!(
            r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>macOS Security Audit</title>
<style>
  :root {{ --bg:#f6f7f9; --card:#fff; --text:#1c2330; --muted:#667085; --line:#e4e7ec;
          --pass:#16794c; --warn:#b26a00; --fail:#c0352b; --unknown:#667085; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#12151b; --card:#1b2029; --text:#e6e9ef; --muted:#98a2b3; --line:#2c3340;
            --pass:#4cc38a; --warn:#f0b34a; --fail:#f2776d; --unknown:#98a2b3; }}
  }}
  body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--text);
         font:15px/1.5 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; }}
  main {{ max-width:960px; margin:0 auto; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:16px; margin:28px 0 8px; }}
  .muted {{ color:var(--muted); }}
  .score {{ display:flex; align-items:baseline; gap:12px; margin:20px 0; }}
  .score strong {{ font-size:48px; line-height:1; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; overflow-x:auto; }}
  table {{ border-collapse:collapse; width:100%; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }}
  tr:last-child td {{ border-bottom:0; }}
  .badge {{ font-size:12px; font-weight:600; white-space:nowrap; }}
  .pass {{ color:var(--pass); }} .warn {{ color:var(--warn); }} .fail {{ color:var(--fail); }}
  .unknown, .exempt {{ color:var(--unknown); }}
</style>
</head>
<body>
<main>
<h1>macOS Security Audit</h1>
<div class="muted">{os} · {time} · read-only audit</div>
<div class="score"><strong class="{score_class}">{score}</strong><span>/ 100 · Grade: {grade}</span>
<span class="muted">{pass} pass · {warn} warn · {fail} fail · {unknown} unknown · {exempt} exempt</span></div>
<div class="card">
<table>
<thead><tr><th>Status</th><th>Check</th><th>Severity</th><th>CIS</th><th>Detail</th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
{trend}<h2>Recommendations</h2>
{advice}
<p class="muted">This tool only audits local configuration; it is not a comprehensive security scan.</p>
</main>
</body>
</html>
"#,
            os = escape_html(&self.os_version),
            time = escape_html(&short_time(&self.timestamp)),
            score = self.score,
            grade = self.grade,
            pass = self.summary.pass,
            warn = self.summary.warn,
            fail = self.summary.fail,
            unknown = self.summary.unknown,
            exempt = self.summary.exempt,
        )
    }
}

/// The colored, aligned text line for a single check.
pub fn text_line(check: &CheckResult) -> String {
    let (icon, paint): (&str, fn(&str) -> ColoredString) = match (&check.exempt, check.status) {
        (Some(_), _) => ("○", |text| text.dimmed()),
        (None, Status::Pass) => ("✔", |text| text.green().bold()),
        (None, Status::Warn) => ("!", |text| text.yellow().bold()),
        (None, Status::Fail) => ("✘", |text| text.red().bold()),
        (None, Status::Unknown) => ("?", |text| text.dimmed()),
    };

    // We pad the label as plain text first and color it afterwards: ANSI
    // color codes do not count toward the width, so alignment stays intact.
    let label = format!("{:<12}", format!("[{}]", status_label(check)));
    format!(
        "{} {} {:<32} {}",
        paint(icon),
        paint(&label),
        check.name,
        detail_with_exemption(check)
    )
}

/// "EXCEPTION" for exempted checks, the status label for the rest.
fn status_label(check: &CheckResult) -> &'static str {
    if check.exempt.is_some() {
        "EXCEPTION"
    } else {
        check.status.label()
    }
}

fn detail_with_exemption(check: &CheckResult) -> String {
    match &check.exempt {
        Some(reason) => format!("{} (exception: {reason})", check.detail),
        None => check.detail.clone(),
    }
}

/// Short info such as "severity: high, CIS 2.2.1".
pub fn meta(check: &CheckResult) -> String {
    match check.cis {
        Some(cis) => format!("severity: {}, CIS {cis}", check.severity.label()),
        None => format!("severity: {}", check.severity.label()),
    }
}

/// Shortens an RFC 3339 timestamp to the form "2026-11-10 14:05".
pub fn short_time(timestamp: &str) -> String {
    timestamp.chars().take(16).collect::<String>().replace('T', " ")
}

/// Makes text safe for a Markdown table cell: a `|` or a line break would
/// end the cell or the whole row.
fn markdown_cell(text: &str) -> String {
    text.replace('|', "\\|").split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Escapes special characters in text that will be embedded in HTML.
fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::tests::result;

    #[test]
    fn markdown_cells_stay_on_one_row() {
        assert_eq!(markdown_cell("a|b\nline two\r\n  three"), "a\\|b line two three");
    }

    fn sample() -> Report {
        let before = [
            result("firewall", Status::Fail, 20),
            result("sip", Status::Pass, 20),
        ];
        let previous = RunRecord::new("2026-11-01T09:00:00+03:00".into(), "macOS 26".into(), 50, &before);

        let mut exempt = result("ssh", Status::Warn, 10);
        exempt.exempt = Some("enabled on purpose".into());
        let now = vec![
            result("firewall", Status::Pass, 20),
            result("sip", Status::Fail, 20),
            exempt,
        ];
        Report::new(
            "2026-11-10T14:05:00+03:00".into(),
            "macOS 26.6.2".into(),
            now,
            Some(&previous),
        )
    }

    #[test]
    fn report_summary_is_correct() {
        let report = sample();
        assert_eq!(report.score, 50);
        assert_eq!(report.grade, "D");
        assert_eq!(report.changes.len(), 2);
        assert_eq!(report.previous.as_ref().unwrap().score, 50);
        assert_eq!(report.issues().count(), 1, "an exempted check does not count as an issue");
    }

    #[test]
    fn json_is_valid_and_fields_are_present() {
        let json: serde_json::Value = serde_json::from_str(&sample().to_json()).unwrap();
        assert_eq!(json["score"], 50);
        assert_eq!(json["summary"]["exempt"], 1);
        assert_eq!(json["checks"][0]["id"], "firewall");
        assert_eq!(json["checks"][0]["status"], "pass");
        assert_eq!(json["checks"][2]["exempt"], "enabled on purpose");
        assert_eq!(json["changes"][0]["from"], "fail");
    }

    #[test]
    fn markdown_table_and_recommendations() {
        let markdown = sample().to_markdown();
        assert!(markdown.contains("**Score: 50/100 (Grade: D)**"));
        assert!(markdown.contains("| FAIL | sip |"));
        assert!(markdown.contains("| EXCEPTION | ssh |"));
        assert!(markdown.contains("## Recommendations"));
    }

    #[test]
    fn html_escapes_special_characters() {
        assert_eq!(
            escape_html("<b>\"a\" & b</b>"),
            "&lt;b&gt;&quot;a&quot; &amp; b&lt;/b&gt;"
        );
        let html = sample().to_html();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("badge fail"));
    }

    #[test]
    fn quiet_text_is_a_single_line() {
        assert_eq!(sample().render(Format::Text, true), "50/100 (D)");
    }

    #[test]
    fn shortens_timestamp() {
        assert_eq!(short_time("2026-11-10T14:05:00+03:00"), "2026-11-10 14:05");
    }
}
