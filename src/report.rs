//! Rapor üretimi: aynı veriden metin, JSON, Markdown ve HTML çıktısı.
//!
//! Tüm biçimler önce bir `String` üretir; nereye yazılacağına (terminal ya
//! da dosya) `main.rs` karar verir.

use crate::checks::{CheckResult, Status};
use crate::history::{Change, RunRecord};
use crate::score::{self, Summary};
use clap::ValueEnum;
use colored::{ColoredString, Colorize};
use serde::Serialize;
use std::fmt::Write as _; // `write!`/`writeln!` makrolarını String üzerinde kullanmak için

/// Desteklenen çıktı biçimleri. `ValueEnum`, clap'in `--format json` gibi
/// değerleri otomatik ayrıştırmasını sağlar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Markdown,
    Html,
}

/// Önceki çalıştırmanın kısa özeti.
#[derive(Debug, Serialize)]
pub struct Previous {
    pub timestamp: String,
    pub score: u32,
}

/// Bir denetimin tüm verisi. JSON çıktısı doğrudan bu yapıdan türetilir.
#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    pub os_version: String,
    pub score: u32,
    pub grade: &'static str,
    pub summary: Summary,
    pub previous: Option<Previous>,
    pub changes: Vec<Change>,
    pub checks: Vec<CheckResult>,
}

impl Report {
    /// Sonuçlardan rapor kurar; `previous` verilirse fark da hesaplanır.
    pub fn new(
        timestamp: String,
        os_version: String,
        checks: Vec<CheckResult>,
        previous: Option<&RunRecord>,
    ) -> Self {
        let score = score::calculate_score(&checks);
        Self {
            tool: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            timestamp,
            os_version,
            score,
            grade: score::grade(score),
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

    /// İstisna tanımlanmamış Fail/Warn kontroller.
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
        // Bu yapıdaki tüm alanlar serileştirilebilir olduğu için hata beklenmez.
        serde_json::to_string_pretty(self).expect("rapor JSON'a çevrilebilir")
    }

    fn to_text_quiet(&self) -> String {
        format!("{}/100 ({})", self.score, self.grade)
    }

    fn to_text(&self) -> String {
        let mut out = String::new();
        let rule = "─".repeat(78).dimmed();

        // String'e yazmak hata üretmez; `let _ =` ile sonucu bilinçli yok sayıyoruz.
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", " macOS Güvenlik Denetimi ".on_blue().white().bold());
        let _ = writeln!(
            out,
            " {} · {} · salt okunur denetim",
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

        let score_text = format!("{}/100", self.score);
        let score_text = match self.score {
            90.. => score_text.green().bold(),
            60..=89 => score_text.yellow().bold(),
            _ => score_text.red().bold(),
        };
        let summary = &self.summary;
        let _ = write!(
            out,
            "Puan: {score_text}  (Not: {})   {} geçti · {} uyarı · {} başarısız",
            self.grade, summary.pass, summary.warn, summary.fail
        );
        if summary.unknown > 0 {
            let _ = write!(out, " · {} bilinmiyor", summary.unknown);
        }
        if summary.exempt > 0 {
            let _ = write!(out, " · {} istisna", summary.exempt);
        }
        let _ = writeln!(out);

        if let Some(previous) = &self.previous {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{} {}",
                "Önceki denetimden beri".bold(),
                format!("({})", short_time(&previous.timestamp)).dimmed()
            );
            let delta = i64::from(self.score) - i64::from(previous.score);
            let trend = match delta {
                0 => "değişmedi".dimmed(),
                1.. => format!("+{delta}").green(),
                _ => delta.to_string().red(),
            };
            let _ = writeln!(out, "  Puan: {} → {} ({trend})", previous.score, self.score);
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
                "Harika! Denetlenen tüm önlemler yerinde.".green()
            );
        } else {
            let _ = writeln!(out, "{}", "Öneriler".bold());
            for issue in issues {
                let _ = writeln!(
                    out,
                    "  {} {} {}: {}",
                    "•".yellow(),
                    issue.name.bold(),
                    format!("[{}]", meta(issue)).dimmed(),
                    issue.advice
                );
            }
            if self.issues().any(|issue| issue.fix.is_some()) {
                let _ = writeln!(out);
                let _ = writeln!(
                    out,
                    "{}",
                    "Bazı sorunlar otomatik düzeltilebilir: `macos-audit --fix --dry-run` ile önizle."
                        .dimmed()
                );
            }
        }

        let _ = writeln!(out);
        let _ = write!(
            out,
            "{}",
            "Not: Bu araç yalnızca yerel yapılandırmayı denetler; kapsamlı bir güvenlik taraması değildir."
                .dimmed()
        );
        out
    }

    fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# macOS Güvenlik Denetimi");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "**Puan: {}/100 (Not: {})** · {} · {}",
            self.score,
            self.grade,
            self.os_version,
            short_time(&self.timestamp)
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "| Durum | Kontrol | Önem | CIS | Ayrıntı |");
        let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
        for check in &self.checks {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                status_label(check),
                check.name,
                check.severity.label(),
                check.cis.unwrap_or("–"),
                detail_with_exemption(check).replace('|', "\\|")
            );
        }

        if let Some(previous) = &self.previous {
            let _ = writeln!(out);
            let _ = writeln!(out, "## Önceki denetimden beri");
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "Puan: {} → {} (önceki: {})",
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
            let _ = writeln!(out, "## Öneriler");
            let _ = writeln!(out);
            for issue in issues {
                let _ = writeln!(out, "- **{}**: {}", issue.name, issue.advice);
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
                "<li><strong>{}</strong>: {}</li>",
                escape_html(issue.name),
                escape_html(issue.advice)
            );
        }
        let advice = if advice.is_empty() {
            "<p>Denetlenen tüm önlemler yerinde.</p>".to_string()
        } else {
            format!("<ul>\n{advice}</ul>")
        };

        let mut trend = String::new();
        if let Some(previous) = &self.previous {
            let _ = writeln!(
                trend,
                "<h2>Önceki denetimden beri</h2>\n<p>Puan: {} → {} (önceki: {})</p>\n<ul>",
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
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>macOS Güvenlik Denetimi</title>
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
<h1>macOS Güvenlik Denetimi</h1>
<div class="muted">{os} · {time} · salt okunur denetim</div>
<div class="score"><strong class="{score_class}">{score}</strong><span>/ 100 · Not: {grade}</span>
<span class="muted">{pass} geçti · {warn} uyarı · {fail} başarısız · {unknown} bilinmiyor · {exempt} istisna</span></div>
<div class="card">
<table>
<thead><tr><th>Durum</th><th>Kontrol</th><th>Önem</th><th>CIS</th><th>Ayrıntı</th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
{trend}<h2>Öneriler</h2>
{advice}
<p class="muted">Bu araç yalnızca yerel yapılandırmayı denetler; kapsamlı bir güvenlik taraması değildir.</p>
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

/// Tek bir kontrolün renkli ve hizalı metin satırı.
pub fn text_line(check: &CheckResult) -> String {
    let (icon, paint): (&str, fn(&str) -> ColoredString) = match (&check.exempt, check.status) {
        (Some(_), _) => ("○", |text| text.dimmed()),
        (None, Status::Pass) => ("✔", |text| text.green().bold()),
        (None, Status::Warn) => ("!", |text| text.yellow().bold()),
        (None, Status::Fail) => ("✘", |text| text.red().bold()),
        (None, Status::Unknown) => ("?", |text| text.dimmed()),
    };

    // Etiketi önce düz metin olarak hizalayıp sonra renklendiriyoruz:
    // ANSI renk kodları genişliğe dahil olmadığı için hizalama bozulmasın.
    let label = format!("{:<12}", format!("[{}]", status_label(check)));
    format!(
        "{} {} {:<32} {}",
        paint(icon),
        paint(&label),
        check.name,
        detail_with_exemption(check)
    )
}

/// İstisnalı kontroller için "İSTİSNA", diğerleri için durum etiketi.
fn status_label(check: &CheckResult) -> &'static str {
    if check.exempt.is_some() {
        "İSTİSNA"
    } else {
        check.status.label()
    }
}

fn detail_with_exemption(check: &CheckResult) -> String {
    match &check.exempt {
        Some(reason) => format!("{} (istisna: {reason})", check.detail),
        None => check.detail.clone(),
    }
}

/// "önem: yüksek, CIS 2.2.1" gibi kısa bilgi.
pub fn meta(check: &CheckResult) -> String {
    match check.cis {
        Some(cis) => format!("önem: {}, CIS {cis}", check.severity.label()),
        None => format!("önem: {}", check.severity.label()),
    }
}

/// RFC 3339 zaman damgasını "2026-11-10 14:05" biçimine kısaltır.
pub fn short_time(timestamp: &str) -> String {
    timestamp.chars().take(16).collect::<String>().replace('T', " ")
}

/// HTML'e gömülecek metindeki özel karakterleri kaçışlar.
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

    fn sample() -> Report {
        let before = [
            result("firewall", Status::Fail, 20),
            result("sip", Status::Pass, 20),
        ];
        let previous = RunRecord::new("2026-11-01T09:00:00+03:00".into(), "macOS 26".into(), 50, &before);

        let mut exempt = result("ssh", Status::Warn, 10);
        exempt.exempt = Some("bilerek açık".into());
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
    fn rapor_ozeti_dogru() {
        let report = sample();
        assert_eq!(report.score, 50);
        assert_eq!(report.grade, "D");
        assert_eq!(report.changes.len(), 2);
        assert_eq!(report.previous.as_ref().unwrap().score, 50);
        assert_eq!(report.issues().count(), 1, "istisnalı kontrol sorun sayılmaz");
    }

    #[test]
    fn json_gecerli_ve_alanlar_yerinde() {
        let json: serde_json::Value = serde_json::from_str(&sample().to_json()).unwrap();
        assert_eq!(json["score"], 50);
        assert_eq!(json["summary"]["exempt"], 1);
        assert_eq!(json["checks"][0]["id"], "firewall");
        assert_eq!(json["checks"][0]["status"], "pass");
        assert_eq!(json["checks"][2]["exempt"], "bilerek açık");
        assert_eq!(json["changes"][0]["from"], "fail");
    }

    #[test]
    fn markdown_tablo_ve_oneriler() {
        let markdown = sample().to_markdown();
        assert!(markdown.contains("**Puan: 50/100 (Not: D)**"));
        assert!(markdown.contains("| BAŞARISIZ | sip |"));
        assert!(markdown.contains("| İSTİSNA | ssh |"));
        assert!(markdown.contains("## Öneriler"));
    }

    #[test]
    fn html_ozel_karakterleri_kacislar() {
        assert_eq!(
            escape_html("<b>\"a\" & b</b>"),
            "&lt;b&gt;&quot;a&quot; &amp; b&lt;/b&gt;"
        );
        let html = sample().to_html();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("badge fail"));
    }

    #[test]
    fn sessiz_metin_tek_satir() {
        assert_eq!(sample().render(Format::Text, true), "50/100 (D)");
    }

    #[test]
    fn zaman_kisaltma() {
        assert_eq!(short_time("2026-11-10T14:05:00+03:00"), "2026-11-10 14:05");
    }
}
