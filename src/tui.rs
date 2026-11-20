//! Interactive terminal dashboard (the default when run without arguments).
//!
//! The dashboard has three kinds of screens:
//! - **Home**: pick a module (audit, vulnerability scan, npm scan, secret scan).
//! - **Running**: the module runs on a worker thread and reports progress
//!   through a channel; the screen shows the current phase, a progress bar
//!   and the most recent details.
//! - **Results**: a list on the left, the selected item's details on the right.
//!
//! `ratatui` works in "immediate mode": on every frame we redraw the whole
//! screen from the `App` state. Key presses and progress events are the only
//! things that change the state.

use crate::checks::{self, CheckResult, Status};
use crate::config::Config;
use crate::progress::{Event as ProgressEvent, Progress};
use crate::runner::SystemRunner;
use crate::score::{self, Summary};
use crate::{history, lockfiles, npm, report, secrets, vulns};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// What the dashboard needs from the command line and configuration.
pub struct Setup {
    /// Save full audits to the history and compare with the previous one
    /// (off for partial runs and with `--no-history`).
    pub save_history: bool,
    /// Ids of the checks to run (after `--only` / `--skip`).
    pub check_ids: Vec<String>,
    pub config: Config,
    pub os_version: String,
}

// ---- Modules ----

/// A scan the user can start from the home screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Module {
    Audit,
    Vulns,
    Npm,
    Secrets,
}

impl Module {
    const ALL: [Module; 4] = [Module::Audit, Module::Vulns, Module::Npm, Module::Secrets];

    fn title(self) -> &'static str {
        match self {
            Module::Audit => "Security audit",
            Module::Vulns => "Vulnerability scan",
            Module::Npm => "npm malware scan",
            Module::Secrets => "Secret scan",
        }
    }

    fn tagline(self) -> &'static str {
        match self {
            Module::Audit => "macOS settings, scored out of 100",
            Module::Vulns => "dependencies, macOS and apps",
            Module::Npm => "hijacked and malicious packages",
            Module::Secrets => "API keys in .env and config files",
        }
    }

    fn description(self) -> &'static [&'static str] {
        match self {
            Module::Audit => &[
                "Checks FileVault, System Integrity Protection, Gatekeeper, the firewall, sharing services, login settings, launch items and more.",
                "",
                "Read-only. Takes a few seconds.",
            ],
            Module::Vulns => &[
                "Reads the lockfiles of your projects (Cargo, npm, yarn, pnpm, Python, Composer, Bundler, Go) and lists macOS plus well-known apps and Homebrew formulae.",
                "",
                "With online lookups: asks OSV.dev and the NVD which known vulnerabilities affect those versions, then ranks them with CISA KEV (exploited in the wild) and EPSS (exploit probability).",
                "",
                "Without: shows the inventory only. The first online run takes a few minutes because the NVD is rate-limited; later runs use the cache.",
            ],
            Module::Npm => &[
                "Inspects every installed npm package, globally and in your projects, for versions known to be malicious, files dropped by known worms and suspicious install scripts.",
                "",
                "With online lookups: also asks OSV.dev for malicious-package records.",
                "",
                "Only package.json files are read; no package code runs.",
            ],
            Module::Secrets => &[
                "Finds API keys, tokens, passwords and unencrypted private keys in .env files, shell history and tool configuration, and shows which provider's keys live where.",
                "",
                "Values are always masked. Never uses the network.",
            ],
        }
    }

    /// Does the online toggle change what this module does?
    fn uses_network(self) -> bool {
        matches!(self, Module::Vulns | Module::Npm)
    }
}

// ---- Result views ----

/// Color role of a piece of text; mapped to a terminal color when drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    Bad,
    Warn,
    Good,
    Dim,
    Plain,
}

impl Tone {
    fn style(self) -> Style {
        match self {
            Tone::Bad => Style::new().fg(Color::Red),
            Tone::Warn => Style::new().fg(Color::Yellow),
            Tone::Good => Style::new().fg(Color::Green),
            Tone::Dim => Style::new().fg(Color::DarkGray),
            Tone::Plain => Style::new(),
        }
    }
}

/// A line in the detail pane.
#[derive(Debug, Clone, PartialEq)]
enum Detail {
    Heading(String),
    Text(String),
    Dim(String),
    Blank,
}

/// One row of a result list.
#[derive(Debug, Clone)]
struct Row {
    /// Short label in front of the title (`KEV`, `HIGH`, `AWS`…).
    tag: String,
    tone: Tone,
    title: String,
    detail: Vec<Detail>,
}

/// The outcome of a scan in a form the dashboard can draw.
struct ResultView {
    module: Module,
    /// Lines shown above the list.
    headline: Vec<(Tone, String)>,
    rows: Vec<Row>,
    list: ListState,
    /// Shown when there are no rows.
    empty: &'static str,
}

impl ResultView {
    fn new(module: Module, headline: Vec<(Tone, String)>, rows: Vec<Row>, empty: &'static str) -> Self {
        let mut list = ListState::default();
        if !rows.is_empty() {
            list.select(Some(0));
        }
        Self {
            module,
            headline,
            rows,
            list,
            empty,
        }
    }
}

/// The audit keeps its own view: it has a score gauge and typed results.
struct AuditView {
    results: Vec<CheckResult>,
    list: ListState,
    /// Comparison with the previous audit, or why there is none.
    trend: Option<String>,
}

impl AuditView {
    fn new(results: Vec<CheckResult>, trend: Option<String>) -> Self {
        let mut list = ListState::default();
        if !results.is_empty() {
            list.select(Some(0));
        }
        Self { results, list, trend }
    }

    fn selected(&self) -> Option<&CheckResult> {
        self.results.get(self.list.selected()?)
    }
}

/// Moves a list selection by `delta`; stops at the list bounds.
fn move_selection(list: &mut ListState, len: usize, delta: isize) {
    if len == 0 {
        return;
    }
    let current = list.selected().unwrap_or(0);
    list.select(Some(current.saturating_add_signed(delta).min(len - 1)));
}

fn short_path(path: &Path) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    secrets::display_path(path, home.as_deref())
}

fn vulns_view(scan: &vulns::Scan) -> ResultView {
    let mut rows = Vec::new();

    for item in &scan.system {
        let title = item.title();
        let mut detail = vec![
            Detail::Heading(title.clone()),
            Detail::Dim(item.cpe.clone()),
            Detail::Blank,
        ];
        let (tag, tone) = if !scan.online {
            detail.push(Detail::Text(
                "Not looked up yet. Enable online lookups on the home screen and run again.".into(),
            ));
            ("APP", Tone::Dim)
        } else if let Some(error) = &item.error {
            detail.push(Detail::Text(format!("The NVD lookup failed: {error}")));
            ("?", Tone::Warn)
        } else if item.exploited.is_empty() {
            detail.push(Detail::Text(
                "No known-exploited vulnerability affects this version.".into(),
            ));
            ("OK", Tone::Good)
        } else {
            detail.push(Detail::Text(format!(
                "{} known-exploited vulnerabilities affect this version. Update it.",
                item.exploited.len()
            )));
            detail.push(Detail::Blank);
            for vuln in &item.exploited {
                detail.push(Detail::Text(format!("{}  {}", vuln.cve, vuln.name)));
                let ransomware = if vuln.ransomware { ", used in ransomware" } else { "" };
                detail.push(Detail::Dim(format!(
                    "added to CISA KEV on {}{ransomware}",
                    vuln.date_added
                )));
            }
            ("KEV", Tone::Bad)
        };
        rows.push(Row {
            tag: tag.into(),
            tone,
            title,
            detail,
        });
    }
    // Products that need attention go first; healthy ones go after the
    // dependency findings so they do not push real problems off screen.
    let (mut rows, healthy): (Vec<Row>, Vec<Row>) = rows.into_iter().partition(|row| row.tone == Tone::Bad);

    for finding in &scan.findings {
        let exploited = finding.kev.is_some() || finding.malware;
        let (tag, tone) = match (finding.malware, &finding.kev, finding.severity) {
            (true, _, _) => ("MALWARE", Tone::Bad),
            (_, Some(_), _) => ("KEV", Tone::Bad),
            (_, _, vulns::Severity::Critical) => ("CRITICAL", Tone::Bad),
            (_, _, vulns::Severity::High) => ("HIGH", Tone::Warn),
            (_, _, vulns::Severity::Medium) => ("MEDIUM", Tone::Plain),
            (_, _, vulns::Severity::Low) => ("LOW", Tone::Dim),
            (_, _, vulns::Severity::Unknown) => ("UNRATED", Tone::Dim),
        };
        let mut detail = vec![
            Detail::Heading(format!("{} {}", finding.package, finding.version)),
            Detail::Dim(format!("{} · {}", finding.ecosystem, finding.id)),
            Detail::Blank,
            Detail::Text(finding.summary.clone()),
            Detail::Blank,
        ];
        if !finding.cves.is_empty() {
            detail.push(Detail::Text(format!("CVE        {}", finding.cves.join(", "))));
        }
        detail.push(Detail::Text(format!("Severity   {}", finding.severity.label())));
        if let Some(epss) = finding.epss {
            detail.push(Detail::Text(format!(
                "EPSS       {:.1}% chance of exploitation in 30 days",
                epss * 100.0
            )));
        }
        if let Some(kev) = &finding.kev {
            let ransomware = if kev.ransomware { ", used in ransomware" } else { "" };
            detail.push(Detail::Text(format!(
                "Exploited  in CISA KEV since {}{ransomware}",
                kev.date_added
            )));
        }
        if !finding.fixed.is_empty() {
            detail.push(Detail::Text(format!("Fixed in   {}", finding.fixed.join(", "))));
        }
        detail.push(Detail::Blank);
        detail.push(Detail::Heading(format!(
            "Pinned by {} lockfile(s)",
            finding.lockfile_count
        )));
        detail.extend(finding.lockfiles.iter().map(|path| Detail::Dim(short_path(path))));
        if exploited {
            detail.push(Detail::Blank);
            detail.push(Detail::Text(
                "This is being exploited in the wild. Fix it first.".into(),
            ));
        }
        rows.push(Row {
            tag: tag.into(),
            tone,
            title: format!("{} {}", finding.package, finding.version),
            detail,
        });
    }

    rows.extend(healthy);

    let mut headline = vec![(
        Tone::Plain,
        format!(
            "{} lockfiles · {} packages · {} system products",
            scan.lockfiles,
            scan.packages,
            scan.system.len()
        ),
    )];
    if scan.online {
        let exploited = scan.exploited();
        let mut summary = format!(
            "{} findings · {exploited} known-exploited or malware",
            scan.findings.len()
        );
        // A failed lookup or an unread lockfile may hide an exploited
        // vulnerability: no green all-clear.
        let tone = match (exploited, scan.incomplete()) {
            (1.., _) => Tone::Bad,
            (0, false) => Tone::Good,
            (0, true) => {
                summary.push_str(" · incomplete: see the warnings below");
                Tone::Warn
            }
        };
        headline.push((tone, summary));
    } else {
        headline.push((
            Tone::Warn,
            "Inventory only: online lookups are off (press esc, then o).".into(),
        ));
    }
    headline.extend(scan.unmatched_note().map(|note| (Tone::Dim, note)));
    let home = std::env::var_os("HOME").map(PathBuf::from);
    headline.extend(scan.skipped_note(home.as_deref()).map(|note| (Tone::Warn, note)));
    headline.extend(scan.warnings.iter().map(|warning| (Tone::Warn, warning.clone())));
    ResultView::new(
        Module::Vulns,
        headline,
        rows,
        "Nothing to scan: no lockfiles or known apps were found.",
    )
}

/// `lookup` is `None` when online lookups are off, otherwise whether the
/// OSV query worked.
fn npm_view(scan: &npm::Scan, lookup: Option<Result<(), String>>) -> ResultView {
    let rows = scan
        .findings
        .iter()
        .map(|finding| {
            let version = if finding.version.is_empty() {
                "?"
            } else {
                &finding.version
            };
            let title = format!("{}@{version}", finding.package);
            let mut detail = vec![
                Detail::Heading(title.clone()),
                Detail::Dim(finding.kind.label().to_string()),
                Detail::Blank,
                Detail::Text(finding.reason.clone()),
                Detail::Blank,
                Detail::Heading(format!("Found in {} install(s)", finding.count)),
            ];
            detail.extend(finding.paths.iter().map(|path| Detail::Dim(short_path(path))));
            detail.push(Detail::Blank);
            detail.push(Detail::Text(finding.kind.advice().into()));
            let (tag, tone) = match finding.kind {
                kind if kind.is_malware() => ("MALWARE", Tone::Bad),
                npm::Kind::Unread => ("UNREAD", Tone::Warn),
                _ => ("SCRIPT", Tone::Warn),
            };
            Row {
                tag: tag.into(),
                tone,
                title,
                detail,
            }
        })
        .collect();

    let malware = scan.malware().count();
    let unread = scan.unread().count();
    let source = match &lookup {
        Some(Ok(())) => "built-in list + OSV.dev",
        Some(Err(_)) => "built-in list + OSV.dev (incomplete)",
        None => "built-in list only (online lookups are off)",
    };
    let mut headline = vec![
        (
            Tone::Plain,
            format!(
                "{} directories · {} package installs · {source}",
                scan.roots.len(),
                scan.packages
            ),
        ),
        (
            if malware > 0 { Tone::Bad } else { Tone::Good },
            format!(
                "{malware} malicious · {} suspicious install scripts",
                scan.suspicious().count() - unread
            ),
        ),
    ];
    if unread > 0 {
        headline.push((
            Tone::Warn,
            format!("{unread} packages not checked: their package.json is too large to read"),
        ));
    }
    if let Some(Err(err)) = lookup {
        headline.push((
            Tone::Warn,
            format!("OSV lookup failed, so the scan is incomplete: {err}"),
        ));
    }
    ResultView::new(
        Module::Npm,
        headline,
        rows,
        "No malicious or suspicious packages found.",
    )
}

fn secrets_view(scan: &secrets::Scan) -> ResultView {
    let rows = scan
        .findings
        .iter()
        .map(|finding| {
            let location = format!("{}:{}", short_path(&finding.path), finding.line);
            let mut detail = vec![
                Detail::Heading(finding.masked.clone()),
                Detail::Dim(format!("{} · rule {}", finding.provider, finding.rule)),
                Detail::Blank,
                Detail::Text(location),
            ];
            if let Some(name) = &finding.name {
                detail.push(Detail::Text(format!("Variable   {name}")));
            }
            if finding.occurrences > 1 {
                detail.push(Detail::Text(format!("Repeated   {} times in this file", finding.occurrences)));
            }
            if let Some(mode) = &finding.mode {
                let note = if finding.others_can_read { " (readable by other users: chmod 600)" } else { "" };
                detail.push(Detail::Text(format!("File mode  {mode}{note}")));
            }
            if finding.git_tracked {
                detail.push(Detail::Blank);
                detail.push(Detail::Text(
                    "This file is tracked in git. If the repository was ever shared, treat the secret as leaked: revoke and rotate it, then untrack the file.".into(),
                ));
            } else if finding.git_unknown {
                detail.push(Detail::Blank);
                detail.push(Detail::Text(secrets::GIT_UNKNOWN_ADVICE.into()));
            }
            let copies: Vec<&secrets::Finding> = scan
                .findings
                .iter()
                .filter(|other| other.secret_id == finding.secret_id && other.path != finding.path)
                .collect();
            if !copies.is_empty() {
                detail.push(Detail::Blank);
                detail.push(Detail::Heading(format!("Same secret in {} other file(s)", copies.len())));
                detail.extend(copies.iter().map(|copy| Detail::Dim(short_path(&copy.path))));
            }
            // `project/.env` says more than `.env` when many projects have one.
            let mut parts: Vec<String> =
                finding.path.iter().rev().take(2).map(|part| part.to_string_lossy().into_owned()).collect();
            parts.reverse();
            let file = parts.join("/");
            Row {
                tag: finding.provider.split(' ').next().unwrap_or_default().to_uppercase(),
                tone: match (finding.git_tracked, finding.others_can_read || finding.git_unknown) {
                    (true, _) => Tone::Bad,
                    (_, true) => Tone::Warn,
                    _ => Tone::Plain,
                },
                title: format!("{}  {}", finding.name.as_deref().unwrap_or(&finding.masked), file),
                detail,
            }
        })
        .collect();

    let tracked = scan.tracked().count();
    let providers: Vec<String> = scan
        .summary
        .iter()
        .map(|row| format!("{} {}", row.provider, row.secrets))
        .collect();
    let mut headline = vec![
        (
            Tone::Plain,
            format!(
                "{} files · {} secrets · {} locations",
                scan.files_scanned,
                scan.unique_secrets(),
                scan.findings.len()
            ),
        ),
        (
            if tracked > 0 { Tone::Bad } else { Tone::Dim },
            if tracked > 0 {
                format!("{tracked} in git-tracked files · {}", providers.join(" · "))
            } else {
                providers.join(" · ")
            },
        ),
    ];
    if scan.files_skipped > 0 {
        headline.push((
            Tone::Warn,
            format!(
                "{} files skipped, not scanned: {}",
                scan.files_skipped,
                scan.skipped.reasons()
            ),
        ));
    }
    headline.extend(scan.skipped.folders_note().map(|note| (Tone::Warn, note)));
    ResultView::new(Module::Secrets, headline, rows, "No secrets found.")
}

// ---- Jobs ----

/// What a finished job hands back.
enum Outcome {
    /// The results and the comparison with the previous audit.
    Audit(Vec<CheckResult>, Option<String>),
    View(ResultView),
}

/// A module running on a worker thread.
struct Job {
    module: Module,
    online: bool,
    started: Instant,
    /// The current phase and how many phases have started so far.
    stage: String,
    stages: usize,
    done: usize,
    total: usize,
    /// The most recent detail lines, newest last.
    notes: VecDeque<String>,
    events: Receiver<ProgressEvent>,
    handle: Option<JoinHandle<Outcome>>,
}

/// Number of detail lines kept on the running screen.
const MAX_NOTES: usize = 7;

impl Job {
    fn start(module: Module, online: bool, setup: &Arc<Setup>) -> Self {
        let (progress, events) = Progress::channel();
        let setup = Arc::clone(setup);
        // The thread owns everything it needs, so the dashboard can drop the
        // job (cancel) without waiting for it.
        let handle = std::thread::spawn(move || work(module, online, &setup, &progress));
        Self {
            module,
            online,
            started: Instant::now(),
            stage: "Starting".to_string(),
            stages: 0,
            done: 0,
            total: 0,
            notes: VecDeque::new(),
            events,
            handle: Some(handle),
        }
    }

    /// Applies the progress events that arrived since the last frame.
    fn pump(&mut self) {
        let events: Vec<ProgressEvent> = self.events.try_iter().collect();
        for event in events {
            self.apply(event);
        }
    }

    fn apply(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::Stage(label) => {
                self.stage = label;
                self.stages += 1;
                (self.done, self.total) = (0, 0);
                self.notes.clear();
            }
            ProgressEvent::Step { done, total } => (self.done, self.total) = (done, total),
            ProgressEvent::Note(text) => {
                if self.notes.len() == MAX_NOTES {
                    self.notes.pop_front();
                }
                self.notes.push_back(text);
            }
        }
    }

    /// Returns the outcome once the worker has finished.
    fn finish(&mut self) -> Option<Result<Outcome, String>> {
        if !self.handle.as_ref().is_some_and(JoinHandle::is_finished) {
            return None;
        }
        let handle = self.handle.take()?;
        Some(
            handle
                .join()
                .map_err(|_| format!("{} stopped unexpectedly.", self.module.title())),
        )
    }
}

/// Runs a module to completion. This is the body of the worker thread.
fn work(module: Module, online: bool, setup: &Setup, progress: &Progress) -> Outcome {
    let runner = SystemRunner::new();
    match module {
        Module::Audit => {
            let mut checks = checks::registry();
            checks.retain(|check| setup.check_ids.iter().any(|id| id == check.id()));
            let results = checks::run_checks_with(&checks, &runner, &setup.config, progress);
            // A cancelled audit is not a result worth recording.
            let trend = (setup.save_history && !progress.cancelled())
                .then(|| record_audit(history::history_path().as_deref(), &results, &setup.os_version));
            Outcome::Audit(results, trend)
        }
        Module::Vulns => {
            progress.stage("Looking for lockfiles in your projects");
            let paths = lockfiles::default_files();
            progress.stage("Listing macOS, installed applications and Homebrew formulae");
            let system = vulns::system_items(&runner);
            let (lockfiles, skipped) = vulns::read_lockfiles(&paths, progress);
            let cache = history::history_path().and_then(|path| path.parent().map(|dir| dir.join("cache")));
            let mut scan = match (online, cache) {
                (true, Some(cache)) => vulns::scan(
                    &lockfiles,
                    system,
                    &vulns::Online {
                        cache,
                        progress: progress.clone(),
                    },
                ),
                _ => vulns::offline(&lockfiles, system),
            };
            scan.skipped = skipped;
            Outcome::View(vulns_view(&scan))
        }
        Module::Npm => {
            progress.stage("Looking for node_modules directories");
            let roots = npm::all_roots(&runner);
            let mut scan = npm::scan_with(&roots, progress);
            let lookup = online.then(|| scan.lookup_osv(progress));
            Outcome::View(npm_view(&scan, lookup))
        }
        Module::Secrets => {
            progress.stage("Looking for files that may hold secrets");
            let files = secrets::default_files();
            Outcome::View(secrets_view(&secrets::scan_with(&files, progress)))
        }
    }
}

/// Saves a dashboard audit to the history, like the command line does, and
/// describes how it compares with the previous one. `path` is the history
/// file (`history::history_path()`), `None` when HOME is not set to an absolute path.
fn record_audit(path: Option<&Path>, results: &[CheckResult], os_version: &str) -> String {
    let Some(path) = path else {
        return "history unavailable (HOME is not set to an absolute path)".to_string();
    };
    // Like the command line: a run in which nothing could be evaluated has no
    // score worth comparing or saving.
    if score::score_if_scorable(results).is_none() {
        return "not recorded: no check could be evaluated".to_string();
    }
    let records = match history::load(path) {
        Ok(records) => records,
        // A corrupt history is left alone rather than overwritten.
        Err(err) => return format!("history unavailable: {err}"),
    };
    let score = score::calculate_score(results);
    let trend = match records.last() {
        None => "first recorded audit".to_string(),
        Some(previous) => {
            let changed = history::diff(previous, results).len();
            let delta = i64::from(score) - i64::from(previous.score);
            format!("previous {} ({delta:+}), {changed} changed", previous.score)
        }
    };
    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let record = history::RunRecord::new(timestamp, os_version.to_string(), score, results);
    match history::append(path, records, record) {
        Ok(()) => trend,
        Err(err) => format!("{trend}; not saved: {err}"),
    }
}

// ---- App state ----

enum Screen {
    Home,
    Running(Job),
    Audit(AuditView),
    Results(ResultView),
    Failed(String),
}

struct App {
    setup: Arc<Setup>,
    screen: Screen,
    /// The selected module on the home screen.
    menu: ListState,
    /// Are online lookups enabled?
    online: bool,
}

/// What the event loop should do after a key press.
#[derive(Debug, PartialEq)]
enum Action {
    Continue,
    Quit,
}

impl App {
    fn new(setup: Setup) -> Self {
        let mut menu = ListState::default();
        menu.select(Some(0));
        Self {
            setup: Arc::new(setup),
            screen: Screen::Home,
            menu,
            online: false,
        }
    }

    fn selected_module(&self) -> Module {
        Module::ALL[self.menu.selected().unwrap_or(0).min(Module::ALL.len() - 1)]
    }

    fn start(&mut self, module: Module) {
        self.screen = Screen::Running(Job::start(module, self.online, &self.setup));
    }

    /// Advances a running job; switches to its result when it is done.
    fn tick(&mut self) {
        let Screen::Running(job) = &mut self.screen else {
            return;
        };
        job.pump();
        if let Some(outcome) = job.finish() {
            // Events sent just before the thread ended are still queued.
            job.pump();
            self.screen = match outcome {
                Ok(Outcome::Audit(results, trend)) => Screen::Audit(AuditView::new(results, trend)),
                Ok(Outcome::View(view)) => Screen::Results(view),
                Err(message) => Screen::Failed(message),
            };
        }
    }

    fn on_key(&mut self, code: KeyCode) -> Action {
        // List navigation shared by every screen that has a list.
        let delta = match code {
            KeyCode::Down | KeyCode::Char('j') => Some(1),
            KeyCode::Up | KeyCode::Char('k') => Some(-1),
            KeyCode::PageDown => Some(10),
            KeyCode::PageUp => Some(-10),
            KeyCode::Home | KeyCode::Char('g') => Some(isize::MIN),
            KeyCode::End | KeyCode::Char('G') => Some(isize::MAX),
            _ => None,
        };

        match &mut self.screen {
            Screen::Home => match code {
                KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
                KeyCode::Enter | KeyCode::Char(' ') => self.start(self.selected_module()),
                KeyCode::Char('o') => self.online = !self.online,
                // Number keys run a module directly.
                KeyCode::Char(digit @ '1'..='4') => {
                    let index = digit as usize - '1' as usize;
                    self.menu.select(Some(index));
                    self.start(Module::ALL[index]);
                }
                _ => {
                    if let Some(delta) = delta {
                        move_selection(&mut self.menu, Module::ALL.len(), delta);
                    }
                }
            },
            // Leaving a running job drops its progress channel, which the
            // worker notices: it stops before its next network request and
            // keeps what it already cached. Enter is not accepted here, so
            // a double press on the home screen cannot cancel the job it
            // just started.
            Screen::Running(_) => match code {
                KeyCode::Char('q') => return Action::Quit,
                KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Home,
                _ => {}
            },
            Screen::Failed(_) => match code {
                KeyCode::Char('q') => return Action::Quit,
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Enter => self.screen = Screen::Home,
                _ => {}
            },
            Screen::Audit(view) => match code {
                KeyCode::Char('q') => return Action::Quit,
                KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Home,
                KeyCode::Char('r') => self.start(Module::Audit),
                _ => {
                    if let Some(delta) = delta {
                        move_selection(&mut view.list, view.results.len(), delta);
                    }
                }
            },
            Screen::Results(view) => match code {
                KeyCode::Char('q') => return Action::Quit,
                KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Home,
                KeyCode::Char('r') => {
                    let module = view.module;
                    self.start(module);
                }
                _ => {
                    if let Some(delta) = delta {
                        move_selection(&mut view.list, view.rows.len(), delta);
                    }
                }
            },
        }
        Action::Continue
    }
}

/// Starts the dashboard and runs it until the user quits.
pub fn run(setup: Setup) -> std::io::Result<()> {
    let mut app = App::new(setup);

    // `init` puts the terminal in raw mode and switches to the alternate
    // screen; `restore` is called after the loop so the terminal is put back
    // even if there was an error.
    let mut terminal = ratatui::init();

    // `init` installs a panic hook that restores the terminal. That is right
    // for this thread, but a panic on a worker thread is caught and shown on
    // the "Something went wrong" screen: leaving raw mode there would garble
    // a dashboard that keeps running. So workers skip the hook.
    let ui_thread = std::thread::current().id();
    let restore_and_report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == ui_thread {
            restore_and_report(info);
        }
    }));

    let outcome = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    // Back to the default hook for the rest of the program.
    drop(std::panic::take_hook());
    outcome
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    /// How long to wait for a key before redrawing; short enough for the
    /// spinner and progress bar to look alive.
    const FRAME: Duration = Duration::from_millis(80);

    // Closing the terminal window (SIGHUP) or `kill` (SIGTERM) would end the
    // process in raw mode on the alternate screen. The handlers only set a
    // flag; the loop sees it within a frame and returns, so `run` restores
    // the terminal the same way as after `q`.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP] {
        signal_hook::flag::register(signal, Arc::clone(&stop))?;
    }

    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        app.tick();
        terminal.draw(|frame| draw(frame, app))?;

        if !event::poll(FRAME)? {
            continue;
        }
        // We only handle key press events (some terminals also send releases).
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        // Raw mode delivers Ctrl-C as a key instead of a signal.
        let interrupt = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        if interrupt || app.on_key(key.code) == Action::Quit {
            return Ok(());
        }
    }
}

// ---- Drawing ----

/// Draws a single frame. Because it is kept separate from the event loop,
/// tests can draw it to a fake terminal (`TestBackend`) and verify the content.
fn draw(frame: &mut Frame, app: &mut App) {
    let [body, footer] = Layout::vertical([Constraint::Min(5), Constraint::Length(1)]).areas(frame.area());

    let keys: &[(&str, &str)] = match &mut app.screen {
        Screen::Home => {
            draw_home(frame, body, &mut app.menu, app.online, &app.setup.os_version);
            &[
                ("↑↓", "select"),
                ("enter", "run"),
                ("o", "online lookups on/off"),
                ("q", "quit"),
            ]
        }
        Screen::Running(job) => {
            draw_running(frame, body, job, job.started.elapsed());
            &[("esc", "stop and go back"), ("q", "quit")]
        }
        Screen::Audit(view) => {
            draw_audit(frame, body, view, &app.setup.os_version);
            &[
                ("↑↓/jk", "navigate"),
                ("r", "re-run audit"),
                ("esc", "home"),
                ("q", "quit"),
            ]
        }
        Screen::Results(view) => {
            draw_results(frame, body, view);
            &[
                ("↑↓/jk", "navigate"),
                ("PgUp/PgDn", "jump"),
                ("r", "re-run"),
                ("esc", "home"),
                ("q", "quit"),
            ]
        }
        Screen::Failed(message) => {
            let text = Paragraph::new(message.as_str()).block(Block::bordered().title(" Something went wrong "));
            frame.render_widget(text, body);
            &[("esc", "home"), ("q", "quit")]
        }
    };

    let mut help = vec![Span::raw(" ")];
    for (key, action) in keys {
        help.push(Span::styled(*key, Style::new().fg(Color::Cyan)));
        help.push(Span::raw(format!(" {action}   ")));
    }
    frame.render_widget(Paragraph::new(Line::from(help)), footer);
}

fn draw_home(frame: &mut Frame, area: Rect, menu: &mut ListState, online: bool, os_version: &str) {
    let [header, body, toggle] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(6), Constraint::Length(4)]).areas(area);
    let [menu_area, about_area] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(body);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Tone::Dim.style();

    let title = Line::from(vec![
        Span::styled(" SwordCheck ", bold),
        Span::styled(format!("· {os_version} · v{}", env!("CARGO_PKG_VERSION")), dim),
    ]);
    frame.render_widget(Paragraph::new(title).block(Block::bordered()), header);

    let selected = Module::ALL[menu.selected().unwrap_or(0).min(Module::ALL.len() - 1)];
    let items: Vec<ListItem> = Module::ALL
        .iter()
        .enumerate()
        .map(|(index, module)| {
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(format!(" {} ", index + 1), dim),
                    Span::styled(module.title(), bold),
                ]),
                Line::from(Span::styled(format!("   {}", module.tagline()), dim)),
            ])
        })
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(" Modules "))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, menu_area, menu);

    let mut about: Vec<Line> = selected.description().iter().map(|line| Line::from(*line)).collect();
    about.push(Line::default());
    about.push(Line::from(Span::styled(
        if selected.uses_network() {
            "Uses the online toggle below."
        } else {
            "Not affected by the online toggle."
        },
        dim,
    )));
    let about = Paragraph::new(about)
        .block(Block::bordered().title(format!(" {} ", selected.title())))
        .wrap(Wrap { trim: false });
    frame.render_widget(about, about_area);

    let state = if online {
        Span::styled("ON ", Tone::Good.style().add_modifier(Modifier::BOLD))
    } else {
        Span::styled("OFF", Tone::Warn.style().add_modifier(Modifier::BOLD))
    };
    // Exactly what leaves the machine (README: Vulnerability scan, API keys).
    let explanation = if online {
        "  names and versions to OSV.dev and the NVD (with your NVD API key, if set), CVE ids to FIRST; nothing else"
    } else {
        "  nothing leaves this machine"
    };
    let line = Line::from(vec![
        Span::raw(" Online lookups: "),
        state,
        Span::styled(explanation, dim),
    ]);
    // Wraps rather than cutting the statement off on a narrow terminal.
    frame.render_widget(
        Paragraph::new(line).block(Block::bordered()).wrap(Wrap { trim: false }),
        toggle,
    );
}

/// `m:ss`.
fn clock(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

fn draw_running(frame: &mut Frame, area: Rect, job: &Job, elapsed: Duration) {
    // A fixed-size box in the middle of the screen.
    let [column] = Layout::horizontal([Constraint::Max(84)]).flex(Flex::Center).areas(area);
    let [boxed] = Layout::vertical([Constraint::Max(MAX_NOTES as u16 + 9)])
        .flex(Flex::Center)
        .areas(column);
    frame.render_widget(Clear, boxed);

    let mode = match (job.module.uses_network(), job.online) {
        (true, true) => " · online",
        (true, false) => " · offline",
        _ => "",
    };
    let block = Block::bordered().title(format!(" {}{mode} ", job.module.title()));
    let inner = block.inner(boxed);
    frame.render_widget(block, boxed);

    let [stage_area, _, bar_area, count_area, _, notes_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .areas(inner.inner(ratatui::layout::Margin {
        horizontal: 2,
        vertical: 1,
    }));

    // The spinner advances with time, so it moves even when no event arrives.
    const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let tick = (elapsed.as_millis() / 100) as usize;
    let stage = Line::from(vec![
        Span::styled(SPINNER[tick % SPINNER.len()], Style::new().fg(Color::Cyan)),
        Span::raw(" "),
        Span::styled(job.stage.as_str(), Style::new().add_modifier(Modifier::BOLD)),
    ]);
    frame.render_widget(Paragraph::new(stage), stage_area);

    let dim = Tone::Dim.style();
    if job.total > 0 {
        let ratio = (job.done as f64 / job.total as f64).clamp(0.0, 1.0);
        let gauge = Gauge::default()
            .gauge_style(Style::new().fg(Color::Cyan).bg(Color::DarkGray))
            .ratio(ratio)
            .label(format!("{:.0}%", ratio * 100.0));
        frame.render_widget(gauge, bar_area);
        let count = format!(
            "{} of {} · step {} · elapsed {}",
            job.done,
            job.total,
            job.stages.max(1),
            clock(elapsed)
        );
        frame.render_widget(Paragraph::new(Span::styled(count, dim)), count_area);
    } else {
        // No total is known for this phase: show a block sliding back and
        // forth instead of a percentage that would be made up.
        let width = bar_area.width as usize;
        let block_width = (width / 5).max(3).min(width);
        let travel = width - block_width;
        let position = match travel {
            0 => 0,
            _ => {
                let cycle = tick % (travel * 2);
                if cycle > travel { travel * 2 - cycle } else { cycle }
            }
        };
        let bar = Line::from(vec![
            Span::styled("░".repeat(position), dim),
            Span::styled("█".repeat(block_width), Style::new().fg(Color::Cyan)),
            Span::styled("░".repeat(travel - position), dim),
        ]);
        frame.render_widget(Paragraph::new(bar), bar_area);
        let count = format!("working · step {} · elapsed {}", job.stages.max(1), clock(elapsed));
        frame.render_widget(Paragraph::new(Span::styled(count, dim)), count_area);
    }

    // Newest note at the bottom, older ones fading above it.
    let notes: Vec<Line> = job
        .notes
        .iter()
        .map(|note| Line::from(Span::styled(note.as_str(), dim)))
        .collect();
    frame.render_widget(Paragraph::new(notes), notes_area);
}

/// Splits `text` into rows at most `width` columns wide, as the terminal
/// shows them: wide characters (CJK, most emoji) take two columns. Rows break
/// between words; a word longer than a row is broken inside.
fn wrap_to_width(text: &str, width: usize) -> Vec<String> {
    let columns = |text: &str| Span::raw(text).width();
    let mut rows = Vec::new();
    let mut row = String::new();
    for (index, word) in text.split(' ').enumerate() {
        let gap = usize::from(index > 0);
        if columns(&row) + gap + columns(word) <= width {
            if index > 0 {
                row.push(' ');
            }
            row.push_str(word);
            continue;
        }
        // The word goes to a new row, broken into pieces if it is too long.
        if !row.is_empty() {
            rows.push(std::mem::take(&mut row));
        }
        for c in word.chars() {
            let mut buffer = [0; 4];
            if !row.is_empty() && columns(&row) + columns(c.encode_utf8(&mut buffer)) > width {
                rows.push(std::mem::take(&mut row));
            }
            row.push(c);
        }
    }
    rows.push(row);
    rows
}

fn draw_results(frame: &mut Frame, area: Rect, view: &mut ResultView) {
    // Long lines (warnings above all) wrap instead of being cut off, so the
    // header grows with them, up to half the screen. The rows are wrapped
    // here and drawn as they are, so the height always matches what is drawn.
    let inner_width = usize::from(area.width.saturating_sub(2)).max(1);
    let headline: Vec<Line> = view
        .headline
        .iter()
        .flat_map(|(tone, text)| {
            wrap_to_width(&format!(" {text}"), inner_width)
                .into_iter()
                .map(|row| Line::from(Span::styled(row, tone.style())))
        })
        .collect();
    let header_height = (headline.len() as u16 + 2).min((area.height / 2).max(3));
    let [header, body] = Layout::vertical([Constraint::Length(header_height), Constraint::Min(5)]).areas(area);
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);

    let title = format!(" {} ", view.module.title());
    let headline = Paragraph::new(headline).block(Block::bordered().title(title));
    frame.render_widget(headline, header);

    let width = view
        .rows
        .iter()
        .map(|row| row.tag.chars().count())
        .max()
        .unwrap_or(0)
        .min(12);
    let items: Vec<ListItem> = view
        .rows
        .iter()
        .map(|row| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {:<width$} ", row.tag),
                    row.tone.style().add_modifier(Modifier::BOLD),
                ),
                Span::raw(row.title.as_str()),
            ]))
        })
        .collect();
    let position = view.list.selected().map_or(0, |index| index + 1);
    let list = List::new(items)
        .block(Block::bordered().title(format!(" Findings {position}/{} ", view.rows.len())))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, list_area, &mut view.list);

    let block = Block::bordered().title(" Detail ");
    let Some(row) = view.list.selected().and_then(|index| view.rows.get(index)) else {
        frame.render_widget(
            Paragraph::new(view.empty).block(block).wrap(Wrap { trim: false }),
            detail_area,
        );
        return;
    };
    let lines: Vec<Line> = row
        .detail
        .iter()
        .map(|line| match line {
            Detail::Heading(text) => Line::from(Span::styled(text.as_str(), Style::new().add_modifier(Modifier::BOLD))),
            Detail::Text(text) => Line::from(text.as_str()),
            Detail::Dim(text) => Line::from(Span::styled(text.as_str(), Tone::Dim.style())),
            Detail::Blank => Line::default(),
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        detail_area,
    );
}

fn draw_audit(frame: &mut Frame, area: Rect, view: &mut AuditView, os_version: &str) {
    let [header, body] = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).areas(area);
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);

    draw_score(frame, header, &view.results, os_version, view.trend.as_deref());
    draw_checks(frame, list_area, view);
    draw_check_detail(frame, detail_area, view.selected());
}

fn draw_score(frame: &mut Frame, area: Rect, results: &[CheckResult], os_version: &str, trend: Option<&str>) {
    let scored = score::score_if_scorable(results);
    let score = scored.unwrap_or(0);
    let summary = Summary::from_results(results);
    let color = match score {
        90.. => Color::Green,
        60..=89 => Color::Yellow,
        _ => Color::Red,
    };

    let trend = trend.map(|trend| format!(" · {trend}")).unwrap_or_default();
    let title = format!(
        " macOS Security Audit · {os_version} · {} pass, {} warn, {} fail{trend} ",
        summary.pass, summary.warn, summary.fail
    );
    let gauge = Gauge::default()
        .block(Block::bordered().title(title))
        .gauge_style(Style::new().fg(color))
        .percent(score.min(100) as u16)
        .label(match scored {
            Some(score) => format!("{score}/100 (Grade: {})", score::grade(score)),
            None => "n/a (no check could be evaluated)".to_string(),
        });
    frame.render_widget(gauge, area);
}

/// Icon and color for a status.
fn status_style(result: &CheckResult) -> (&'static str, Color) {
    match (&result.exempt, result.status) {
        (Some(_), _) => ("○", Color::DarkGray),
        (None, Status::Pass) => ("✔", Color::Green),
        (None, Status::Warn) => ("!", Color::Yellow),
        (None, Status::Fail) => ("✘", Color::Red),
        (None, Status::Unknown) => ("?", Color::DarkGray),
    }
}

fn draw_checks(frame: &mut Frame, area: Rect, view: &mut AuditView) {
    let items: Vec<ListItem> = view
        .results
        .iter()
        .map(|result| {
            let (icon, color) = status_style(result);
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {icon} "), Style::new().fg(color)),
                Span::raw(result.name),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::bordered().title(" Checks "))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));

    // `ListState` holds the selected row and the scroll position.
    frame.render_stateful_widget(list, area, &mut view.list);
}

fn draw_check_detail(frame: &mut Frame, area: Rect, selected: Option<&CheckResult>) {
    let block = Block::bordered().title(" Detail ");
    let Some(result) = selected else {
        frame.render_widget(Paragraph::new("No checks to show.").block(block), area);
        return;
    };

    let (_, color) = status_style(result);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Style::new().fg(Color::DarkGray);

    let status = if result.exempt.is_some() {
        "EXCEPTION"
    } else {
        result.status.label()
    };

    let mut lines = vec![
        Line::from(Span::styled(result.name, bold)),
        Line::from(vec![
            Span::styled(status, Style::new().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("  ·  {}  ·  weight {}", report::meta(result), result.weight),
                dim,
            ),
        ]),
        Line::default(),
        Line::from(result.detail.as_str()),
    ];

    if let Some(reason) = &result.exempt {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("Exception reason", bold)));
        lines.push(Line::from(reason.as_str()));
    }
    if result.is_issue() && !result.advice.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("Advice", bold)));
        lines.push(Line::from(result.advice));
    }
    if let (true, Some(fix)) = (result.is_issue(), result.fix) {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("Command to run yourself", bold)));
        lines.push(Line::from(Span::styled(
            fix.command_line(),
            Style::new().fg(Color::Cyan),
        )));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(format!("id: {}", result.id), dim)));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::tests::result;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn app() -> App {
        App::new(Setup {
            save_history: false,
            check_ids: Vec::new(),
            config: Config::default(),
            os_version: "macOS 26.6.2".into(),
        })
    }

    fn audit_app() -> App {
        let mut app = app();
        app.screen = Screen::Audit(AuditView::new(
            vec![
                result("firewall", Status::Pass, 20),
                result("filevault", Status::Fail, 25),
                result("ssh", Status::Warn, 10),
            ],
            Some("previous 40 (+5), 1 changed".into()),
        ));
        app
    }

    /// A job that is not backed by a thread, for drawing and event tests.
    fn idle_job(module: Module, online: bool) -> Job {
        let (_, events) = Progress::channel();
        Job {
            module,
            online,
            started: Instant::now(),
            stage: "Starting".into(),
            stages: 0,
            done: 0,
            total: 0,
            notes: VecDeque::new(),
            events,
            handle: None,
        }
    }

    fn row(tag: &str, title: &str) -> Row {
        Row {
            tag: tag.into(),
            tone: Tone::Bad,
            title: title.into(),
            detail: vec![Detail::Heading(title.into()), Detail::Text(format!("{title} detail"))],
        }
    }

    /// Draws the frame to a fake terminal and returns the on-screen text.
    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 28)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer();
        buffer
            .content()
            .chunks(buffer.area.width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn selection_stops_at_bounds() {
        let mut list = ListState::default();
        list.select(Some(0));

        move_selection(&mut list, 3, -1);
        assert_eq!(list.selected(), Some(0), "does not go above the first row");
        move_selection(&mut list, 3, 10);
        assert_eq!(list.selected(), Some(2), "does not go below the last row");
        move_selection(&mut list, 3, isize::MIN);
        assert_eq!(list.selected(), Some(0));
        move_selection(&mut list, 3, isize::MAX);
        assert_eq!(list.selected(), Some(2));

        let mut empty = ListState::default();
        move_selection(&mut empty, 0, 1);
        assert_eq!(empty.selected(), None);
    }

    #[test]
    fn home_lists_every_module_and_the_online_toggle() {
        let mut app = app();
        let screen = render(&mut app);
        for module in Module::ALL {
            assert!(screen.contains(module.title()), "{}", module.title());
        }
        assert!(screen.contains("macOS 26.6.2"));
        assert!(screen.contains("Online lookups: OFF"));
        assert!(screen.contains("nothing leaves this machine"));

        assert_eq!(app.on_key(KeyCode::Char('o')), Action::Continue);
        assert!(render(&mut app).contains("Online lookups: ON"));
    }

    #[test]
    fn online_toggle_says_exactly_what_leaves_the_machine() {
        let screen = |width: u16| {
            let mut app = app();
            app.online = true;
            let mut terminal = Terminal::new(TestBackend::new(width, 28)).unwrap();
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            let buffer = terminal.backend().buffer();
            buffer
                .content()
                .chunks(usize::from(width))
                .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let wide = screen(220);
        assert!(
            wide.contains("names and versions to OSV.dev and the NVD (with your NVD API key, if set), CVE ids to FIRST; nothing else"),
            "{wide}"
        );
        // On an 80-column terminal the statement wraps instead of being cut off.
        let narrow = screen(80);
        assert!(
            narrow.contains("API key, if set") && narrow.contains("nothing else"),
            "{narrow}"
        );
    }

    #[test]
    fn home_navigation_and_quit() {
        let mut app = app();
        assert_eq!(app.selected_module(), Module::Audit);
        app.on_key(KeyCode::Down);
        assert_eq!(app.selected_module(), Module::Vulns);
        assert!(render(&mut app).contains("Uses the online toggle below."));
        app.on_key(KeyCode::End);
        assert_eq!(app.selected_module(), Module::Secrets);
        assert!(render(&mut app).contains("Not affected by the online toggle."));
        assert_eq!(app.on_key(KeyCode::Char('q')), Action::Quit);
    }

    #[test]
    fn job_tracks_stages_steps_and_recent_notes() {
        let mut job = idle_job(Module::Vulns, true);
        job.apply(ProgressEvent::Stage("Asking OSV.dev".into()));
        job.apply(ProgressEvent::Step { done: 3, total: 6 });
        for index in 0..MAX_NOTES + 2 {
            job.apply(ProgressEvent::Note(format!("note {index}")));
        }
        assert_eq!((job.stages, job.done, job.total), (1, 3, 6));
        assert_eq!(job.notes.len(), MAX_NOTES);
        assert_eq!(job.notes.front().unwrap(), "note 2", "the oldest notes are dropped");

        job.apply(ProgressEvent::Stage("Fetching EPSS".into()));
        assert_eq!(
            (job.stages, job.done, job.total),
            (2, 0, 0),
            "a new stage resets the counter"
        );
        assert!(job.notes.is_empty());
    }

    #[test]
    fn running_screen_shows_stage_percentage_and_notes() {
        let mut app = app();
        let mut job = idle_job(Module::Vulns, true);
        job.apply(ProgressEvent::Stage("Checking 23 system products in the NVD".into()));
        job.apply(ProgressEvent::Step { done: 5, total: 20 });
        job.apply(ProgressEvent::Note("Google Chrome 157.0".into()));
        app.screen = Screen::Running(job);

        let screen = render(&mut app);
        assert!(screen.contains("Vulnerability scan · online"), "{screen}");
        assert!(screen.contains("Checking 23 system products in the NVD"));
        assert!(screen.contains("25%"));
        assert!(screen.contains("5 of 20"));
        assert!(screen.contains("Google Chrome 157.0"));
        assert!(screen.contains("stop and go back"));
    }

    #[test]
    fn enter_does_not_cancel_a_running_job_but_esc_does() {
        let mut app = app();
        app.screen = Screen::Running(idle_job(Module::Vulns, true));
        app.on_key(KeyCode::Enter);
        assert!(
            matches!(app.screen, Screen::Running(_)),
            "a double press on the home screen must not abandon the job"
        );
        app.on_key(KeyCode::Esc);
        assert!(matches!(app.screen, Screen::Home));
    }

    #[test]
    fn leaving_a_job_tells_its_worker_to_stop() {
        let (progress, events) = Progress::channel();
        let mut job = idle_job(Module::Vulns, true);
        job.events = events;
        let mut app = app();
        app.screen = Screen::Running(job);
        progress.note("still watched");
        assert!(!progress.cancelled());

        app.on_key(KeyCode::Esc);
        progress.note("nobody is listening");
        assert!(progress.cancelled());
    }

    #[test]
    fn long_warnings_wrap_instead_of_being_cut_off() {
        let warning = format!(
            "OSV lookup failed: {} END-OF-WARNING",
            "curl: (6) could not resolve host ".repeat(5)
        );
        let mut app = app();
        app.screen = Screen::Results(ResultView::new(
            Module::Vulns,
            vec![(Tone::Plain, "1 lockfiles".into()), (Tone::Warn, warning)],
            vec![row("KEV", "pkg 1.0")],
            "",
        ));
        let screen = render(&mut app);
        assert!(screen.contains("END-OF-WARNING"), "{screen}");
        assert!(screen.contains("pkg 1.0"), "the list still fits below the header");
    }

    #[test]
    fn warnings_with_long_urls_or_wide_characters_are_not_cut_off() {
        // Word wrapping cannot break a URL, and CJK characters take two
        // columns: counting characters made the header too short for both.
        let url = "EPSS lookup failed (curl: (28) timed out after 60000 milliseconds \
                   https://api.first.org/data/v1/epss?cve=CVE-2024-21626,CVE-2024-3094,CVE-2023-44487,CVE-2023-4863,CVE-2021-44228 \
                   https://api.first.org/data/v1/epss?cve=CVE-2022-22965,CVE-2023-34362,CVE-2024-1086,CVE-2023-20198,CVE-2022-1388); \
                   END-OF-URL-WARNING";
        let wide = "Could not read /Users/田中太郎/プロジェクト/在庫管理システム/フロントエンド/パッケージ/サブモジュール/package-lock.json END-OF-WIDE-WARNING";
        let mut app = app();
        app.screen = Screen::Results(ResultView::new(
            Module::Vulns,
            vec![
                (Tone::Plain, "1 lockfiles".into()),
                (Tone::Warn, url.into()),
                (Tone::Warn, wide.into()),
            ],
            vec![row("KEV", "pkg 1.0")],
            "",
        ));
        let screen = render(&mut app);
        assert!(screen.contains("END-OF-URL-WARNING"), "{screen}");
        assert!(screen.contains("END-OF-WIDE-WARNING"), "{screen}");
        assert!(screen.contains("pkg 1.0"), "the list still fits below the header");
    }

    #[test]
    fn header_rows_wrap_at_display_width() {
        assert_eq!(wrap_to_width("abcd efgh", 9), ["abcd efgh"]);
        assert_eq!(wrap_to_width("abcd efghi", 9), ["abcd", "efghi"]);
        assert_eq!(wrap_to_width(" ab cdefghij", 4), [" ab", "cdef", "ghij"]);
        assert_eq!(wrap_to_width("abc田", 4), ["abc", "田"]);
        assert_eq!(wrap_to_width("", 5), [""]);
    }

    #[test]
    fn failed_npm_lookup_is_not_reported_as_switched_off() {
        let scan = npm::scan(&[]);
        let failed = npm_view(&scan, Some(Err("offline".into())));
        let text: Vec<&str> = failed.headline.iter().map(|(_, text)| text.as_str()).collect();
        assert!(text[0].ends_with("built-in list + OSV.dev (incomplete)"), "{text:?}");
        assert!(
            text.iter()
                .any(|line| line.contains("OSV lookup failed") && line.contains("offline"))
        );
        assert!(npm_view(&scan, None).headline[0].1.contains("online lookups are off"));
        assert!(npm_view(&scan, Some(Ok(()))).headline[0].1.contains("OSV.dev"));
    }

    #[test]
    fn secrets_view_says_when_git_status_is_unknown() {
        let dir = std::env::temp_dir().join(format!("swordcheck-tui-gitunknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".env"),
            "DATABASE_URL=postgres://app:Zq9K2mx7LwPa4@db.prod.internal/app\n",
        )
        .unwrap();
        let mut scan = secrets::scan(&secrets::files_under(&dir));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !secrets_view(&scan)
                .headline
                .iter()
                .any(|(_, line)| line.contains("folder"))
        );
        scan.skipped.unreadable_folders = 1;
        assert!(secrets_view(&scan).headline.contains(&(
            Tone::Warn,
            "1 folder could not be opened, so the files in it were not scanned".to_string()
        )));
        scan.findings[0].git_unknown = true;
        scan.findings[0].others_can_read = false;
        let view = secrets_view(&scan);
        assert_eq!(view.rows[0].tone, Tone::Warn);
        assert!(
            view.rows[0]
                .detail
                .contains(&Detail::Text(secrets::GIT_UNKNOWN_ADVICE.into()))
        );
    }

    #[test]
    fn vulnerability_summary_is_not_green_when_lookups_failed() {
        let summary = |warnings: Vec<String>, kev: bool| {
            let mut scan = vulns::Scan {
                online: true,
                warnings,
                ..vulns::Scan::default()
            };
            if kev {
                scan.system.push(vulns::SystemItem {
                    source: vulns::Source::App,
                    name: "Chrome".into(),
                    version: "1.0".into(),
                    cpe: "cpe:2.3:a:google:chrome:1.0".into(),
                    checked: true,
                    error: None,
                    exploited: vec![vulns::SystemVuln {
                        cve: "CVE-2023-7024".into(),
                        name: "WebRTC".into(),
                        date_added: "2024-01-02".into(),
                        ransomware: false,
                    }],
                });
            }
            vulns_view(&scan).headline[1].clone()
        };
        let failed = || vec!["CISA KEV download failed: timeout".to_string()];

        let (tone, text) = summary(Vec::new(), false);
        assert_eq!(
            (tone, text.as_str()),
            (Tone::Good, "0 findings · 0 known-exploited or malware")
        );
        let (tone, text) = summary(failed(), false);
        assert_eq!(tone, Tone::Warn);
        assert!(text.ends_with("incomplete: see the warnings below"), "{text}");
        let (tone, text) = summary(failed(), true);
        assert_eq!(tone, Tone::Bad, "an exploited product stays red");
        assert!(!text.contains("incomplete"), "{text}");
        // The failed lookup itself is still listed below the summary.
        let scan = vulns::Scan {
            online: true,
            warnings: failed(),
            ..vulns::Scan::default()
        };
        assert!(
            vulns_view(&scan)
                .headline
                .iter()
                .any(|(tone, text)| *tone == Tone::Warn && text.contains("CISA KEV"))
        );
    }

    #[test]
    fn unread_npm_packages_are_not_called_scripts() {
        let finding = |kind, package: &str| npm::Finding {
            kind,
            package: package.into(),
            version: String::new(),
            reason: "reason".into(),
            count: 1,
            paths: Vec::new(),
        };
        let scan = npm::Scan {
            findings: vec![
                finding(npm::Kind::Unread, "event-stream"),
                finding(npm::Kind::Script, "helper"),
                finding(npm::Kind::Known, "chalk"),
            ],
            ..npm::Scan::default()
        };
        let mut scan = scan;
        scan.findings[2].version = "5.6.1".into();
        let view = npm_view(&scan, None);
        let tags: Vec<&str> = view.rows.iter().map(|row| row.tag.as_str()).collect();
        assert_eq!(tags, ["UNREAD", "SCRIPT", "MALWARE"]);
        let titles: Vec<&str> = view.rows.iter().map(|row| row.title.as_str()).collect();
        assert_eq!(titles, ["event-stream@?", "helper@?", "chalk@5.6.1"]);
        assert!(
            view.rows[0]
                .detail
                .contains(&Detail::Text(npm::Kind::Unread.advice().into()))
        );
        let headline: Vec<&str> = view.headline.iter().map(|(_, text)| text.as_str()).collect();
        assert!(headline[1].ends_with("1 suspicious install scripts"), "{headline:?}");
        assert!(headline[2].starts_with("1 packages not checked"), "{headline:?}");
    }

    #[test]
    fn running_screen_without_a_total_shows_no_percentage() {
        let mut app = app();
        let mut job = idle_job(Module::Secrets, false);
        job.apply(ProgressEvent::Stage("Looking for files".into()));
        app.screen = Screen::Running(job);

        let screen = render(&mut app);
        assert!(screen.contains("Looking for files"));
        assert!(screen.contains("working"));
        assert!(!screen.contains('%'), "{screen}");
        assert!(screen.contains("█"));

        app.on_key(KeyCode::Esc);
        assert!(
            matches!(app.screen, Screen::Home),
            "esc cancels back to the home screen"
        );
    }

    #[test]
    fn results_screen_shows_rows_and_selected_detail() {
        let mut app = app();
        let headline = vec![(Tone::Bad, "2 findings".to_string())];
        app.screen = Screen::Results(ResultView::new(
            Module::Npm,
            headline,
            vec![row("KEV", "first"), row("HIGH", "second")],
            "none",
        ));

        let screen = render(&mut app);
        assert!(screen.contains("npm malware scan"));
        assert!(screen.contains("2 findings"));
        assert!(screen.contains("Findings 1/2"));
        assert!(screen.contains("first detail"));

        app.on_key(KeyCode::Down);
        let screen = render(&mut app);
        assert!(screen.contains("Findings 2/2"));
        assert!(screen.contains("second detail"));

        app.on_key(KeyCode::Esc);
        assert!(matches!(app.screen, Screen::Home));
    }

    #[test]
    fn empty_results_show_the_empty_message() {
        let mut app = app();
        app.screen = Screen::Results(ResultView::new(
            Module::Secrets,
            Vec::new(),
            Vec::new(),
            "No secrets found.",
        ));
        app.on_key(KeyCode::Down);
        assert!(render(&mut app).contains("No secrets found."));
    }

    #[test]
    fn audit_screen_shows_score_list_and_detail() {
        let mut app = audit_app();
        assert!(render(&mut app).contains("previous 40 (+5), 1 changed"));
        app.on_key(KeyCode::Down); // filevault (failing) is selected

        let screen = render(&mut app);
        // 20 full + 0 + 5 half = 25 / 55 → 45%
        assert!(screen.contains("45/100 (Grade: D)"), "{screen}");
        assert!(screen.contains("Checks"));
        assert!(screen.contains("✘ filevault"));
        assert!(screen.contains("FAIL"));
        assert!(screen.contains("filevault detail"));
        assert!(screen.contains("Advice"));
        assert!(screen.contains("re-run audit"));
    }

    #[test]
    fn empty_audit_does_not_panic() {
        let mut app = app();
        app.screen = Screen::Audit(AuditView::new(Vec::new(), None));
        app.on_key(KeyCode::Down);
        assert!(render(&mut app).contains("No checks to show."));
    }

    #[test]
    fn secrets_view_marks_tracked_files_and_copies() {
        let dir = std::env::temp_dir().join(format!("swordcheck-tui-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::create_dir_all(dir.join("b")).unwrap();
        // Built at run time so that no key-shaped string sits in the source.
        let key = format!(
            "ghp_{}",
            "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6".chars().rev().collect::<String>()
        );
        std::fs::write(dir.join("a/.env"), format!("GITHUB_TOKEN={key}\n")).unwrap();
        std::fs::write(dir.join("b/.env"), format!("GH={key}\n")).unwrap();

        let view = secrets_view(&secrets::scan(&secrets::files_under(&dir)));
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(view.rows.len(), 2);
        assert_eq!(view.rows[0].tag, "GITHUB");
        assert!(view.rows[0].title.starts_with("GITHUB_TOKEN"));
        assert!(
            view.rows[0]
                .detail
                .contains(&Detail::Heading("Same secret in 1 other file(s)".into()))
        );
        assert!(view.headline[0].1.contains("1 secrets · 2 locations"));
        let everything = format!("{:?}{:?}", view.rows, view.headline);
        assert!(!everything.contains(&key), "the raw secret never reaches the dashboard");
    }

    #[test]
    fn an_audit_with_nothing_to_score_is_not_recorded() {
        let dir = std::env::temp_dir().join(format!("swordcheck-tui-unscored-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        let before = [result("firewall", Status::Fail, 20)];
        let previous = history::RunRecord::new("2026-11-01T09:00:00+03:00".into(), "macOS 26".into(), 50, &before);
        history::append(&path, Vec::new(), previous).unwrap();

        // Every check Unknown: no score, so nothing to compare or save.
        let trend = record_audit(Some(&path), &[result("firewall", Status::Unknown, 20)], "macOS 26");
        let unscored: Vec<u32> = history::load(&path)
            .unwrap()
            .iter()
            .map(|record| record.score)
            .collect();
        // A scored run is still saved and compared.
        let scored_trend = record_audit(Some(&path), &[result("firewall", Status::Pass, 20)], "macOS 26");
        let scored: Vec<u32> = history::load(&path)
            .unwrap()
            .iter()
            .map(|record| record.score)
            .collect();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(trend, "not recorded: no check could be evaluated");
        assert_eq!(unscored, [50], "the placeholder score must not reach the history");
        assert!(scored_trend.starts_with("previous 50 (+50)"), "{scored_trend}");
        assert_eq!(scored, [50, 100]);
        assert_eq!(
            record_audit(None, &[result("firewall", Status::Pass, 20)], "macOS 26"),
            "history unavailable (HOME is not set to an absolute path)"
        );
    }

    #[test]
    fn unread_lockfiles_are_shown_and_not_green() {
        let scan = vulns::Scan {
            online: true,
            skipped: vec![vulns::Skipped {
                path: PathBuf::from("/nowhere/app/requirements.txt"),
                reason: "over 64 MB",
            }],
            ..vulns::Scan::default()
        };
        let view = vulns_view(&scan);
        assert_eq!(view.headline[1].0, Tone::Warn);
        assert!(view.headline[1].1.ends_with("incomplete: see the warnings below"));
        assert!(view.headline.iter().any(|(tone, text)| *tone == Tone::Warn
            && text
                == "1 lockfile could not be read, so the packages they pin were not checked: \
                        /nowhere/app/requirements.txt (over 64 MB)"));
    }

    #[test]
    fn installed_products_say_when_a_kev_entry_is_used_in_ransomware() {
        let vuln = |cve: &str, ransomware: bool| vulns::SystemVuln {
            cve: cve.into(),
            name: "Flaw".into(),
            date_added: "2024-03-01".into(),
            ransomware,
        };
        let scan = vulns::Scan {
            online: true,
            system: vec![vulns::SystemItem {
                source: vulns::Source::App,
                name: "Chrome".into(),
                version: "1.0".into(),
                cpe: "cpe:2.3:a:google:chrome:1.0".into(),
                checked: true,
                error: None,
                exploited: vec![vuln("CVE-2024-2", true), vuln("CVE-2024-3", false)],
            }],
            ..vulns::Scan::default()
        };
        let view = vulns_view(&scan);
        let detail = &view.rows[0].detail;
        assert!(detail.contains(&Detail::Dim(
            "added to CISA KEV on 2024-03-01, used in ransomware".into()
        )));
        assert!(detail.contains(&Detail::Dim("added to CISA KEV on 2024-03-01".into())));
    }

    /// The vulnerability worker reads HOME, so it runs in a child process of
    /// this test binary with a HOME of its own; this process's environment
    /// is left alone.
    #[test]
    fn the_vulnerability_worker_passes_on_unread_lockfiles() {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("SWORDCHECK_WORKER_TEST").is_some() {
            let setup = Setup {
                save_history: false,
                check_ids: Vec::new(),
                config: Config::default(),
                os_version: "macOS 26".into(),
            };
            let (progress, _events) = Progress::channel();
            let outcome = work(Module::Vulns, false, &setup, &progress);
            let reported = |view: &ResultView| {
                view.headline.iter().any(|(_, line)| {
                    line.starts_with("1 lockfile could not be read")
                        && line.ends_with("~/app/package-lock.json (permission denied)")
                })
            };
            assert!(matches!(&outcome, Outcome::View(view) if reported(view)));
            return;
        }
        let home = std::env::temp_dir().join(format!("swordcheck-tui-worker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("app")).unwrap();
        let lockfile = home.join("app/package-lock.json");
        std::fs::write(
            &lockfile,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&lockfile, std::fs::Permissions::from_mode(0o000)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tui::tests::the_vulnerability_worker_passes_on_unread_lockfiles",
                "--nocapture",
            ])
            .env("SWORDCHECK_WORKER_TEST", "1")
            .env("HOME", &home)
            .env("SWORDCHECK_HOME", home.join(".swordcheck"))
            .output()
            .unwrap();
        std::fs::set_permissions(&lockfile, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = std::fs::remove_dir_all(&home);
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{out}{err}");
        assert!(out.contains("1 passed"), "the child ran the test: {out}");
    }

    /// The npm worker with online lookups on, through a `curl` that times
    /// out: the view says the OSV lookup failed. Runs in a child process with
    /// its own HOME and PATH, like the test above.
    #[test]
    fn the_npm_worker_says_when_the_osv_lookup_failed() {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("SWORDCHECK_WORKER_TEST").is_some() {
            let setup = Setup {
                save_history: false,
                check_ids: Vec::new(),
                config: Config::default(),
                os_version: "macOS 26".into(),
            };
            let (progress, _events) = Progress::channel();
            let outcome = work(Module::Npm, true, &setup, &progress);
            let reported = |view: &ResultView| {
                let text: Vec<&str> = view.headline.iter().map(|(_, line)| line.as_str()).collect();
                text[0].ends_with("built-in list + OSV.dev (incomplete)")
                    && text
                        .iter()
                        .any(|line| line.starts_with("OSV lookup failed") && line.contains("(28)"))
            };
            assert!(matches!(&outcome, Outcome::View(view) if reported(view)));
            return;
        }
        let home = std::env::temp_dir().join(format!("swordcheck-tui-npm-worker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("app/node_modules/left-pad")).unwrap();
        std::fs::write(
            home.join("app/node_modules/left-pad/package.json"),
            r#"{"name":"left-pad","version":"1.3.0"}"#,
        )
        .unwrap();
        let shim = home.join("shim");
        std::fs::create_dir_all(&shim).unwrap();
        std::fs::write(
            shim.join("curl"),
            "#!/bin/sh\ncat > /dev/null\necho 'curl: (28) Operation timed out' >&2\nexit 28\n",
        )
        .unwrap();
        std::fs::set_permissions(shim.join("curl"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tui::tests::the_npm_worker_says_when_the_osv_lookup_failed",
                "--nocapture",
            ])
            .env("SWORDCHECK_WORKER_TEST", "1")
            .env("HOME", &home)
            .env("SWORDCHECK_HOME", home.join(".swordcheck"))
            .env("PATH", format!("{}:/usr/bin:/bin", shim.display()))
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&home);
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{out}{err}");
        assert!(out.contains("1 passed"), "the child ran the test: {out}");
    }

    #[test]
    fn a_real_audit_job_runs_to_completion() {
        // No checks selected: the worker still starts, reports and finishes.
        let mut app = app();
        app.start(Module::Audit);
        let deadline = Instant::now() + Duration::from_secs(10);
        while matches!(app.screen, Screen::Running(_)) && Instant::now() < deadline {
            app.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(app.screen, Screen::Audit(_)));
    }
}
