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
                "Reads the lockfiles of your projects (Cargo, npm, yarn, pnpm, Python, Composer, Bundler, Go) and lists macOS plus well-known apps.",
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
        Self { module, headline, rows, list, empty }
    }
}

/// The audit keeps its own view: it has a score gauge and typed results.
struct AuditView {
    results: Vec<CheckResult>,
    list: ListState,
}

impl AuditView {
    fn new(results: Vec<CheckResult>) -> Self {
        let mut list = ListState::default();
        if !results.is_empty() {
            list.select(Some(0));
        }
        Self { results, list }
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
        let title = format!("{} {}", item.name, item.version);
        let mut detail = vec![Detail::Heading(title.clone()), Detail::Dim(item.cpe.clone()), Detail::Blank];
        let (tag, tone) = if !scan.online {
            detail.push(Detail::Text("Not looked up yet. Enable online lookups on the home screen and run again.".into()));
            ("APP", Tone::Dim)
        } else if let Some(error) = &item.error {
            detail.push(Detail::Text(format!("The NVD lookup failed: {error}")));
            ("?", Tone::Warn)
        } else if item.exploited.is_empty() {
            detail.push(Detail::Text("No known-exploited vulnerability affects this version.".into()));
            ("OK", Tone::Good)
        } else {
            detail.push(Detail::Text(format!(
                "{} known-exploited vulnerabilities affect this version. Update it.",
                item.exploited.len()
            )));
            detail.push(Detail::Blank);
            for vuln in &item.exploited {
                detail.push(Detail::Text(format!("{}  {}", vuln.cve, vuln.name)));
                detail.push(Detail::Dim(format!("added to CISA KEV on {}", vuln.date_added)));
            }
            ("KEV", Tone::Bad)
        };
        rows.push(Row { tag: tag.into(), tone, title, detail });
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
        detail.push(Detail::Text(format!("Severity   {:?}", finding.severity)));
        if let Some(epss) = finding.epss {
            detail.push(Detail::Text(format!("EPSS       {:.1}% chance of exploitation in 30 days", epss * 100.0)));
        }
        if let Some(kev) = &finding.kev {
            let ransomware = if kev.ransomware { ", used in ransomware" } else { "" };
            detail.push(Detail::Text(format!("Exploited  in CISA KEV since {}{ransomware}", kev.date_added)));
        }
        if !finding.fixed.is_empty() {
            detail.push(Detail::Text(format!("Fixed in   {}", finding.fixed.join(", "))));
        }
        detail.push(Detail::Blank);
        detail.push(Detail::Heading(format!("Pinned by {} lockfile(s)", finding.lockfile_count)));
        detail.extend(finding.lockfiles.iter().map(|path| Detail::Dim(short_path(path))));
        if exploited {
            detail.push(Detail::Blank);
            detail.push(Detail::Text("This is being exploited in the wild. Fix it first.".into()));
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
        format!("{} lockfiles · {} packages · {} system products", scan.lockfiles, scan.packages, scan.system.len()),
    )];
    if scan.online {
        let exploited = scan.exploited();
        headline.push((
            if exploited > 0 { Tone::Bad } else { Tone::Good },
            format!("{} findings · {exploited} known-exploited or malware", scan.findings.len()),
        ));
    } else {
        headline.push((Tone::Warn, "Inventory only: online lookups are off (press esc, then o).".into()));
    }
    headline.extend(scan.warnings.iter().map(|warning| (Tone::Warn, warning.clone())));
    ResultView::new(Module::Vulns, headline, rows, "Nothing to scan: no lockfiles or known apps were found.")
}

fn npm_view(scan: &npm::Scan, online: bool) -> ResultView {
    let rows = scan
        .findings
        .iter()
        .map(|finding| {
            let version = if finding.version.is_empty() { "?" } else { &finding.version };
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
            detail.push(Detail::Text(if finding.kind.is_malware() {
                "Remove the package or move to a clean version, reinstall node_modules, and rotate the npm / GitHub / cloud credentials on this machine.".into()
            } else {
                "Heuristic warning: read the install script and decide.".into()
            }));
            Row {
                tag: if finding.kind.is_malware() { "MALWARE" } else { "SCRIPT" }.into(),
                tone: if finding.kind.is_malware() { Tone::Bad } else { Tone::Warn },
                title,
                detail,
            }
        })
        .collect();

    let malware = scan.malware().count();
    let source = if online { "built-in list + OSV.dev" } else { "built-in list only (online lookups are off)" };
    let headline = vec![
        (Tone::Plain, format!("{} directories · {} package installs · {source}", scan.roots.len(), scan.packages)),
        (
            if malware > 0 { Tone::Bad } else { Tone::Good },
            format!("{malware} malicious · {} suspicious install scripts", scan.suspicious().count()),
        ),
    ];
    ResultView::new(Module::Npm, headline, rows, "No malicious or suspicious packages found.")
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
                tone: match (finding.git_tracked, finding.others_can_read) {
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
    let providers: Vec<String> = scan.summary.iter().map(|row| format!("{} {}", row.provider, row.secrets)).collect();
    let headline = vec![
        (
            Tone::Plain,
            format!("{} files · {} secrets · {} locations", scan.files_scanned, scan.unique_secrets(), scan.findings.len()),
        ),
        (
            if tracked > 0 { Tone::Bad } else { Tone::Dim },
            if tracked > 0 { format!("{tracked} in git-tracked files · {}", providers.join(" · ")) } else { providers.join(" · ") },
        ),
    ];
    ResultView::new(Module::Secrets, headline, rows, "No secrets found.")
}

// ---- Jobs ----

/// What a finished job hands back.
enum Outcome {
    Audit(Vec<CheckResult>),
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
        Some(handle.join().map_err(|_| format!("{} stopped unexpectedly.", self.module.title())))
    }
}

/// Runs a module to completion. This is the body of the worker thread.
fn work(module: Module, online: bool, setup: &Setup, progress: &Progress) -> Outcome {
    let runner = SystemRunner::new();
    match module {
        Module::Audit => {
            let mut checks = checks::registry();
            checks.retain(|check| setup.check_ids.iter().any(|id| id == check.id()));
            Outcome::Audit(checks::run_checks_with(&checks, &runner, &setup.config, progress))
        }
        Module::Vulns => {
            progress.stage("Looking for lockfiles in your projects");
            let paths = lockfiles::default_files();
            progress.stage("Listing macOS and installed applications");
            let system = vulns::system_items(&runner);
            let lockfiles = vulns::read_lockfiles(&paths, progress);
            let cache = history::history_path().and_then(|path| path.parent().map(|dir| dir.join("cache")));
            let scan = match (online, cache) {
                (true, Some(cache)) => {
                    vulns::scan(&lockfiles, system, &vulns::Online { cache, progress: progress.clone() })
                }
                _ => vulns::offline(&lockfiles, system),
            };
            Outcome::View(vulns_view(&scan))
        }
        Module::Npm => {
            progress.stage("Looking for node_modules directories");
            let roots = npm::all_roots(&runner);
            let mut scan = npm::scan_with(&roots, progress);
            let mut looked_up = false;
            if online {
                match npm::osv_lookup_with(&scan.installed, progress) {
                    Ok(hits) => {
                        scan.add_osv(hits);
                        looked_up = true;
                    }
                    Err(err) => progress.note(format!("OSV lookup failed: {err}")),
                }
            }
            Outcome::View(npm_view(&scan, looked_up))
        }
        Module::Secrets => {
            progress.stage("Looking for files that may hold secrets");
            let files = secrets::default_files();
            Outcome::View(secrets_view(&secrets::scan_with(&files, progress)))
        }
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
        Self { setup: Arc::new(setup), screen: Screen::Home, menu, online: false }
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
                Ok(Outcome::Audit(results)) => Screen::Audit(AuditView::new(results)),
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
            // Leaving a running job abandons it; the worker finishes on its
            // own and its cached downloads are kept.
            Screen::Running(_) | Screen::Failed(_) => match code {
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
    let outcome = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    outcome
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    /// How long to wait for a key before redrawing; short enough for the
    /// spinner and progress bar to look alive.
    const FRAME: Duration = Duration::from_millis(80);

    loop {
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
            &[("↑↓", "select"), ("enter", "run"), ("o", "online lookups on/off"), ("q", "quit")]
        }
        Screen::Running(job) => {
            draw_running(frame, body, job, job.started.elapsed());
            &[("esc", "cancel and go back"), ("q", "quit")]
        }
        Screen::Audit(view) => {
            draw_audit(frame, body, view, &app.setup.os_version);
            &[("↑↓/jk", "navigate"), ("r", "re-run audit"), ("esc", "home"), ("q", "quit")]
        }
        Screen::Results(view) => {
            draw_results(frame, body, view);
            &[("↑↓/jk", "navigate"), ("PgUp/PgDn", "jump"), ("r", "re-run"), ("esc", "home"), ("q", "quit")]
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
        Layout::vertical([Constraint::Length(3), Constraint::Min(6), Constraint::Length(3)]).areas(area);
    let [menu_area, about_area] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(body);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Tone::Dim.style();

    let title = Line::from(vec![
        Span::styled(" macOS Security Auditor ", bold),
        Span::styled(format!("· {os_version} · v{}", env!("CARGO_PKG_VERSION")), dim),
    ]);
    frame.render_widget(Paragraph::new(title).block(Block::bordered()), header);

    let selected = Module::ALL[menu.selected().unwrap_or(0).min(Module::ALL.len() - 1)];
    let items: Vec<ListItem> = Module::ALL
        .iter()
        .enumerate()
        .map(|(index, module)| {
            ListItem::new(vec![
                Line::from(vec![Span::styled(format!(" {} ", index + 1), dim), Span::styled(module.title(), bold)]),
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
        if selected.uses_network() { "Uses the online toggle below." } else { "Not affected by the online toggle." },
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
    let explanation = if online {
        "  package names and versions are sent to OSV.dev, NVD, CISA and FIRST; nothing else"
    } else {
        "  nothing leaves this machine"
    };
    let line = Line::from(vec![Span::raw(" Online lookups: "), state, Span::styled(explanation, dim)]);
    frame.render_widget(Paragraph::new(line).block(Block::bordered()), toggle);
}

/// `m:ss`.
fn clock(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

fn draw_running(frame: &mut Frame, area: Rect, job: &Job, elapsed: Duration) {
    // A fixed-size box in the middle of the screen.
    let [column] = Layout::horizontal([Constraint::Max(84)]).flex(Flex::Center).areas(area);
    let [boxed] = Layout::vertical([Constraint::Max(MAX_NOTES as u16 + 9)]).flex(Flex::Center).areas(column);
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
    .areas(inner.inner(ratatui::layout::Margin { horizontal: 2, vertical: 1 }));

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
        let count = format!("{} of {} · step {} · elapsed {}", job.done, job.total, job.stages.max(1), clock(elapsed));
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
    let notes: Vec<Line> = job.notes.iter().map(|note| Line::from(Span::styled(note.as_str(), dim))).collect();
    frame.render_widget(Paragraph::new(notes), notes_area);
}

fn draw_results(frame: &mut Frame, area: Rect, view: &mut ResultView) {
    let [header, body] =
        Layout::vertical([Constraint::Length(view.headline.len() as u16 + 2), Constraint::Min(5)]).areas(area);
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);

    let headline: Vec<Line> =
        view.headline.iter().map(|(tone, text)| Line::from(Span::styled(format!(" {text}"), tone.style()))).collect();
    let title = format!(" {} ", view.module.title());
    frame.render_widget(Paragraph::new(headline).block(Block::bordered().title(title)), header);

    let width = view.rows.iter().map(|row| row.tag.chars().count()).max().unwrap_or(0).min(12);
    let items: Vec<ListItem> = view
        .rows
        .iter()
        .map(|row| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<width$} ", row.tag), row.tone.style().add_modifier(Modifier::BOLD)),
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
        frame.render_widget(Paragraph::new(view.empty).block(block).wrap(Wrap { trim: false }), detail_area);
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
    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), detail_area);
}

fn draw_audit(frame: &mut Frame, area: Rect, view: &mut AuditView, os_version: &str) {
    let [header, body] = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).areas(area);
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);

    draw_score(frame, header, &view.results, os_version);
    draw_checks(frame, list_area, view);
    draw_check_detail(frame, detail_area, view.selected());
}

fn draw_score(frame: &mut Frame, area: Rect, results: &[CheckResult], os_version: &str) {
    let score = score::calculate_score(results);
    let summary = Summary::from_results(results);
    let color = match score {
        90.. => Color::Green,
        60..=89 => Color::Yellow,
        _ => Color::Red,
    };

    let title = format!(
        " macOS Security Audit · {os_version} · {} pass, {} warn, {} fail ",
        summary.pass, summary.warn, summary.fail
    );
    let gauge = Gauge::default()
        .block(Block::bordered().title(title))
        .gauge_style(Style::new().fg(color))
        .percent(score.min(100) as u16)
        .label(format!("{score}/100 (Grade: {})", score::grade(score)));
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

    let status = if result.exempt.is_some() { "EXCEPTION" } else { result.status.label() };

    let mut lines = vec![
        Line::from(Span::styled(result.name, bold)),
        Line::from(vec![
            Span::styled(status, Style::new().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  ·  {}  ·  weight {}", report::meta(result), result.weight), dim),
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
        lines.push(Line::from(Span::styled("Fix command (--fix)", bold)));
        lines.push(Line::from(Span::styled(fix.command_line(), Style::new().fg(Color::Cyan))));
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
        App::new(Setup { check_ids: Vec::new(), config: Config::default(), os_version: "macOS 26.6.2".into() })
    }

    fn audit_app() -> App {
        let mut app = app();
        app.screen = Screen::Audit(AuditView::new(vec![
            result("firewall", Status::Pass, 20),
            result("filevault", Status::Fail, 25),
            result("ssh", Status::Warn, 10),
        ]));
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
        assert_eq!((job.stages, job.done, job.total), (2, 0, 0), "a new stage resets the counter");
        assert!(job.notes.is_empty());
    }

    #[test]
    fn running_screen_shows_stage_percentage_and_notes() {
        let mut app = app();
        let mut job = idle_job(Module::Vulns, true);
        job.apply(ProgressEvent::Stage("Checking macOS and 22 apps in the NVD".into()));
        job.apply(ProgressEvent::Step { done: 5, total: 20 });
        job.apply(ProgressEvent::Note("Google Chrome 157.0".into()));
        app.screen = Screen::Running(job);

        let screen = render(&mut app);
        assert!(screen.contains("Vulnerability scan · online"), "{screen}");
        assert!(screen.contains("Checking macOS and 22 apps in the NVD"));
        assert!(screen.contains("25%"));
        assert!(screen.contains("5 of 20"));
        assert!(screen.contains("Google Chrome 157.0"));
        assert!(screen.contains("cancel and go back"));
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
        assert!(matches!(app.screen, Screen::Home), "esc cancels back to the home screen");
    }

    #[test]
    fn results_screen_shows_rows_and_selected_detail() {
        let mut app = app();
        let headline = vec![(Tone::Bad, "2 findings".to_string())];
        app.screen = Screen::Results(ResultView::new(Module::Npm, headline, vec![row("KEV", "first"), row("HIGH", "second")], "none"));

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
        app.screen = Screen::Results(ResultView::new(Module::Secrets, Vec::new(), Vec::new(), "No secrets found."));
        app.on_key(KeyCode::Down);
        assert!(render(&mut app).contains("No secrets found."));
    }

    #[test]
    fn audit_screen_shows_score_list_and_detail() {
        let mut app = audit_app();
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
        app.screen = Screen::Audit(AuditView::new(Vec::new()));
        app.on_key(KeyCode::Down);
        assert!(render(&mut app).contains("No checks to show."));
    }

    #[test]
    fn secrets_view_marks_tracked_files_and_copies() {
        let dir = std::env::temp_dir().join(format!("macos-audit-tui-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::create_dir_all(dir.join("b")).unwrap();
        // Built at run time so that no key-shaped string sits in the source.
        let key = format!("ghp_{}", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lM6".chars().rev().collect::<String>());
        std::fs::write(dir.join("a/.env"), format!("GITHUB_TOKEN={key}\n")).unwrap();
        std::fs::write(dir.join("b/.env"), format!("GH={key}\n")).unwrap();

        let view = secrets_view(&secrets::scan(&secrets::files_under(&dir)));
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(view.rows.len(), 2);
        assert_eq!(view.rows[0].tag, "GITHUB");
        assert!(view.rows[0].title.starts_with("GITHUB_TOKEN"));
        assert!(view.rows[0].detail.contains(&Detail::Heading("Same secret in 1 other file(s)".into())));
        assert!(view.headline[0].1.contains("1 secrets · 2 locations"));
        let everything = format!("{:?}{:?}", view.rows, view.headline);
        assert!(!everything.contains(&key), "the raw secret never reaches the dashboard");
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
