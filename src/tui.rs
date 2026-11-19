//! Interactive terminal dashboard (`--tui`).
//!
//! `ratatui` works in "immediate mode": on every frame we redraw the whole
//! screen from the `App` state. Key events are the only thing that changes
//! the state.

use crate::checks::{self, Check, CheckResult, Status};
use crate::config::Config;
use crate::report;
use crate::runner::SystemRunner;
use crate::score::{self, Summary};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

/// The entire state of the dashboard.
pub struct App {
    os_version: String,
    results: Vec<CheckResult>,
    /// The selected row in the list.
    list: ListState,
}

impl App {
    pub fn new(os_version: String, results: Vec<CheckResult>) -> Self {
        let mut list = ListState::default();
        if !results.is_empty() {
            list.select(Some(0));
        }
        Self {
            os_version,
            results,
            list,
        }
    }

    fn selected(&self) -> Option<&CheckResult> {
        self.results.get(self.list.selected()?)
    }

    /// Moves the selection by `delta`; stops at the list bounds.
    fn move_selection(&mut self, delta: isize) {
        if self.results.is_empty() {
            return;
        }
        let last = self.results.len() - 1;
        let current = self.list.selected().unwrap_or(0);
        let next = current.saturating_add_signed(delta).min(last);
        self.list.select(Some(next));
    }

    fn select_first(&mut self) {
        self.move_selection(isize::MIN);
    }

    fn select_last(&mut self) {
        self.move_selection(isize::MAX);
    }

    /// Installs the new results; keeps the selected row.
    fn replace_results(&mut self, results: Vec<CheckResult>) {
        self.results = results;
        self.move_selection(0);
    }
}

/// Starts the dashboard and runs it until the user quits.
pub fn run(
    checks: &[Box<dyn Check>],
    config: &Config,
    os_version: String,
    results: Vec<CheckResult>,
) -> std::io::Result<()> {
    let mut app = App::new(os_version, results);

    // `init` puts the terminal in raw mode and switches to the alternate
    // screen; `restore` is called after the loop so the terminal is put back
    // even if there was an error.
    let mut terminal = ratatui::init();
    let outcome = event_loop(&mut terminal, &mut app, checks, config);
    ratatui::restore();
    outcome
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    checks: &[Box<dyn Check>],
    config: &Config,
) -> std::io::Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;

        // Blocks until an event arrives. We only handle key press events
        // (some terminals also send release events).
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
            KeyCode::Home | KeyCode::Char('g') => app.select_first(),
            KeyCode::End | KeyCode::Char('G') => app.select_last(),
            KeyCode::Char('r') => {
                // New runner: the cache is empty, commands run again.
                let results = checks::run_checks(checks, &SystemRunner::new(), config);
                app.replace_results(results);
            }
            _ => {}
        }
    }
}

/// Draws a single frame. Because it is kept separate from the event loop,
/// tests can draw it to a fake terminal (`TestBackend`) and verify the content.
fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);

    draw_score(frame, header, app);
    draw_list(frame, list_area, app);
    draw_detail(frame, detail_area, app);

    let help = Line::from(vec![
        Span::styled(" ↑↓/jk ", Style::new().fg(Color::Cyan)),
        Span::raw("navigate  "),
        Span::styled("r ", Style::new().fg(Color::Cyan)),
        Span::raw("re-run audit  "),
        Span::styled("q ", Style::new().fg(Color::Cyan)),
        Span::raw("quit"),
    ]);
    frame.render_widget(Paragraph::new(help), footer);
}

fn draw_score(frame: &mut Frame, area: Rect, app: &App) {
    let score = score::calculate_score(&app.results);
    let summary = Summary::from_results(&app.results);
    let color = match score {
        90.. => Color::Green,
        60..=89 => Color::Yellow,
        _ => Color::Red,
    };

    let title = format!(
        " macOS Security Audit · {} · {} pass, {} warn, {} fail ",
        app.os_version, summary.pass, summary.warn, summary.fail
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

fn draw_list(frame: &mut Frame, area: Rect, app: &mut App) {
    let items: Vec<ListItem> = app
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
    frame.render_stateful_widget(list, area, &mut app.list);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" Detail ");
    let Some(result) = app.selected() else {
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
        lines.push(Line::from(Span::styled("Fix command (--fix)", bold)));
        lines.push(Line::from(Span::styled(
            fix.command_line(),
            Style::new().fg(Color::Cyan),
        )));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(format!("id: {}", result.id), dim)));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::tests::result;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn app() -> App {
        App::new(
            "macOS 26.6.2".into(),
            vec![
                result("firewall", Status::Pass, 20),
                result("filevault", Status::Fail, 25),
                result("ssh", Status::Warn, 10),
            ],
        )
    }

    /// Draws the frame to a fake terminal and returns the on-screen text.
    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
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
        let mut app = app();
        assert_eq!(app.list.selected(), Some(0));

        app.move_selection(-1);
        assert_eq!(app.list.selected(), Some(0), "does not go above the first row");

        app.move_selection(1);
        app.move_selection(1);
        app.move_selection(1);
        assert_eq!(app.list.selected(), Some(2), "does not go below the last row");

        app.select_first();
        assert_eq!(app.list.selected(), Some(0));
        app.select_last();
        assert_eq!(app.list.selected(), Some(2));
    }

    #[test]
    fn selection_stays_valid_when_results_shrink() {
        let mut app = app();
        app.select_last();
        app.replace_results(vec![result("firewall", Status::Pass, 20)]);
        assert_eq!(app.list.selected(), Some(0));
        assert_eq!(app.selected().unwrap().id, "firewall");
    }

    #[test]
    fn empty_list_does_not_panic() {
        let mut app = App::new("macOS".into(), Vec::new());
        app.move_selection(1);
        assert!(app.selected().is_none());
        assert!(render(&mut app).contains("No checks to show."));
    }

    #[test]
    fn frame_shows_score_list_and_detail() {
        let mut app = app();
        app.move_selection(1); // filevault (failing) is selected

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
}
