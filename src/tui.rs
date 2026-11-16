//! Etkileşimli terminal panosu (`--tui`).
//!
//! `ratatui` "immediate mode" çalışır: her karede tüm ekranı `App`
//! durumundan yeniden çizeriz. Durumu değiştiren tek şey tuş olaylarıdır.

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

/// Panonun tüm durumu.
pub struct App {
    os_version: String,
    results: Vec<CheckResult>,
    /// Listede seçili satır.
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

    /// Seçimi `delta` kadar kaydırır; liste sınırlarında durur.
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

    /// Yeni sonuçları yerleştirir; seçili satırı korur.
    fn replace_results(&mut self, results: Vec<CheckResult>) {
        self.results = results;
        self.move_selection(0);
    }
}

/// Panoyu başlatır ve kullanıcı çıkana kadar çalıştırır.
pub fn run(
    checks: &[Box<dyn Check>],
    config: &Config,
    os_version: String,
    results: Vec<CheckResult>,
) -> std::io::Result<()> {
    let mut app = App::new(os_version, results);

    // `init` terminali ham moda alıp alternatif ekrana geçer; `restore`
    // hata olsa bile eski haline döndürmek için döngüden sonra çağrılır.
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

        // Bir olay gelene kadar bekler. Yalnızca tuşa basma olaylarını
        // işliyoruz (bazı terminaller bırakma olayı da gönderir).
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
                // Yeni runner: önbellek boş, komutlar yeniden çalışır.
                let results = checks::run_checks(checks, &SystemRunner::new(), config);
                app.replace_results(results);
            }
            _ => {}
        }
    }
}

/// Tek bir kareyi çizer. Olay döngüsünden ayrı tutulduğu için testlerde
/// sahte bir terminale (`TestBackend`) çizilip içeriği doğrulanabilir.
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
        Span::raw("gezin  "),
        Span::styled("r ", Style::new().fg(Color::Cyan)),
        Span::raw("yeniden denetle  "),
        Span::styled("q ", Style::new().fg(Color::Cyan)),
        Span::raw("çık"),
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
        " macOS Güvenlik Denetimi · {} · {} geçti, {} uyarı, {} başarısız ",
        app.os_version, summary.pass, summary.warn, summary.fail
    );
    let gauge = Gauge::default()
        .block(Block::bordered().title(title))
        .gauge_style(Style::new().fg(color))
        .percent(score.min(100) as u16)
        .label(format!("{score}/100 (Not: {})", score::grade(score)));
    frame.render_widget(gauge, area);
}

/// Duruma göre simge ve renk.
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
        .block(Block::bordered().title(" Kontroller "))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));

    // Seçili satırı ve kaydırma konumunu `ListState` tutar.
    frame.render_stateful_widget(list, area, &mut app.list);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" Ayrıntı ");
    let Some(result) = app.selected() else {
        frame.render_widget(Paragraph::new("Gösterilecek kontrol yok.").block(block), area);
        return;
    };

    let (_, color) = status_style(result);
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let dim = Style::new().fg(Color::DarkGray);

    let status = if result.exempt.is_some() {
        "İSTİSNA"
    } else {
        result.status.label()
    };

    let mut lines = vec![
        Line::from(Span::styled(result.name, bold)),
        Line::from(vec![
            Span::styled(status, Style::new().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("  ·  {}  ·  ağırlık {}", report::meta(result), result.weight),
                dim,
            ),
        ]),
        Line::default(),
        Line::from(result.detail.as_str()),
    ];

    if let Some(reason) = &result.exempt {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("İstisna gerekçesi", bold)));
        lines.push(Line::from(reason.as_str()));
    }
    if result.is_issue() && !result.advice.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("Öneri", bold)));
        lines.push(Line::from(result.advice));
    }
    if let (true, Some(fix)) = (result.is_issue(), result.fix) {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled("Düzeltme komutu (--fix)", bold)));
        lines.push(Line::from(Span::styled(
            fix.command_line(),
            Style::new().fg(Color::Cyan),
        )));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(format!("kimlik: {}", result.id), dim)));

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

    /// Kareyi sahte bir terminale çizip ekrandaki metni döndürür.
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
    fn secim_sinirlarda_durur() {
        let mut app = app();
        assert_eq!(app.list.selected(), Some(0));

        app.move_selection(-1);
        assert_eq!(app.list.selected(), Some(0), "ilk satırdan yukarı çıkmaz");

        app.move_selection(1);
        app.move_selection(1);
        app.move_selection(1);
        assert_eq!(app.list.selected(), Some(2), "son satırdan aşağı inmez");

        app.select_first();
        assert_eq!(app.list.selected(), Some(0));
        app.select_last();
        assert_eq!(app.list.selected(), Some(2));
    }

    #[test]
    fn sonuclar_azalinca_secim_gecerli_kalir() {
        let mut app = app();
        app.select_last();
        app.replace_results(vec![result("firewall", Status::Pass, 20)]);
        assert_eq!(app.list.selected(), Some(0));
        assert_eq!(app.selected().unwrap().id, "firewall");
    }

    #[test]
    fn bos_listede_panic_etmez() {
        let mut app = App::new("macOS".into(), Vec::new());
        app.move_selection(1);
        assert!(app.selected().is_none());
        assert!(render(&mut app).contains("Gösterilecek kontrol yok."));
    }

    #[test]
    fn kare_puani_listeyi_ve_ayrintiyi_gosterir() {
        let mut app = app();
        app.move_selection(1); // filevault (başarısız) seçili

        let screen = render(&mut app);
        // 20 tam + 0 + 5 yarım = 25 / 55 → %45
        assert!(screen.contains("45/100 (Not: D)"), "{screen}");
        assert!(screen.contains("Kontroller"));
        assert!(screen.contains("✘ filevault"));
        assert!(screen.contains("BAŞARISIZ"));
        assert!(screen.contains("filevault ayrıntısı"));
        assert!(screen.contains("Öneri"));
        assert!(screen.contains("yeniden denetle"));
    }
}
