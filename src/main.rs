//! macOS Güvenlik Denetçisi
//!
//! Yerel macOS güvenlik ayarlarını salt okunur şekilde denetler, puanlar ve
//! raporlar. Rust öğrenme projesi olarak her bölüm ayrıntılı yorumlanmıştır.
//!
//! Modüller:
//! - `checks`  : `Check` trait'i ve tüm kontroller
//! - `runner`  : dış komut çalıştırma katmanı (testlerde sahtesi kullanılır)
//! - `config`  : `audit.toml` yapılandırması
//! - `score`   : puan ve not hesabı
//! - `history` : önceki çalıştırmalarla karşılaştırma
//! - `report`  : metin / JSON / Markdown / HTML çıktısı
//! - `npm`     : zararlı npm paketi taraması (`--npm`)
//! - `fix`     : onaylı düzeltme modu
//! - `tui`     : etkileşimli pano

mod checks;
mod config;
mod fix;
mod history;
mod npm;
mod report;
mod runner;
mod score;
mod tui;

use checks::{Check, CheckResult};
use clap::{ArgAction, Parser};
use colored::Colorize;
use config::Config;
use report::{Format, Report};
use runner::SystemRunner;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

/// Komut satırı argümanları. `clap`, bu yapıdaki alanlardan ve doc
/// yorumlarından ayrıştırıcıyı ve `--help` çıktısını üretir.
#[derive(Debug, Parser)]
#[command(
    name = "macos-audit",
    version,
    about = "Yerel macOS güvenlik ayarlarını salt okunur denetler ve 100 üzerinden puanlar.",
    disable_help_flag = true,
    disable_version_flag = true,
    override_usage = "macos-audit [SEÇENEKLER]",
    help_template = "{name} {version}\n{about}\n\nKullanım: {usage}\n\nSeçenekler:\n{options}\n{after-help}",
    after_help = "Çıkış kodu:\n  0  başarısız kontrol yok ve puan eşiğin üzerinde\n  1  en az bir kontrol başarısız ya da puan --min-score altında\n  2  kullanım ya da yapılandırma hatası\n\nYapılandırma: ./audit.toml ya da ~/.config/macos-audit/audit.toml"
)]
struct Cli {
    /// Çıktı biçimi
    #[arg(long, value_enum, default_value_t = Format::Text, value_name = "BİÇİM")]
    format: Format,

    /// `--format json` kısayolu
    #[arg(long, conflicts_with = "format")]
    json: bool,

    /// Raporu terminal yerine dosyaya yaz
    #[arg(short, long, value_name = "DOSYA")]
    output: Option<PathBuf>,

    /// Yalnızca bu kontrolleri çalıştır (virgülle ayrılmış kimlikler)
    #[arg(long, value_delimiter = ',', value_name = "KİMLİKLER")]
    only: Vec<String>,

    /// Bu kontrolleri atla (virgülle ayrılmış kimlikler)
    #[arg(long, value_delimiter = ',', value_name = "KİMLİKLER")]
    skip: Vec<String>,

    /// Puan bu değerin altındaysa çıkış kodu 1 olsun (CI için)
    #[arg(long, value_name = "PUAN", value_parser = clap::value_parser!(u32).range(0..=100))]
    min_score: Option<u32>,

    /// Yalnızca puanı yazdır
    #[arg(short, long)]
    quiet: bool,

    /// Renkli çıktıyı kapat
    #[arg(long)]
    no_color: bool,

    /// Yapılandırma dosyası yolu
    #[arg(long, value_name = "DOSYA")]
    config: Option<PathBuf>,

    /// Kontrolleri kimlik, ağırlık ve CIS bölümleriyle listele
    #[arg(long)]
    list: bool,

    /// Geçmiş denetimleri listele
    #[arg(long)]
    history: bool,

    /// Bu çalıştırmayı geçmişe kaydetme ve karşılaştırma yapma
    #[arg(long)]
    no_history: bool,

    /// Düzeltilebilir sorunlar için komutu göster ve onayla uygula
    #[arg(long, conflicts_with_all = ["json", "output", "tui", "quiet"])]
    fix: bool,

    /// --fix ile: komutları yalnızca göster, çalıştırma
    #[arg(long, requires = "fix")]
    dry_run: bool,

    /// --fix ile: onay sormadan uygula
    #[arg(short = 'y', long, requires = "fix")]
    yes: bool,

    /// Etkileşimli panoyu aç
    #[arg(long, conflicts_with_all = ["json", "output", "quiet"])]
    tui: bool,

    /// Tüm npm paketlerini (genel + projeler) zararlı yazılıma karşı tara
    #[arg(long, conflicts_with_all = ["fix", "tui", "list", "history"])]
    npm: bool,

    /// --npm ile: yalnızca bu dizini tara (yinelenebilir)
    #[arg(long, value_name = "DİZİN", requires = "npm")]
    npm_path: Vec<PathBuf>,

    /// --npm ile: paket ad ve sürümlerini OSV.dev zararlı paket veritabanına sor
    #[arg(long, requires = "npm")]
    online: bool,

    /// Yardımı göster
    #[arg(short = 'h', long, action = ArgAction::Help)]
    help: Option<bool>,

    /// Sürümü göster
    #[arg(short = 'V', long, action = ArgAction::Version)]
    version: Option<bool>,
}

fn main() -> ExitCode {
    // Hatalı argümanlarda clap kendi mesajını yazdırıp 2 koduyla çıkar.
    let cli = Cli::parse();

    // `run` içindeki `?` ile iletilen tüm hatalar burada tek yerde ele alınır.
    match run(cli) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{} {message}", "Hata:".red().bold());
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    // Çıktı terminale gitmiyorsa (dosya, boru) renk kodları anlamsızdır.
    if cli.no_color || cli.output.is_some() || !std::io::stdout().is_terminal() {
        colored::control::set_override(false);
    }

    // Kullanılan komutlar macOS'a özgü. `cfg!` derleme zamanında true/false üretir.
    if !cfg!(target_os = "macos") {
        return Err("Bu araç yalnızca macOS üzerinde çalışır.".to_string());
    }

    let config = Config::load(cli.config.as_deref())?;
    let mut checks = checks::registry();
    validate_ids(&cli, &config, &checks)?;

    if cli.list {
        print_check_list(&checks, &config);
        return Ok(ExitCode::SUCCESS);
    }

    let history_path = history::history_path();
    if cli.history {
        let path = history_path.ok_or("Geçmiş dizini belirlenemedi (HOME tanımsız).")?;
        print_history(&history::load(&path)?);
        return Ok(ExitCode::SUCCESS);
    }

    // Çalıştırılacak kontrolleri seç: --only, --skip ve yapılandırmadaki skip.
    checks.retain(|check| {
        let id = check.id();
        let wanted = cli.only.is_empty() || cli.only.iter().any(|only| only == id);
        let skipped = cli.skip.iter().chain(&config.skip).any(|skip| skip == id);
        wanted && !skipped
    });
    if checks.is_empty() {
        return Err("Çalıştırılacak kontrol kalmadı (--only / --skip seçimlerini gözden geçir).".to_string());
    }

    if cli.npm {
        return run_npm(&cli);
    }

    let runner = SystemRunner::new();
    let os_version = checks::os_version(&runner);
    let results = checks::run_checks(&checks, &runner, &config);

    if cli.tui {
        if !std::io::stdout().is_terminal() {
            return Err("--tui etkileşimli bir terminal gerektirir.".to_string());
        }
        tui::run(&checks, &config, os_version, results)
            .map_err(|err| format!("Pano çalıştırılamadı: {err}"))?;
        return Ok(ExitCode::SUCCESS);
    }

    // Kısmi çalıştırmalar (--only/--skip) geçmişe yazılmaz: puanları tam
    // denetimle karşılaştırılamaz.
    let use_history = !cli.no_history && cli.only.is_empty() && cli.skip.is_empty();
    let mut records = Vec::new();
    let mut history_file = None;
    if use_history && let Some(path) = history_path {
        match history::load(&path) {
            Ok(loaded) => {
                records = loaded;
                history_file = Some(path);
            }
            // Bozuk geçmiş denetimi engellemesin; uyarıp geçmişsiz devam et.
            Err(err) => eprintln!("{} geçmiş kullanılamıyor: {err}", "Uyarı:".yellow()),
        }
    }

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let format = if cli.json { Format::Json } else { cli.format };
    let mut report = Report::new(timestamp.clone(), os_version.clone(), results, records.last());

    let rendered = report.render(format, cli.quiet);
    match &cli.output {
        Some(path) => {
            std::fs::write(path, format!("{rendered}\n"))
                .map_err(|err| format!("{} yazılamadı: {err}", path.display()))?;
            if !cli.quiet {
                eprintln!("Rapor yazıldı: {}", path.display());
            }
        }
        None => println!("{rendered}"),
    }

    if cli.fix {
        let options = fix::FixOptions {
            dry_run: cli.dry_run,
            yes: cli.yes,
        };
        let summary = fix::run_fixes(&report.checks, &checks, &config, &options);

        // Bir şey değiştiyse tüm denetimi yeniden çalıştırıp yeni puanı göster.
        if summary.applied > 0 {
            let before = report.score;
            let results = checks::run_checks(&checks, &SystemRunner::new(), &config);
            report = Report::new(timestamp.clone(), os_version.clone(), results, records.last());
            println!("Puan: {before} → {}", report.score.to_string().bold());
        }
    }

    if let Some(path) = history_file {
        let record = history::RunRecord::new(timestamp, os_version, report.score, &report.checks);
        if let Err(err) = history::append(&path, records, record) {
            eprintln!("{} geçmiş kaydedilemedi: {err}", "Uyarı:".yellow());
        }
    }

    Ok(exit_code(&cli, &config, &report))
}

/// `--npm`: kurulu npm paketlerini ayrıntılı tarar. Çıkış kodu, kesin bir
/// zararlı paket bulunduysa 1'dir; sezgisel betik uyarıları kodu etkilemez.
fn run_npm(cli: &Cli) -> Result<ExitCode, String> {
    let format = if cli.json { Format::Json } else { cli.format };
    if !matches!(format, Format::Text | Format::Json) {
        return Err("--npm yalnızca text ve json biçimlerini destekler.".to_string());
    }

    let roots = if cli.npm_path.is_empty() {
        npm::all_roots(&SystemRunner::new())
    } else {
        let mut roots = Vec::new();
        for path in &cli.npm_path {
            if !path.is_dir() {
                return Err(format!("{} bir dizin değil.", path.display()));
            }
            roots.extend(npm::roots_under(path));
        }
        roots
    };

    let mut scan = npm::scan(&roots);

    // OSV'ye ulaşılamazsa yerel sonuçlar yine de gösterilir.
    let mut online = false;
    if cli.online {
        match npm::osv_lookup(&scan.installed) {
            Ok(hits) => {
                scan.add_osv(hits);
                online = true;
            }
            Err(err) => eprintln!("{} OSV sorgusu yapılamadı: {err}", "Uyarı:".yellow()),
        }
    }

    let timestamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let report = npm::NpmReport::new(timestamp, online, scan);
    let found_malware = report.scan.malware().next().is_some();

    let rendered = match format {
        Format::Json => report.to_json(),
        _ if cli.quiet => format!(
            "{} zararlı, {} şüpheli",
            report.scan.malware().count(),
            report.scan.suspicious().count()
        ),
        _ => report.to_text(),
    };
    match &cli.output {
        Some(path) => {
            std::fs::write(path, format!("{rendered}\n"))
                .map_err(|err| format!("{} yazılamadı: {err}", path.display()))?;
            if !cli.quiet {
                eprintln!("Rapor yazıldı: {}", path.display());
            }
        }
        None => println!("{rendered}"),
    }

    Ok(if found_malware { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

/// Betiklerde ve CI'da kullanılmak üzere çıkış kodunu belirler.
fn exit_code(cli: &Cli, config: &Config, report: &Report) -> ExitCode {
    // Komut satırındaki eşik yapılandırmadakinin önüne geçer.
    let min_score = cli.min_score.or(config.min_score);
    let below_threshold = min_score.is_some_and(|min| report.score < min);

    if below_threshold && !cli.quiet {
        eprintln!(
            "{} puan {} eşiğin ({}) altında.",
            "Uyarı:".yellow(),
            report.score,
            min_score.unwrap_or_default()
        );
    }

    if below_threshold || report.checks.iter().any(CheckResult::is_failure) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Komut satırında ve yapılandırmada geçen kontrol kimliklerini doğrular;
/// yazım hatası sessizce "hiçbir şey yapmama"ya dönüşmesin.
fn validate_ids(cli: &Cli, config: &Config, checks: &[Box<dyn Check>]) -> Result<(), String> {
    let known: Vec<&str> = checks.iter().map(|check| check.id()).collect();
    let referenced = cli
        .only
        .iter()
        .chain(&cli.skip)
        .map(String::as_str)
        .chain(config.referenced_ids());

    for id in referenced {
        if !known.contains(&id) {
            return Err(format!(
                "Bilinmeyen kontrol kimliği: `{id}`. Geçerli kimlikler: {}",
                known.join(", ")
            ));
        }
    }
    Ok(())
}

/// `--list`: tüm kontrolleri tablo halinde yazdırır.
fn print_check_list(checks: &[Box<dyn Check>], config: &Config) {
    println!(
        "{}",
        format!(
            "{:<16} {:>7}  {:<8} {:<8} {:<9} {}",
            "KİMLİK", "AĞIRLIK", "ÖNEM", "CIS", "DÜZELTME", "AD"
        )
        .bold()
    );
    for check in checks {
        let weight = config
            .weights
            .get(check.id())
            .copied()
            .unwrap_or_else(|| check.weight());
        let mut name = check.name().to_string();
        if config.skip.iter().any(|skip| skip == check.id()) {
            name.push_str(" (atlanıyor)");
        } else if config.exceptions.contains_key(check.id()) {
            name.push_str(" (istisna)");
        }
        println!(
            "{:<16} {:>7}  {:<8} {:<8} {:<9} {}",
            check.id(),
            weight,
            check.severity().label(),
            check.cis().unwrap_or("–"),
            if check.fix().is_some() { "var" } else { "elle" },
            name
        );
    }
}

/// `--history`: geçmiş denetimleri eskiden yeniye yazdırır.
fn print_history(records: &[history::RunRecord]) {
    if records.is_empty() {
        println!("Henüz kayıtlı denetim yok.");
        return;
    }
    println!(
        "{}",
        format!("{:<17} {:>4}  {:<3} {:<14} {}", "TARİH", "PUAN", "NOT", "SİSTEM", "SORUNLAR").bold()
    );
    for record in records {
        let count = |status| record.checks.values().filter(|s| **s == status).count();
        println!(
            "{:<17} {:>4}  {:<3} {:<14} {} başarısız, {} uyarı",
            report::short_time(&record.timestamp),
            record.score,
            score::grade(record.score),
            record.os_version,
            count(checks::Status::Fail),
            count(checks::Status::Warn),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("macos-audit").chain(args.iter().copied()))
    }

    #[test]
    fn clap_tanimi_tutarli() {
        // Çakışan kısa adlar, eksik `requires` hedefleri gibi hataları yakalar.
        Cli::command().debug_assert();
    }

    #[test]
    fn virgullu_listeler_ayrilir() {
        let cli = parse(&["--only", "filevault,sip", "--skip", "ssh"]).unwrap();
        assert_eq!(cli.only, ["filevault", "sip"]);
        assert_eq!(cli.skip, ["ssh"]);
    }

    #[test]
    fn gecersiz_kombinasyonlar_reddedilir() {
        assert!(parse(&["--dry-run"]).is_err(), "--dry-run tek başına olmaz");
        assert!(parse(&["--fix", "--json"]).is_err());
        assert!(parse(&["--min-score", "101"]).is_err());
        assert!(parse(&["--bilinmeyen"]).is_err());
        assert!(parse(&["--fix", "--dry-run"]).is_ok());
        assert!(parse(&["--online"]).is_err(), "--online yalnızca --npm ile");
        assert!(parse(&["--npm-path", "."]).is_err());
        assert!(parse(&["--npm", "--fix"]).is_err());
        assert!(parse(&["--npm", "--online", "--npm-path", "a", "--npm-path", "b"]).is_ok());
    }

    #[test]
    fn bilinmeyen_kimlik_hata_verir() {
        let checks = checks::registry();
        let config = Config::default();

        let cli = parse(&["--only", "filevalt"]).unwrap();
        let error = validate_ids(&cli, &config, &checks).unwrap_err();
        assert!(error.contains("filevalt"));

        let cli = parse(&["--only", "filevault"]).unwrap();
        assert!(validate_ids(&cli, &config, &checks).is_ok());

        let config = Config::parse("skip = [\"yok\"]").unwrap();
        assert!(validate_ids(&parse(&[]).unwrap(), &config, &checks).is_err());
    }
}
