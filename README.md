# macOS Güvenlik Denetçisi

Rust öğrenme projesi: yerel macOS güvenlik ayarlarını denetler, 100 üzerinden
puanlar ve raporlar. Denetim **salt okunurdur**; sistemde değişiklik yapan tek
yol, her komut için onay isteyen `--fix` modudur.

## Çalıştırma

```sh
cargo run                         # renkli metin raporu
cargo run -- --tui                # etkileşimli pano
cargo run -- --json               # JSON çıktısı (betikler / CI için)
cargo run -- --format html -o rapor.html
cargo run -- --only filevault,sip # yalnızca seçili kontroller
cargo run -- --min-score 80 -q    # CI: puan 80'in altındaysa çıkış kodu 1
cargo run -- --fix --dry-run      # düzeltme komutlarını önizle
cargo run -- --help
```

Testler: `cargo test`

## Kontroller

`cargo run -- --list` güncel listeyi kimlik, ağırlık ve CIS bölümüyle gösterir.

| Kimlik | Kontrol | Ağırlık | Önem | `--fix` |
| --- | --- | --- | --- | --- |
| `filevault` | FileVault disk şifrelemesi | 25 | kritik | elle |
| `sip` | Sistem Bütünlüğü Koruması | 20 | kritik | elle |
| `gatekeeper` | Gatekeeper | 15 | yüksek | elle |
| `auto-update` | Otomatik güncellemeler | 10 | yüksek | var |
| `pending-updates` | Bekleyen güncellemeler | 10 | orta | elle |
| `xprotect` | XProtect imzalarının güncelliği | 5 | orta | elle |
| `firewall` | Uygulama güvenlik duvarı | 20 | yüksek | var |
| `stealth` | Güvenlik duvarı gizli modu | 5 | düşük | var |
| `ssh` | Uzak giriş (port 22) | 10 | orta | var |
| `sharing` | Ekran / dosya paylaşımı, uzaktan yönetim | 10 | orta | elle |
| `airdrop` | AirDrop görünürlüğü | 5 | düşük | elle |
| `auto-login` | Otomatik giriş | 10 | yüksek | var |
| `guest` | Misafir hesabı | 5 | orta | var |
| `screen-lock` | Kilit sonrası parola isteme süresi | 10 | orta | elle |
| `sudo` | Parolasız sudo (NOPASSWD) | 10 | yüksek | elle |
| `launch-items` | Şüpheli LaunchAgent / LaunchDaemon öğeleri | 10 | orta | elle |

### Puanlama

- `Pass` tam puan, `Warn` yarım puan, `Fail` sıfır puan.
- Durumu tespit edilemeyen (`Unknown`) ve istisna tanımlanan kontroller
  paydaya dahil edilmez.
- Not: 90+ A, 75+ B, 60+ C, 40+ D, altı F.

### Çıkış kodu

| Kod | Anlam |
| --- | --- |
| 0 | Başarısız kontrol yok ve puan eşiğin üzerinde |
| 1 | En az bir kontrol başarısız ya da puan `--min-score` altında |
| 2 | Kullanım ya da yapılandırma hatası |

## Çıktı biçimleri

`--format text|json|markdown|html` (ya da kısaca `--json`). `-o DOSYA` raporu
dosyaya yazar. JSON çıktısı puanı, özeti, her kontrolün ayrıntısını, önceki
çalıştırmayı ve değişen kontrolleri içerir.

## Geçmiş ve karşılaştırma

Her tam denetim `~/.macos-audit/history.json` dosyasına kaydedilir (son 100
kayıt). Sonraki çalıştırmada puan farkı ve durumu değişen kontroller gösterilir.

- `--history` : geçmiş denetimleri listeler
- `--no-history` : kaydetmez ve karşılaştırmaz
- `--only` / `--skip` ile yapılan kısmi çalıştırmalar kaydedilmez
- `MACOS_AUDIT_HOME` ortam değişkeni kayıt dizinini değiştirir

## Yapılandırma (`audit.toml`)

Sırayla `--config DOSYA`, `./audit.toml`, `~/.config/macos-audit/audit.toml`
aranır. Örnek için [`audit.example.toml`](audit.example.toml):

```toml
min_score = 80
skip = ["airdrop"]

[weights]
filevault = 40

[exceptions]
ssh = "Geliştirme makinesi; SSH bilerek açık"
```

İstisnalı kontrol çalışır ve raporda `İSTİSNA` olarak görünür ama puana ve
çıkış koduna etki etmez. Bilinmeyen kimlikler ve alanlar hata verir.

## Düzeltme modu (`--fix`)

Otomatik düzeltmesi olan her sorun için çalıştırılacak komutu gösterir ve tek
tek onay ister (`e`/`evet`). Komuttan sonra kontrol yeniden çalıştırılır; sorun
sürüyorsa bildirilir.

- `--fix --dry-run` : komutları yalnızca gösterir, hiçbir şey çalıştırmaz
- `--fix --yes` : onay sormadan uygular
- Komutların çoğu `sudo` gerektirir; parola doğrudan `sudo` tarafından sorulur.
- FileVault, SIP, Gatekeeper gibi ayarlar yalnızca elle değiştirilebilir;
  bunlar için öneri gösterilir.

## Pano (`--tui`)

| Tuş | İşlev |
| --- | --- |
| `↑` `↓` / `j` `k` | Kontroller arasında gezin |
| `g` / `G` | İlk / son kontrol |
| `r` | Denetimi yeniden çalıştır |
| `q` / `Esc` | Çık |

## Kod yapısı

| Dosya | İçerik |
| --- | --- |
| `src/main.rs` | Komut satırı (`clap`) ve akış |
| `src/checks/mod.rs` | `Check` trait'i, kayıt listesi, paralel çalıştırma |
| `src/checks/{system,network,accounts,persistence}.rs` | Kontroller |
| `src/runner.rs` | Komut çalıştırma katmanı (`CommandRunner`) ve test sahtesi |
| `src/config.rs` | `audit.toml` |
| `src/score.rs` | Puan, not, özet |
| `src/history.rs` | Geçmiş kaydı ve fark |
| `src/report.rs` | Metin / JSON / Markdown / HTML |
| `src/fix.rs` | Düzeltme modu |
| `src/tui.rs` | `ratatui` panosu |

Yeni kontrol eklemek için: bir tip tanımla, `Check` trait'ini uygula ve
`checks::registry()` listesine ekle. Kontroller komutları `CommandRunner`
üzerinden çalıştırdığı için `MockRunner` ile sahte çıktılarla test edilebilir.

## Notlar

- CIS sütunu, CIS Apple macOS Benchmark'taki ilgili bölümü gösterir. Bölüm
  numaraları benchmark sürümüne göre değişir; uyumluluk raporunda kullanmadan
  önce elindeki sürümle karşılaştır.
- `launch-items` basit sezgisel kurallar kullanır (geçici ya da gizli dizinden
  çalışan program, indirip çalıştırma vb.); uyarı kesin hüküm değildir.
- Bu araç kapsamlı bir güvenlik taraması değildir; temel yapılandırma
  kontrollerini gösteren eğitici bir örnektir.
