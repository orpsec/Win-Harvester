# WinHarvest

Kapsamlı, modüler bir **Windows Forensic Artifact Collector** (Go). Windows 10 ve
Windows 11 üzerinde; olay müdahalesi (IR), adli bilişim (DFIR), zararlı yazılım
analizi ve tehdit avcılığı için **salt-okunur** delil toplama amacıyla
tasarlanmıştır. Hedef seviye: KAPE / Velociraptor / CyLR.

## Temel İlkeler

- **Salt-okunur:** Hiçbir kaynak dosya değiştirilmez; kopyalarda timestamp'ler korunur.
- **Kilitli dosyalar:** Volume Shadow Copy (VSS) üzerinden okunur (SAM, SYSTEM, `$MFT`, EVTX...).
- **Bütünlük:** Toplanan her dosya için **SHA256 + SHA1 + MD5** ve tam metadata.
- **Denetlenebilirlik:** Başarısız toplamalar dahil her işlem loglanır ve manifest'e yazılır.
- **Ölçeklenebilir:** Modüller goroutine'lerle paralel çalışır.

## Mimari

```
cmd/winharvest          → CLI giriş noktası, orkestrasyon
internal/core           → tipler, Collector interface, plugin registry, config,
                          OutputWriter (kopya+hash+metadata), timeline sink
internal/platform       → OS tespiti, ACL/timestamp, komut çalıştırma, VSS
                          (//go:build windows + cross-platform stub)
internal/rawio          → ham NTFS okuyucu ($MFT, $LogFile çıkarımı)
internal/collect        → modüller için ortak yardımcılar (kopyalama, glob, exec)
internal/modules        → her artefact kategorisi bir collector modülü
internal/report         → JSON/CSV/HTML/Markdown + ZIP
internal/timeline       → birleşik süper zaman çizelgesi
internal/hashing        → tek geçişte üçlü hash
internal/logging        → seviyeli, dosya+konsol logger
```

### Yeni modül ekleme (plugin deseni)

`internal/modules/` altına `core.Collector` arayüzünü uygulayan bir dosya ekleyip
`init()` içinde `core.Register(...)` çağırmanız yeterlidir. `main.go`'da değişiklik
gerekmez.

```go
type myModule struct{}
func (myModule) Name() string        { return "mymodule" }
func (myModule) Category() string    { return "System" }
func (myModule) Description() string { return "..." }
func (m myModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
    h := collect.New(cc, m.Name(), m.Category())
    h.CopyFile(`C:\path\to\artifact`)
    return h.Result(), nil
}
func init() { core.Register(myModule{}) }
```

## Toplanan Artefact Kategorileri

| Modül | Kategori | İçerik |
|---|---|---|
| `system` | System | Host kimliği, donanım, OS, BitLocker, TPM, VM tespiti, SID |
| `eventlogs` | EventLogs | Ham EVTX (Operational/Analytic/Debug dahil) |
| `registry` | Registry | SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT + NTUSER/UsrClass + RegBack + transaction log + anahtar export'ları |
| `filesystem` | FileSystem | `$MFT`, `$LogFile` (ham NTFS), `$UsnJrnl`, Recycle Bin, ADS, reparse, VSS metadata |
| `execution` | FileSystem | Prefetch, Amcache, SRUM, JumpList, LNK, Recent, WER |
| `tasks` | Tasks | Zamanlanmış görev XML, TaskCache, listeleme |
| `services` | Services | Servisler, sürücüler, ImagePath, ServiceDLL, FailureActions |
| `wmi` | WMI | Repository + kalıcı event subscription (filter/consumer/binding) |
| `powershell` | System | PSReadLine history, transcript |
| `browser` | Browser | Chrome/Edge/Brave/Opera/Vivaldi/Firefox: history, cookies, logins, extensions, storage |
| `network` | Network | Bağlantılar, ARP/DNS cache, route, firewall, Wi-Fi (clear key), VPN, hosts, proxy |
| `usb` | USB | USBSTOR, MountedDevices, SetupAPI logları, portable devices |
| `users` | Users | Recent, clipboard, Sticky Notes, OneDrive/GDrive/Dropbox metadata |
| `memory` | Memory | Process/thread/DLL/handle/driver/logon session/connection metadata (RAM dump'sız) |
| `persistence` | System | Run keys, IFEO, AppInit, COM hijack, Winlogon, BITS, startup, Office add-in |
| `logs` | System | CBS/DISM/Panther/Defender/WindowsUpdate logları, crash dump metadata |

## Okunabilir / Parse Edilmiş Çıktılar (Analiz İçin)

Ham (binary) artefact'ların yanında, doğrudan analiz edilebilen **parse edilmiş**
çıktılar da üretilir (her modülün altında `parsed/` klasörü). Bu sayede çıktıları
ek bir araç gerekmeden (örn. bir analiste/AI'ya) verip inceletebilirsiniz.

| Kaynak | Parse Çıktısı | Yöntem |
|---|---|---|
| EVTX (önemli kanallar) | `EventLogs/eventlogs/parsed/<kanal>.json` | `Get-WinEvent` → JSON (TimeCreated, Id, Provider, Message) |
| Prefetch (`.pf`) | `FileSystem/execution/parsed/prefetch.json` | **Native Go** SCCA v30/v31 + MAM (Xpress Huffman) dekompresyon |
| LNK (`.lnk`) | `FileSystem/execution/parsed/lnk.json` | **Native Go** Shell Link parser (hedef yol, args, volume) |
| Amcache.hve | `FileSystem/execution/parsed/amcache.json` | **Native Go** regf + InventoryApplicationFile |
| ShimCache (AppCompatCache) | `Registry/registry/parsed/shimcache.json` | **Native Go** regf + Win10/11 `10ts` parser |
| UserAssist | `Registry/registry/parsed/userassist_<user>.json` | **Native Go** regf + ROT13 + run count/last run |
| USBSTOR | `Registry/registry/parsed/usbstor.json` | **Native Go** regf |
| `$MFT` | `FileSystem/filesystem/parsed/mft.csv` | **Native Go** NTFS MFT parser ($SI/$FN MAC times) |
| Registry anahtarları | `Registry/registry/exported/*.txt` | `reg query /s` |
| Tarayıcı (history vb.) | ham SQLite dosyaları | doğrudan SQLite olarak sorgulanabilir |

Tüm bu parse çıktılarındaki olaylar (Prefetch/LNK/UserAssist/ShimCache/USB)
ayrıca birleşik **`Reports/timeline.csv`** süper zaman çizelgesine eklenir.

> Native parser'lar saf Go'dur ve kaynak dosyayı **değiştirmez**; çıktıları
> herhangi bir platformda offline ayrıştırılabilir (Prefetch MAM dekompresyonu
> yalnızca Windows'ta, ntdll üzerinden).

## Derleme

```bash
# Windows hedefi (geliştirme makinesi macOS/Linux olabilir — cross-compile)
GOOS=windows GOARCH=amd64 go build -o winharvest.exe ./cmd/winharvest
GOOS=windows GOARCH=arm64 go build -o winharvest-arm64.exe ./cmd/winharvest

# Yerel Windows'ta
go build -o winharvest.exe ./cmd/winharvest

go test ./...
```

## Kullanım

> **Yönetici (Administrator) olarak çalıştırın.** Aksi halde SAM/SECURITY, `$MFT`
> ve kilitli EVTX gibi birçok artefact alınamaz.

```powershell
# Tüm modüller, varsayılan ayarlar
.\winharvest.exe -output D:\Evidence -case IR-2026-0001 -examiner analyst

# Sadece belirli modüller
.\winharvest.exe -modules registry,eventlogs,execution

# Bazı modülleri hariç tut, ZIP'siz, daha fazla paralellik
.\winharvest.exe -exclude browser,memory -no-zip -concurrency 8

# Config dosyasıyla
.\winharvest.exe -config config.yaml

# Mevcut modülleri listele
.\winharvest.exe -list
```

### Önemli Bayraklar

| Bayrak | Açıklama | Varsayılan |
|---|---|---|
| `-output` | Çıktı dizini | `.` |
| `-config` | YAML config yolu | — |
| `-modules` | Çalıştırılacak modüller (CSV) | tümü |
| `-exclude` | Hariç tutulacak modüller (CSV) | — |
| `-concurrency` | Paralel modül sayısı | 4 |
| `-vss` | VSS kullan | true |
| `-no-hash` | Hash'i kapat | false |
| `-no-acl` | ACL toplamayı kapat | false |
| `-no-zip` | ZIP'lemeyi kapat | false |
| `-max-file-size` | Üst boyut sınırı (bayt) | 0 (sınırsız) |
| `-volume` | Hedef birim | `C:\` |
| `-verbose` | Debug log | false |

## Çıktı Yapısı

```
Collection_<host>_<timestamp>/
├── System/        EventLogs/   Registry/   FileSystem/
├── Users/         Browser/     Network/    Memory/
├── USB/           Services/    WMI/        Tasks/
├── Reports/
│   ├── manifest.json     # tam, kendini tanımlayan kayıt
│   ├── artifacts.csv     # her dosya: yol, boyut, MAC, owner, 3 hash, durum
│   ├── timeline.csv      # birleşik süper zaman çizelgesi
│   ├── report.html       # özet + zaman çizelgesi (interaktif)
│   └── report.md
└── collection.log        # ayrıntılı çalışma logu
Collection_<host>_<timestamp>.zip
```

Her dosya için kaydedilen metadata: Orijinal yol, boyut, oluşturma/değiştirme/erişim
zamanı, owner, ACL (SDDL), SHA256/SHA1/MD5, toplanma zamanı, kaynak
(`live`/`vss`/`rawio`), başarı durumu ve hata mesajı.

## Notlar / Sınırlamalar

- Tam RAM imajı alınmaz (yalnızca volatile metadata). Gerekirse özel bir imaj
  alıcı kullanın; `memory` modülü process/handle/driver/oturum dökümü sağlar.
- `MEMORY.DMP` çok büyük olduğunda yalnızca metadata kaydedilir (kopyalanmaz).
- EVTX/registry hive'ları **ham** toplanır; ayrıştırma için Eric Zimmerman
  araçları, Velociraptor veya Plaso ile post-processing önerilir.
- Araç delili **değiştirmez**; ancak canlı komutlar (`netstat`, `ipconfig` vb.)
  sistemde normal okuma işlemleridir.
