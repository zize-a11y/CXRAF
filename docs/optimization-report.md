# Laporan Optimasi — CSP-XSS Auditor (Tahap 13)

Dokumen ini mencatat seluruh upaya optimasi yang **benar-benar diukur**
selama pengembangan — termasuk satu hipotesis optimasi yang **gagal**
saat diuji, karena kejujuran proses pengujian sama pentingnya dengan
hasil akhirnya untuk BAB IV.

## 1. Optimasi yang Sudah Ada Sejak Tahap 11 (Audit Ulang)

| Optimasi | Lokasi | Verifikasi |
|---|---|---|
| Regex sink/source di-compile SEKALI di constructor, bukan per pemanggilan `analyze()` | `ScriptAnalyzer`, `SourceSinkTracer` | Diaudit ulang kodenya di Tahap 13 — konfirmasi tidak ada `new RegExp()` di dalam loop |
| Header CSP di-cache per tab (event-driven), bukan fetch ulang saat popup dibuka | `CSPHeaderService` | Sesuai desain Tahap 2/10 |
| Config JSON dimuat sekali per service worker wake, bukan per pesan masuk | `background/index.js` (lazy `routerPromise`) | Diaudit ulang, konfirmasi memoized |

## 2. Eksperimen Optimasi yang DITOLAK (Diuji, Terbukti Tidak Membantu)

**Hipotesis**: mengganti `_extractEventHandlerAttributes()` di `DOMScannerService`
dari `querySelectorAll('*')` + cek atribut manual menjadi query selector
gabungan (`querySelectorAll('[onclick],[onerror],...')`) akan lebih cepat
karena mengurangi jumlah elemen yang diiterasi.

**Hasil benchmark** (jsdom, 10.000 elemen, 200 memiliki handler, 30 run):

| Pendekatan | Rata-rata |
|---|---|
| `querySelectorAll('*')` + `hasAttribute()` manual (kode saat ini) | **36.51ms** |
| `querySelectorAll('[onclick],[onerror],...')` gabungan | 48.03ms (+31%) |

**Kesimpulan**: hipotesis DITOLAK. Engine CSS selector (baik di jsdom
maupun kemungkinan besar di V8/Blink) tidak selalu lebih cepat untuk
selector gabungan panjang dibanding iterasi native `hasAttribute()`.
**Kode `DOMScannerService` dipertahankan seperti Tahap 11**, tidak diubah.
Ini contoh nyata pentingnya *mengukur*, bukan berasumsi dari intuisi.

## 3. Optimasi yang DITERAPKAN: Cap Performa pada ScriptAnalyzer

**Masalah yang ditemukan**: benchmark terhadap jumlah entry yang terus
meningkat menunjukkan waktu eksekusi tumbuh signifikan pada input ekstrem:

| Jumlah entry | Waktu eksekusi (loop, warmed-up) |
|---|---|
| 300 | 17.94ms |
| 1.000 | 45.35ms |
| 3.000 | 43.02ms |
| 8.000 | **132.19ms** (melebihi budget NFR-01: 100ms) |

**Pertimbangan tambahan — cold start**: karena service worker Manifest V3
bersifat non-persisten (bisa restart kapan saja), skenario yang lebih
representatif adalah eksekusi **cold** (sekali jalan, belum di-JIT-warm),
bukan loop berulang. Hasil ukur cold:

| Jumlah entry | Waktu eksekusi (cold, sekali proses) |
|---|---|
| 500 | 25.75ms |
| 1.000 | 57.26ms |
| 1.500 | 71.19ms |
| 2.000 | 83.80ms |
| 3.000 | 93.62ms (margin ke 100ms terlalu tipis) |

**Solusi**: menambahkan cap defensif `DEFAULT_MAX_ENTRIES = 800` pada
`ScriptAnalyzer` — jumlah entry di atas cap ini tidak diproses, dan hasil
ditandai `truncated: true` (transparan, dilaporkan ke pengguna via
notice di popup, BUKAN dipotong diam-diam).

**Verifikasi setelah perbaikan**: input ekstrem 8.000 entry dengan cap 800,
kondisi cold:

```
cap=800, input 8000 entries cold -> 43.12ms, truncated: true
```

Margin ~57ms tersisa untuk overhead message-passing antar context MV3
yang tidak dapat diukur di sandbox non-browser ini.

**Catatan penting**: halaman web wajar (bahkan yang berat sekalipun)
sangat jarang memiliki >800 inline script + event handler attribute
sekaligus — cap ini murni pengaman kasus anomali/pathological, bukan
pembatasan yang memengaruhi akurasi audit pada halaman nyata.

## 4. Tooling Maintainability: Validasi Arsitektur Otomatis

Menambahkan `scripts/check-architecture.mjs` — validasi otomatis bahwa
domain layer (`packages/xss-risk-core/`) tidak pernah mengimpor/memanggil `chrome.*`
API, sesuai prinsip Clean Architecture yang dirancang sejak Tahap 2.

```
$ npm run lint:architecture
✅ Domain layer bersih — 6 file diperiksa, 0 pelanggaran chrome.* API.
```

Ini mengubah klaim "domain layer itu pure/testable" dari sekadar
pernyataan desain menjadi sesuatu yang **diverifikasi otomatis** setiap
kali kode diubah — relevan untuk argumen maintainability di BAB III/IV.

## 5. Regresi Testing

Seluruh 41 unit/integration test (termasuk 3 test baru untuk cap) tetap
lulus 100% setelah seluruh perubahan Tahap 13 — tidak ada fitur yang
rusak akibat optimasi.

```
Test Suites: 5 passed, 5 total
Tests:       41 passed, 41 total
```

## 6. Ringkasan untuk BAB IV

| Aspek | Sebelum Tahap 13 | Sesudah Tahap 13 |
|---|---|---|
| Worst-case time (8000 entries) | 132ms (melebihi budget) | 43ms cold (aman, dengan truncation transparan) |
| Transparansi ke pengguna saat data terpotong | Tidak ada | Notice eksplisit di popup |
| Validasi arsitektur | Manual (asumsi) | Otomatis via `npm run lint:architecture` |
| Keputusan optimasi DOM scanning | — | Diuji, ditolak berdasar data, kode dipertahankan |

## 7. Keputusan Arsitektur: Menolak AST Parser (Acorn) demi Keamanan Extension

Saat memperbaiki Temuan #4 (review arsitektur — tokenisasi naif `split(';')`
pada `SourceSinkTracer`), opsi pertama yang dicoba adalah mengganti
tokenisasi dengan AST parser sungguhan (Acorn). Opsi ini **DIBATALKAN**
setelah dipertimbangkan lebih lanjut:

**Masalah**: Acorn adalah npm package yang diimpor via bare module
specifier (`import ... from 'acorn'`). Browser (termasuk Chrome extension
tanpa bundler) **tidak bisa** me-resolve bare specifier semacam ini tanpa
import map atau build step — sedangkan proyek ini sengaja dibangun tanpa
bundler. Memaksakan dependency ini berisiko membuat extension **gagal
total saat di-load ke Chrome**, dengan risiko yang tidak bisa diverifikasi
ulang dari sandbox pengembangan (tidak ada Chrome browser sungguhan di
sini untuk menguji).

**Solusi yang diambil**: tokenizer buatan sendiri (`_splitStatements()`)
yang menelusuri kode karakter demi karakter, sadar akan boundary string
literal (`'...'`, `"..."`), template literal (`` `...` ``, termasuk
ekspresi interpolasi `${...}` bersarang), komentar (`//`, `/* */`), dan
escape character. Ini bebas dependency (aman di SEMUA konteks: extension,
CLI, test) sekaligus memperbaiki kelemahan konkret yang ditunjukkan di
review.

**Bukti perbaikan** (kode: `el.innerHTML = "prefix;suffix" + location.hash;`):

| | Sebelum (split naif) | Sesudah (tokenizer sadar-syntax) |
|---|---|---|
| Jumlah fragmen | 2 (`'el.innerHTML = "prefix'`, `'suffix" + location.hash'`) | 1 (statement utuh) |
| Sink & source di fragmen sama? | Tidak — di fragmen berbeda | Ya |
| Korelasi DIRECT terdeteksi? | **Gagal total** (false negative) | Terdeteksi, confidence 0.9 |

**Keterbatasan yang tetap ada** (didokumentasikan jujur, bukan
disembunyikan): tokenizer ini belum membedakan regex literal (`/a;b/`)
dari operator pembagian — karakter `;` di dalam regex literal berpotensi
masih salah dianggap boundary statement. Risiko ini dinilai jauh lebih
kecil dibanding kasus string literal yang sudah diperbaiki, mengingat
sink pattern yang relevan (eval, innerHTML, dst) jarang berdampingan
langsung dengan regex literal kompleks dalam satu statement yang sama.
AST parsing sungguhan (Acorn atau sejenisnya) didokumentasikan sebagai
**future work** yang membutuhkan build step (esbuild/Vite) — lihat
`architecture.md`.

Total setelah perbaikan ini: **66 test lulus** (59 sebelumnya + 7 baru),
termasuk test pembuktian eksplisit untuk kasus string literal, template
literal, escape character, dan komentar.
