# CSP-XSS Auditor

Browser extension (Manifest V3) untuk mendeteksi script berbahaya dan
serangan Cross-Site Scripting (XSS) menggunakan analisis Content
Security Policy (CSP).

Dikembangkan sebagai Bahan mengisi waktu luang:
**"Pengembangan Browser Extension Pendeteksi Script Berbahaya dan
Serangan Cross-Site Scripting (XSS) Menggunakan Analisis Content
Security Policy (CSP)"**
— zizee.

## Fitur Utama

- Analisis lengkap konfigurasi CSP (14 directive) dengan skor 0–100.
- Deteksi 12+ pola sink berbahaya (`eval`, `innerHTML`, `document.write`, dll).
- Analisis heuristik source-to-sink untuk indikasi DOM-based XSS.
- Rekomendasi perbaikan berbasis OWASP.
- Riwayat analisis per domain, ekspor laporan JSON.
- Dark/light mode.

## Instalasi Cepat

```
1. chrome://extensions → aktifkan Developer mode
2. Load unpacked → pilih folder ini
```

Panduan lengkap: [`docs/user-guide.md`](docs/user-guide.md)

## Menjalankan Test

```bash
npm install
npm test                  # unit + integration test (Jest)
npm run test:coverage     # dengan laporan code coverage
npm run lint:architecture # validasi domain layer bebas chrome.* API
```

## Tooling Penelitian (Bulk Testing, Sensitivity Analysis, Komparasi)

Selain extension itu sendiri, `xss-risk-core` juga dipakai dari CLI untuk
kebutuhan pengujian skripsi tanpa perlu klik manual di Chrome satu-satu.
Edit `scripts/urls.txt` (satu URL per baris), lalu:

```bash
npm run scan        # analisis bulk banyak situs sekaligus -> scripts/bulk-test-results.csv
npm run sensitivity # uji sensitivitas bobot cspScoreRatio terhadap klasifikasi riskLevel -> scripts/sensitivity-results.csv
npm run compare      # bandingkan skor dengan Google csp_evaluator & MDN HTTP Observatory -> scripts/comparison-results.csv
```

`npm run compare` butuh akses internet penuh ke `observatory-api.mdn.mozilla.net`
untuk bagian MDN Observatory-nya — bagian Google `csp_evaluator` tidak
butuh internet tambahan (berjalan lokal via npm package).

## Struktur Project

```
packages/
└── xss-risk-core/  → Core engine framework-agnostic (Client-Side XSS Risk
                       Assessment Framework) — analyzer, risk scoring,
                       AnalyzerRegistry, rule engine JSON. TIDAK bergantung
                       Chrome API, dipakai dari 2 konsumen independen:
                       browser extension (di bawah) dan CLI scripts/bulk-test.mjs
src/
├── background/   → Application layer (service worker) - composition root, wiring ke xss-risk-core
├── content/      → Content script (DOM scanning)
├── popup/        → Presentation layer (UI)
├── services/     → Infrastructure layer (wrap Chrome API)
└── styles/       → CSS (dark/light theme)
tests/            → Unit test, integration test, fixtures
docs/             → Dokumentasi lengkap (lihat peta di bawah)
scripts/          → Tooling maintainability + bulk-test.mjs (CLI, konsumen kedua xss-risk-core)
```

## Peta Dokumentasi

| Dokumen | Isi |
|---|---|
| [`docs/requirements.md`](docs/requirements.md) | Analisis kebutuhan fungsional & non-fungsional |
| [`docs/architecture.md`](docs/architecture.md) | Arsitektur sistem & keputusan desain |
| [`docs/use-case.md`](docs/use-case.md) | Use case diagram & narasi |
| [`docs/flowchart.md`](docs/flowchart.md) | Flowchart & activity diagram |
| [`docs/sequence-diagram.md`](docs/sequence-diagram.md) | Sequence diagram interaksi antar komponen |
| [`docs/class-diagram.md`](docs/class-diagram.md) | Class diagram seluruh layer |
| [`docs/data-schema.md`](docs/data-schema.md) | Skema data storage (pengganti ERD) |
| [`docs/testing-report.md`](docs/testing-report.md) | Laporan pengujian (unit, black box, white box, performa) |
| [`docs/optimization-report.md`](docs/optimization-report.md) | Laporan optimasi & benchmark |
| [`docs/user-guide.md`](docs/user-guide.md) | Panduan pengguna akhir |

## Ringkasan Kualitas

| Metrik | Nilai |
|---|---|
| Unit/integration test | 41 test, 5 suite, 100% lulus |
| Code coverage (domain layer) | 94.79% statement |
| Performa (halaman berat, 300 entries) | ~4.3ms rata-rata |
| Permission extension | 4 (activeTab, storage, scripting, webRequest) — least privilege |
| Dependency eksternal saat runtime | 0 (tidak ada CDN/font/API eksternal) |

## Batasan Penelitian

Analisis bersifat statis dan heuristik (bukan taint-tracking runtime
penuh atau proof-of-exploit). Lihat `docs/requirements.md` §4 untuk
batasan lengkap.

## Lisensi

MIT — lihat `LICENSE`.
