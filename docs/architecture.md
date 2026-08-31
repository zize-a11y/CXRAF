# Arsitektur Sistem — CSP-XSS Auditor

## 1. Pendekatan

Clean Architecture diadaptasi untuk konteks browser extension Manifest
V3 (service worker non-persisten, tiga context eksekusi terpisah).
Prinsip yang dipegang: Dependency Rule, Separation of Concern, SOLID.

## 2. Lapisan Arsitektur

```
┌─────────────────────────────────────────────────────┐
│  PRESENTATION LAYER (src/popup/)                      │
│  - PopupController, UIRenderer, komponen UI           │
└───────────────────────┬─────────────────────────────┘
                         │ chrome.runtime.sendMessage
┌───────────────────────▼─────────────────────────────┐
│  APPLICATION LAYER (src/background/)                  │
│  - AnalysisOrchestrator, MessageRouter, AnalyzerRegistry│
└───────────────────────┬─────────────────────────────┘
                         │ relative import (browser context)
┌───────────────────────▼─────────────────────────────┐
│  CORE PACKAGE: xss-risk-core (packages/xss-risk-core/)│
│  PURE, tanpa chrome.* — framework-agnostic            │
│  - CSPAnalyzer, ScriptAnalyzer, SourceSinkTracer       │
│  - ScoreEngine, RiskCalculator, AnalyzerRegistry       │
│  - Dikonsumsi via package name 'xss-risk-core' dari    │
│    Node.js (test, CLI bulk-test.mjs) DAN via relative  │
│    import dari browser (extension) — DUA konsumen      │
│    independen, kode logic TIDAK diduplikasi.           │
└───────────────────────┬─────────────────────────────┘
                         │
┌───────────────────────▼─────────────────────────────┐
│  INFRASTRUCTURE LAYER (src/services/, src/content/)   │
│  - CSPHeaderService, DOMScannerService                │
│  - StorageService, ConfigService                      │
└───────────────────────────────────────────────────────┘
```

**Perubahan struktural (Temuan #5 dari review arsitektur)**: domain layer yang
sebelumnya berada di `src/modules/`, `src/models/`, `src/config/` (menyatu
dalam folder extension) sekarang diekstrak menjadi package npm mandiri
`xss-risk-core` di `packages/xss-risk-core/`, lengkap dengan `package.json`
sendiri dan barrel export (`index.js`) sebagai API permukaan resmi.
Extension bukan lagi satu-satunya "pemilik" logic analisis — ia menjadi
salah satu dari DUA konsumen nyata package ini (bersama CLI
`scripts/bulk-test.mjs`), sesuai posisi "Client-Side XSS Risk Assessment
Framework" yang ditargetkan penelitian ini.

**Kepatuhan domain layer diverifikasi otomatis**: `npm run lint:architecture`
memindai `packages/xss-risk-core/` dan memastikan tidak ada import/pemanggilan
`chrome.*` — ini yang membuat domain layer bisa diuji murni dengan Jest
tanpa Chrome environment (lihat 94.79% test coverage di `testing-report.md`).

## 3. Komponen Utama

| Komponen | Layer | Tanggung Jawab |
|---|---|---|
| `PopupController` | Presentation | Orkestrasi UI popup, request analisis ke background |
| `UIRenderer` | Presentation | Transformasi FinalReport → DOM (aman, tanpa innerHTML) |
| `AnalysisOrchestrator` | Application | Koordinasi use case penuh: header → DOM scan → analyzer → risk → simpan |
| `MessageRouter` | Application | Routing pesan popup ↔ background |
| `CSPAnalyzer` | Domain | Parsing & evaluasi directive CSP |
| `ScriptAnalyzer` | Domain | Deteksi pattern sink berbahaya |
| `SourceSinkTracer` | Domain | Analisis heuristik source→sink |
| `ScoreEngine` | Domain | Rumus skor CSP |
| `RiskCalculator` | Domain | Agregasi skor akhir & level risiko (titik agregasi tunggal) |
| `CSPHeaderService` | Infrastructure | Tangkap header CSP via `webRequest.onHeadersReceived` |
| `DOMScannerService` | Infrastructure (content script) | Ekstraksi inline script, event handler, meta CSP |
| `StorageService` | Infrastructure | CRUD riwayat via `chrome.storage.local` |
| `ConfigService` | Infrastructure | Muat rule engine JSON |

## 4. Rule Engine sebagai Konfigurasi

Seluruh keyword berbahaya dan bobot skor disimpan di `packages/xss-risk-core/config/*.json`
(`csp-rules.json`, `sink-patterns.json`, `weights.json`), bukan hardcode
— mendukung eksperimen sensitivitas parameter untuk BAB IV tanpa
menyentuh kode logic (Open/Closed Principle).

## 5. Keamanan Extension Sendiri (Self-Security)

- Tidak ada `innerHTML`/`document.write`/`insertAdjacentHTML` di
  presentation layer — diverifikasi via grep (lihat `testing-report.md` §7).
- `content_security_policy.extension_pages` dikunci `script-src 'self'`.
- Permission dibatasi seminimal mungkin (lihat `requirements.md` NFR-03).

## 6. Keputusan Desain Penting

| Keputusan | Alasan |
|---|---|
| `RiskCalculator` sebagai titik agregasi tunggal | Rubric penilaian bisa diverifikasi di satu tempat, bukan tersebar |
| Critical override (1 sink CRITICAL = riskLevel CRITICAL) | CSP baik di atas kertas tidak menjamin aman jika ada eval() aktif |
| Cap 800 entry pada ScriptAnalyzer | Pengaman performa untuk halaman anomali, transparan via flag `truncated` |
| Fallback meta-tag CSP | Menutup celah situs statis tanpa kontrol header server-side |
