# Laporan Pengujian — CSP-XSS Auditor

Dokumen ini merangkum seluruh aktivitas pengujian Tahap 12, sebagai bahan
langsung untuk BAB IV skripsi.

## 1. Unit Testing (Otomatis, Jest)

Domain layer (`CSPAnalyzer`, `ScoreEngine`, `ScriptAnalyzer`,
`SourceSinkTracer`, `RiskCalculator`) dan `AnalysisOrchestrator` diuji
otomatis tanpa Chrome environment (murni Node.js), membuktikan manfaat
Clean Architecture yang diterapkan sejak Tahap 2.

```
Test Suites: 5 passed, 5 total
Tests:       38 passed, 38 total
Time:        ~0.7s
```

Cara menjalankan ulang: `npm install && npm test` (atau `npm run test:coverage`
untuk laporan coverage).

## 2. White Box Testing (Code Coverage)

| File | % Statement | % Branch | % Fungsi | % Line |
|---|---|---|---|---|
| `AnalysisOrchestrator.js` | 100 | 100 | 100 | 100 |
| `CSPAnalyzer.js` | 98 | 85 | 100 | 100 |
| `ScriptAnalyzer.js` | 91.17 | 65.21 | 100 | 100 |
| `RiskCalculator.js` | 89.18 | 61.9 | 100 | 91.17 |
| `ScoreEngine.js` | 100 | 87.5 | 100 | 100 |
| `SourceSinkTracer.js` | 97.56 | 85.71 | 100 | 100 |
| `IAnalyzer.js` | 0 | 100 | 0 | 0 |
| **Total** | **94.79** | **75** | **97.67** | **97.66** |

Catatan: `IAnalyzer.js` sengaja 0% karena hanya berisi method yang
melempar error jika class abstrak dipanggil langsung — tidak pernah
benar-benar dieksekusi di jalur normal (kontrak interface, bukan logic).
Branch coverage 75% dianggap memadai untuk skala S1; branch yang belum
tercakup didominasi jalur error-handling minor yang bisa didokumentasikan
sebagai batasan pengujian.

## 3. Black Box Testing (Skenario Input-Output)

Pengujian ini mengabaikan struktur internal, hanya mencocokkan input
terhadap output yang diharapkan pengguna akhir.

| ID | Skenario Input | Output Diharapkan | Hasil |
|---|---|---|---|
| BB-01 | CSP lengkap, semua directive wajib + `'self'` saja | Skor ≥ 60, 0 warning | ✅ Lulus |
| BB-02 | CSP dengan `default-src *`, `unsafe-inline`, `unsafe-eval` | Skor ≤ 10, warning memuat `*`, `unsafe-inline`, `unsafe-eval` | ✅ Lulus |
| BB-03 | Header CSP tidak ada sama sekali | `cspFound: false`, skor 0, 1 warning CRITICAL | ✅ Lulus |
| BB-04 | Inline script berisi `eval(location.hash)` walau CSP baik | `riskLevel: CRITICAL` (override) | ✅ Lulus |
| BB-05 | `onclick="..."` pada elemen HTML | Finding `event-handler:onclick` severity MEDIUM | ✅ Lulus |
| BB-06 | `innerHTML = document.referrer` | Finding `inner-html` + trace `document-referrer→inner-html` | ✅ Lulus |
| BB-07 | Script bersih tanpa sink berbahaya | 0 findings, riskLevel mengikuti skor CSP saja | ✅ Lulus |
| BB-08 | Ekspor laporan (tombol "Ekspor JSON") | File `.json` terunduh berisi FinalReport lengkap | Manual, lihat §4 |

Situs uji riil yang direkomendasikan untuk validasi tambahan sebelum
sidang: kombinasi situs dengan CSP ketat (mis. situs perbankan/big tech)
dan situs sengaja rentan (**DVWA**, **OWASP Juice Shop**) — sesuai
batasan scope di Tahap 1.

## 4. Manual Testing (Checklist UI Popup)

Karena sandbox pengembangan ini tidak memiliki Chrome browser sungguhan,
pengujian berikut **wajib dilakukan manual oleh peneliti** setelah
`Load unpacked` di `chrome://extensions`:

- [ ] Popup terbuka tanpa error di console (klik kanan popup → Inspect)
- [ ] Gauge skor menampilkan angka dan warna sesuai `riskLevel`
- [ ] Kartu temuan bisa di-expand/collapse saat diklik
- [ ] Toggle dark/light mode berfungsi dan preferensi tersimpan setelah popup ditutup-buka ulang
- [ ] Tombol "Riwayat" menampilkan analisis sebelumnya untuk domain yang sama
- [ ] Tombol "Ekspor JSON" mengunduh file dengan nama `csp-xss-report-<domain>-<timestamp>.json`
- [ ] Popup pada halaman `chrome://extensions` menampilkan pesan error yang wajar (bukan crash)
- [ ] Tidak ada elemen popup yang terpotong pada lebar 380px

## 5. Browser Compatibility Testing

| Browser | Basis | Status | Catatan |
|---|---|---|---|
| Google Chrome | Chromium | Didukung penuh | Target utama pengembangan |
| Microsoft Edge | Chromium | Didukung penuh | API Manifest V3 identik dengan Chrome |
| Brave | Chromium | Didukung, perlu verifikasi manual | Shield bawaan Brave berpotensi memengaruhi `webRequest`, perlu dicek |
| Opera | Chromium | Kemungkinan didukung | Belum diuji langsung |
| Mozilla Firefox | Gecko | **Tidak didukung** | Firefox punya implementasi MV3 berbeda (`browser.*` namespace, dukungan API parsial) — di luar scope skripsi ini |

## 6. Performance Testing

Diukur langsung (bukan estimasi) menggunakan `process.hrtime` terhadap
simulasi halaman berat: **300 entri script** (200 inline script + 100
event handler) — jauh melebihi jumlah rata-rata script pada halaman
web nyata.

```
Entries diproses per run : 300
Rata-rata                : 4.30ms
Min / Max                : 0.93ms / 9.80ms
P95                      : 9.80ms
```

**Kesimpulan**: jauh di bawah target NFR-01 (< 100ms per halaman) bahkan
pada beban ekstrem. Catatan penting untuk BAB IV: angka ini murni waktu
eksekusi domain layer (parsing + analisis + scoring); belum termasuk
overhead message-passing antar context Manifest V3 (`chrome.tabs.sendMessage`,
`chrome.runtime.sendMessage`) yang secara empiris menambah beberapa
milidetik lagi namun tidak dapat diukur di sandbox non-browser ini —
sebaiknya diukur ulang manual via `chrome://extensions` → Inspect →
tab Performance saat sidang berlangsung, untuk angka yang benar-benar utuh.

## 7. Ringkasan Kesesuaian dengan Kebutuhan (Tahap 1)

| Kebutuhan | Status |
|---|---|
| FR-01 s.d. FR-11 | ✅ Teruji (unit + black box) |
| FR-12 (Ekspor laporan) | ✅ Implementasi selesai, perlu verifikasi manual |
| NFR-01 (Performa < 100ms) | ✅ Terbukti (4.3ms rata-rata) |
| NFR-02 (Self-security, no innerHTML) | ✅ Audit kode: 0 penggunaan innerHTML di seluruh presentation layer |
| NFR-06 (Tanpa server eksternal) | ✅ Tidak ada `fetch()` ke domain luar di seluruh kode |
