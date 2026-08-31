# Analisis Kebutuhan — CSP-XSS Auditor

## 1. Deskripsi Umum

Browser extension berbasis Manifest V3 yang mengaudit konfigurasi
Content Security Policy (CSP) dan mendeteksi indikasi script berbahaya
(XSS) pada tab aktif. Bersifat **defensive tool** — mengaudit tab milik
pengguna sendiri, bukan menyerang domain pihak ketiga.

## 2. Kebutuhan Fungsional

| Kode | Kebutuhan |
|---|---|
| FR-01 | Mengambil header CSP dari response HTTP tab aktif |
| FR-02 | Mem-parsing setiap directive CSP |
| FR-03 | Mendeteksi keyword berisiko (unsafe-inline, unsafe-eval, wildcard, dll) |
| FR-04 | Menghitung skor keamanan CSP (0–100) dengan bobot per directive |
| FR-05 | Memindai DOM & inline script untuk pola sink berbahaya |
| FR-06 | Analisis source-to-sink sederhana (heuristik statis) |
| FR-07 | Klasifikasi tingkat risiko (Low/Medium/High/Critical) per temuan |
| FR-08 | Menampilkan hasil analisis dalam popup UI |
| FR-09 | Menyimpan riwayat analisis per domain |
| FR-10 | Rekomendasi perbaikan berbasis OWASP |
| FR-11 | Dark mode dan popup responsif |
| FR-12 | Ekspor laporan analisis sebagai JSON |

## 3. Kebutuhan Non-Fungsional

| Kode | Kebutuhan | Status Verifikasi |
|---|---|---|
| NFR-01 | Overhead analisis < 100ms per halaman | ✅ Terverifikasi (lihat `testing-report.md`, `optimization-report.md`) |
| NFR-02 | Extension sendiri tidak boleh introduce XSS/CSP violation | ✅ Terverifikasi via audit kode (0 penggunaan `innerHTML`) |
| NFR-03 | Least privilege permission | ✅ Hanya `activeTab`, `storage`, `scripting`, `webRequest` |
| NFR-04 | Maintainability (modular, SOLID, testable) | ✅ Clean Architecture, DI, 94.79% test coverage |
| NFR-05 | Kompatibel Chrome, Edge, Brave (Chromium) | Lihat `testing-report.md` §5 |
| NFR-06 | Tidak mengirim data ke server eksternal | ✅ Terverifikasi via audit kode (0 `fetch()` eksternal) |
| NFR-07 | Bundle ringan (<2MB) | Tidak pakai framework berat, vanilla JS |

## 4. Batasan Sistem

1. Analisis statis (pattern matching), bukan taint-tracking runtime penuh.
2. CSP dianalisis dari header HTTP ATAU meta tag — bukan config server-side.
3. Deteksi XSS bersifat indikatif/heuristik, bukan proof-of-exploit.
4. Dataset uji: kombinasi situs CSP ketat dan situs sengaja rentan (DVWA, OWASP Juice Shop).
5. Tidak menangani CSP Level 3 directive eksperimental yang belum stabil lintas browser.

## 5. Stakeholder

- **Primary user**: web developer/security auditor.
- **Secondary user**: peneliti/mahasiswa yang mempelajari implementasi CSP.

## 6. Data yang Diproses

HTTP response header, DOM tab aktif. Tidak ada PII yang dikumpulkan atau dikirim keluar.
