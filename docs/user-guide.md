# Panduan Pengguna — CSP-XSS Auditor

## 1. Instalasi (Mode Developer)

1. Buka Chrome/Edge/Brave, arahkan ke `chrome://extensions`.
2. Aktifkan **Developer mode** (toggle di kanan atas).
3. Klik **Load unpacked**, pilih folder `csp-xss-auditor` (folder yang
   berisi `manifest.json`).
4. Ikon shield teal akan muncul di toolbar browser.

## 2. Cara Menggunakan

1. Buka situs web apa pun (harus `http://` atau `https://`).
2. Klik ikon extension di toolbar.
3. Popup akan menampilkan:
   - **Gauge skor** (0–100) di bagian atas, warnanya menunjukkan level risiko.
   - **Label risiko**: Aman / Sedang / Berisiko Tinggi / Kritis.
   - **3 chip ringkasan**: Skor CSP, jumlah Warning, jumlah Script Berisiko.
   - **Daftar Temuan** — klik tiap kartu untuk melihat penjelasan detail.
   - **Rekomendasi** — saran perbaikan berbasis OWASP, diurutkan dari prioritas tertinggi.

## 3. Fitur Tambahan

| Tombol/Ikon | Fungsi |
|---|---|
| 🌙 / ☀️ (kanan atas) | Ganti tema dark/light — preferensi tersimpan otomatis |
| **Riwayat** | Melihat histori analisis sebelumnya untuk domain yang sama |
| **Ekspor JSON** | Mengunduh laporan lengkap sebagai file `.json` |

## 4. Membaca Skor

- **Skor CSP** (chip): seberapa lengkap & ketat konfigurasi CSP situs.
- **Skor akhir** (gauge): kombinasi skor CSP (60%) dan keamanan script (40%).
- **Penting**: jika ditemukan satu saja pola kode kritis (mis. `eval()`
  aktif menerima data dari URL), level risiko akan otomatis **Kritis**
  meskipun skor CSP situs terlihat baik — karena satu celah aktif tetap
  risiko nyata.

## 5. Batasan yang Perlu Dipahami

- Analisis bersifat **indikasi**, bukan bukti eksploitasi 100% pasti —
  selalu verifikasi manual untuk temuan penting.
- Tidak berjalan pada halaman `chrome://`, `about:`, atau halaman
  non-http lainnya.
- Pada halaman dengan jumlah script sangat banyak (>800 inline
  script/event handler), sebagian tidak dianalisis demi menjaga
  performa — popup akan menampilkan notice jika ini terjadi.

## 6. Troubleshooting

| Masalah | Solusi |
|---|---|
| Popup menampilkan "halaman ini bukan halaman web biasa" | Extension hanya bekerja di `http://`/`https://`, bukan `chrome://` |
| Skor tidak berubah setelah reload halaman | Tutup dan buka ulang popup agar analisis dijalankan ulang |
| Riwayat kosong | Riwayat tersimpan per domain — pastikan sudah pernah menganalisis domain tersebut sebelumnya |
