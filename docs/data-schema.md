# Skema Data Storage — CSP-XSS Auditor

Sistem ini **tidak menggunakan database relasional**. Seluruh data
bersifat lokal per-pengguna, disimpan via `chrome.storage.local`
(key-value/document-based), sehingga ERD konvensional (crow's foot)
digantikan skema dokumen berikut.

## Entitas 1: AnalysisHistory (key: `history:<domain>`)

```json
{
  "domain": "example.com",
  "entries": [
    {
      "id": "uuid",
      "timestamp": 1234567890,
      "cspScore": 60,
      "finalScore": 76,
      "riskLevel": "MEDIUM",
      "findingsCount": 2,
      "warningsCount": 1,
      "report": { "...": "FinalReport lengkap, lihat class-diagram.md" }
    }
  ]
}
```

## Entitas 2: UserPreferences (key: `preferences`)

```json
{
  "theme": "dark",
  "autoScanEnabled": false,
  "maxHistoryPerDomain": 10
}
```

## Relasi (Konseptual, Embedded — Bukan Foreign Key)

```
AnalysisHistory (1) --embeds--> FinalReport (banyak, array `entries`)
FinalReport (1)     --embeds--> Finding[] (nested array)
UserPreferences (1) --independent-- (tidak berelasi ke entitas lain)
```

Tidak ada JOIN antar "tabel" karena setiap domain menyimpan riwayatnya
sendiri secara self-contained — sesuai pola akses (`getHistory(domain)`
selalu query by domain). Retensi dibatasi `maxHistoryPerDomain` (default
10) untuk mencegah storage membengkak (mendukung NFR-07).
