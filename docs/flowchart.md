# Flowchart & Activity Diagram — CSP-XSS Auditor

## 1. Flowchart Proses Analisis (High-Level)

```mermaid
flowchart TD
    A[Pengguna membuka/navigasi tab] --> B[Tangkap header CSP<br/>CSPHeaderService]
    A --> C[Scan DOM & inline script<br/>DOMScannerService]
    B --> D[Kirim ke AnalysisOrchestrator]
    C --> D
    D --> E[CSPAnalyzer: evaluasi directive]
    D --> F[ScriptAnalyzer: deteksi sink]
    E --> G[RiskCalculator: gabungkan & hitung skor]
    F --> G
    G --> H[Simpan hasil StorageService]
    H --> I[Render hasil di popup]
```

## 2. Activity Diagram: Penentuan Level Risiko (Detail Percabangan)

```mermaid
flowchart TD
    Start([Mulai: tab diakses]) --> AmbilHeader[Ambil header CSP<br/>via CSPHeaderService]
    AmbilHeader --> D1{Header CSP<br/>ditemukan?}
    D1 -->|Ya| Parse[Parse & evaluasi directive]
    D1 -->|Tidak| ScoreZero[Skor CSP = 0]
    Parse --> Score[Deteksi keyword &<br/>hitung skor akhir]
    ScoreZero --> Score
    Score --> D2{Skor akhir<br/>< 50?}
    D2 -->|Ya| LevelCrit[Level: Critical/High]
    D2 -->|Tidak| LevelSafe[Level: Medium/Low/Aman]
    LevelCrit --> Simpan[Simpan & tampilkan hasil]
    LevelSafe --> Simpan
```

Catatan penting: level risiko akhir yang sesungguhnya di `RiskCalculator`
memiliki SATU pengecualian tambahan di luar diagram di atas — jika ada
minimal satu temuan script severity CRITICAL (mis. `eval()` aktif),
riskLevel dipaksa CRITICAL **terlepas dari skor akhir** (lihat
`architecture.md` §6 "Critical override" dan `optimization-report.md`
untuk pembahasan lengkap beserta bukti unit test-nya).
