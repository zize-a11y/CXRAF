# Sequence Diagram — CSP-XSS Auditor

## Skenario: Pengguna Membuka Popup dan Melihat Hasil Analisis (UC-01)

```mermaid
sequenceDiagram
    actor User
    participant Popup as PopupController
    participant Router as MessageRouter
    participant Orch as AnalysisOrchestrator
    participant CSPSvc as CSPHeaderService
    participant DOMSvc as DOMScannerService
    participant CSPAn as CSPAnalyzer
    participant ScriptAn as ScriptAnalyzer
    participant Risk as RiskCalculator
    participant Storage as StorageService
    participant UI as UIRenderer

    User->>Popup: klik icon extension
    Popup->>Router: REQUEST_ANALYSIS(tabId, domain)
    Router->>Orch: runAnalysis(tabId, domain)
    Orch->>CSPSvc: getHeaderForTab(tabId)
    CSPSvc-->>Orch: cspHeader (dari cache)
    Orch->>DOMSvc: requestDomScan(tabId)
    DOMSvc-->>Orch: {scriptEntries[], metaCSP}
    Orch->>CSPAn: analyze(cspHeader)
    CSPAn-->>Orch: CSPResult{score, warnings[]}
    Orch->>ScriptAn: analyze(scriptEntries[])
    ScriptAn-->>Orch: ScriptResult{findings[], traceResults[]}
    Orch->>Risk: calculate(CSPResult, ScriptResult)
    Risk-->>Orch: FinalReport{score, riskLevel, recommendations[]}
    Orch->>Storage: save(domain, FinalReport)
    Storage-->>Orch: ack
    Orch-->>Router: FinalReport
    Router-->>Popup: ANALYSIS_RESULT(FinalReport)
    Popup->>UI: renderReport(FinalReport)
    UI-->>User: tampilan popup (gauge, badge, findings, rekomendasi)
```

## Catatan Penting

- Langkah `getHeaderForTab` bersifat **cache lookup**, bukan fetch ulang
  — header sudah tertangkap sebelumnya via `chrome.webRequest.onHeadersReceived`
  saat navigasi terjadi (event-driven), sehingga tidak menambah beban
  saat popup dibuka (mendukung NFR-01).
- Tidak ada roundtrip ke server eksternal manapun di seluruh sequence
  ini (mendukung NFR-06).
- Sequence ini adalah dasar skenario Black Box Testing di `testing-report.md`.
