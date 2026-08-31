# Class Diagram — CSP-XSS Auditor

## Domain Layer

```mermaid
classDiagram
    class IAnalyzer {
        <<interface>>
        +analyze(input) AnalysisResult
    }

    class CSPAnalyzer {
        -ruleSet: CSPRuleConfig
        +analyze(cspHeader) CSPResult
        +parseDirectives(cspHeader) DirectiveMap
        -evaluateDirective(name, values) DirectiveFinding
        -detectRiskyKeywords(values) Warning[]
    }

    class ScriptAnalyzer {
        -sinkPatterns: SinkPatternConfig
        -sourceSinkTracer: SourceSinkTracer
        -maxEntries: number
        +analyze(scriptList) ScriptResult
        -detectSinks(code) SinkFinding[]
        -detectEventHandlers(entry) SinkFinding[]
    }

    class SourceSinkTracer {
        -sourcePatterns: string[]
        -sinkPatterns: string[]
        +trace(code) TraceResult[]
        -isTainted(variable, context) boolean
    }

    class ScoreEngine {
        -weights: WeightConfig
        +calculateCSPScore(findings) number
        -applyPenalty(baseScore, warnings) number
    }

    class RiskCalculator {
        -scoreEngine: ScoreEngine
        +calculate(cspResult, scriptResult) FinalReport
        -determineRiskLevel(score, criticalCount) RiskLevel
        -generateRecommendations(findings) Recommendation[]
    }

    IAnalyzer <|.. CSPAnalyzer : implements
    IAnalyzer <|.. ScriptAnalyzer : implements
    RiskCalculator *-- ScoreEngine : composition
    ScriptAnalyzer *-- SourceSinkTracer : composition
```

## Application & Infrastructure Layer

```mermaid
classDiagram
    class AnalysisOrchestrator {
        -cspHeaderService: CSPHeaderService
        -requestDomScan: function
        -cspAnalyzer: IAnalyzer
        -scriptAnalyzer: IAnalyzer
        -riskCalculator: RiskCalculator
        -storageService: StorageService
        +runAnalysis(tabId, domain) FinalReport
        +gatherInputs(tabId) object
    }

    class MessageRouter {
        -orchestrator: AnalysisOrchestrator
        -storageService: StorageService
        +handleMessage(message, sender, sendResponse) boolean
    }

    class CSPHeaderService {
        -headerCache: Map
        +listenHeaders() void
        +getHeaderForTab(tabId) string
    }

    class DOMScannerService {
        -eventHandlerAttributes: string[]
        +scan() object
    }

    class StorageService {
        +save(domain, report) Promise
        +getHistory(domain) Promise~FinalReport[]~
        +clear(domain) Promise
    }

    class ConfigService {
        +loadCSPRules() Promise~object~
        +loadSinkPatterns() Promise~object~
        +loadWeights() Promise~object~
        +loadAll() Promise~object~
    }

    AnalysisOrchestrator o-- CSPHeaderService : aggregation
    AnalysisOrchestrator o-- StorageService : aggregation
    AnalysisOrchestrator ..> IAnalyzer : dependency (DI)
    MessageRouter ..> AnalysisOrchestrator : dependency
```

## Presentation Layer

```mermaid
classDiagram
    class PopupController {
        -uiRenderer: UIRenderer
        -storageService: StorageService
        +init() Promise
        +onPopupOpen() Promise
        +requestAnalysis(tabId, domain) Promise~FinalReport~
    }

    class UIRenderer {
        +renderReport(report, options) void
        +renderLoading() void
        +renderError(message) void
        +renderHistory(history, onBack) void
        +applyTheme(theme) void
    }

    PopupController *-- UIRenderer : composition
```

## Data Class (DTO)

```
CSPResult      { score, cspFound, findings[], warnings[] }
ScriptResult   { findings[], traceResults[], criticalCount, highCount, truncated, totalEntriesReceived }
FinalReport    { domain, timestamp, cspScore, finalScore, riskLevel, cspWarnings[], scriptFindings[], recommendations[], truncated }
RiskLevel      = enum { LOW, MEDIUM, HIGH, CRITICAL }
```

## Ringkasan Relasi

| Relasi | Jenis |
|---|---|
| `CSPAnalyzer`/`ScriptAnalyzer` → `IAnalyzer` | Realization |
| `RiskCalculator` *−−♦* `ScoreEngine` | Composition |
| `ScriptAnalyzer` *−−♦* `SourceSinkTracer` | Composition |
| `AnalysisOrchestrator` *−−◇* `CSPHeaderService`, `StorageService` | Aggregation |
| `AnalysisOrchestrator` → `IAnalyzer` (via constructor) | Dependency (DI) |
| `PopupController` *−−♦* `UIRenderer` | Composition |

Class diagram ini mencerminkan seluruh prinsip SOLID: SRP per class,
OCP via `IAnalyzer`, DIP via dependency injection ke `AnalysisOrchestrator`
(diverifikasi lulus 41 unit/integration test — lihat `testing-report.md`).
