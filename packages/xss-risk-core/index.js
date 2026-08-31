/**
 * index.js (xss-risk-core)
 *
 * API PERMUKAAN RESMI package ini. Konsumen (browser extension, CLI
 * bulk-test, atau aplikasi Node.js lain di masa depan) SEHARUSNYA hanya
 * mengimpor dari file ini, bukan menjangkau file internal langsung
 * (mis. `xss-risk-core/analyzers/CSPAnalyzer.js`) — supaya struktur
 * internal package ini bisa direorganisasi di masa depan tanpa
 * mematahkan kode konsumen (encapsulation di level package, bukan cuma
 * class).
 *
 * Package ini TIDAK bergantung pada Chrome API, DOM, atau environment
 * spesifik apapun — murni logic analisis (lihat lint:architecture di
 * root project yang memverifikasi ini secara otomatis). Ini yang membuat
 * package ini bisa dipakai dari THREE konteks berbeda:
 *   1. Browser extension (via relative import, lihat src/background/index.js)
 *   2. CLI bulk-test.mjs (via package name 'xss-risk-core', Node.js murni)
 *   3. Unit test (Jest, Node.js murni)
 */

// Analyzer (domain layer utama)
export { IAnalyzer } from './analyzers/IAnalyzer.js';
export { CSPAnalyzer } from './analyzers/CSPAnalyzer.js';
export { ScriptAnalyzer } from './analyzers/ScriptAnalyzer.js';

// Source-sink tracing
export { SourceSinkTracer } from './tracer/SourceSinkTracer.js';

// Risk scoring
export { ScoreEngine } from './risk/ScoreEngine.js';
export { RiskCalculator } from './risk/RiskCalculator.js';

// Extension point (Temuan #5)
export { AnalyzerRegistry } from './registry/AnalyzerRegistry.js';

// Model / DTO
export { createCSPResult } from './models/CSPResult.js';
export { createScriptResult } from './models/ScriptResult.js';
export { createFinalReport } from './models/FinalReport.js';
export { RiskLevel, Severity, riskLevelFromScore } from './models/RiskLevel.js';
