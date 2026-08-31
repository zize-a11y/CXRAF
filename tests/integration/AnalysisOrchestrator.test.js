/**
 * AnalysisOrchestrator.test.js
 *
 * Integration test yang memvalidasi ALUR PENUH use case "analisis tab
 * aktif" dari gatherInputs() hingga penyimpanan hasil, memakai MOCK untuk
 * CSPHeaderService, requestDomScan, dan StorageService (bukan chrome.*
 * asli) — membuktikan manfaat nyata Dependency Injection yang dirancang
 * di Tahap 2 & 7: seluruh use case bisa diuji tanpa Chrome environment.
 */

import { readFileSync } from 'fs';
import { jest } from '@jest/globals';
import { AnalysisOrchestrator } from '../../src/background/AnalysisOrchestrator.js';
import {
  CSPAnalyzer,
  ScriptAnalyzer,
  SourceSinkTracer,
  ScoreEngine,
  RiskCalculator,
  AnalyzerRegistry,
} from 'xss-risk-core';

const cspRules = JSON.parse(readFileSync(new URL('../../packages/xss-risk-core/config/csp-rules.json', import.meta.url)));
const sinkPatterns = JSON.parse(readFileSync(new URL('../../packages/xss-risk-core/config/sink-patterns.json', import.meta.url)));
const weights = JSON.parse(readFileSync(new URL('../../packages/xss-risk-core/config/weights.json', import.meta.url)));

/** Membangun instance AnalysisOrchestrator siap pakai dengan real domain layer + mock infra. */
function buildOrchestrator({ cspHeader, scriptEntries, metaCSP = null }) {
  const scoreEngine = new ScoreEngine(weights);
  const tracer = new SourceSinkTracer(sinkPatterns);
  const riskCalculator = new RiskCalculator(scoreEngine, weights);

  // Pola registry (Temuan #5) - sama seperti composition root sesungguhnya
  // di src/background/index.js, membuktikan AnalysisOrchestrator benar-benar
  // generik terhadap registry, bukan cuma di production code.
  const registry = new AnalyzerRegistry();
  registry.register('csp', new CSPAnalyzer(cspRules, scoreEngine), 'csp');
  registry.register('script', new ScriptAnalyzer(sinkPatterns, tracer), 'script');

  const savedReports = [];
  const mockStorageService = {
    save: jest.fn(async (domain, report) => { savedReports.push({ domain, report }); }),
  };
  const mockCspHeaderService = { getHeaderForTab: jest.fn(() => cspHeader) };
  const mockRequestDomScan = jest.fn(async () => ({ scriptEntries, metaCSP }));

  const orchestrator = new AnalysisOrchestrator({
    cspHeaderService: mockCspHeaderService,
    requestDomScan: mockRequestDomScan,
    registry,
    riskCalculator,
    storageService: mockStorageService,
  });

  return { orchestrator, savedReports, mockCspHeaderService, mockRequestDomScan, mockStorageService };
}

describe('AnalysisOrchestrator (integration, mocked infra)', () => {
  test('gatherInputs() memakai header HTTP CSP jika tersedia', async () => {
    const { orchestrator } = buildOrchestrator({
      cspHeader: "default-src 'self'",
      scriptEntries: [],
      metaCSP: "default-src *", // seharusnya diabaikan karena header HTTP ada
    });

    const inputs = await orchestrator.gatherInputs(1);
    expect(inputs.cspHeader).toBe("default-src 'self'");
  });

  test('gatherInputs() fallback ke meta tag CSP jika header HTTP tidak ada', async () => {
    const { orchestrator } = buildOrchestrator({
      cspHeader: null,
      scriptEntries: [],
      metaCSP: "default-src 'self'",
    });

    const inputs = await orchestrator.gatherInputs(1);
    expect(inputs.cspHeader).toBe("default-src 'self'");
  });

  test('runAnalysis() menghasilkan FinalReport lengkap dan menyimpannya ke storage', async () => {
    const { orchestrator, savedReports, mockStorageService } = buildOrchestrator({
      cspHeader: "default-src 'self'; script-src 'self' 'unsafe-inline'",
      scriptEntries: [{ type: 'inline-script', code: 'document.body.innerHTML = location.hash;' }],
    });

    const report = await orchestrator.runAnalysis(42, 'contoh-uji.test');

    expect(report.domain).toBe('contoh-uji.test');
    expect(report.cspWarnings.some((w) => w.keyword === 'unsafe-inline')).toBe(true);
    expect(report.scriptFindings.some((f) => f.sinkId === 'inner-html')).toBe(true);
    expect(mockStorageService.save).toHaveBeenCalledTimes(1);
    expect(savedReports).toHaveLength(1);
    expect(savedReports[0].domain).toBe('contoh-uji.test');
  });

  test('runAnalysis() pada halaman bersih menghasilkan riskLevel LOW/MEDIUM, bukan CRITICAL', async () => {
    const { orchestrator } = buildOrchestrator({
      cspHeader: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
      scriptEntries: [{ type: 'inline-script', code: 'const a = 1 + 1;' }],
    });

    const report = await orchestrator.runAnalysis(7, 'aman.test');
    expect(['LOW', 'MEDIUM']).toContain(report.riskLevel);
  });

  /**
   * TEST PEMBUKTIAN (implementasi Temuan #5 - AnalyzerRegistry):
   * membuktikan bahwa analyzer KETIGA (fiktif) bisa didaftarkan ke
   * registry dan benar-benar IKUT DIJALANKAN oleh AnalysisOrchestrator,
   * TANPA satu baris pun kode AnalysisOrchestrator.js perlu diubah. Ini
   * bukti konkret Open/Closed Principle — bukan sekadar interface
   * IAnalyzer yang ada tapi tidak benar-benar dipakai untuk ekstensi.
   */
  test('PEMBUKTIAN: analyzer ketiga (fiktif) yang didaftarkan ke registry ikut dijalankan tanpa mengubah AnalysisOrchestrator', async () => {
    const scoreEngine = new ScoreEngine(weights);
    const tracer = new SourceSinkTracer(sinkPatterns);
    const riskCalculator = new RiskCalculator(scoreEngine, weights);

    const registry = new AnalyzerRegistry();
    registry.register('csp', new CSPAnalyzer(cspRules, scoreEngine), 'csp');
    registry.register('script', new ScriptAnalyzer(sinkPatterns, tracer), 'script');

    // Analyzer FIKTIF ketiga, mensimulasikan mis. "CORSAnalyzer" di masa
    // depan - satu-satunya kontrak yang harus dipenuhi adalah method analyze().
    const fakeAnalyzeSpy = jest.fn((input) => ({ fakeResult: true, receivedInput: input }));
    registry.register('fictitious', { analyze: fakeAnalyzeSpy }, 'script');

    const mockStorageService = { save: jest.fn() };
    const orchestrator = new AnalysisOrchestrator({
      cspHeaderService: { getHeaderForTab: () => "default-src 'self'" },
      requestDomScan: async () => ({ scriptEntries: [{ type: 'inline-script', code: 'const a = 1;' }], metaCSP: null }),
      registry,
      riskCalculator,
      storageService: mockStorageService,
    });

    await orchestrator.runAnalysis(99, 'ocp-test.test');

    // Analyzer fiktif benar-benar dipanggil oleh orchestrator generik,
    // tanpa AnalysisOrchestrator.js tahu apa-apa soal keberadaannya.
    expect(fakeAnalyzeSpy).toHaveBeenCalledTimes(1);
  });
});
