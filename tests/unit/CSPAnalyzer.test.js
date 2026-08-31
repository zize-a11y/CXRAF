/**
 * CSPAnalyzer.test.js
 *
 * Unit test murni domain layer — TIDAK memerlukan mock chrome.* apapun,
 * karena CSPAnalyzer memang dirancang sebagai pure class (lihat komentar
 * desain di CSPAnalyzer.js). Ini adalah bukti nyata manfaat Clean
 * Architecture yang diterapkan di Tahap 2 & 7.
 */

import { readFileSync } from 'fs';
import { CSPAnalyzer, ScoreEngine } from 'xss-risk-core';

const cspRules = JSON.parse(readFileSync(new URL('../../packages/xss-risk-core/config/csp-rules.json', import.meta.url)));
const weights = JSON.parse(readFileSync(new URL('../../packages/xss-risk-core/config/weights.json', import.meta.url)));
const strongFixture = JSON.parse(readFileSync(new URL('../fixtures/strong-csp.json', import.meta.url)));
const weakFixture = JSON.parse(readFileSync(new URL('../fixtures/weak-csp.json', import.meta.url)));

describe('CSPAnalyzer', () => {
  /** @type {CSPAnalyzer} */
  let analyzer;

  beforeEach(() => {
    const scoreEngine = new ScoreEngine(weights);
    analyzer = new CSPAnalyzer(cspRules, scoreEngine);
  });

  describe('parseDirectives()', () => {
    test('mem-parsing string CSP menjadi Map directive->values dengan benar', () => {
      const map = analyzer.parseDirectives("script-src 'self' example.com; object-src 'none'");
      expect(map.get('script-src')).toEqual(["'self'", 'example.com']);
      expect(map.get('object-src')).toEqual(["'none'"]);
    });

    test('mengembalikan Map kosong untuk input null/undefined/string kosong', () => {
      expect(analyzer.parseDirectives(null).size).toBe(0);
      expect(analyzer.parseDirectives('').size).toBe(0);
      expect(analyzer.parseDirectives(undefined).size).toBe(0);
    });
  });

  describe('detectRiskyKeywords()', () => {
    test('mendeteksi unsafe-inline dan unsafe-eval', () => {
      const found = analyzer.detectRiskyKeywords(["'unsafe-inline'", "'unsafe-eval'"]);
      expect(found.map((f) => f.keyword)).toEqual(['unsafe-inline', 'unsafe-eval']);
    });

    test('mendeteksi wildcard subdomain seperti *.example.com', () => {
      const found = analyzer.detectRiskyKeywords(['*.example.com']);
      expect(found).toHaveLength(1);
      expect(found[0].keyword).toBe('*.example.com');
    });

    test('tidak mendeteksi apapun pada value yang aman', () => {
      const found = analyzer.detectRiskyKeywords(["'self'", 'trusted.example.com']);
      expect(found).toHaveLength(0);
    });
  });

  describe('analyze() - skenario CSP kuat', () => {
    test(`skor >= ${strongFixture.expectedScoreMin} untuk CSP dengan seluruh directive wajib terisi ketat`, () => {
      const result = analyzer.analyze(strongFixture.header);
      expect(result.cspFound).toBe(strongFixture.expectedCspFound);
      expect(result.score).toBeGreaterThanOrEqual(strongFixture.expectedScoreMin);
      expect(result.warnings).toHaveLength(0);
    });
  });

  describe('analyze() - skenario CSP lemah', () => {
    test(`skor <= ${weakFixture.expectedScoreMax} untuk CSP dengan wildcard dan unsafe keyword`, () => {
      const result = analyzer.analyze(weakFixture.header);
      expect(result.score).toBeLessThanOrEqual(weakFixture.expectedScoreMax);
      const foundKeywords = result.warnings.map((w) => w.keyword);
      for (const expected of weakFixture.expectedWarningKeywords) {
        expect(foundKeywords).toContain(expected);
      }
    });
  });

  describe('analyze() - skenario tanpa header CSP', () => {
    test('mengembalikan skor sesuai cspNotFoundScore dan cspFound=false', () => {
      const result = analyzer.analyze(null);
      expect(result.cspFound).toBe(false);
      expect(result.score).toBe(cspRules.cspNotFoundScore);
      expect(result.warnings[0].severity).toBe('CRITICAL');
    });
  });

  describe('analyze() - directive wajib hilang', () => {
    test('memunculkan warning HIGH untuk tiap directive wajib yang tidak ada di header', () => {
      const result = analyzer.analyze("script-src 'self'");
      const missingDirectives = result.warnings
        .filter((w) => w.keyword === '-')
        .map((w) => w.directive);

      expect(missingDirectives).toEqual(
        expect.arrayContaining(['default-src', 'object-src', 'base-uri', 'frame-ancestors'])
      );
    });
  });

  /**
   * TEST PEMBUKTIAN END-TO-END (perbaikan Temuan #1 dari review arsitektur):
   * membuktikan bahwa rule engine SECARA KESELURUHAN — bukan cuma
   * ScoreEngine terisolasi — benar-benar membaca `penaltyRatio` dari
   * csp-rules.json. Dijalankan lewat CSPAnalyzer.analyze() yang sesungguhnya
   * (bukan memanggil ScoreEngine langsung), pada header CSP yang SAMA,
   * hanya beda konfigurasi. Sebelum perbaikan, kedua hasil ini akan
   * IDENTIK (karena penaltyRatio diabaikan) — sekarang harus berbeda.
   */
  describe('rule engine data-driven (Temuan #1)', () => {
    test('mengubah penaltyRatio di csp-rules.json mengubah skor akhir CSPAnalyzer.analyze()', () => {
      const header = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";

      // Konfigurasi A: unsafe-inline penaltyRatio rendah (penalti ringan)
      const rulesLenient = JSON.parse(JSON.stringify(cspRules));
      rulesLenient.riskyKeywordPenalties['unsafe-inline'].penaltyRatio = 0.2;
      const analyzerLenient = new CSPAnalyzer(rulesLenient, new ScoreEngine(weights));

      // Konfigurasi B: unsafe-inline penaltyRatio tinggi (penalti berat) — nilai asli project
      const rulesStrict = JSON.parse(JSON.stringify(cspRules));
      rulesStrict.riskyKeywordPenalties['unsafe-inline'].penaltyRatio = 0.9;
      const analyzerStrict = new CSPAnalyzer(rulesStrict, new ScoreEngine(weights));

      const scoreLenient = analyzerLenient.analyze(header).score;
      const scoreStrict = analyzerStrict.analyze(header).score;

      expect(scoreLenient).toBeGreaterThan(scoreStrict);
      // script-src weight = 20. Lenient: 20*(1-0.2)=16. Strict: 20*(1-0.9)=2. Selisih=14.
      expect(scoreLenient - scoreStrict).toBe(14);
    });

    test('mengubah missingDirectivePenaltyRatio mengubah skor saat directive wajib hilang', () => {
      const header = "script-src 'self'"; // default-src, object-src, base-uri, frame-ancestors hilang

      const rulesFullPenalty = JSON.parse(JSON.stringify(cspRules));
      rulesFullPenalty.missingDirectivePenaltyRatio = 1.0;
      const analyzerFullPenalty = new CSPAnalyzer(rulesFullPenalty, new ScoreEngine(weights));

      const rulesPartialPenalty = JSON.parse(JSON.stringify(cspRules));
      rulesPartialPenalty.missingDirectivePenaltyRatio = 0.5; // beri "setengah kredit" utk directive hilang
      const analyzerPartialPenalty = new CSPAnalyzer(rulesPartialPenalty, new ScoreEngine(weights));

      const scoreFullPenalty = analyzerFullPenalty.analyze(header).score;
      const scorePartialPenalty = analyzerPartialPenalty.analyze(header).score;

      expect(scorePartialPenalty).toBeGreaterThan(scoreFullPenalty);
    });
  });
});
