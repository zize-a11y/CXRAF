/**
 * ScoreEngine.test.js
 *
 * Menguji rumus perhitungan skor secara terisolasi dari parsing/deteksi
 * keyword (yang jadi tanggung jawab CSPAnalyzer) — sesuai Single
 * Responsibility Principle yang dipisah di Tahap 7.
 */

import { readFileSync } from 'fs';
import { ScoreEngine } from 'xss-risk-core';

const weights = JSON.parse(readFileSync(new URL('../../packages/xss-risk-core/config/weights.json', import.meta.url)));

describe('ScoreEngine', () => {
  /** @type {ScoreEngine} */
  let engine;

  beforeEach(() => {
    engine = new ScoreEngine(weights);
  });

  describe('applyPenalty()', () => {
    test('mengembalikan bobot penuh jika tidak ada keyword berisiko', () => {
      expect(engine.applyPenalty(20, [])).toBe(20);
    });

    test('mengurangi bobot sesuai penaltyRatio yang dilampirkan (bukan severity)', () => {
      const result = engine.applyPenalty(20, [{ keyword: '*', severity: 'CRITICAL', penaltyRatio: 1.0 }]);
      expect(result).toBe(0);
    });

    test('mengurangi bobot proporsional sesuai penaltyRatio, bukan tabel severity hardcoded', () => {
      const result = engine.applyPenalty(10, [{ keyword: 'data:', severity: 'MEDIUM', penaltyRatio: 0.5 }]);
      expect(result).toBeCloseTo(5, 1); // 10 * (1 - 0.5) = 5
    });

    test('mengambil penaltyRatio TERBESAR jika ada beberapa keyword berisiko dalam satu directive', () => {
      const result = engine.applyPenalty(
        20,
        [
          { keyword: 'data:', severity: 'MEDIUM', penaltyRatio: 0.5 },
          { keyword: '*', severity: 'CRITICAL', penaltyRatio: 1.0 },
        ]
      );
      expect(result).toBe(0); // penaltyRatio 1.0 mendominasi, bukan dijumlah dengan 0.5
    });

    /**
     * TEST PEMBUKTIAN (perbaikan Temuan #1 dari review arsitektur):
     * membuktikan bahwa mengubah penaltyRatio benar-benar mengubah hasil
     * skor — ini yang SEBELUMNYA GAGAL, karena ScoreEngine dulu menurunkan
     * ulang rasio dari `severity` via tabel hardcoded dan mengabaikan
     * `penaltyRatio` yang dilampirkan sama sekali (dead configuration).
     * Test ini secara eksplisit menjalankan applyPenalty dengan DUA nilai
     * penaltyRatio yang berbeda pada severity yang SAMA, dan memverifikasi
     * hasilnya berbeda — kalau rule engine tidak data-driven, test ini
     * akan gagal karena hasil keduanya akan identik.
     */
    test('PEMBUKTIAN: dua penaltyRatio berbeda pada severity SAMA menghasilkan skor berbeda (rule engine benar-benar data-driven)', () => {
      const withLowPenalty = engine.applyPenalty(20, [{ keyword: 'custom-a', severity: 'HIGH', penaltyRatio: 0.3 }]);
      const withHighPenalty = engine.applyPenalty(20, [{ keyword: 'custom-b', severity: 'HIGH', penaltyRatio: 0.9 }]);

      expect(withLowPenalty).toBeCloseTo(14, 1); // 20 * (1 - 0.3) = 14
      expect(withHighPenalty).toBeCloseTo(2, 1); // 20 * (1 - 0.9) = 2
      expect(withLowPenalty).not.toBe(withHighPenalty);
    });
  });

  describe('calculateCSPScore()', () => {
    test('menjumlahkan seluruh contributionScore dan membulatkan ke integer', () => {
      const findings = [
        { contributionScore: 12.4 },
        { contributionScore: 20.0 },
        { contributionScore: 7.8 },
      ];
      expect(engine.calculateCSPScore(findings)).toBe(40); // 12.4+20+7.8=40.2 -> round 40
    });

    test('skor tidak pernah melebihi 100 walau total contributionScore lebih besar', () => {
      const findings = [{ contributionScore: 150 }];
      expect(engine.calculateCSPScore(findings)).toBe(100);
    });

    test('skor tidak pernah negatif', () => {
      expect(engine.calculateCSPScore([])).toBe(0);
    });
  });
});
