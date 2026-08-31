/**
 * ScoreEngine.js
 *
 * Fungsi: Satu-satunya tempat rumus perhitungan skor CSP dihitung. Dipisah
 * dari CSPAnalyzer supaya rumus skor bisa diuji dan diubah tanpa menyentuh
 * logic parsing/deteksi keyword (Single Responsibility Principle).
 *
 * Alur kerja:
 *   - applyPenalty(): dipanggil per-directive oleh CSPAnalyzer, mengurangi
 *     bobot directive berdasarkan keyword berisiko yang ditemukan.
 *   - calculateCSPScore(): dipanggil sekali di akhir oleh CSPAnalyzer,
 *     menjumlahkan seluruh contributionScore dari semua findings.
 */

export class ScoreEngine {
  /**
   * @param {object} weights - isi weights.json (lihat packages/xss-risk-core/config/weights.json)
   */
  constructor(weights) {
    this.weights = weights;
  }

  /**
   * Mengurangi bobot dasar suatu directive berdasarkan keyword berisiko
   * yang ditemukan pada directive tersebut. Penalti bersifat multiplikatif
   * (bukan pengurangan tetap) agar directive dengan bobot besar tetap
   * proporsional turunnya ketika ditemukan keyword berisiko.
   *
   * PERBAIKAN TEMUAN #1 (review arsitektur): sebelumnya method ini
   * menurunkan rasio penalti dari `severity` via tabel hardcoded
   * (_severityToRatio), sehingga field `penaltyRatio` yang eksplisit
   * ditulis di csp-rules.json TIDAK PERNAH benar-benar dipakai — dead
   * configuration. Sekarang method ini membaca `penaltyRatio` LANGSUNG
   * dari setiap item `riskyFound` (yang sudah dilampirkan oleh
   * CSPAnalyzer.detectRiskyKeywords() langsung dari JSON config), sehingga
   * mengubah nilai di csp-rules.json benar-benar mengubah skor akhir —
   * rule engine kini benar-benar data-driven, bukan cuma di permukaan.
   *
   * @param {number} baseWeight - bobot dasar directive (dari csp-rules.json)
   * @param {{keyword: string, severity: string, penaltyRatio: number}[]} riskyFound - hasil detectRiskyKeywords
   * @returns {number} kontribusi skor akhir directive ini (0..baseWeight)
   */
  applyPenalty(baseWeight, riskyFound) {
    if (!riskyFound || riskyFound.length === 0) return baseWeight;

    // Ambil penalti TERBESAR di antara semua keyword berisiko yang ditemukan
    // pada directive ini (bukan dijumlahkan semua, agar tidak menghasilkan
    // skor negatif jika satu directive punya banyak keyword berisiko).
    const penaltyRatios = riskyFound.map((r) => r.penaltyRatio);
    const maxPenaltyRatio = Math.max(...penaltyRatios);

    const remaining = baseWeight * (1 - maxPenaltyRatio);
    return Math.max(0, Math.round(remaining * 100) / 100);
  }

  /**
   * Menjumlahkan seluruh contributionScore dari semua findings menjadi
   * skor akhir 0-100.
   *
   * @param {import('../../models/CSPResult.js').DirectiveFinding[]} findings
   * @returns {number} skor 0-100, dibulatkan ke integer
   */
  calculateCSPScore(findings) {
    const total = findings.reduce((sum, f) => sum + (f.contributionScore || 0), 0);
    return Math.max(0, Math.min(100, Math.round(total)));
  }
}
