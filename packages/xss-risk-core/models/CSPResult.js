/**
 * CSPResult.js
 *
 * Fungsi: Mendefinisikan struktur data (DTO/Value Object) untuk hasil
 * analisis CSP oleh CSPAnalyzer. File ini TIDAK berisi logic apapun,
 * hanya factory function untuk membuat objek dengan bentuk konsisten
 * dan JSDoc typedef untuk dokumentasi & dukungan autocomplete IDE.
 *
 * Kenapa dipisah dari CSPAnalyzer: agar bentuk data hasil analisis bisa
 * dirujuk oleh banyak modul lain (RiskCalculator, UIRenderer, StorageService)
 * tanpa membuat mereka bergantung langsung pada implementasi CSPAnalyzer.
 */

/**
 * @typedef {Object} DirectiveFinding
 * @property {string} directive - nama directive, mis. "script-src"
 * @property {string[]} values - daftar value directive tersebut
 * @property {boolean} present - apakah directive ditemukan di header
 * @property {string[]} riskyKeywordsFound - keyword berisiko yang ditemukan
 * @property {number} contributionScore - kontribusi skor directive ini (0..weight)
 */

/**
 * @typedef {Object} Warning
 * @property {string} directive
 * @property {string} keyword - keyword berisiko, mis. "unsafe-inline"
 * @property {string} severity - salah satu Severity
 * @property {string} explanation - penjelasan mengapa berbahaya
 */

/**
 * @typedef {Object} CSPResult
 * @property {number} score - skor CSP 0-100
 * @property {boolean} cspFound - apakah header CSP ditemukan sama sekali
 * @property {DirectiveFinding[]} findings
 * @property {Warning[]} warnings
 */

/**
 * Membuat objek CSPResult dengan bentuk konsisten.
 *
 * @param {Partial<CSPResult>} data
 * @returns {CSPResult}
 */
export function createCSPResult(data = {}) {
  return {
    score: data.score ?? 0,
    cspFound: data.cspFound ?? false,
    findings: data.findings ?? [],
    warnings: data.warnings ?? [],
  };
}
