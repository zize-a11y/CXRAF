/**
 * AnalyzerRegistry.js
 *
 * Fungsi: Extension point FORMAL untuk mendaftarkan analyzer (implementasi
 * IAnalyzer) ke dalam pipeline analisis, TANPA perlu mengubah kode
 * AnalysisOrchestrator sama sekali. Ini adalah perbaikan langsung untuk
 * Temuan #5 dari review arsitektur: sebelumnya, IAnalyzer secara teori
 * mendukung Open/Closed Principle, tapi menambah analyzer baru tetap
 * mengharuskan mengedit constructor AnalysisOrchestrator secara manual
 * (parameter bernama `cspAnalyzer`, `scriptAnalyzer` — bukan array generik).
 *
 * Dengan AnalyzerRegistry, menambah analyzer ketiga (mis. CORSAnalyzer di
 * masa depan) HANYA memerlukan satu baris di composition root:
 *
 *   registry.register('cors', corsAnalyzer, 'corsInput');
 *
 * AnalysisOrchestrator tidak perlu tahu apa-apa soal analyzer baru ini —
 * ia hanya melakukan iterasi generik atas seluruh entry yang terdaftar
 * (lihat AnalysisOrchestrator.runAnalysis()).
 *
 * KETERBATASAN YANG PERLU DICATAT SECARA JUJUR (untuk BAB III): registry
 * ini membuat TAHAP ANALISIS individual (memanggil analyzer.analyze())
 * benar-benar extensible tanpa mengubah orchestrator. TAPI tahap AGREGASI
 * SKOR di RiskCalculator.calculate() saat ini masih menerima tepat dua
 * hasil (CSPResult, ScriptResult) secara eksplisit — menambah analyzer
 * ketiga akan menghasilkan result-nya (bisa diambil dari registry), tapi
 * BELUM otomatis ikut memengaruhi skor akhir kecuali RiskCalculator juga
 * digeneralisasi menerima array hasil, bukan dua parameter tetap. Ini
 * didokumentasikan sebagai future work yang jelas, bukan diklaim selesai.
 */

export class AnalyzerRegistry {
  constructor() {
    /** @type {Array<{name: string, analyzer: import('../analyzers/IAnalyzer.js').IAnalyzer, inputKey: string}>} */
    this._entries = [];
  }

  /**
   * Mendaftarkan satu analyzer ke registry.
   *
   * @param {string} name - identifier unik, mis. "csp", "script", "cors"
   * @param {import('../analyzers/IAnalyzer.js').IAnalyzer} analyzer - instance yang mengimplementasikan IAnalyzer
   * @param {string} inputKey - key untuk mengambil input yang sesuai dari
   *   input map yang disiapkan AnalysisOrchestrator (mis. "csp" -> cspHeader,
   *   "script" -> scriptEntries). Memisahkan "siapa butuh input apa" dari
   *   logic pengumpulan input itu sendiri (Separation of Concern).
   * @returns {void}
   * @throws {Error} jika `name` sudah terdaftar sebelumnya (mencegah override tidak sengaja)
   */
  register(name, analyzer, inputKey) {
    if (this._entries.some((e) => e.name === name)) {
      throw new Error(`AnalyzerRegistry: analyzer dengan nama "${name}" sudah terdaftar.`);
    }
    this._entries.push({ name, analyzer, inputKey });
  }

  /**
   * Mengambil seluruh analyzer yang terdaftar, dalam urutan pendaftaran.
   * @returns {Array<{name: string, analyzer: object, inputKey: string}>}
   */
  getAll() {
    return [...this._entries];
  }

  /**
   * Mengambil satu analyzer berdasarkan nama, atau undefined jika tidak ada.
   * @param {string} name
   * @returns {import('../analyzers/IAnalyzer.js').IAnalyzer|undefined}
   */
  get(name) {
    return this._entries.find((e) => e.name === name)?.analyzer;
  }

  /**
   * Jumlah analyzer yang terdaftar. Berguna untuk logging/debugging dan
   * untuk unit test yang memverifikasi registrasi berhasil.
   * @returns {number}
   */
  count() {
    return this._entries.length;
  }
}
