/**
 * AnalysisOrchestrator.js
 *
 * Fungsi: Application layer class yang mengoordinasikan SELURUH alur
 * use case "analisis tab aktif" — mulai dari mengambil header CSP,
 * meminta scan DOM ke content script, menjalankan analyzer domain layer,
 * menghitung risiko, hingga menyimpan hasil. Ini adalah satu-satunya
 * "pintu masuk" use case dari luar (dipanggil oleh MessageRouter).
 *
 * PENTING (Dependency Injection): seluruh dependency diterima lewat
 * constructor, TIDAK dibuat sendiri dengan `new` di dalam class ini.
 * Ini yang membuat class ini bisa diuji dengan mock service tanpa Chrome
 * environment nyata (lihat tests/integration/AnalysisOrchestrator.test.js).
 *
 * PERBAIKAN TEMUAN #5 (review arsitektur): sebelumnya class ini menerima
 * `cspAnalyzer` dan `scriptAnalyzer` sebagai parameter BERNAMA terpisah,
 * artinya menambah analyzer ketiga (mis. CORSAnalyzer di masa depan)
 * MENGHARUSKAN mengubah signature constructor ini. Sekarang class ini
 * menerima satu `AnalyzerRegistry` generik dan melakukan iterasi atas
 * seluruh analyzer yang terdaftar — menambah analyzer baru HANYA perlu
 * memanggil `registry.register(...)` di composition root (background/index.js),
 * TANPA menyentuh file ini sama sekali. Ini extension point sungguhan,
 * bukan sekadar interface IAnalyzer yang ada tapi tidak benar-benar
 * dipakai untuk ekstensi (lihat AnalyzerRegistry.js untuk detail).
 *
 * KETERBATASAN YANG DICATAT SECARA JUJUR: RiskCalculator.calculate() saat
 * ini masih menerima dua hasil (CSPResult, ScriptResult) secara eksplisit
 * — bukan array generik. Jadi analyzer ketiga BISA dijalankan lewat
 * registry ini tanpa mengubah orchestrator, tapi skor akhirnya belum
 * otomatis ikut mempengaruhi RiskCalculator kecuali RiskCalculator juga
 * digeneralisasi (didokumentasikan sebagai future work, bukan diklaim selesai).
 */

export class AnalysisOrchestrator {
  /**
   * @param {object} deps
   * @param {import('../services/CSPHeaderService.js').CSPHeaderService} deps.cspHeaderService
   * @param {(tabId: number) => Promise<{scriptEntries: object[], metaCSP: string|null}>} deps.requestDomScan -
   *   fungsi untuk meminta scan DOM ke content script (dibungkus MessageRouter,
   *   supaya Orchestrator tidak perlu tahu detail chrome.tabs.sendMessage)
   * @param {import('xss-risk-core').AnalyzerRegistry} deps.registry - registry analyzer (Temuan #5)
   * @param {import('xss-risk-core').RiskCalculator} deps.riskCalculator
   * @param {import('../services/StorageService.js').StorageService} deps.storageService
   */
  constructor({
    cspHeaderService,
    requestDomScan,
    registry,
    riskCalculator,
    storageService,
  }) {
    this.cspHeaderService = cspHeaderService;
    this.requestDomScan = requestDomScan;
    this.registry = registry;
    this.riskCalculator = riskCalculator;
    this.storageService = storageService;
  }

  /**
   * Mengumpulkan seluruh input mentah yang dibutuhkan analisis: header CSP
   * (dari cache CSPHeaderService, fallback ke meta tag hasil scan DOM jika
   * header tidak ada) dan daftar script/event-handler dari DOM.
   *
   * @param {number} tabId
   * @returns {Promise<{cspHeader: string|null, scriptEntries: object[]}>}
   */
  async gatherInputs(tabId) {
    const headerFromHttp = this.cspHeaderService.getHeaderForTab(tabId);
    const domScan = await this.requestDomScan(tabId);

    // Fallback: jika header HTTP tidak ada, pakai meta tag CSP (batasan scope Tahap 1 #2)
    const cspHeader = headerFromHttp ?? domScan.metaCSP;

    return { cspHeader, scriptEntries: domScan.scriptEntries };
  }

  /**
   * Entry point utama use case ini. Dipanggil oleh MessageRouter saat
   * menerima pesan REQUEST_ANALYSIS dari popup.
   *
   * Menjalankan SELURUH analyzer yang terdaftar di registry secara generik
   * (implementasi Temuan #5) — tidak ada lagi pemanggilan
   * `this.cspAnalyzer.analyze()` / `this.scriptAnalyzer.analyze()` yang
   * di-hardcode satu-satu.
   *
   * @param {number} tabId
   * @param {string} domain - hostname tab aktif, dipakai sebagai key riwayat
   * @returns {Promise<import('xss-risk-core').FinalReport>}
   */
  async runAnalysis(tabId, domain) {
    const { cspHeader, scriptEntries } = await this.gatherInputs(tabId);

    // Input map: key harus cocok dengan `inputKey` yang dipakai saat
    // registry.register() dipanggil di composition root.
    const inputMap = { csp: cspHeader, script: scriptEntries };

    /** @type {Record<string, object>} hasil per-nama analyzer, mis. { csp: CSPResult, script: ScriptResult } */
    const results = {};
    for (const { name, analyzer, inputKey } of this.registry.getAll()) {
      results[name] = analyzer.analyze(inputMap[inputKey]);
    }

    // RiskCalculator saat ini masih spesifik menerima (csp, script) — lihat
    // catatan keterbatasan di komentar file ini. Analyzer lain yang mungkin
    // terdaftar di registry di masa depan sudah ikut TERJALANKAN di atas
    // (results akan berisi hasilnya), tinggal RiskCalculator perlu
    // digeneralisasi untuk benar-benar memakainya dalam skor akhir.
    const finalReport = this.riskCalculator.calculate(results.csp, results.script, domain);

    await this.storageService.save(domain, finalReport);

    return finalReport;
  }
}
