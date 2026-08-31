/**
 * StorageService.js
 *
 * Fungsi: Infrastructure layer service yang membungkus chrome.storage.local
 * (bukan localStorage — tidak tersedia di service worker MV3). Menyediakan
 * CRUD riwayat analisis per domain (FR-09) dan retensi otomatis agar
 * storage tidak membengkak (NFR-07).
 *
 * Bentuk data yang disimpan mengikuti skema di Tahap 8 (AnalysisHistory).
 *
 * Alur kerja: dipanggil oleh AnalysisOrchestrator setelah RiskCalculator
 * menghasilkan FinalReport, dan oleh PopupController saat menampilkan
 * riwayat (UC-08).
 */

const DEFAULT_MAX_HISTORY_PER_DOMAIN = 10;

export class StorageService {
  /**
   * Menyimpan satu FinalReport ke riwayat domain terkait. Entri lama akan
   * dipangkas jika melebihi batas retensi (default 10 entri terakhir).
   *
   * @param {string} domain
   * @param {import('../models/FinalReport.js').FinalReport} report
   * @param {number} [maxHistory]
   * @returns {Promise<void>}
   */
  async save(domain, report, maxHistory = DEFAULT_MAX_HISTORY_PER_DOMAIN) {
    const key = `history:${domain}`;
    const existing = await this._getRaw(key);
    const entries = existing?.entries ?? [];

    entries.unshift({
      id: crypto.randomUUID(),
      timestamp: report.timestamp,
      cspScore: report.cspScore,
      finalScore: report.finalScore,
      riskLevel: report.riskLevel,
      findingsCount: report.scriptFindings.length,
      warningsCount: report.cspWarnings.length,
      report,
    });

    const trimmed = entries.slice(0, maxHistory);
    await chrome.storage.local.set({ [key]: { domain, entries: trimmed } });
  }

  /**
   * Mengambil seluruh riwayat analisis untuk suatu domain.
   *
   * @param {string} domain
   * @returns {Promise<import('../models/FinalReport.js').FinalReport[]>}
   */
  async getHistory(domain) {
    const data = await this._getRaw(`history:${domain}`);
    return data?.entries?.map((e) => e.report) ?? [];
  }

  /**
   * Menghapus seluruh riwayat analisis untuk suatu domain.
   *
   * @param {string} domain
   * @returns {Promise<void>}
   */
  async clear(domain) {
    await chrome.storage.local.remove(`history:${domain}`);
  }

  /**
   * Menyimpan preferensi pengguna (tema, auto-scan, dll — FR-11).
   *
   * @param {object} preferences
   * @returns {Promise<void>}
   */
  async savePreferences(preferences) {
    await chrome.storage.local.set({ preferences });
  }

  /**
   * Mengambil preferensi pengguna, dengan default jika belum pernah diset.
   *
   * @returns {Promise<{theme: string, autoScanEnabled: boolean, maxHistoryPerDomain: number}>}
   */
  async getPreferences() {
    const data = await this._getRaw('preferences');
    return data ?? { theme: 'dark', autoScanEnabled: false, maxHistoryPerDomain: DEFAULT_MAX_HISTORY_PER_DOMAIN };
  }

  /**
   * Helper internal untuk membaca satu key dari chrome.storage.local.
   *
   * @param {string} key
   * @returns {Promise<any|null>}
   */
  async _getRaw(key) {
    const result = await chrome.storage.local.get(key);
    return result[key] ?? null;
  }
}
