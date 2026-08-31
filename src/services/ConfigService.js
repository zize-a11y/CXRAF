/**
 * ConfigService.js
 *
 * Fungsi: Infrastructure layer service yang memuat file konfigurasi JSON
 * (csp-rules.json, sink-patterns.json, weights.json) dari dalam bundle
 * extension menggunakan fetch() + chrome.runtime.getURL(). Dipisah dari
 * analyzer agar rule engine bisa diganti tanpa mengubah kode logic
 * (lihat justifikasi di Tahap 2.5).
 *
 * Alur kerja: dipanggil sekali oleh background/index.js saat service
 * worker start, hasilnya di-cache di memori (service worker sendiri
 * bisa restart sewaktu-waktu oleh Chrome, jadi loadAll() dipanggil ulang
 * tiap kali service worker aktif — biaya baca file lokal sangat kecil).
 */

export class ConfigService {
  /**
   * Memuat satu file JSON dari dalam bundle extension.
   *
   * @param {string} relativePath - path relatif dari root extension, mis. "packages/xss-risk-core/config/csp-rules.json"
   * @returns {Promise<object>}
   */
  async _loadJSON(relativePath) {
    const url = chrome.runtime.getURL(relativePath);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`ConfigService: gagal memuat ${relativePath} (status ${response.status})`);
    }
    return response.json();
  }

  /** @returns {Promise<object>} isi csp-rules.json */
  async loadCSPRules() {
    return this._loadJSON('packages/xss-risk-core/config/csp-rules.json');
  }

  /** @returns {Promise<object>} isi sink-patterns.json */
  async loadSinkPatterns() {
    return this._loadJSON('packages/xss-risk-core/config/sink-patterns.json');
  }

  /** @returns {Promise<object>} isi weights.json */
  async loadWeights() {
    return this._loadJSON('packages/xss-risk-core/config/weights.json');
  }

  /**
   * Memuat ketiga file konfigurasi sekaligus secara paralel.
   *
   * @returns {Promise<{cspRules: object, sinkPatterns: object, weights: object}>}
   */
  async loadAll() {
    const [cspRules, sinkPatterns, weights] = await Promise.all([
      this.loadCSPRules(),
      this.loadSinkPatterns(),
      this.loadWeights(),
    ]);
    return { cspRules, sinkPatterns, weights };
  }
}
