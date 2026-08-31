/**
 * CSPHeaderService.js
 *
 * Fungsi: Infrastructure layer service yang menangkap header
 * Content-Security-Policy dari response HTTP tab aktif menggunakan
 * chrome.webRequest.onHeadersReceived (non-blocking observer — TIDAK
 * memerlukan permission "webRequestBlocking" yang sudah dihapus di MV3).
 *
 * Alur kerja:
 *   1. listenHeaders() dipanggil sekali saat service worker start, mendaftarkan
 *      listener untuk request bertipe "main_frame" (navigasi halaman utama,
 *      bukan sub-resource seperti gambar/script agar tidak salah tangkap).
 *   2. Setiap kali header response diterima, header CSP (case-insensitive,
 *      karena browser tidak menjamin casing "Content-Security-Policy")
 *      diekstrak dan disimpan ke headerCache dengan key tabId.
 *   3. getHeaderForTab() dipanggil oleh AnalysisOrchestrator saat popup
 *      dibuka — mengambil dari cache, BUKAN fetch ulang (penting untuk
 *      performa, sesuai NFR-01).
 *   4. Cache dibersihkan saat tab ditutup agar tidak membengkak (NFR-07).
 *
 * PENTING: Ini adalah satu-satunya file yang boleh menyentuh chrome.webRequest
 * API secara langsung — bagian lain sistem berinteraksi lewat method publik
 * di class ini saja (Dependency Inversion).
 */

export class CSPHeaderService {
  constructor() {
    /** @type {Map<number, string|null>} tabId -> header CSP mentah (atau null jika tidak ada) */
    this.headerCache = new Map();
  }

  /**
   * Mendaftarkan listener webRequest. Dipanggil sekali dari background/index.js
   * saat service worker pertama kali aktif.
   *
   * @returns {void}
   */
  listenHeaders() {
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => this._onHeadersReceived(details),
      { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] },
      ['responseHeaders']
    );

    // Bersihkan cache saat tab ditutup agar chrome.storage/memory tidak membengkak.
    chrome.tabs.onRemoved.addListener((tabId) => {
      this.headerCache.delete(tabId);
    });
  }

  /**
   * Handler internal yang dipanggil setiap kali response header diterima
   * untuk main_frame request. Mengekstrak header CSP dan menyimpannya ke cache.
   *
   * @param {chrome.webRequest.WebResponseHeadersDetails} details
   * @returns {void}
   */
  _onHeadersReceived(details) {
    const headers = details.responseHeaders || [];
    const cspHeader = headers.find(
      (h) => h.name.toLowerCase() === 'content-security-policy'
    );
    this.headerCache.set(details.tabId, cspHeader ? cspHeader.value : null);
  }

  /**
   * Mengambil header CSP untuk tab tertentu dari cache (bukan fetch ulang).
   *
   * @param {number} tabId
   * @returns {string|null} header CSP mentah, atau null jika tidak ditemukan/belum tertangkap
   */
  getHeaderForTab(tabId) {
    return this.headerCache.get(tabId) ?? null;
  }
}
