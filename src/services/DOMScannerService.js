/**
 * DOMScannerService.js
 *
 * Fungsi: Infrastructure layer service yang berjalan DI DALAM context
 * content script (bukan background), sehingga punya akses langsung ke
 * `document` milik halaman yang sedang dibuka pengguna. Bertanggung jawab
 * mengekstrak:
 *   1. Kode inline <script> (tanpa atribut src)
 *   2. Atribut event handler inline (onclick, onerror, dll) beserta isinya
 *   3. Meta tag CSP (<meta http-equiv="Content-Security-Policy">) sebagai
 *      fallback jika header HTTP CSP tidak ditemukan (memenuhi batasan
 *      scope #2 di Tahap 1: CSP dianalisis dari header ATAU meta tag).
 *
 * PENTING: File ini SATU-SATUNYA yang boleh menyentuh `document`/DOM API
 * halaman secara langsung. Hasil scan-nya berupa plain object biasa
 * (ScriptEntry[]), dikirim ke background via message passing, BUKAN
 * dengan mengirim objek DOM asli (tidak bisa di-serialize lewat
 * chrome.runtime.sendMessage).
 *
 * Alur kerja: dipanggil oleh content/index.js saat menerima pesan
 * "SCAN_DOM" dari background (lihat MessageRouter).
 */

export class DOMScannerService {
  /**
   * @param {string[]} eventHandlerAttributes - daftar nama atribut event
   *   handler yang dianggap relevan (dari sink-patterns.json), disuntikkan
   *   dari luar agar file ini tidak perlu tahu cara memuat config sendiri.
   */
  constructor(eventHandlerAttributes) {
    this.eventHandlerAttributes = eventHandlerAttributes;
  }

  /**
   * Entry point utama — menjalankan seluruh proses scan terhadap DOM
   * halaman aktif.
   *
   * @returns {{ scriptEntries: Array<object>, metaCSP: string|null }}
   */
  scan() {
    return {
      scriptEntries: [
        ...this._extractInlineScripts(),
        ...this._extractEventHandlerAttributes(),
      ],
      metaCSP: this._extractMetaCSP(),
    };
  }

  /**
   * Mengekstrak seluruh <script> tanpa atribut src (inline script murni).
   * Script eksternal (dengan src) SENGAJA tidak diperiksa isinya karena
   * di luar scope analisis statis kode halaman (batasan Tahap 1).
   *
   * @returns {Array<{type: string, code: string}>}
   */
  _extractInlineScripts() {
    const scripts = document.querySelectorAll('script:not([src])');
    return Array.from(scripts)
      .map((el) => ({ type: 'inline-script', code: el.textContent || '' }))
      .filter((entry) => entry.code.trim().length > 0);
  }

  /**
   * Mengekstrak atribut event handler inline (onclick, onerror, dll) dari
   * SELURUH elemen di halaman. Dibatasi hanya atribut yang ada di daftar
   * eventHandlerAttributes agar tidak salah tangkap atribut biasa.
   *
   * @returns {Array<{type: string, attribute: string, code: string, tagName: string}>}
   */
  _extractEventHandlerAttributes() {
    const entries = [];
    const allElements = document.querySelectorAll('*');

    for (const el of allElements) {
      for (const attrName of this.eventHandlerAttributes) {
        if (el.hasAttribute(attrName)) {
          entries.push({
            type: 'event-handler',
            attribute: attrName,
            code: el.getAttribute(attrName) || '',
            tagName: el.tagName.toLowerCase(),
          });
        }
      }
    }
    return entries;
  }

  /**
   * Mengekstrak isi meta tag CSP jika ada, sebagai fallback ketika header
   * HTTP CSP tidak ditemukan (mis. situs statis tanpa kontrol server-side header).
   *
   * @returns {string|null}
   */
  _extractMetaCSP() {
    const meta = document.querySelector(
      'meta[http-equiv="Content-Security-Policy" i]'
    );
    return meta ? meta.getAttribute('content') : null;
  }
}
