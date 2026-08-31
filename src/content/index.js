/**
 * index.js (content script)
 *
 * Fungsi: Entry point yang berjalan di context halaman web aktif.
 * Mendengarkan pesan SCAN_DOM dari background, menjalankan logic scan DOM,
 * dan mengirim balik hasilnya.
 *
 * PENTING — KENAPA FILE INI TIDAK MEMAKAI import/export:
 * Content script yang dideklarasikan lewat `content_scripts` di manifest.json
 * berjalan sebagai CLASSIC SCRIPT, bukan ES module — berbeda dari
 * background.service_worker yang mendukung "type": "module". Manifest V3
 * TIDAK menyediakan opsi apapun untuk membuat content script berjalan
 * sebagai module. Karena itu:
 *
 *   1. Logic yang identik dengan DOMScannerService.js (src/services/) SENGAJA
 *      diduplikasi di sini sebagai class biasa (tanpa `export`), BUKAN
 *      di-import — karena `import` akan membuat seluruh content script
 *      gagal load dengan "Cannot use import statement outside a module".
 *   2. DOMScannerService.js di src/services/ tetap menjadi SATU-SATUNYA
 *      referensi yang diuji unit test (Jest, environment Node.js murni).
 *      Jika logic scan DOM diubah, WAJIB ubah kedua tempat ini secara
 *      bersamaan — ini trade-off yang disengaja untuk MVP tanpa bundler
 *      (Vite/esbuild akan menghilangkan duplikasi ini sepenuhnya).
 *   3. Nilai tipe pesan "SCAN_DOM" di-hardcode sebagai string literal
 *      (bukan import dari background/messageTypes.js) dengan alasan yang
 *      sama. Nilai ini HARUS selalu sama persis dengan MessageType.SCAN_DOM.
 */

/** @type {string[]|null} di-cache setelah pertama kali fetch, karena content
 *  script bisa dipanggil berkali-kali (SPA/navigasi) tanpa reload penuh. */
let cachedEventHandlerAttributes = null;

/**
 * Memuat daftar eventHandlerAttributes dari sink-patterns.json (dibundel
 * sebagai web_accessible_resources di manifest.json).
 * @returns {Promise<string[]>}
 */
async function loadEventHandlerAttributes() {
  if (cachedEventHandlerAttributes) return cachedEventHandlerAttributes;

  const url = chrome.runtime.getURL('packages/xss-risk-core/config/sink-patterns.json');
  const response = await fetch(url);
  const sinkPatterns = await response.json();
  cachedEventHandlerAttributes = sinkPatterns.eventHandlerAttributes;
  return cachedEventHandlerAttributes;
}

/**
 * DUPLIKASI DISENGAJA dari src/services/DOMScannerService.js — lihat
 * penjelasan lengkap di komentar atas file ini soal kenapa tidak di-import.
 */
class DOMScannerService {
  /** @param {string[]} eventHandlerAttributes */
  constructor(eventHandlerAttributes) {
    this.eventHandlerAttributes = eventHandlerAttributes;
  }

  /** @returns {{ scriptEntries: Array<object>, metaCSP: string|null }} */
  scan() {
    return {
      scriptEntries: [
        ...this._extractInlineScripts(),
        ...this._extractEventHandlerAttributes(),
      ],
      metaCSP: this._extractMetaCSP(),
    };
  }

  /** @returns {Array<{type: string, code: string}>} */
  _extractInlineScripts() {
    const scripts = document.querySelectorAll('script:not([src])');
    return Array.from(scripts)
      .map((el) => ({ type: 'inline-script', code: el.textContent || '' }))
      .filter((entry) => entry.code.trim().length > 0);
  }

  /** @returns {Array<{type: string, attribute: string, code: string, tagName: string}>} */
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

  /** @returns {string|null} */
  _extractMetaCSP() {
    const meta = document.querySelector(
      'meta[http-equiv="Content-Security-Policy" i]'
    );
    return meta ? meta.getAttribute('content') : null;
  }
}

// Nilai ini HARUS sama persis dengan MessageType.SCAN_DOM di
// src/background/messageTypes.js (lihat penjelasan duplikasi di atas).
const SCAN_DOM_MESSAGE_TYPE = 'SCAN_DOM';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== SCAN_DOM_MESSAGE_TYPE) return false;

  loadEventHandlerAttributes()
    .then((attrs) => {
      const scanner = new DOMScannerService(attrs);
      sendResponse(scanner.scan());
    })
    .catch((error) => {
      sendResponse({ scriptEntries: [], metaCSP: null, error: error.message });
    });

  return true; // response bersifat asynchronous
});
