/**
 * fetchPageInputs.mjs
 *
 * Fungsi: Logic BERSAMA untuk fetch HTTP + parsing HTML sebuah URL,
 * dipakai oleh tiga script berbeda (bulk-test.mjs, sensitivity-analysis.mjs,
 * compare-baseline.mjs) — diekstrak ke satu tempat supaya tidak triple
 * duplikasi (konsisten dengan kritik DRY yang sama diterapkan untuk
 * memperbaiki Temuan #6 di review arsitektur, bukan standar ganda).
 *
 * TIDAK mengimpor `xss-risk-core` sama sekali — modul ini murni infra
 * "ambil data mentah dari internet", terpisah dari logic analisis.
 */

import { readFileSync, existsSync } from 'fs';
import { JSDOM } from 'jsdom';

/**
 * DUPLIKASI DISENGAJA dari DOMScannerService — logic ekstraksi identik,
 * tapi sumber DOM-nya dari jsdom (parsing HTML hasil fetch), bukan
 * `document` browser tab aktif. Lihat penjelasan pola sama di
 * src/content/index.js soal kenapa duplikasi ini disengaja.
 *
 * @param {Document} document - dokumen hasil parsing jsdom
 * @param {string[]} eventHandlerAttributes
 * @returns {{ scriptEntries: object[], metaCSP: string|null }}
 */
export function scanDocument(document, eventHandlerAttributes) {
  const scriptEntries = [];

  const scripts = document.querySelectorAll('script:not([src])');
  for (const el of scripts) {
    const code = el.textContent || '';
    if (code.trim().length > 0) scriptEntries.push({ type: 'inline-script', code });
  }

  const allElements = document.querySelectorAll('*');
  for (const el of allElements) {
    for (const attr of eventHandlerAttributes) {
      if (el.hasAttribute(attr)) {
        scriptEntries.push({
          type: 'event-handler',
          attribute: attr,
          code: el.getAttribute(attr) || '',
          tagName: el.tagName.toLowerCase(),
        });
      }
    }
  }

  const meta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
  const metaCSP = meta ? meta.getAttribute('content') : null;

  return { scriptEntries, metaCSP };
}

/**
 * Fetch satu URL dan kembalikan input mentah (header CSP, script entries,
 * meta CSP fallback) TANPA menjalankan analyzer apapun — pemisahan ini
 * memungkinkan konsumen berbeda (bulk-test, sensitivity-analysis,
 * compare-baseline) menjalankan analyzer yang berbeda-beda di atas input
 * mentah yang SAMA, tanpa fetch berulang ke jaringan.
 *
 * @param {string} url
 * @param {string[]} eventHandlerAttributes
 * @returns {Promise<{url: string, ok: boolean, domain?: string, cspHeader?: string|null, scriptEntries?: object[], error?: string}>}
 */
export async function fetchPageInputs(url, eventHandlerAttributes) {
  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CSP-XSS-Auditor-BulkTest/1.0)' },
      redirect: 'follow',
    });

    // PENTING: jika status bukan 2xx, ini KEMUNGKINAN BESAR bukan halaman
    // asli — bisa jadi halaman blokir dari firewall/proxy jaringan, WAF
    // situs target, atau error server. Menganalisis halaman semacam itu
    // akan menghasilkan skor PALSU, BUKAN cerminan konfigurasi situs
    // sungguhan (ditemukan secara empiris — lihat docs/optimization-report.md).
    if (!response.ok) {
      const bodyPreview = (await response.text()).slice(0, 150).replace(/\s+/g, ' ').trim();
      return {
        url,
        ok: false,
        error: `HTTP ${response.status} — kemungkinan diblokir firewall/proxy/WAF, bukan halaman asli. Cuplikan respons: "${bodyPreview}"`,
      };
    }

    const cspHeaderFromHttp = response.headers.get('content-security-policy');
    const html = await response.text();

    const dom = new JSDOM(html);
    const { scriptEntries, metaCSP } = scanDocument(dom.window.document, eventHandlerAttributes);

    const cspHeader = cspHeaderFromHttp ?? metaCSP;
    const domain = new URL(url).hostname;

    return { url, ok: true, domain, cspHeader, scriptEntries };
  } catch (error) {
    return { url, ok: false, error: error.message };
  }
}

/**
 * Memuat daftar URL dari scripts/urls.txt (satu URL per baris, baris
 * diawali # diabaikan sebagai komentar).
 *
 * @returns {string[]}
 */
export function loadUrls() {
  const path = new URL('../urls.txt', import.meta.url);
  if (!existsSync(path)) {
    console.error('File scripts/urls.txt tidak ditemukan. Buat file itu, satu URL per baris.');
    process.exit(1);
  }
  return readFileSync(path, 'utf-8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}
