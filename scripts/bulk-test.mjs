/**
 * bulk-test.mjs
 *
 * Fungsi: Menjalankan analisis CSP + script berbahaya terhadap SEKUMPULAN
 * URL sekaligus lewat HTTP fetch murni — TANPA Chrome, TANPA klik manual.
 * Ini bukan simulasi terpisah; script ini meng-import LANGSUNG dari
 * package `xss-risk-core` (packages/xss-risk-core) — package INTI YANG
 * SAMA PERSIS dipakai oleh browser extension (lihat src/background/index.js).
 *
 * Ini adalah BUKTI KONKRET klaim "framework, bukan sekadar extension"
 * (Temuan #5 dari review arsitektur): xss-risk-core sekarang punya DUA
 * konsumen independen — extension (via relative import, karena browser
 * tidak resolve bare specifier tanpa bundler) dan CLI ini (via nama
 * package 'xss-risk-core', resolusi npm workspace standar) — tanpa
 * duplikasi kode logic analisis sama sekali.
 *
 * KETERBATASAN YANG PERLU DICATAT DI BAB III/IV:
 *   - Tidak menjalankan JavaScript halaman (jsdom parse HTML statis saja),
 *     sehingga script yang di-inject secara dinamis oleh JS lain tidak
 *     akan ikut terdeteksi (sama seperti keterbatasan analisis statis
 *     yang sudah didokumentasikan di requirements.md §4).
 *   - Beberapa situs bisa memblokir request tanpa header browser lengkap
 *     (User-Agent, dll) — script ini sudah set User-Agent standar untuk
 *     meminimalkan itu, tapi tidak 100% menjamin semua situs bisa diakses.
 *   - Cocok untuk pengujian cepat/bulk; untuk laporan detail per-situs
 *     (screenshot popup, fitur riwayat, ekspor JSON per-situs), tetap
 *     pakai extension langsung di Chrome.
 *
 * CARA PAKAI:
 *   1. Jalankan `npm install` di root (sekali saja, agar workspace ter-link).
 *   2. Edit file scripts/urls.txt — satu URL per baris.
 *   3. Jalankan: npm run scan (atau node scripts/bulk-test.mjs)
 *   4. Hasil tercetak di terminal DAN tersimpan ke scripts/bulk-test-results.csv
 *      (siap di-copy-paste ke template-pengujian-skripsi.xlsx).
 */

import { readFileSync, writeFileSync } from 'fs';
import { CSPAnalyzer, ScriptAnalyzer, SourceSinkTracer, ScoreEngine, RiskCalculator } from 'xss-risk-core';
import { fetchPageInputs, loadUrls } from './lib/fetchPageInputs.mjs';

const cspRules = JSON.parse(readFileSync(new URL('../packages/xss-risk-core/config/csp-rules.json', import.meta.url)));
const sinkPatterns = JSON.parse(readFileSync(new URL('../packages/xss-risk-core/config/sink-patterns.json', import.meta.url)));
const weights = JSON.parse(readFileSync(new URL('../packages/xss-risk-core/config/weights.json', import.meta.url)));

const scoreEngine = new ScoreEngine(weights);
const cspAnalyzer = new CSPAnalyzer(cspRules, scoreEngine);
const tracer = new SourceSinkTracer(sinkPatterns);
const scriptAnalyzer = new ScriptAnalyzer(sinkPatterns, tracer);
const riskCalculator = new RiskCalculator(scoreEngine, weights);

/**
 * Menganalisis satu URL: fetch input mentah via fetchPageInputs, lalu
 * jalankan seluruh domain layer xss-risk-core, kembalikan FinalReport
 * (bentuknya identik dengan yang dipakai popup).
 *
 * @param {string} url
 * @returns {Promise<{url: string, ok: boolean, report?: object, error?: string}>}
 */
async function analyzeUrl(url) {
  const input = await fetchPageInputs(url, sinkPatterns.eventHandlerAttributes);
  if (!input.ok) return input;

  const cspResult = cspAnalyzer.analyze(input.cspHeader);
  const scriptResult = scriptAnalyzer.analyze(input.scriptEntries);
  const report = riskCalculator.calculate(cspResult, scriptResult, input.domain);

  return { url, ok: true, report };
}

async function main() {
  const urls = loadUrls();
  console.log(`Menganalisis ${urls.length} situs...\n`);

  const results = [];
  for (const url of urls) {
    process.stdout.write(`  ${url} ... `);
    const result = await analyzeUrl(url);
    results.push(result);
    console.log(result.ok ? `OK (skor ${result.report.finalScore}, ${result.report.riskLevel})` : `GAGAL (${result.error})`);
  }

  console.log('\n=== RINGKASAN ===');
  console.table(
    results.map((r) => ({
      URL: r.url,
      'Skor CSP': r.ok ? r.report.cspScore : '-',
      'Skor Akhir': r.ok ? r.report.finalScore : '-',
      'Risk Level': r.ok ? r.report.riskLevel : 'ERROR',
      Warning: r.ok ? r.report.cspWarnings.length : '-',
      'Script Berisiko': r.ok ? r.report.scriptFindings.length : '-',
    }))
  );

  const csvHeader = 'No,Nama Situs,URL,Kategori,Tanggal Uji,Skor CSP,Skor Akhir,Level Risiko,Jumlah Warning,Jumlah Script Berisiko,Truncated,Catatan\n';
  const csvRows = results.map((r, i) => {
    if (!r.ok) return `${i + 1},,${r.url},,${new Date().toISOString().slice(0, 10)},,,ERROR,,,,"${r.error.replace(/"/g, "'")}"`;
    const rep = r.report;
    return [
      i + 1,
      new URL(r.url).hostname,
      r.url,
      '',
      new Date().toISOString().slice(0, 10),
      rep.cspScore,
      rep.finalScore,
      rep.riskLevel,
      rep.cspWarnings.length,
      rep.scriptFindings.length,
      rep.truncated ? 'Ya' : 'Tidak',
      '',
    ].join(',');
  });

  const csvPath = new URL('./bulk-test-results.csv', import.meta.url);
  writeFileSync(csvPath, csvHeader + csvRows.join('\n') + '\n');
  console.log(`\nHasil tersimpan ke scripts/bulk-test-results.csv (${results.length} baris, siap copy-paste ke template Excel)`);
}

main();
