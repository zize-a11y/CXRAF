/**
 * compare-baseline.mjs
 *
 * Fungsi: Menjawab Temuan #8 dari review arsitektur — argumen novelty
 * penelitian ini TIDAK PERNAH dibandingkan langsung dengan tools sejenis
 * yang sudah ada. Script ini menjalankan tiga sistem terhadap situs yang
 * SAMA dan menampilkan hasilnya berdampingan:
 *
 *   1. xss-risk-core (sistem penelitian ini)         - skor CSP + script XSS
 *   2. csp_evaluator (library RESMI Google, npm)      - skor CSP saja
 *   3. MDN HTTP Observatory (API resmi mozilla/MDN)   - skor header keamanan umum
 *
 * PENTING SOAL STATUS VERIFIKASI:
 *   - Perbandingan dengan csp_evaluator SUDAH DIUJI LANGSUNG dari sandbox
 *     pengembangan ini (npm registry bisa diakses) — bekerja normal.
 *   - Perbandingan dengan MDN HTTP Observatory API BELUM BISA diuji dari
 *     sandbox ini (domain observatory-api.mdn.mozilla.net tidak masuk
 *     allowlist jaringan sandbox). Kode ditulis mengikuti dokumentasi
 *     resmi API v2 (https://github.com/mdn/mdn-http-observatory), TAPI
 *     WAJIB diverifikasi ulang oleh peneliti di komputer dengan akses
 *     internet penuh sebelum datanya dipakai di BAB IV. Kegagalan pada
 *     bagian ini TIDAK menghentikan perbandingan csp_evaluator (dibungkus
 *     try/catch terpisah).
 *
 * CATATAN PENTING SOAL CAKUPAN: csp_evaluator dan MDN Observatory HANYA
 * mengevaluasi header/konfigurasi (CSP, security headers lain) — TIDAK
 * ADA satupun dari keduanya yang melakukan analisis script/source-sink
 * seperti xss-risk-core. Ini justru argumen novelty utama penelitian ini:
 * kombinasi analisis CSP + script + confidence score dalam satu sistem
 * belum ada pada tools pembanding.
 *
 * CARA PAKAI: node scripts/compare-baseline.mjs
 * OUTPUT: tabel perbandingan + scripts/comparison-results.csv
 */

import { readFileSync, writeFileSync } from 'fs';
import { CSPAnalyzer, ScoreEngine } from 'xss-risk-core';
import { fetchPageInputs, loadUrls } from './lib/fetchPageInputs.mjs';
import { CspParser } from 'csp_evaluator/dist/parser.js';
import { CspEvaluator } from 'csp_evaluator/dist/evaluator.js';
import { Version } from 'csp_evaluator/dist/csp.js';
import { Severity as GoogleSeverity } from 'csp_evaluator/dist/finding.js';

const cspRules = JSON.parse(readFileSync(new URL('../packages/xss-risk-core/config/csp-rules.json', import.meta.url)));
const sinkPatterns = JSON.parse(readFileSync(new URL('../packages/xss-risk-core/config/sink-patterns.json', import.meta.url)));
const weights = JSON.parse(readFileSync(new URL('../packages/xss-risk-core/config/weights.json', import.meta.url)));

const scoreEngine = new ScoreEngine(weights);
const cspAnalyzer = new CSPAnalyzer(cspRules, scoreEngine);

/**
 * Menjalankan Google CSP Evaluator terhadap satu header CSP.
 * @param {string|null} cspHeader
 * @returns {{ ok: boolean, highSeverityCount?: number, totalFindings?: number, error?: string }}
 */
function runGoogleCspEvaluator(cspHeader) {
  if (!cspHeader) return { ok: true, highSeverityCount: 0, totalFindings: 0, note: 'Tidak ada CSP untuk dievaluasi' };
  try {
    const parser = new CspParser(cspHeader);
    const evaluator = new CspEvaluator(parser.csp, Version.CSP3);
    const findings = evaluator.evaluate();
    const highSeverityCount = findings.filter(
      (f) => f.severity === GoogleSeverity.HIGH || f.severity === GoogleSeverity.HIGH_MAYBE
    ).length;
    return { ok: true, highSeverityCount, totalFindings: findings.length };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

/**
 * Menjalankan MDN HTTP Observatory API (BELUM TERUJI dari sandbox ini —
 * lihat catatan status verifikasi di komentar atas file). Dibungkus
 * try/catch terpisah supaya kegagalan di sini tidak menghentikan
 * perbandingan csp_evaluator untuk situs yang sama.
 *
 * @param {string} host - hostname tanpa protokol, mis. "github.com"
 * @returns {Promise<{ ok: boolean, grade?: string, score?: number, error?: string }>}
 */
async function runMdnObservatory(host) {
  try {
    const response = await fetch(`https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(host)}`, {
      method: 'POST',
    });
    if (!response.ok) {
      return { ok: false, error: `HTTP ${response.status}` };
    }
    const data = await response.json();
    if (data.error) return { ok: false, error: data.error };
    return { ok: true, grade: data.grade, score: data.score };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function main() {
  const urls = loadUrls();
  console.log(`Membandingkan ${urls.length} situs terhadap xss-risk-core vs csp_evaluator (Google) vs MDN HTTP Observatory...\n`);

  const results = [];

  for (const url of urls) {
    console.log(`--- ${url} ---`);
    const input = await fetchPageInputs(url, sinkPatterns.eventHandlerAttributes);

    if (!input.ok) {
      console.log(`  GAGAL fetch: ${input.error}\n`);
      results.push({ url, ok: false, error: input.error });
      continue;
    }

    const ourResult = cspAnalyzer.analyze(input.cspHeader);
    const googleResult = runGoogleCspEvaluator(input.cspHeader);
    const observatoryResult = await runMdnObservatory(input.domain);

    console.log(`  xss-risk-core   : skor CSP ${ourResult.score}/100, ${ourResult.warnings.length} warning`);
    console.log(
      googleResult.ok
        ? `  csp_evaluator   : ${googleResult.totalFindings} findings (${googleResult.highSeverityCount} severity HIGH)`
        : `  csp_evaluator   : GAGAL (${googleResult.error})`
    );
    console.log(
      observatoryResult.ok
        ? `  MDN Observatory : grade ${observatoryResult.grade}, skor ${observatoryResult.score}`
        : `  MDN Observatory : GAGAL/tidak terverifikasi (${observatoryResult.error})`
    );
    console.log('');

    results.push({
      url,
      ok: true,
      domain: input.domain,
      ourScore: ourResult.score,
      ourWarnings: ourResult.warnings.length,
      googleFindings: googleResult.ok ? googleResult.totalFindings : null,
      googleHighSeverity: googleResult.ok ? googleResult.highSeverityCount : null,
      observatoryGrade: observatoryResult.ok ? observatoryResult.grade : null,
      observatoryScore: observatoryResult.ok ? observatoryResult.score : null,
    });
  }

  console.log('=== RINGKASAN PERBANDINGAN ===');
  console.table(
    results.map((r) => ({
      Domain: r.ok ? r.domain : r.url,
      'Skor CSP (kami)': r.ok ? r.ourScore : '-',
      'Findings Google': r.ok ? (r.googleFindings ?? '-') : '-',
      'HIGH severity (Google)': r.ok ? (r.googleHighSeverity ?? '-') : '-',
      'Grade Observatory': r.ok ? (r.observatoryGrade ?? '-') : '-',
    }))
  );

  const csvHeader = 'Domain,SkorCSP_Kami,Warning_Kami,Findings_Google,HighSeverity_Google,Grade_Observatory,Skor_Observatory\n';
  const csvRows = results
    .filter((r) => r.ok)
    .map((r) => [r.domain, r.ourScore, r.ourWarnings, r.googleFindings ?? '', r.googleHighSeverity ?? '', r.observatoryGrade ?? '', r.observatoryScore ?? ''].join(','));

  const csvPath = new URL('./comparison-results.csv', import.meta.url);
  writeFileSync(csvPath, csvHeader + csvRows.join('\n') + '\n');
  console.log(`\nHasil tersimpan ke scripts/comparison-results.csv`);
  console.log('\nPENTING: verifikasi ulang kolom Observatory di komputer dengan akses internet penuh sebelum dipakai di BAB IV (lihat catatan status verifikasi di kepala file ini).');
}

main();
