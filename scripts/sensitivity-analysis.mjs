/**
 * sensitivity-analysis.mjs
 *
 * Fungsi: Menjawab Temuan #3 dari review arsitektur — bobot
 * `cspScoreRatio`/`scriptSafetyRatio` di weights.json (default 0.6/0.4)
 * tidak punya justifikasi empiris. Script ini menjalankan SWEEP nilai
 * cspScoreRatio di seluruh rentang wajar (0.3 s.d. 0.8) terhadap dataset
 * situs yang sama, dan mengukur SEBERAPA SERING klasifikasi riskLevel
 * berubah akibat pergeseran bobot — argumen "robustness" atau bukti
 * bahwa pemilihan 0.6 memang perlu dipertimbangkan ulang.
 *
 * DESAIN EFISIEN: setiap URL hanya di-fetch SATU KALI (network mahal),
 * karena CSPResult dan ScriptResult TIDAK bergantung pada
 * cspScoreRatio/scriptSafetyRatio (nilai itu hanya dipakai saat
 * RiskCalculator MENGGABUNGKAN kedua hasil itu). RiskCalculator dibangun
 * ulang untuk tiap titik sweep dan dipanggil berkali-kali di atas hasil
 * analisis yang SAMA — murah secara komputasi, tidak perlu fetch ulang.
 *
 * CARA PAKAI:
 *   node scripts/sensitivity-analysis.mjs
 *   (memakai daftar URL yang sama dengan scripts/urls.txt)
 *
 * OUTPUT: tabel matriks (baris=situs, kolom=nilai cspScoreRatio),
 * ringkasan jumlah situs yang berubah klasifikasi, dan file CSV
 * scripts/sensitivity-results.csv untuk lampiran BAB IV/BAB III.
 */

import { readFileSync, writeFileSync } from "fs";
import {
  CSPAnalyzer,
  ScriptAnalyzer,
  SourceSinkTracer,
  ScoreEngine,
  RiskCalculator,
} from "xss-risk-core";
import { fetchPageInputs, loadUrls } from "./lib/fetchPageInputs.mjs";

const cspRules = JSON.parse(
  readFileSync(
    new URL("../packages/xss-risk-core/config/csp-rules.json", import.meta.url),
  ),
);
const sinkPatterns = JSON.parse(
  readFileSync(
    new URL(
      "../packages/xss-risk-core/config/sink-patterns.json",
      import.meta.url,
    ),
  ),
);
const baseWeights = JSON.parse(
  readFileSync(
    new URL("../packages/xss-risk-core/config/weights.json", import.meta.url),
  ),
);

const scoreEngine = new ScoreEngine(baseWeights);
const cspAnalyzer = new CSPAnalyzer(cspRules, scoreEngine);
const tracer = new SourceSinkTracer(sinkPatterns);
const scriptAnalyzer = new ScriptAnalyzer(sinkPatterns, tracer);

// Rentang sweep cspScoreRatio. scriptSafetyRatio = 1 - cspScoreRatio agar
// totalnya selalu 1 (konsisten dengan desain asli finalScoreWeights).
const SWEEP_VALUES = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8];
const DEFAULT_VALUE = baseWeights.likelihoodWeights.cspWeaknessRatio;

/**
 * Membuat RiskCalculator baru dengan cspScoreRatio tertentu, seluruh
 * field weights.json lainnya (penalti, threshold, dsb) tetap sama.
 * @param {number} cspScoreRatio
 * @returns {RiskCalculator}
 */
function buildRiskCalculatorWithRatio(cspWeaknessRatio) {
  const weights = JSON.parse(JSON.stringify(baseWeights));

  weights.likelihoodWeights.cspWeaknessRatio = cspWeaknessRatio;
  weights.likelihoodWeights.confidenceRatio = 1 - cspWeaknessRatio;

  return new RiskCalculator(scoreEngine, weights);
}

async function main() {
  const urls = loadUrls();
  console.log(
    `Mengambil input mentah untuk ${urls.length} situs (fetch SATU KALI per situs)...\n`,
  );

  /** @type {Array<{url: string, domain: string, cspResult: object, scriptResult: object}>} */
  const analyzedInputs = [];
  const fetchErrors = [];

  for (const url of urls) {
    process.stdout.write(`  ${url} ... `);
    const input = await fetchPageInputs(
      url,
      sinkPatterns.eventHandlerAttributes,
    );
    if (!input.ok) {
      console.log(`GAGAL (${input.error.slice(0, 60)}...)`);
      fetchErrors.push({ url, error: input.error });
      continue;
    }
    const cspResult = cspAnalyzer.analyze(input.cspHeader);
    const scriptResult = scriptAnalyzer.analyze(input.scriptEntries);
    analyzedInputs.push({ url, domain: input.domain, cspResult, scriptResult });
    console.log("OK");
  }

  if (analyzedInputs.length === 0) {
    console.error(
      "\nTidak ada situs yang berhasil diambil. Sensitivity analysis dibatalkan.",
    );
    process.exit(1);
  }

  console.log(
    `\n${analyzedInputs.length} situs berhasil diambil, ${fetchErrors.length} gagal.`,
  );
  console.log(
    `\nMenjalankan sweep cspScoreRatio: ${SWEEP_VALUES.join(", ")} (default project: ${DEFAULT_VALUE})\n`,
  );

  // Matriks hasil: untuk setiap situs, riskLevel pada setiap titik sweep
  const matrix = analyzedInputs.map(
    ({ url, domain, cspResult, scriptResult }) => {
      const row = { url, domain };
      for (const ratio of SWEEP_VALUES) {
        const calc = buildRiskCalculatorWithRatio(ratio);
        const report = calc.calculate(cspResult, scriptResult, domain);
        row[`ratio_${ratio}`] = report.riskLevel;
        row[`score_${ratio}`] = report.finalScore;
      }
      return row;
    },
  );

  console.log("=== MATRIKS RISK LEVEL PER NILAI cspScoreRatio ===");
  console.table(
    matrix.map((row) => {
      const display = { Domain: row.domain };
      for (const ratio of SWEEP_VALUES) {
        display[`${ratio}${ratio === DEFAULT_VALUE ? "*" : ""}`] =
          row[`ratio_${ratio}`];
      }
      return display;
    }),
  );
  console.log("(* = nilai default project saat ini)\n");

  // Hitung berapa banyak situs yang KLASIFIKASINYA BERUBAH di sepanjang sweep
  const changedCount = matrix.filter((row) => {
    const levels = new Set(SWEEP_VALUES.map((r) => row[`ratio_${r}`]));
    return levels.size > 1; // lebih dari satu riskLevel berbeda di rentang sweep = tidak stabil
  }).length;

  const stablePercentage = Math.round(
    ((matrix.length - changedCount) / matrix.length) * 100,
  );

  console.log("=== RINGKASAN SENSITIVITAS ===");
  console.log(`Total situs dianalisis     : ${matrix.length}`);
  console.log(
    `Klasifikasi STABIL (tidak berubah di seluruh rentang sweep 0.3-0.8): ${matrix.length - changedCount} situs (${stablePercentage}%)`,
  );
  console.log(
    `Klasifikasi BERUBAH di suatu titik sweep: ${changedCount} situs`,
  );
  console.log("");
  console.log(
    stablePercentage >= 80
      ? "INTERPRETASI: mayoritas situs stabil terhadap perubahan bobot -> ada dasar argumen robustness untuk BAB III,"
      : "INTERPRETASI: banyak situs berubah klasifikasi tergantung bobot -> bobot 0.6/0.4 BUKAN pilihan yang robust,",
  );
  console.log(
    "  tapi ini TETAP BUKAN pengganti expert elicitation (AHP/Delphi) - hanya bukti tambahan pendukung diskusi BAB III.",
  );

  // Simpan CSV lengkap
  const header = [
    "Domain",
    ...SWEEP_VALUES.map((r) => `RiskLevel@${r}`),
    ...SWEEP_VALUES.map((r) => `Score@${r}`),
    "Stabil?",
  ].join(",");
  const rows = matrix.map((row) => {
    const levels = new Set(SWEEP_VALUES.map((r) => row[`ratio_${r}`]));
    const stabil = levels.size === 1 ? "Ya" : "Tidak";
    return [
      row.domain,
      ...SWEEP_VALUES.map((r) => row[`ratio_${r}`]),
      ...SWEEP_VALUES.map((r) => row[`score_${r}`]),
      stabil,
    ].join(",");
  });

  const csvPath = new URL("./sensitivity-results.csv", import.meta.url);
  writeFileSync(csvPath, header + "\n" + rows.join("\n") + "\n");
  console.log(`\nHasil lengkap tersimpan ke scripts/sensitivity-results.csv`);
}

main();
