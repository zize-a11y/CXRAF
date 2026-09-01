/**
 * sensitivity-analysis.mjs
 *
 * Fungsi:
 * Menguji sensitivitas Risk Level terhadap perubahan bobot Likelihood
 * pada model Likelihood × Impact.
 *
 * MODEL YANG DIUJI:
 *
 * Likelihood =
 *   (100 - CSP Score) × cspWeaknessRatio
 *   +
 *   (Average Confidence × 100) × confidenceRatio
 *
 * dengan:
 *
 *   cspWeaknessRatio + confidenceRatio = 1
 *
 * Impact:
 *   Ditentukan oleh severity tertinggi (worst-case) dari temuan script.
 *
 * Risk Level:
 *   Ditentukan oleh riskMatrix[Likelihood Category][Impact Category].
 *
 * CATATAN:
 * Script ini TIDAK mengubah weights.json.
 * Script hanya membuat salinan weights untuk setiap titik sensitivity
 * kemudian mengubah:
 *
 *   likelihoodWeights.cspWeaknessRatio
 *   likelihoodWeights.confidenceRatio
 *
 * DESAIN EFISIEN:
 * Setiap URL hanya di-fetch SATU KALI.
 * Hasil CSPAnalyzer dan ScriptAnalyzer kemudian digunakan berulang kali
 * untuk setiap titik sensitivity.
 *
 * CARA PAKAI:
 *   npm run sensitivity
 *
 * OUTPUT:
 *   - Matriks Risk Level berdasarkan cspWeaknessRatio
 *   - Ringkasan jumlah situs stabil/berubah
 *   - scripts/sensitivity-results.csv
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

/**
 * ============================================================
 * LOAD CONFIGURATION
 * ============================================================
 */

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

/**
 * ============================================================
 * INITIALIZE ANALYZERS
 * ============================================================
 */

const scoreEngine = new ScoreEngine(baseWeights);

const cspAnalyzer = new CSPAnalyzer(cspRules, scoreEngine);

const tracer = new SourceSinkTracer(sinkPatterns);

const scriptAnalyzer = new ScriptAnalyzer(sinkPatterns, tracer);

/**
 * ============================================================
 * SENSITIVITY PARAMETERS
 * ============================================================
 *
 * Yang diuji adalah cspWeaknessRatio.
 *
 * confidenceRatio otomatis dihitung:
 *
 * confidenceRatio = 1 - cspWeaknessRatio
 *
 * Sehingga total bobot Likelihood selalu = 1.
 */

const SWEEP_VALUES = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8];

const DEFAULT_CSP_WEAKNESS_RATIO =
  baseWeights.likelihoodWeights.cspWeaknessRatio;

/**
 * ============================================================
 * VALIDATION
 * ============================================================
 */

function validateWeights() {
  if (!baseWeights.likelihoodWeights) {
    throw new Error("weights.json tidak memiliki 'likelihoodWeights'.");
  }

  if (typeof baseWeights.likelihoodWeights.cspWeaknessRatio !== "number") {
    throw new Error(
      "weights.json tidak memiliki 'likelihoodWeights.cspWeaknessRatio' yang valid.",
    );
  }

  if (typeof baseWeights.likelihoodWeights.confidenceRatio !== "number") {
    throw new Error(
      "weights.json tidak memiliki 'likelihoodWeights.confidenceRatio' yang valid.",
    );
  }

  const total =
    baseWeights.likelihoodWeights.cspWeaknessRatio +
    baseWeights.likelihoodWeights.confidenceRatio;

  if (Math.abs(total - 1) > 0.000001) {
    throw new Error(`Total bobot Likelihood harus = 1. Saat ini = ${total}.`);
  }

  if (!baseWeights.riskMatrix) {
    throw new Error("weights.json tidak memiliki 'riskMatrix'.");
  }

  if (!baseWeights.impactSeverityScale) {
    throw new Error("weights.json tidak memiliki 'impactSeverityScale'.");
  }

  if (!baseWeights.likelihoodThresholds) {
    throw new Error("weights.json tidak memiliki 'likelihoodThresholds'.");
  }

  if (!baseWeights.impactThresholds) {
    throw new Error("weights.json tidak memiliki 'impactThresholds'.");
  }
}

/**
 * ============================================================
 * BUILD RISK CALCULATOR
 * ============================================================
 *
 * Membuat RiskCalculator dengan bobot Likelihood tertentu.
 *
 * Hanya dua nilai berikut yang diubah:
 *
 *   cspWeaknessRatio
 *   confidenceRatio
 *
 * Semua konfigurasi lain tetap menggunakan weights.json asli.
 */

function buildRiskCalculator(cspWeaknessRatio) {
  const weights = JSON.parse(JSON.stringify(baseWeights));

  const confidenceRatio = 1 - cspWeaknessRatio;

  weights.likelihoodWeights.cspWeaknessRatio = cspWeaknessRatio;

  weights.likelihoodWeights.confidenceRatio = confidenceRatio;

  return new RiskCalculator(scoreEngine, weights);
}

/**
 * ============================================================
 * FORMAT ANGKA
 * ============================================================
 */

function formatRatio(value) {
  return Number(value).toFixed(1);
}

/**
 * ============================================================
 * MAIN
 * ============================================================
 */

async function main() {
  try {
    validateWeights();

    const urls = loadUrls();

    console.log(
      `Mengambil input mentah untuk ${urls.length} situs (fetch SATU KALI per situs)...\n`,
    );

    /**
     * Menyimpan hasil analisis mentah.
     *
     * Tidak ada fetch ulang pada saat sensitivity sweep.
     */
    const analyzedInputs = [];

    const fetchErrors = [];

    /**
     * ========================================================
     * FETCH + ANALYZE SATU KALI
     * ========================================================
     */

    for (const url of urls) {
      process.stdout.write(`  ${url} ... `);

      try {
        const input = await fetchPageInputs(
          url,
          sinkPatterns.eventHandlerAttributes,
        );

        if (!input.ok) {
          console.log(
            `GAGAL (${input.error?.slice(0, 60) ?? "fetch failed"}...)`,
          );

          fetchErrors.push({
            url,
            error: input.error ?? "fetch failed",
          });

          continue;
        }

        /**
         * Analisis CSP hanya dilakukan satu kali.
         */
        const cspResult = cspAnalyzer.analyze(input.cspHeader);

        /**
         * Analisis script/source-sink hanya dilakukan satu kali.
         */
        const scriptResult = scriptAnalyzer.analyze(input.scriptEntries);

        analyzedInputs.push({
          url,
          domain: input.domain,
          cspResult,
          scriptResult,
        });

        console.log("OK");
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);

        console.log(`GAGAL (${message.slice(0, 60)}...)`);

        fetchErrors.push({
          url,
          error: message,
        });
      }
    }

    /**
     * ========================================================
     * CHECK HASIL FETCH
     * ========================================================
     */

    if (analyzedInputs.length === 0) {
      console.error("\nTidak ada situs yang berhasil diambil.");

      console.error("Sensitivity analysis dibatalkan.");

      process.exit(1);
    }

    console.log(
      `\n${analyzedInputs.length} situs berhasil diambil, ${fetchErrors.length} gagal.`,
    );

    console.log(`\nModel sensitivity: Likelihood × Impact`);

    console.log(`Default cspWeaknessRatio : ${DEFAULT_CSP_WEAKNESS_RATIO}`);

    console.log(`Default confidenceRatio  : ${1 - DEFAULT_CSP_WEAKNESS_RATIO}`);

    console.log(
      `\nMenjalankan sweep cspWeaknessRatio: ${SWEEP_VALUES.join(", ")}\n`,
    );

    /**
     * ========================================================
     * SENSITIVITY SWEEP
     * ========================================================
     *
     * Untuk setiap situs:
     *
     * 1. Gunakan cspResult yang sudah dianalisis.
     * 2. Gunakan scriptResult yang sudah dianalisis.
     * 3. Buat RiskCalculator baru.
     * 4. Ubah bobot Likelihood.
     * 5. Hitung ulang FinalReport.
     *
     * Tidak ada network request pada tahap ini.
     */

    const matrix = analyzedInputs.map(
      ({ url, domain, cspResult, scriptResult }) => {
        const row = {
          url,
          domain,
        };

        for (const cspWeaknessRatio of SWEEP_VALUES) {
          const confidenceRatio = 1 - cspWeaknessRatio;

          const calculator = buildRiskCalculator(cspWeaknessRatio);

          const report = calculator.calculate(cspResult, scriptResult, domain);

          const ratioLabel = formatRatio(cspWeaknessRatio);

          row[`risk_${ratioLabel}`] = report.riskLevel;

          row[`score_${ratioLabel}`] = report.finalScore;

          row[`likelihood_${ratioLabel}`] = report.likelihoodScore;

          row[`impact_${ratioLabel}`] = report.impactScore;

          row[`confidenceRatio_${ratioLabel}`] = confidenceRatio;
        }

        return row;
      },
    );

    /**
     * ========================================================
     * DISPLAY MATRIX
     * ========================================================
     */

    console.log("=== MATRIKS RISK LEVEL PER NILAI cspWeaknessRatio ===");

    console.table(
      matrix.map((row) => {
        const display = {
          Domain: row.domain,
        };

        for (const cspWeaknessRatio of SWEEP_VALUES) {
          const ratioLabel = formatRatio(cspWeaknessRatio);

          const marker =
            cspWeaknessRatio === DEFAULT_CSP_WEAKNESS_RATIO ? "*" : "";

          display[`${ratioLabel}${marker}`] = row[`risk_${ratioLabel}`];
        }

        return display;
      }),
    );

    console.log("(* = nilai default cspWeaknessRatio pada project)\n");

    /**
     * ========================================================
     * STABILITY ANALYSIS
     * ========================================================
     *
     * Stabil:
     * Risk Level tidak berubah pada seluruh rentang
     * cspWeaknessRatio 0.3 - 0.8.
     */

    const changedCount = matrix.filter((row) => {
      const levels = new Set(
        SWEEP_VALUES.map((ratio) => row[`risk_${formatRatio(ratio)}`]),
      );

      return levels.size > 1;
    }).length;

    const stableCount = matrix.length - changedCount;

    const stablePercentage =
      matrix.length > 0 ? Math.round((stableCount / matrix.length) * 100) : 0;

    /**
     * ========================================================
     * SUMMARY
     * ========================================================
     */

    console.log("=== RINGKASAN SENSITIVITAS ===");

    console.log(`Total situs dianalisis     : ${matrix.length}`);

    console.log(
      `Klasifikasi STABIL         : ${stableCount} situs (${stablePercentage}%)`,
    );

    console.log(`Klasifikasi BERUBAH        : ${changedCount} situs`);

    console.log("");

    if (stablePercentage >= 80) {
      console.log(
        "INTERPRETASI: mayoritas situs stabil terhadap perubahan bobot Likelihood.",
      );

      console.log(
        "Hasil ini dapat digunakan sebagai bukti tambahan robustness.",
      );
    } else {
      console.log(
        "INTERPRETASI: banyak situs berubah klasifikasi ketika bobot Likelihood digeser.",
      );

      console.log(
        "Artinya hasil klasifikasi sensitif terhadap pemilihan bobot.",
      );
    }

    console.log(
      "Sensitivity analysis BUKAN pengganti expert elicitation seperti AHP/Delphi.",
    );

    console.log(
      "Hasil ini digunakan sebagai bukti tambahan untuk pembahasan metodologi.",
    );

    /**
     * ========================================================
     * CSV OUTPUT
     * ========================================================
     *
     * CSV menyimpan:
     *
     * - Domain
     * - Risk Level
     * - Final Score
     * - Likelihood Score
     * - Impact Score
     * - Confidence Ratio
     * - Status stabilitas
     */

    const header = [
      "Domain",

      ...SWEEP_VALUES.map(
        (ratio) => `RiskLevel@cspWeaknessRatio=${formatRatio(ratio)}`,
      ),

      ...SWEEP_VALUES.map(
        (ratio) => `FinalScore@cspWeaknessRatio=${formatRatio(ratio)}`,
      ),

      ...SWEEP_VALUES.map(
        (ratio) => `LikelihoodScore@cspWeaknessRatio=${formatRatio(ratio)}`,
      ),

      ...SWEEP_VALUES.map(
        (ratio) => `ImpactScore@cspWeaknessRatio=${formatRatio(ratio)}`,
      ),

      "Stabil?",
    ].join(",");

    const rows = matrix.map((row) => {
      const levels = new Set(
        SWEEP_VALUES.map((ratio) => row[`risk_${formatRatio(ratio)}`]),
      );

      const stable = levels.size === 1 ? "Ya" : "Tidak";

      return [
        row.domain,

        ...SWEEP_VALUES.map((ratio) => row[`risk_${formatRatio(ratio)}`]),

        ...SWEEP_VALUES.map((ratio) => row[`score_${formatRatio(ratio)}`]),

        ...SWEEP_VALUES.map((ratio) => row[`likelihood_${formatRatio(ratio)}`]),

        ...SWEEP_VALUES.map((ratio) => row[`impact_${formatRatio(ratio)}`]),

        stable,
      ].join(",");
    });

    const csvPath = new URL("./sensitivity-results.csv", import.meta.url);

    writeFileSync(csvPath, header + "\n" + rows.join("\n") + "\n", "utf8");

    console.log(`\nHasil lengkap tersimpan ke scripts/sensitivity-results.csv`);

    /**
     * ========================================================
     * OPTIONAL FETCH ERROR SUMMARY
     * ========================================================
     */

    if (fetchErrors.length > 0) {
      console.log(
        `\nCatatan: ${fetchErrors.length} situs gagal di-fetch dan tidak dimasukkan ke sensitivity matrix.`,
      );
    }
  } catch (error) {
    console.error("\nSensitivity analysis gagal:");

    console.error(
      error instanceof Error ? (error.stack ?? error.message) : error,
    );

    process.exit(1);
  }
}

main();
