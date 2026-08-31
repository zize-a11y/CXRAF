/**
 * compare-semgrep.mjs
 *
 * Fungsi: Melengkapi Temuan #8 dari review arsitektur — sebelumnya
 * perbandingan (compare-baseline.mjs) hanya mencakup csp_evaluator
 * (Google) dan MDN HTTP Observatory, yang KEDUANYA hanya mengevaluasi
 * HEADER/konfigurasi HTTP, TIDAK ADA yang menganalisis isi script.
 * Script ini menutup celah itu dengan membandingkan `ScriptAnalyzer`
 * (xss-risk-core) terhadap Semgrep — static analysis tool sungguhan yang
 * BENAR-BENAR menganalisis kode, bukan cuma header.
 *
 * KENAPA RULE CUSTOM, BUKAN RULE PACK REGISTRY (p/javascript, dsb):
 * Rule pack resmi Semgrep (p/javascript, p/security-audit) di-download
 * dari semgrep.dev saat runtime — tidak reproducible (isinya bisa berubah
 * kapan saja tanpa version pinning yang jelas dari sisi pengguna), dan
 * mencampur banyak rule yang tidak relevan dengan kategori sink yang
 * dipakai xss-risk-core. Sebagai gantinya, digunakan rule CUSTOM
 * (scripts/semgrep-rules/xss-risk-core-equivalent-rules.yaml) yang
 * ditulis SPESIFIK mencerminkan ke-12 kategori sink yang sama persis
 * dengan sink-patterns.json — memastikan perbandingan apple-to-apple
 * (kategori sink identik, mesin deteksi berbeda: regex+tokenizer buatan
 * sendiri vs AST-based pattern matching Semgrep).
 *
 * PRASYARAT: Semgrep CLI harus terinstall (bukan npm package, CLI
 * terpisah). Install via:
 *   pip install semgrep
 * atau lihat https://semgrep.dev/docs/getting-started/quickstart
 *
 * CARA PAKAI: node scripts/compare-semgrep.mjs
 * OUTPUT: tabel perbandingan + scripts/semgrep-comparison-results.csv
 */

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { execFileSync } from "child_process";
import {
  CSPAnalyzer,
  ScriptAnalyzer,
  SourceSinkTracer,
  ScoreEngine,
} from "xss-risk-core";
import { fetchPageInputs, loadUrls } from "./lib/fetchPageInputs.mjs";
import { fileURLToPath } from "url";

const sinkPatterns = JSON.parse(
  readFileSync(
    new URL(
      "../packages/xss-risk-core/config/sink-patterns.json",
      import.meta.url,
    ),
  ),
);
const cspRules = JSON.parse(
  readFileSync(
    new URL("../packages/xss-risk-core/config/csp-rules.json", import.meta.url),
  ),
);
const weights = JSON.parse(
  readFileSync(
    new URL("../packages/xss-risk-core/config/weights.json", import.meta.url),
  ),
);

const scoreEngine = new ScoreEngine(weights);
const cspAnalyzer = new CSPAnalyzer(cspRules, scoreEngine); // dipakai hanya untuk konsistensi fetchPageInputs, tidak dibandingkan di sini
const tracer = new SourceSinkTracer(sinkPatterns);
const scriptAnalyzer = new ScriptAnalyzer(sinkPatterns, tracer);

const SEMGREP_RULE_FILE = fileURLToPath(
  new URL(
    "./semgrep-rules/xss-risk-core-equivalent-rules.yaml",
    import.meta.url,
  ),
);
/**
 * Cek Semgrep CLI terinstall, keluar dengan pesan jelas jika tidak.
 * @returns {void}
 */
function assertSemgrepInstalled() {
  try {
    execFileSync("semgrep", ["--version"], { stdio: "pipe" });
  } catch {
    console.error("❌ Semgrep CLI tidak ditemukan.");
    console.error("   Install dulu: pip install semgrep");
    console.error(
      "   Lihat: https://semgrep.dev/docs/getting-started/quickstart",
    );
    process.exit(1);
  }
}

/**
 * Menjalankan Semgrep terhadap kumpulan script entries dari satu situs.
 * Setiap entry ditulis ke file .js sementara (Semgrep butuh file, bukan
 * string mentah), lalu di-scan sekaligus dalam satu direktori temp.
 *
 * @param {Array<{type: string, code: string}>} scriptEntries
 * @returns {{ ok: boolean, findingsCount?: number, findingsByRule?: Record<string, number>, error?: string }}
 */
function runSemgrepOnEntries(scriptEntries) {
  const codeEntries = scriptEntries.filter(
    (e) => e.code && e.code.trim().length > 0,
  );
  if (codeEntries.length === 0) {
    return { ok: true, findingsCount: 0, findingsByRule: {} };
  }

  const tmpDir = mkdtempSync(join(tmpdir(), "xss-risk-semgrep-"));
  try {
    codeEntries.forEach((entry, i) => {
      // Bungkus atribut event handler jadi bentuk statement JS valid agar
      // bisa di-parse Semgrep (atribut handler bukan JS lengkap, mis.
      // "doSomething()" perlu jadi "doSomething();" agar valid sebagai file .js).
      const code =
        entry.type === "event-handler" ? `${entry.code};` : entry.code;
      writeFileSync(join(tmpDir, `entry-${i}.js`), code);
    });

    const outputPath = join(tmpDir, "result.json");
    try {
      execFileSync(
        "semgrep",
        [
          "--config",
          SEMGREP_RULE_FILE,
          "--json",
          "--quiet",
          "-o",
          outputPath,
          tmpDir,
        ],
        { stdio: "pipe" },
      );
    } catch (error) {
      // Semgrep exit code bisa non-zero walau scan sukses (mis. saat ada
      // finding severity ERROR, dianggap "blocking") - cek dulu apakah
      // result.json tetap dihasilkan sebelum dianggap gagal total.
      if (!existsSyncSafe(outputPath)) {
        return { ok: false, error: error.message };
      }
    }

    const raw = JSON.parse(readFileSync(outputPath, "utf-8"));
    const findingsByRule = {};
    for (const result of raw.results) {
      findingsByRule[result.check_id] =
        (findingsByRule[result.check_id] ?? 0) + 1;
    }

    return { ok: true, findingsCount: raw.results.length, findingsByRule };
  } catch (error) {
    return { ok: false, error: error.message };
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** @param {string} path @returns {boolean} */
function existsSyncSafe(path) {
  try {
    readFileSync(path);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  assertSemgrepInstalled();

  const urls = loadUrls();
  console.log(
    `Membandingkan xss-risk-core vs Semgrep (rule custom setara) untuk ${urls.length} situs...\n`,
  );

  const results = [];

  for (const url of urls) {
    process.stdout.write(`  ${url} ... `);
    const input = await fetchPageInputs(
      url,
      sinkPatterns.eventHandlerAttributes,
    );

    if (!input.ok) {
      console.log(`GAGAL fetch (${input.error.slice(0, 50)}...)`);
      results.push({ url, ok: false, error: input.error });
      continue;
    }

    const ourResult = scriptAnalyzer.analyze(input.scriptEntries);
    const semgrepResult = runSemgrepOnEntries(input.scriptEntries);

    if (!semgrepResult.ok) {
      console.log(`GAGAL Semgrep (${semgrepResult.error})`);
      results.push({
        url,
        ok: false,
        error: `Semgrep: ${semgrepResult.error}`,
      });
      continue;
    }

    const match =
      ourResult.findings.length === semgrepResult.findingsCount
        ? "SAMA"
        : "BEDA";
    console.log(
      `kami=${ourResult.findings.length}, semgrep=${semgrepResult.findingsCount} (${match})`,
    );

    results.push({
      url,
      ok: true,
      domain: input.domain,
      ourCount: ourResult.findings.length,
      semgrepCount: semgrepResult.findingsCount,
      semgrepByRule: semgrepResult.findingsByRule,
    });
  }

  console.log("\n=== RINGKASAN PERBANDINGAN ===");
  console.table(
    results.map((r) => ({
      Domain: r.ok ? r.domain : r.url,
      "Findings xss-risk-core": r.ok ? r.ourCount : "-",
      "Findings Semgrep": r.ok ? r.semgrepCount : "-",
      Selisih: r.ok ? r.ourCount - r.semgrepCount : "-",
    })),
  );

  const okResults = results.filter((r) => r.ok);
  const exactMatch = okResults.filter(
    (r) => r.ourCount === r.semgrepCount,
  ).length;
  const weFoundMore = okResults.filter(
    (r) => r.ourCount > r.semgrepCount,
  ).length;
  const semgrepFoundMore = okResults.filter(
    (r) => r.semgrepCount > r.ourCount,
  ).length;

  console.log("\n=== ANALISIS KESESUAIAN ===");
  console.log(`Total situs dibandingkan       : ${okResults.length}`);
  console.log(
    `Jumlah temuan SAMA PERSIS       : ${exactMatch} situs (${Math.round((exactMatch / okResults.length) * 100)}%)`,
  );
  console.log(`xss-risk-core temukan LEBIH BANYAK : ${weFoundMore} situs`);
  console.log(`Semgrep temukan LEBIH BANYAK    : ${semgrepFoundMore} situs`);
  console.log("");
  console.log("CATATAN INTERPRETASI (wajib dibaca sebelum dikutip di BAB IV):");
  console.log(
    '- Selisih TIDAK OTOMATIS berarti salah satu sistem "lebih benar" - bisa juga karena',
  );
  console.log(
    "  perbedaan cakupan pattern, cara tokenisasi, atau false-positive di salah satu sisi.",
  );
  console.log(
    "- Semgrep berbasis AST asli (parsing sungguhan), xss-risk-core pakai tokenizer buatan",
  );
  console.log(
    "  sendiri (lihat docs/optimization-report.md soal keterbatasan regex literal).",
  );
  console.log(
    "  Kasus di mana Semgrep > kami berpotensi menunjukkan pola yang lolos dari tokenizer kami.",
  );

  const csvHeader = "Domain,Findings_xss-risk-core,Findings_Semgrep,Selisih\n";
  const csvRows = okResults.map(
    (r) =>
      `${r.domain},${r.ourCount},${r.semgrepCount},${r.ourCount - r.semgrepCount}`,
  );
  const csvPath = new URL("./semgrep-comparison-results.csv", import.meta.url);
  writeFileSync(csvPath, csvHeader + csvRows.join("\n") + "\n");
  console.log(`\nHasil tersimpan ke scripts/semgrep-comparison-results.csv`);
}

main();
