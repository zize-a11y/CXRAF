/**
 * RiskCalculator.js
 *
 * Fungsi: Titik agregasi TUNGGAL yang menggabungkan CSPResult dan
 * ScriptResult menjadi satu FinalReport.
 *
 * REDESAIN TOTAL: model skoring sekarang mengikuti OWASP Risk Rating
 * Methodology — Likelihood dan Impact dihitung sebagai DUA SUMBU TERPISAH,
 * baru digabung lewat MATRIX (bukan satu angka blended yang di-threshold
 * langsung seperti versi sebelumnya). Ini implementasi eksplisit dari
 * framing "CSP = Likelihood, source-sink findings = Impact" yang menjadi
 * spesifikasi output penelitian.
 *
 *   LIKELIHOOD (seberapa MUNGKIN eksploitasi berhasil):
 *     - Diturunkan dari KELEMAHAN CSP (100 - cspScore) — CSP lemah/tidak
 *       ada berarti browser tidak punya pertahanan, eksploitasi lebih
 *       mudah berhasil (mengacu istilah OWASP: "Ease of Exploit").
 *     - Ditambah rata-rata CONFIDENCE temuan script — makin yakin taint
 *       benar-benar mengalir dari source ke sink, makin besar kemungkinan
 *       ini benar-benar bisa dieksploitasi (bukan false-positive).
 *
 *   IMPACT (seberapa PARAH dampaknya JIKA berhasil dieksploitasi):
 *     - Diturunkan MURNI dari severity TERTINGGI (worst-case) di antara
 *       seluruh temuan script — mengukur besaran dampak, sengaja TIDAK
 *       dicampur dengan confidence (confidence adalah bagian dari
 *       Likelihood, bukan Impact — dua sumbu ini harus tetap independen).
 *
 *   RISK LEVEL akhir = riskMatrix[likelihoodCategory][impactCategory],
 *     BUKAN dari threshold satu angka. Ini juga menggantikan mekanisme
 *     "critical override" manual dari versi sebelumnya (Temuan #9 review
 *     arsitektur) — sekarang override itu terjadi SECARA NATURAL lewat
 *     matrix: Impact=CRITICAL dengan Likelihood>=MEDIUM otomatis
 *     menghasilkan RiskLevel HIGH/CRITICAL tanpa logic terpisah.
 */

import { createFinalReport } from "../models/FinalReport.js";
import { categoryFromScore } from "../models/RiskLevel.js";

export class RiskCalculator {
  /**
   * @param {import('./ScoreEngine.js').ScoreEngine} scoreEngine - dipertahankan
   *   di signature untuk backward-compat dengan seluruh titik instansiasi
   *   yang sudah ada (background/index.js, scripts/*.mjs) — TIDAK dipanggil
   *   langsung di logic calculate() versi baru ini (skor CSP sudah dihitung
   *   duluan oleh CSPAnalyzer yang memakainya secara internal, RiskCalculator
   *   cukup menerima cspResult.score yang sudah jadi).
   * @param {object} weights - isi weights.json
   */
  constructor(scoreEngine, weights) {
    this.scoreEngine = scoreEngine;
    this.weights = weights;
  }

  /**
   * Menghitung Likelihood (0-100) — seberapa mungkin eksploitasi berhasil.
   *
   * @param {number} cspScore - skor CSP 0-100 (100 = sangat kuat)
   * @param {number} averageConfidence - 0.0-1.0, rata-rata confidence temuan script
   * @returns {number} likelihoodScore 0-100
   */
  calculateLikelihood(cspScore, averageConfidence) {
    const { cspWeaknessRatio, confidenceRatio } =
      this.weights.likelihoodWeights;
    const cspWeakness = 100 - cspScore;
    const confidenceContribution = averageConfidence * 100;
    const likelihood =
      cspWeakness * cspWeaknessRatio + confidenceContribution * confidenceRatio;
    return Math.max(0, Math.min(100, Math.round(likelihood)));
  }

  /**
   * Menghitung Impact (0-100) — seberapa parah dampak JIKA eksploitasi
   * berhasil. Diambil dari severity TERTINGGI (worst-case) di antara
   * seluruh temuan, BUKAN rata-rata — standar praktik risk assessment
   * mengasumsikan skenario terburuk untuk pengukuran dampak.
   *
   * @param {import('../models/ScriptResult.js').SinkFinding[]} findings
   * @returns {number} impactScore 0-100
   */
  calculateImpact(findings) {
    if (!findings || findings.length === 0) return 0;
    const scale = this.weights.impactSeverityScale;
    const impactValues = findings.map((f) => scale[f.severity] ?? 0);
    return Math.max(...impactValues);
  }

  /**
   * Entry point utama — menggabungkan CSPResult dan ScriptResult menjadi
   * FinalReport lewat model Likelihood x Impact.
   *
   * @param {import('../models/CSPResult.js').CSPResult} cspResult
   * @param {import('../models/ScriptResult.js').ScriptResult} scriptResult
   * @param {string} domain
   * @returns {import('../models/FinalReport.js').FinalReport}
   */
  calculate(cspResult, scriptResult, domain = "") {
    const likelihoodScore = this.calculateLikelihood(
      cspResult.score,
      scriptResult.averageConfidence,
    );
    const impactScore = this.calculateImpact(scriptResult.findings);

    const likelihoodCategory = categoryFromScore(
      likelihoodScore,
      this.weights.likelihoodThresholds,
    );
    const impactCategory = categoryFromScore(
      impactScore,
      this.weights.impactThresholds,
    );

    const riskLevel =
      this.weights.riskMatrix[likelihoodCategory][impactCategory];

    // finalScore untuk gauge UI: 100 = paling aman. Dihitung dari rata-rata
    // Likelihood+Impact (keduanya "0=baik, 100=buruk"), lalu dibalik arah
    // (100 - x) supaya konsisten dengan konvensi tampilan gauge yang sudah
    // ada ("skor tinggi = aman") — TIDAK dipakai untuk menentukan riskLevel
    // (itu murni dari matrix), murni representasi numerik ringkas untuk UI.
    const finalScore = Math.max(
      0,
      Math.min(100, Math.round(100 - (likelihoodScore + impactScore) / 2)),
    );

    const recommendations = this.generateRecommendations(
      cspResult.warnings,
      scriptResult.findings,
    );

    return createFinalReport({
      domain,
      timestamp: Date.now(),
      cspScore: cspResult.score,
      finalScore,
      likelihoodScore,
      likelihoodCategory,
      impactScore,
      impactCategory,
      riskLevel,
      cspWarnings: cspResult.warnings,
      scriptFindings: scriptResult.findings,
      recommendations,
      truncated: scriptResult.truncated,
      averageConfidence: scriptResult.averageConfidence,
    });
  }

  /**
   * Menghasilkan daftar rekomendasi berbasis OWASP untuk setiap temuan
   * CSP dan script yang bermasalah. Rekomendasi di-dedupe berdasarkan
   * jenis temuan (bukan per-instance) agar tidak ada saran berulang.
   *
   * @param {import('../models/CSPResult.js').Warning[]} cspWarnings
   * @param {import('../models/ScriptResult.js').SinkFinding[]} scriptFindings
   * @returns {import('../models/FinalReport.js').Recommendation[]}
   */
  generateRecommendations(cspWarnings, scriptFindings) {
    const recs = [];
    const seen = new Set();

    const push = (key, suggestion, priority) => {
      if (seen.has(key)) return;
      seen.add(key);
      recs.push({ relatedFindingId: key, suggestion, priority });
    };

    for (const w of cspWarnings) {
      const suggestion = this._cspRecommendation(w.keyword, w.directive);
      push(
        `csp:${w.keyword}:${w.directive}`,
        suggestion,
        w.severity === "CRITICAL" || w.severity === "HIGH" ? "HIGH" : "MEDIUM",
      );
    }

    for (const f of scriptFindings) {
      const suggestion = this._scriptRecommendation(f.sinkId);
      push(
        `script:${f.sinkId}`,
        suggestion,
        f.severity === "CRITICAL" || f.severity === "HIGH" ? "HIGH" : "MEDIUM",
      );
    }

    return recs;
  }

  /** @param {string} keyword @param {string} directive @returns {string} */
  _cspRecommendation(keyword, directive) {
    const map = {
      "unsafe-inline": `Hapus 'unsafe-inline' dari ${directive}. Gunakan nonce (nonce-xxx) atau hash (sha256-xxx) untuk script/style yang sah.`,
      "unsafe-eval": `Hapus 'unsafe-eval' dari ${directive}. Refactor kode yang bergantung pada eval()/Function() menjadi kode statis.`,
      "*": `Ganti wildcard (*) pada ${directive} dengan daftar domain eksplisit yang benar-benar dipercaya.`,
      "data:": `Batasi skema data: pada ${directive} hanya jika benar-benar diperlukan (mis. untuk favicon), hindari untuk script-src.`,
      "blob:": `Tinjau kebutuhan skema blob: pada ${directive}, batasi hanya untuk konteks yang memerlukan (mis. Web Worker tepercaya).`,
      "http:": `Ganti skema http: dengan https: pada ${directive} untuk mencegah downgrade attack.`,
      "-": "Tambahkan header Content-Security-Policy pada response halaman dan konfigurasi directive CSP yang sesuai untuk membatasi sumber script.",
    };
    return (
      map[keyword] ||
      `Tinjau kembali penggunaan "${keyword}" pada directive ${directive}, pertimbangkan mempersempit cakupannya.`
    );
  }

  /** @param {string} sinkId @returns {string} */
  _scriptRecommendation(sinkId) {
    const map = {
      eval: "Ganti eval() dengan alternatif aman seperti JSON.parse() untuk parsing data, atau refactor logic menjadi fungsi statis.",
      "function-constructor":
        "Hindari new Function() untuk membangun logic dinamis; gunakan pemetaan fungsi statis (mis. object lookup) sebagai gantinya.",
      "document-write":
        "Ganti document.write() dengan manipulasi DOM API standar (createElement, appendChild).",
      "inner-html":
        "Ganti innerHTML dengan textContent untuk teks biasa, atau gunakan DOMPurify.sanitize() sebelum menyisipkan HTML.",
      "outer-html":
        "Ganti outerHTML dengan textContent atau elemen DOM yang dibangun manual via createElement.",
      "insert-adjacent-html":
        "Sanitasi input dengan DOMPurify sebelum memanggil insertAdjacentHTML, atau gunakan insertAdjacentText jika hanya teks.",
      "settimeout-string":
        "Ganti argumen string pada setTimeout dengan referensi fungsi langsung, mis. setTimeout(fn, delay).",
      "setinterval-string":
        "Ganti argumen string pada setInterval dengan referensi fungsi langsung.",
      atob: "Pastikan hasil decode atob() divalidasi/di-escape sebelum dipakai, jangan langsung dirender ke DOM.",
      unescape:
        "Hindari unescape() (deprecated); gunakan decodeURIComponent() dan validasi hasilnya.",
      "javascript-uri":
        "Hindari skema javascript: pada atribut href/src; gunakan event listener terpisah (addEventListener).",
      srcdoc:
        "Sanitasi konten sebelum diisikan ke srcdoc, atau gunakan sandbox attribute pada iframe.",
    };
    if (map[sinkId]) return map[sinkId];
    if (sinkId?.startsWith("event-handler:")) {
      return `Hindari atribut event handler inline (${sinkId.split(":")[1]}); gunakan addEventListener() dari script eksternal agar tunduk pada CSP script-src.`;
    }
    return "Tinjau kembali pola kode ini terhadap panduan OWASP DOM-based XSS Prevention Cheat Sheet.";
  }
}
