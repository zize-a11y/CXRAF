/**
 * FinalReport.js
 *
 * Fungsi: DTO untuk laporan akhir yang dihasilkan RiskCalculator, dikonsumsi
 * oleh StorageService (disimpan) dan UIRenderer (ditampilkan). Ini adalah
 * "kontrak data" antara domain layer dan dua sisi luar (storage & UI),
 * sehingga perubahan bentuk data cukup dilakukan di satu tempat ini.
 */

/**
 * @typedef {Object} Recommendation
 * @property {string} relatedFindingId
 * @property {string} suggestion - saran perbaikan berbasis OWASP
 * @property {string} priority - "HIGH" | "MEDIUM" | "LOW"
 */

/**
 * @typedef {Object} FinalReport
 * @property {string} domain
 * @property {number} timestamp
 * @property {number} cspScore
 * @property {number} finalScore - skor komposit 0-100 untuk gauge UI (100=paling aman).
 *   Dihitung dari (likelihoodScore + impactScore), BUKAN sumber utama klasifikasi
 *   riskLevel lagi — riskLevel sekarang murni dari riskMatrix (lihat di bawah).
 * @property {number} likelihoodScore - 0-100, seberapa MUNGKIN eksploitasi berhasil
 *   (dari kelemahan CSP + confidence temuan). Implementasi framing OWASP Risk
 *   Rating Methodology: CSP = Likelihood.
 * @property {string} likelihoodCategory - "LOW" | "MEDIUM" | "HIGH"
 * @property {number} impactScore - 0-100, seberapa PARAH dampaknya JIKA berhasil
 *   dieksploitasi (dari severity terburuk temuan script). Implementasi framing
 *   OWASP Risk Rating Methodology: source-sink findings = Impact.
 * @property {string} impactCategory - "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
 * @property {string} riskLevel - hasil lookup riskMatrix[likelihoodCategory][impactCategory],
 *   BUKAN lagi dari threshold satu angka gabungan
 * @property {import('./CSPResult.js').Warning[]} cspWarnings
 * @property {import('./ScriptResult.js').SinkFinding[]} scriptFindings
 * @property {Recommendation[]} recommendations
 * @property {boolean} truncated - true jika jumlah script/handler pada halaman melebihi cap performa
 * @property {number} averageConfidence - rata-rata confidence seluruh scriptFindings (0.0-1.0)
 */

/**
 * Membuat objek FinalReport dengan bentuk konsisten.
 *
 * @param {Partial<FinalReport>} data
 * @returns {FinalReport}
 */
export function createFinalReport(data = {}) {
  return {
    domain: data.domain ?? '',
    timestamp: data.timestamp ?? Date.now(),
    cspScore: data.cspScore ?? 0,
    finalScore: data.finalScore ?? 0,
    likelihoodScore: data.likelihoodScore ?? 0,
    likelihoodCategory: data.likelihoodCategory ?? 'LOW',
    impactScore: data.impactScore ?? 0,
    impactCategory: data.impactCategory ?? 'LOW',
    riskLevel: data.riskLevel ?? 'CRITICAL',
    cspWarnings: data.cspWarnings ?? [],
    scriptFindings: data.scriptFindings ?? [],
    recommendations: data.recommendations ?? [],
    truncated: data.truncated ?? false,
    averageConfidence: data.averageConfidence ?? 0,
  };
}
