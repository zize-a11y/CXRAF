/**
 * ScriptResult.js
 *
 * Fungsi: DTO untuk hasil analisis ScriptAnalyzer (deteksi sink berbahaya
 * dan hasil pelacakan source-sink). Sama seperti CSPResult.js, murni
 * struktur data tanpa logic.
 */

/**
 * @typedef {Object} SinkFinding
 * @property {string} sinkId - id sink, mis. "eval"
 * @property {string} severity - salah satu Severity (mengukur DAMPAK jika benar-benar eksploitable)
 * @property {number} confidence - 0.0-1.0, seberapa yakin ini BUKAN false-positive
 *   (mengukur LIKELIHOOD/keyakinan, sumbu terpisah dari severity - lihat
 *   OWASP Risk Rating Methodology yang memisahkan Impact dari Likelihood).
 *   Nilai awal berasal dari baseConfidence sink di sink-patterns.json;
 *   dinaikkan oleh ScriptAnalyzer jika ditemukan korelasi source-sink
 *   (lihat traceConfidence di sink-patterns.json dan _correlateWithTrace()).
 * @property {string} description - penjelasan risiko
 * @property {string} matchedText - potongan kode yang cocok pattern (dipotong pendek)
 * @property {string} location - "inline-script" | "event-handler"
 * @property {boolean} [correlatedWithSource] - true jika confidence dinaikkan karena korelasi source-sink ditemukan
 */

/**
 * @typedef {Object} TraceResult
 * @property {string} sourceId
 * @property {string} sinkId
 * @property {boolean} tainted - apakah data dari source mengalir ke sink tanpa sanitasi
 * @property {number} confidence - 0.0-1.0, seberapa yakin korelasi ini benar.
 *   DIRECT (source & sink 1 statement) > INDIRECT (1-hop assignment variabel),
 *   karena INDIRECT tidak menelusuri kemungkinan sanitasi di antara keduanya.
 * @property {string} explanation
 */

/**
 * @typedef {Object} ScriptResult
 * @property {SinkFinding[]} findings
 * @property {TraceResult[]} traceResults
 * @property {number} criticalCount
 * @property {number} highCount
 * @property {number} averageConfidence - rata-rata confidence seluruh findings (0 jika tidak ada temuan)
 * @property {boolean} truncated - true jika jumlah entry melebihi cap performa (lihat ScriptAnalyzer)
 * @property {number} totalEntriesReceived - jumlah entry asli sebelum truncation
 */

/**
 * Membuat objek ScriptResult dengan bentuk konsisten.
 *
 * @param {Partial<ScriptResult>} data
 * @returns {ScriptResult}
 */
export function createScriptResult(data = {}) {
  const findings = data.findings ?? [];
  const totalConfidence = findings.reduce((sum, f) => sum + (f.confidence ?? 0), 0);

  return {
    findings,
    traceResults: data.traceResults ?? [],
    criticalCount: findings.filter((f) => f.severity === 'CRITICAL').length,
    highCount: findings.filter((f) => f.severity === 'HIGH').length,
    averageConfidence: findings.length > 0 ? Math.round((totalConfidence / findings.length) * 100) / 100 : 0,
    truncated: data.truncated ?? false,
    totalEntriesReceived: data.totalEntriesReceived ?? findings.length,
  };
}
