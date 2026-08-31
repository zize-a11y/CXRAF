/**
 * CSPAnalyzer.js
 *
 * Fungsi: Domain layer class yang bertanggung jawab mem-parsing string
 * header Content-Security-Policy menjadi struktur directive, mendeteksi
 * keyword berisiko, dan menghitung skor per-directive. TIDAK melakukan
 * agregasi skor akhir (0-100) — itu tanggung jawab ScoreEngine, sesuai
 * Single Responsibility Principle.
 *
 * PENTING: File ini murni pure function/class, TIDAK mengimpor apapun
 * dari `chrome.*`. Ini disengaja agar bisa diuji dengan Jest tanpa mock
 * Chrome API (lihat tests/unit/CSPAnalyzer.test.js).
 *
 * Alur kerja:
 *   1. parseDirectives()   -> ubah string CSP jadi Map<directive, values[]>
 *   2. evaluateDirective() -> cek tiap directive terhadap ruleSet (bobot, wajib/tidak)
 *   3. detectRiskyKeywords() -> cek value tiap directive terhadap daftar keyword berisiko
 *   4. analyze()           -> orkestrasi 3 langkah di atas + hitung skor via ScoreEngine
 */

import { IAnalyzer } from './IAnalyzer.js';
import { createCSPResult } from '../models/CSPResult.js';
import { Severity } from '../models/RiskLevel.js';

export class CSPAnalyzer extends IAnalyzer {
  /**
   * @param {object} ruleSet - isi csp-rules.json (lihat packages/xss-risk-core/config/csp-rules.json)
   * @param {import('../risk/ScoreEngine.js').ScoreEngine} scoreEngine - untuk hitung skor
   */
  constructor(ruleSet, scoreEngine) {
    super();
    this.ruleSet = ruleSet;
    this.scoreEngine = scoreEngine;
  }

  /**
   * Mem-parsing string header CSP mentah menjadi Map directive -> values[].
   * Format CSP: "directive1 val1 val2; directive2 val1; ..."
   *
   * @param {string} cspHeader
   * @returns {Map<string, string[]>}
   */
  parseDirectives(cspHeader) {
    const map = new Map();
    if (!cspHeader || typeof cspHeader !== 'string') return map;

    const directives = cspHeader.split(';').map((d) => d.trim()).filter(Boolean);
    for (const directive of directives) {
      const parts = directive.split(/\s+/).filter(Boolean);
      const name = parts[0]?.toLowerCase();
      if (!name) continue;
      const values = parts.slice(1);
      map.set(name, values);
    }
    return map;
  }

  /**
   * Mendeteksi keyword berisiko pada daftar value suatu directive.
   *
   * PENTING (perbaikan Temuan #1 review): setiap hasil menyertakan
   * `penaltyRatio` yang diambil LANGSUNG dari csp-rules.json, bukan
   * cuma `severity`. Sebelumnya, ScoreEngine menurunkan ulang rasio
   * penalti dari `severity` via tabel hardcoded (`_severityToRatio`),
   * sehingga field `penaltyRatio` di JSON menjadi dead configuration —
   * mengubahnya tidak berpengaruh ke skor sama sekali. Dengan
   * menyertakan `penaltyRatio` di sini, ScoreEngine tinggal memakainya
   * langsung, membuat rule engine benar-benar data-driven.
   *
   * @param {string[]} values
   * @returns {{keyword: string, severity: string, penaltyRatio: number}[]}
   */
  detectRiskyKeywords(values) {
    const found = [];
    const penalties = this.ruleSet.riskyKeywordPenalties;

    for (const value of values) {
      const cleaned = value.replace(/^'|'$/g, ''); // buang tanda kutip: 'unsafe-inline' -> unsafe-inline

      if (penalties[cleaned]) {
        found.push({
          keyword: cleaned,
          severity: penalties[cleaned].severity,
          penaltyRatio: penalties[cleaned].penaltyRatio,
        });
        continue;
      }
      // Deteksi wildcard subdomain, mis. "*.example.com"
      if (/^\*\.[a-z0-9.-]+$/i.test(cleaned) && penalties.wildcardSubdomain) {
        found.push({
          keyword: cleaned,
          severity: penalties.wildcardSubdomain.severity,
          penaltyRatio: penalties.wildcardSubdomain.penaltyRatio,
        });
      }
    }
    return found;
  }

  /**
   * Mengevaluasi satu directive terhadap ruleSet: apakah wajib, apakah ada
   * keyword berisiko, dan berapa kontribusi skornya (dihitung oleh ScoreEngine
   * agar rumus skor tetap terpusat di satu tempat).
   *
   * @param {string} name - nama directive
   * @param {string[]} values
   * @returns {import('../../models/CSPResult.js').DirectiveFinding}
   */
  evaluateDirective(name, values) {
    const config = this.ruleSet.directives[name];
    const riskyFound = this.detectRiskyKeywords(values);

    return {
      directive: name,
      values,
      present: true,
      riskyKeywordsFound: riskyFound.map((r) => r.keyword),
      _riskySeverities: riskyFound.map((r) => r.severity), // dipakai internal oleh ScoreEngine
      contributionScore: config
        ? this.scoreEngine.applyPenalty(config.weight, riskyFound)
        : 0,
    };
  }

  /**
   * Entry point utama analyzer ini (implementasi kontrak IAnalyzer).
   *
   * @param {string} cspHeader - nilai mentah header Content-Security-Policy,
   *   atau null/undefined jika header tidak ditemukan sama sekali di response.
   * @returns {import('../../models/CSPResult.js').CSPResult}
   */
  analyze(cspHeader) {
    if (!cspHeader) {
      return createCSPResult({
        score: this.ruleSet.cspNotFoundScore,
        cspFound: false,
        findings: [],
        warnings: [{
          directive: '-',
          keyword: '-',
          severity: Severity.CRITICAL,
          explanation: 'Header Content-Security-Policy tidak ditemukan pada response halaman ini.',
        }],
      });
    }

    const directiveMap = this.parseDirectives(cspHeader);
    const findings = [];
    const warnings = [];

    // Evaluasi directive yang ADA di header
    for (const [name, values] of directiveMap.entries()) {
      const finding = this.evaluateDirective(name, values);
      findings.push(finding);

      for (let i = 0; i < finding.riskyKeywordsFound.length; i++) {
        warnings.push({
          directive: name,
          keyword: finding.riskyKeywordsFound[i],
          severity: finding._riskySeverities[i],
          explanation: this._explainKeyword(finding.riskyKeywordsFound[i]),
        });
      }
    }

    // Cek directive WAJIB yang hilang dari header
    for (const requiredName of this.ruleSet.requiredDirectives) {
      if (!directiveMap.has(requiredName)) {
        const config = this.ruleSet.directives[requiredName];
        // PENTING (perbaikan Temuan #1): contributionScore dihitung via
        // ScoreEngine memakai missingDirectivePenaltyRatio dari config,
        // BUKAN hardcode 0 — supaya field ini benar-benar data-driven
        // (sebelumnya nilai di JSON ini tidak pernah dibaca sama sekali).
        const contributionScore = config
          ? this.scoreEngine.applyPenalty(config.weight, [{
              keyword: '-',
              severity: Severity.HIGH,
              penaltyRatio: this.ruleSet.missingDirectivePenaltyRatio,
            }])
          : 0;

        findings.push({
          directive: requiredName,
          values: [],
          present: false,
          riskyKeywordsFound: [],
          contributionScore,
        });
        warnings.push({
          directive: requiredName,
          keyword: '-',
          severity: Severity.HIGH,
          explanation: `Directive wajib "${requiredName}" tidak ditemukan pada header CSP.`,
        });
      }
    }

    const score = this.scoreEngine.calculateCSPScore(findings);

    return createCSPResult({ score, cspFound: true, findings, warnings });
  }

  /**
   * Menerjemahkan keyword teknis menjadi penjelasan bahasa manusia untuk
   * ditampilkan ke pengguna (FR-06: "Berikan penjelasan mengapa berbahaya").
   *
   * @param {string} keyword
   * @returns {string}
   */
  _explainKeyword(keyword) {
    const explanations = {
      'unsafe-inline': 'Mengizinkan eksekusi script/style inline, membuka celah utama untuk XSS.',
      'unsafe-eval': 'Mengizinkan eval() dan sejenisnya, mempermudah eksekusi kode dari string.',
      '*': 'Wildcard mengizinkan sumber dari domain manapun, menghilangkan proteksi origin.',
      'data:': 'Mengizinkan skema data: yang dapat menyisipkan konten tanpa validasi origin.',
      'blob:': 'Mengizinkan skema blob: yang dapat disalahgunakan untuk memuat konten dinamis.',
      'http:': 'Mengizinkan sumber tanpa enkripsi (non-HTTPS), rentan man-in-the-middle.',
    };
    return explanations[keyword] || `Wildcard subdomain "${keyword}" memperluas cakupan sumber yang dipercaya.`;
  }
}
