/**
 * RiskCalculator.test.js
 *
 * REDESAIN TOTAL mengikuti model Likelihood x Impact (OWASP Risk Rating
 * Methodology). Test lama yang menguji API sebelumnya (finalScoreWeights
 * blended score, criticalConfidenceThreshold, determineRiskLevel(score,
 * criticalCount)) SUDAH TIDAK RELEVAN — diganti total dengan file ini.
 */

import { readFileSync } from "fs";
import {
  RiskCalculator,
  createCSPResult,
  createScriptResult,
} from "xss-risk-core";

const weights = JSON.parse(
  readFileSync(
    new URL(
      "../../packages/xss-risk-core/config/weights.json",
      import.meta.url,
    ),
  ),
);

describe("RiskCalculator (model Likelihood x Impact)", () => {
  /** @type {RiskCalculator} */
  let calculator;

  beforeEach(() => {
    calculator = new RiskCalculator(null, weights);
  });

  describe("calculateLikelihood()", () => {
    test("CSP sempurna + tanpa temuan -> Likelihood 0", () => {
      expect(calculator.calculateLikelihood(100, 0)).toBe(0);
    });

    test("CSP tidak ada + tanpa temuan -> Likelihood murni dari cspWeaknessRatio", () => {
      // (100-0)*0.6 + 0*0.4 = 60
      expect(calculator.calculateLikelihood(0, 0)).toBe(60);
    });

    test("CSP sempurna + confidence temuan tinggi -> Likelihood murni dari confidenceRatio", () => {
      // (100-100)*0.6 + (0.9*100)*0.4 = 36
      expect(calculator.calculateLikelihood(100, 0.9)).toBe(36);
    });
  });

  describe("calculateImpact()", () => {
    test("tanpa temuan -> Impact 0", () => {
      expect(calculator.calculateImpact([])).toBe(0);
    });

    test("mengambil severity TERTINGGI (worst-case), bukan rata-rata", () => {
      const findings = [
        { severity: "LOW" },
        { severity: "CRITICAL" },
        { severity: "MEDIUM" },
      ];
      expect(calculator.calculateImpact(findings)).toBe(
        weights.impactSeverityScale.CRITICAL,
      );
    });
  });

  describe("calculate() - integrasi penuh via riskMatrix", () => {
    test("CSP sempurna + tanpa temuan -> RiskLevel LOW", () => {
      const cspResult = createCSPResult({
        score: 100,
        cspFound: true,
        warnings: [],
      });
      const scriptResult = createScriptResult({ findings: [] });
      const report = calculator.calculate(cspResult, scriptResult, "aman.test");

      expect(report.likelihoodCategory).toBe("LOW");
      expect(report.impactCategory).toBe("LOW");
      expect(report.riskLevel).toBe("LOW");
    });

    /**
     * TEST PEMBUKTIAN: dampak paling signifikan dari redesain ini —
     * CSP lemah TANPA temuan konkret TIDAK otomatis CRITICAL lagi
     * (beda dari model sebelumnya). Didokumentasikan eksplisit sebagai
     * bukti perilaku yang DISENGAJA, bukan regresi tak disadari.
     */
    test("PEMBUKTIAN: CSP tidak ada TAPI tanpa temuan konkret -> RiskLevel rendah (BUKAN otomatis CRITICAL)", () => {
      const cspResult = createCSPResult({
        score: 0,
        cspFound: false,
        warnings: [],
      });
      const scriptResult = createScriptResult({ findings: [] });
      const report = calculator.calculate(
        cspResult,
        scriptResult,
        "tanpa-csp-tanpa-temuan.test",
      );

      expect(report.likelihoodCategory).toBe("MEDIUM");
      expect(report.impactCategory).toBe("LOW");
      expect(report.riskLevel).not.toBe("CRITICAL");
    });

    test("PEMBUKTIAN: CSP sempurna TAPI ada eval() confidence tinggi -> RiskLevel tetap CRITICAL (Impact mendominasi)", () => {
      const cspResult = createCSPResult({
        score: 100,
        cspFound: true,
        warnings: [],
      });
      const scriptResult = createScriptResult({
        findings: [
          {
            sinkId: "eval",
            severity: "CRITICAL",
            confidence: 0.9,
            description: "",
            matchedText: "",
            location: "inline-script",
          },
        ],
      });
      const report = calculator.calculate(
        cspResult,
        scriptResult,
        "csp-bagus-tapi-eval.test",
      );

      expect(report.impactCategory).toBe("CRITICAL");
      expect(report.riskLevel).toBe("CRITICAL");
    });

    test("CSP tidak ada + eval() confidence tinggi -> kombinasi terburuk, RiskLevel CRITICAL", () => {
      const cspResult = createCSPResult({
        score: 0,
        cspFound: false,
        warnings: [],
      });
      const scriptResult = createScriptResult({
        findings: [
          {
            sinkId: "eval",
            severity: "CRITICAL",
            confidence: 0.9,
            description: "",
            matchedText: "",
            location: "inline-script",
          },
        ],
      });
      const report = calculator.calculate(
        cspResult,
        scriptResult,
        "terburuk.test",
      );

      expect(report.likelihoodCategory).toBe("HIGH");
      expect(report.impactCategory).toBe("CRITICAL");
      expect(report.riskLevel).toBe("CRITICAL");
    });

    test("finalScore (gauge) tetap 100=paling aman, konsisten dengan konvensi UI lama", () => {
      const cspResult = createCSPResult({
        score: 100,
        cspFound: true,
        warnings: [],
      });
      const scriptResult = createScriptResult({ findings: [] });
      const report = calculator.calculate(cspResult, scriptResult, "aman.test");
      expect(report.finalScore).toBe(100);
    });

    test("report menyertakan likelihoodScore, impactScore, likelihoodCategory, impactCategory", () => {
      const cspResult = createCSPResult({
        score: 50,
        cspFound: true,
        warnings: [],
      });
      const scriptResult = createScriptResult({ findings: [] });
      const report = calculator.calculate(cspResult, scriptResult, "x.test");

      expect(typeof report.likelihoodScore).toBe("number");
      expect(typeof report.impactScore).toBe("number");
      expect(["LOW", "MEDIUM", "HIGH"]).toContain(report.likelihoodCategory);
      expect(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).toContain(
        report.impactCategory,
      );
    });
  });

  describe("generateRecommendations()", () => {
    test("tidak menghasilkan saran duplikat untuk temuan sejenis", () => {
      const cspWarnings = [
        {
          directive: "script-src",
          keyword: "unsafe-inline",
          severity: "HIGH",
          explanation: "",
        },
        {
          directive: "style-src",
          keyword: "unsafe-inline",
          severity: "HIGH",
          explanation: "",
        },
      ];
      const recs = calculator.generateRecommendations(cspWarnings, []);
      expect(recs).toHaveLength(2); // beda directive -> tetap 2, bukan salah tergabung
    });
  });
});
