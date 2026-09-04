import { RiskCalculator } from "../risk/RiskCalculator.js";
import weights from "../config/weights.json" with { type: "json" };

const calculator = new RiskCalculator(null, weights);

const cases = [
  {
    name: "A - CSP kuat, tidak ada finding",
    cspScore: 100,
    findings: [],
  },
  {
    name: "B - CSP tidak ada, tidak ada finding",
    cspScore: 0,
    findings: [],
  },
  {
    name: "C - CSP sedang, LOW finding",
    cspScore: 50,
    findings: [
      {
        severity: "LOW",
        confidence: 0.3,
      },
    ],
  },
  {
    name: "D - CSP sedang, HIGH finding",
    cspScore: 50,
    findings: [
      {
        severity: "HIGH",
        confidence: 0.55,
      },
    ],
  },
  {
    name: "E - CSP sedang, CRITICAL finding",
    cspScore: 50,
    findings: [
      {
        severity: "CRITICAL",
        confidence: 0.6,
      },
    ],
  },
  {
    name: "F - CSP tidak ada, CRITICAL finding",
    cspScore: 0,
    findings: [
      {
        severity: "CRITICAL",
        confidence: 0.6,
      },
    ],
  },
];

for (const test of cases) {
  const scriptResult = {
    findings: test.findings,
    averageConfidence:
      test.findings.length === 0
        ? 0
        : test.findings.reduce(
            (sum, finding) => sum + finding.confidence,
            0,
          ) / test.findings.length,
  };

  const cspResult = {
    score: test.cspScore,
    warnings: [],
  };

  const report = calculator.calculate(
    cspResult,
    scriptResult,
    "test.example",
  );

  console.log("\n========================================");
  console.log(test.name);
  console.log("========================================");
  console.log("CSP Score       :", report.cspScore);
  console.log("Likelihood      :", report.likelihoodScore);
  console.log("Likelihood Cat. :", report.likelihoodCategory);
  console.log("Impact          :", report.impactScore);
  console.log("Impact Cat.     :", report.impactCategory);
  console.log("Risk Level      :", report.riskLevel);
  console.log("Final Score     :", report.finalScore);
}