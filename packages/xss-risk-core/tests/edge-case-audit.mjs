import { RiskCalculator } from "../risk/RiskCalculator.js";
import weights from "../config/weights.json" with { type: "json" };

const calculator = new RiskCalculator(null, weights);

function makeCSPResult(score, warnings = []) {
  return {
    score,
    warnings,
  };
}

function makeScriptResult(findings = [], averageConfidence = 0) {
  return {
    findings,
    averageConfidence,
    truncated: false,
  };
}

const scenarios = [
  {
    name: "A - CSP sempurna, tidak ada finding",
    cspScore: 100,
    findings: [],
    confidence: 0,
  },
  {
    name: "B - CSP tidak ada, tidak ada finding",
    cspScore: 0,
    findings: [],
    confidence: 0,
  },
  {
    name: "C - CSP sempurna + LOW finding",
    cspScore: 100,
    findings: [
      { severity: "LOW", confidence: 0.3, sinkId: "atob" },
    ],
    confidence: 0.3,
  },
  {
    name: "D - CSP sempurna + HIGH finding",
    cspScore: 100,
    findings: [
      { severity: "HIGH", confidence: 0.55, sinkId: "inner-html" },
    ],
    confidence: 0.55,
  },
  {
    name: "E - CSP tidak ada + CRITICAL finding",
    cspScore: 0,
    findings: [
      { severity: "CRITICAL", confidence: 0.6, sinkId: "eval" },
    ],
    confidence: 0.6,
  },
  {
    name: "F - Confidence 0",
    cspScore: 50,
    findings: [
      { severity: "HIGH", confidence: 0, sinkId: "inner-html" },
    ],
    confidence: 0,
  },
  {
    name: "G - Confidence 1",
    cspScore: 50,
    findings: [
      { severity: "HIGH", confidence: 1, sinkId: "inner-html" },
    ],
    confidence: 1,
  },
  {
    name: "H - Banyak finding berbeda",
    cspScore: 50,
    findings: [
      { severity: "LOW", confidence: 0.3, sinkId: "atob" },
      { severity: "MEDIUM", confidence: 0.5, sinkId: "srcdoc" },
      { severity: "HIGH", confidence: 0.55, sinkId: "inner-html" },
      { severity: "CRITICAL", confidence: 0.6, sinkId: "eval" },
    ],
    confidence: 0.4875,
  },
  {
    name: "I - Hanya CRITICAL",
    cspScore: 80,
    findings: [
      { severity: "CRITICAL", confidence: 0.6, sinkId: "eval" },
    ],
    confidence: 0.6,
  },
  {
    name: "J - Data finding kosong",
    cspScore: 50,
    findings: [],
    confidence: 0,
  },
];

console.log("=== EDGE CASE AUDIT ===\n");

for (const scenario of scenarios) {
  const cspResult = makeCSPResult(scenario.cspScore);

  const scriptResult = makeScriptResult(
    scenario.findings,
    scenario.confidence,
  );

  const result = calculator.calculate(
    cspResult,
    scriptResult,
    "edge-case.test",
  );

  console.log(scenario.name);
  console.log(`CSP Score       : ${scenario.cspScore}`);
  console.log(`Likelihood      : ${result.likelihoodScore}`);
  console.log(`Likelihood Cat. : ${result.likelihoodCategory}`);
  console.log(`Impact          : ${result.impactScore}`);
  console.log(`Impact Cat.     : ${result.impactCategory}`);
  console.log(`Risk Level      : ${result.riskLevel}`);
  console.log(`Final Score     : ${result.finalScore}`);
  console.log("----------------------------------------");
}

console.log("\n=== PARAMETER BOUNDARY CHECK ===");

const boundaryCases = [
  { name: "CSP 0", cspScore: 0 },
  { name: "CSP 100", cspScore: 100 },
  { name: "CSP negatif", cspScore: -10 },
  { name: "CSP > 100", cspScore: 150 },
];

for (const test of boundaryCases) {
  const result = calculator.calculate(
    makeCSPResult(test.cspScore),
    makeScriptResult(),
    "boundary.test",
  );

  console.log(
    `${test.name.padEnd(15)} → Likelihood ${result.likelihoodScore}, Risk ${result.riskLevel}, Final ${result.finalScore}`,
  );
}

console.log("\n=== EDGE CASE AUDIT SELESAI ===");