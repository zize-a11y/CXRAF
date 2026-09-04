import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { CSPAnalyzer } from "../analyzers/CSPAnalyzer.js";
import { ScoreEngine } from "../risk/ScoreEngine.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rulesPath = path.join(__dirname, "../config/csp-rules.json");
const weightsPath = path.join(__dirname, "../config/weights.json");

const cspRules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
const weights = JSON.parse(fs.readFileSync(weightsPath, "utf8"));

const scoreEngine = new ScoreEngine(weights);
const analyzer = new CSPAnalyzer(cspRules, scoreEngine);

const cases = [
  {
    name: "NO-CSP",
    csp: null,
    expect: {
      score: cspRules.cspNotFoundScore,
      warningSeverity: "CRITICAL",
    },
  },
  {
    name: "EMPTY-CSP",
    csp: "",
    expect: {
      score: cspRules.cspNotFoundScore,
      warningSeverity: "CRITICAL",
    },
  },
 {
  name: "STRONG-CSP",
  csp: [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
  ].join("; "),
  expectNoWarnings: true,
},
  {
    name: "UNSAFE-INLINE",
    csp: "script-src 'self' 'unsafe-inline'",
    expectKeyword: "unsafe-inline",
  },
  {
    name: "UNSAFE-EVAL",
    csp: "script-src 'self' 'unsafe-eval'",
    expectKeyword: "unsafe-eval",
  },
  {
    name: "WILDCARD",
    csp: "script-src *",
    expectKeyword: "*",
  },
  {
    name: "WILDCARD-SUBDOMAIN",
    csp: "script-src *.example.com",
    expectKeyword: "*.example.com",
  },
  {
    name: "MISSING-REQUIRED-DIRECTIVE",
    csp: "default-src 'self'",
    expectHighWarning: true,
  },
];

let passed = 0;
let failed = 0;

console.log("=== CSP RULE AUDIT ===");

for (const test of cases) {
  try {
    const result = analyzer.analyze(test.csp);

    let ok = true;

    if (
      test.expect?.score !== undefined &&
      result.score !== test.expect.score
    ) {
      ok = false;
    }

    if (test.expect?.warningSeverity) {
      const found = result.warnings.some(
        (w) => w.severity === test.expect.warningSeverity
      );

      if (!found) ok = false;
    }

    if (test.expectNoWarnings && result.warnings.length > 0) {
      ok = false;
    }

    if (test.expectKeyword) {
      const found = result.warnings.some(
        (w) => w.keyword === test.expectKeyword
      );

      if (!found) ok = false;
    }

    if (test.expectHighWarning) {
      const found = result.warnings.some(
        (w) => w.severity === "HIGH"
      );

      if (!found) ok = false;
    }

    if (ok) {
      passed++;
      console.log(`✅ ${test.name}`);
    } else {
      failed++;
      console.log(`❌ ${test.name}`);
      console.log(`   CSP Score : ${result.score}`);
      console.log(
        `   Warnings : ${result.warnings.length}`
      );
      console.log(
        "   Detail   :",
        result.warnings
          .map(
            (w) =>
              `${w.directive}/${w.keyword}/${w.severity}`
          )
          .join(", ")
      );
    }
  } catch (error) {
    failed++;
    console.log(`❌ ${test.name}`);
    console.log(`   ERROR: ${error.message}`);
  }
}

const total = passed + failed;
const percentage = total
  ? ((passed / total) * 100).toFixed(2)
  : "0.00";

console.log(`Total CSP test : ${total}`);
console.log(`Lulus          : ${passed}`);
console.log(`Gagal          : ${failed}`);
console.log(`Persentase     : ${percentage}%`);