import { ScriptAnalyzer } from "../analyzers/ScriptAnalyzer.js";
import { SourceSinkTracer } from "../tracer/SourceSinkTracer.js";
import sinkPatterns from "../config/sink-patterns.json" with { type: "json" };

const tracer = new SourceSinkTracer(sinkPatterns);
const analyzer = new ScriptAnalyzer(sinkPatterns, tracer);

const tests = [
  {
    id: "eval",
    code: `eval(userInput);`,
    expectedSeverity: "CRITICAL",
    expectedConfidence: 0.6,
  },
  {
    id: "function-constructor",
    code: `const fn = new Function(userInput);`,
    expectedSeverity: "CRITICAL",
    expectedConfidence: 0.6,
  },
  {
    id: "document-write",
    code: `document.write(userInput);`,
    expectedSeverity: "HIGH",
    expectedConfidence: 0.55,
  },
  {
    id: "inner-html",
    code: `element.innerHTML = userInput;`,
    expectedSeverity: "HIGH",
    expectedConfidence: 0.55,
  },
  {
    id: "outer-html",
    code: `element.outerHTML = userInput;`,
    expectedSeverity: "HIGH",
    expectedConfidence: 0.55,
  },
  {
    id: "insert-adjacent-html",
    code: `element.insertAdjacentHTML("beforeend", userInput);`,
    expectedSeverity: "HIGH",
    expectedConfidence: 0.55,
  },
  {
    id: "settimeout-string",
    code: `setTimeout("alert(userInput)", 1000);`,
    expectedSeverity: "MEDIUM",
    expectedConfidence: 0.5,
  },
  {
    id: "setinterval-string",
    code: `setInterval("alert(userInput)", 1000);`,
    expectedSeverity: "MEDIUM",
    expectedConfidence: 0.5,
  },
  {
    id: "atob",
    code: `const data = atob(userInput);`,
    expectedSeverity: "LOW",
    expectedConfidence: 0.3,
  },
  {
    id: "unescape",
    code: `const data = unescape(userInput);`,
    expectedSeverity: "LOW",
    expectedConfidence: 0.3,
  },
  {
    id: "javascript-uri",
    code: `link.href = "javascript:" + userInput;`,
    expectedSeverity: "HIGH",
    expectedConfidence: 0.5,
  },
  {
    id: "srcdoc",
    code: `iframe.srcdoc = userInput;`,
    expectedSeverity: "MEDIUM",
    expectedConfidence: 0.45,
  },
  {
    id: "event-handler",
    code: `doSomething(userInput);`,
    type: "event-handler",
    attribute: "onclick",
    expectedSeverity: "MEDIUM",
  },
];

console.log("=== SOURCE-SINK RULE AUDIT ===\n");

let passed = 0;
let failed = 0;

for (const test of tests) {
  let result;

  try {
    result = analyzer.analyze([
      {
        type: test.type ?? "inline-script",
        code: test.code,
        attribute: test.attribute,
      },
    ]);
  } catch (error) {
    console.log(`❌ ${test.id}`);
    console.log(`   ERROR: ${error.message}`);
    failed++;
    continue;
  }

  const findings = result?.findings ?? [];

  const finding = findings.find(
    (f) =>
      f.sinkId === test.id ||
      f.sinkId?.startsWith(`${test.id}:`) ||
      f.sinkId?.includes(test.id),
  );

  if (!finding) {
    console.log(`❌ ${test.id}`);
    console.log("   Finding tidak ditemukan.");
    console.log(
      `   Findings aktual: ${
        findings.map((f) => f.sinkId).join(", ") || "(tidak ada)"
      }`,
    );
    failed++;
    continue;
  }

  const severityOk = finding.severity === test.expectedSeverity;

  const confidenceOk =
    test.expectedConfidence === undefined ||
    finding.confidence === test.expectedConfidence;

  const matchedTextOk =
    typeof finding.matchedText === "string" &&
    finding.matchedText.length > 0;

  const ok = severityOk && confidenceOk && matchedTextOk;

  if (ok) {
    passed++;
    console.log(`✅ ${test.id}`);
  } else {
    failed++;
    console.log(`❌ ${test.id}`);
  }

  console.log(`   sinkId     : ${finding.sinkId}`);
  console.log(`   severity   : ${finding.severity}`);
  console.log(`   confidence : ${finding.confidence}`);
  console.log(`   matched    : ${finding.matchedText}`);

  if (!severityOk) {
    console.log(
      `   Expected severity   : ${test.expectedSeverity}`,
    );
  }

  if (!confidenceOk) {
    console.log(
      `   Expected confidence : ${test.expectedConfidence}`,
    );
  }

  if (!matchedTextOk) {
    console.log(
      "   Expected matchedText : tidak kosong",
    );
  }

  console.log();
}

console.log("==============================");
console.log(`Total rule test : ${tests.length}`);
console.log(`Lulus           : ${passed}`);
console.log(`Gagal           : ${failed}`);
console.log("==============================");

if (failed > 0) {
  process.exit(1);
}