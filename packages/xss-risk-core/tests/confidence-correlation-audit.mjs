import { ScriptAnalyzer } from "../analyzers/ScriptAnalyzer.js";
import { SourceSinkTracer } from "../tracer/SourceSinkTracer.js";
import sinkPatterns from "../config/sink-patterns.json" with { type: "json" };

const tracer = new SourceSinkTracer(sinkPatterns);
const analyzer = new ScriptAnalyzer(sinkPatterns, tracer);

const tests = [
  {
    id: "DIRECT-INNERHTML",
    description: "Confidence sink naik karena DIRECT source-sink trace",
    entry: {
      type: "inline-script",
      code: `element.innerHTML = location.hash;`,
    },
    sinkId: "inner-html",
    baseConfidence: 0.55,
    expectedConfidence: 0.9,
    expectedCorrelated: true,
  },

  {
    id: "INDIRECT-INNERHTML",
    description: "Confidence sink naik karena INDIRECT 1-hop",
    entry: {
      type: "inline-script",
      code: `
        const data = location.hash;
        element.innerHTML = data;
      `,
    },
    sinkId: "inner-html",
    baseConfidence: 0.55,
    expectedConfidence: 0.65,
    expectedCorrelated: true,
  },

  {
    id: "DIRECT-EVAL",
    description: "eval mendapat confidence DIRECT",
    entry: {
      type: "inline-script",
      code: `eval(location.hash);`,
    },
    sinkId: "eval",
    baseConfidence: 0.6,
    expectedConfidence: 0.9,
    expectedCorrelated: true,
  },

  {
    id: "INDIRECT-EVAL",
    description: "eval mendapat confidence INDIRECT 1-hop",
    entry: {
      type: "inline-script",
      code: `
        const payload = location.hash;
        eval(payload);
      `,
    },
    sinkId: "eval",
    baseConfidence: 0.6,
    expectedConfidence: 0.65,
    expectedCorrelated: true,
  },

  {
    id: "SINK-WITHOUT-SOURCE",
    description: "Sink tanpa source tidak mengalami korelasi",
    entry: {
      type: "inline-script",
      code: `element.innerHTML = "Hello World";`,
    },
    sinkId: "inner-html",
    baseConfidence: 0.55,
    expectedConfidence: 0.55,
    expectedCorrelated: false,
  },

  {
    id: "SAFE-TEXTCONTENT",
    description: "textContent bukan sink sehingga tidak ada finding",
    entry: {
      type: "inline-script",
      code: `element.textContent = location.hash;`,
    },
    sinkId: "textContent",
    expectedFinding: false,
  },

  {
    id: "EVENT-HANDLER",
    description: "Event handler tetap menggunakan confidence konfigurasi",
    entry: {
      type: "event-handler",
      code: `doSomething(location.hash);`,
      attribute: "onclick",
    },
    sinkId: "event-handler:onclick",
    baseConfidence: 0.4,
    expectedConfidence: 0.4,
    expectedCorrelated: false,
  },
];

console.log("=== CONFIDENCE CORRELATION AUDIT ===\n");

let passed = 0;
let failed = 0;

for (const test of tests) {
  try {
    const result = analyzer.analyze([test.entry]);
    const findings = result.findings ?? [];

    const finding = findings.find(
      (f) => f.sinkId === test.sinkId,
    );

    // Test yang memang tidak seharusnya menghasilkan finding.
    if (test.expectedFinding === false) {
      if (!finding) {
        console.log(`✅ ${test.id}`);
        console.log("   Finding : tidak ada");
        console.log("   Sesuai  : textContent tidak dikategorikan sebagai sink.");
        passed++;
      } else {
        console.log(`❌ ${test.id}`);
        console.log(`   Finding tidak diharapkan, tetapi ditemukan: ${finding.sinkId}`);
        failed++;
      }

      console.log();
      continue;
    }

    if (!finding) {
      console.log(`❌ ${test.id}`);
      console.log(`   Finding ${test.sinkId} tidak ditemukan.`);
      failed++;
      console.log();
      continue;
    }

    const confidenceOk =
      finding.confidence === test.expectedConfidence;

    const correlationOk =
      Boolean(finding.correlatedWithSource) ===
      test.expectedCorrelated;

    const ok = confidenceOk && correlationOk;

    if (ok) {
      console.log(`✅ ${test.id}`);
      passed++;
    } else {
      console.log(`❌ ${test.id}`);
      failed++;
    }

    console.log(`   Sink ID              : ${finding.sinkId}`);
    console.log(`   Base confidence      : ${test.baseConfidence}`);
    console.log(`   Actual confidence    : ${finding.confidence}`);
    console.log(`   Expected confidence  : ${test.expectedConfidence}`);
    console.log(`   correlatedWithSource : ${finding.correlatedWithSource ?? false}`);
    console.log(`   Expected correlation : ${test.expectedCorrelated}`);

    if (!confidenceOk) {
      console.log(
        `   ❌ Confidence tidak sesuai.`,
      );
    }

    if (!correlationOk) {
      console.log(
        `   ❌ Status korelasi tidak sesuai.`,
      );
    }

    console.log();
  } catch (error) {
    console.log(`❌ ${test.id}`);
    console.log(`   ERROR: ${error.message}`);
    failed++;
    console.log();
  }
}

console.log("==============================");
console.log(`Total correlation test : ${tests.length}`);
console.log(`Lulus                   : ${passed}`);
console.log(`Gagal                   : ${failed}`);
console.log(
  `Persentase              : ${((passed / tests.length) * 100).toFixed(2)}%`,
);
console.log("==============================");

if (failed > 0) {
  process.exit(1);
}