import { SourceSinkTracer } from "../tracer/SourceSinkTracer.js";
import sinkPatterns from "../config/sink-patterns.json" with { type: "json" };

const tracer = new SourceSinkTracer(sinkPatterns);

const tests = [
  {
    id: "DIRECT",
    description: "location.hash langsung ke innerHTML",
    code: `
      element.innerHTML = location.hash;
    `,
    expected: true,
    expectedConfidence: 0.9,
    expectedSource: "location-hash",
    expectedSink: "inner-html",
  },

  {
    id: "INDIRECT-1-HOP",
    description: "location.hash → variabel → innerHTML",
    code: `
      const userData = location.hash;
      element.innerHTML = userData;
    `,
    expected: true,
    expectedConfidence: 0.65,
    expectedSource: "location-hash",
    expectedSink: "inner-html",
  },

  {
    id: "NO-SOURCE-SINK",
    description: "innerHTML tanpa source terdeteksi",
    code: `
      element.innerHTML = "Hello World";
    `,
    expected: false,
  },

  {
    id: "SAFE-TEXTCONTENT",
    description: "location.hash ke textContent",
    code: `
      element.textContent = location.hash;
    `,
    expected: false,
  },

  {
    id: "INDIRECT-2-HOP",
    description: "location.hash → x → y → innerHTML",
    code: `
      const x = location.hash;
      const y = x;
      element.innerHTML = y;
    `,
    expected: false,
  },

  {
    id: "DIRECT-EVAL",
    description: "location.hash langsung ke eval",
    code: `
      eval(location.hash);
    `,
    expected: true,
    expectedConfidence: 0.9,
    expectedSource: "location-hash",
    expectedSink: "eval",
  },

  {
    id: "INDIRECT-EVAL",
    description: "location.hash → variabel → eval",
    code: `
      const payload = location.hash;
      eval(payload);
    `,
    expected: true,
    expectedConfidence: 0.65,
    expectedSource: "location-hash",
    expectedSink: "eval",
  },

  {
    id: "STRING-SEMICOLON",
    description: "semicolon di dalam string tidak boleh merusak tracing",
    code: `
      const message = "hello;world";
      element.innerHTML = location.hash;
    `,
    expected: true,
    expectedConfidence: 0.9,
    expectedSource: "location-hash",
    expectedSink: "inner-html",
  },
];

console.log("=== SOURCE-SINK TRACE AUDIT ===\n");

let passed = 0;
let failed = 0;

for (const test of tests) {
  let results;

  try {
    results = tracer.trace(test.code);
  } catch (error) {
    console.log(`❌ ${test.id}`);
    console.log(`   ERROR: ${error.message}\n`);
    failed++;
    continue;
  }

  const matchingResult = results.find(
    (r) =>
      (!test.expectedSource || r.sourceId === test.expectedSource) &&
      (!test.expectedSink || r.sinkId === test.expectedSink),
  );

  const detected = Boolean(matchingResult);

  let ok = detected === test.expected;

  if (test.expected && matchingResult) {
    if (matchingResult.confidence !== test.expectedConfidence) {
      ok = false;
    }
  }

  if (ok) {
    console.log(`✅ ${test.id}`);
    passed++;
  } else {
    console.log(`❌ ${test.id}`);
    failed++;
  }

  console.log(`   Deskripsi : ${test.description}`);
  console.log(`   Expected  : ${test.expected ? "TERDETEKSI" : "TIDAK TERDETEKSI"}`);
  console.log(`   Aktual    : ${detected ? "TERDETEKSI" : "TIDAK TERDETEKSI"}`);

  if (matchingResult) {
    console.log(`   Source    : ${matchingResult.sourceId}`);
    console.log(`   Sink      : ${matchingResult.sinkId}`);
    console.log(`   Tainted   : ${matchingResult.tainted}`);
    console.log(`   Confidence: ${matchingResult.confidence}`);
  }

  if (results.length > 0) {
    console.log(
      `   Semua trace: ${results
        .map((r) => `${r.sourceId} → ${r.sinkId} (${r.confidence})`)
        .join(", ")}`,
    );
  }

  console.log();
}

console.log("==============================");
console.log(`Total trace test : ${tests.length}`);
console.log(`Lulus             : ${passed}`);
console.log(`Gagal             : ${failed}`);
console.log(
  `Persentase        : ${((passed / tests.length) * 100).toFixed(2)}%`,
);
console.log("==============================");

if (failed > 0) {
  process.exit(1);
}