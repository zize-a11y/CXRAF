import weights from "../config/weights.json" with { type: "json" };

const likelihoodCategories = ["LOW", "MEDIUM", "HIGH"];
const impactCategories = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

console.log("=== RISK MATRIX AUDIT ===\n");

let total = 0;
let passed = 0;

for (const likelihood of likelihoodCategories) {
  for (const impact of impactCategories) {
    const result = weights.riskMatrix[likelihood][impact];

    total++;

    if (result) {
      passed++;
      console.log(
        `${likelihood.padEnd(7)} × ${impact.padEnd(8)} → ${result}`,
      );
    } else {
      console.log(
        `${likelihood.padEnd(7)} × ${impact.padEnd(8)} → INVALID`,
      );
    }
  }
}

console.log("\n==========================");
console.log(`Total kombinasi : ${total}`);
console.log(`Lulus           : ${passed}`);
console.log(`Gagal           : ${total - passed}`);
console.log("==========================");

if (passed !== total) {
  process.exit(1);
}