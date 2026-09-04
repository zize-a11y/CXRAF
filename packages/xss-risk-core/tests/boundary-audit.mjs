import { categoryFromScore } from "../models/RiskLevel.js";
import weights from "../config/weights.json" with { type: "json" };

console.log("=== LIKELIHOOD BOUNDARY ===");

for (const score of [0, 1, 32, 33, 34, 65, 66, 67, 99, 100]) {
  console.log(
    `Score ${score} -> ${categoryFromScore(
      score,
      weights.likelihoodThresholds,
    )}`,
  );
}

console.log("\n=== IMPACT BOUNDARY ===");

for (const score of [0, 15, 25, 26, 40, 50, 51, 70, 75, 76, 100]) {
  console.log(
    `Score ${score} -> ${categoryFromScore(
      score,
      weights.impactThresholds,
    )}`,
  );
}