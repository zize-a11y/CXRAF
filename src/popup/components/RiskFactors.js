/**
 * RiskFactors.js
 *
 * Fungsi: Menampilkan dua faktor utama penilaian risiko:
 * Likelihood (Kemungkinan) dan Impact (Dampak).
 *
 * Komponen ini hanya presentation layer.
 * Tidak melakukan perhitungan risiko.
 */

const CATEGORY_LABEL = {
  LOW: "Rendah",
  MEDIUM: "Sedang",
  HIGH: "Tinggi",
  CRITICAL: "Kritis",
};

function createFactorCard(title, score, category) {
  const card = document.createElement("div");
  card.className = "risk-factor-card";

  const titleEl = document.createElement("div");
  titleEl.className = "risk-factor-card__title";
  titleEl.textContent = title;

  const categoryEl = document.createElement("div");
  categoryEl.className = "risk-factor-card__category";
  categoryEl.textContent = CATEGORY_LABEL[category] ?? category;

  const scoreEl = document.createElement("div");
  scoreEl.className = "risk-factor-card__score font-mono";
  scoreEl.textContent = `${score} / 100`;

  card.append(titleEl, categoryEl, scoreEl);

  return card;
}

/**
 * @param {number} likelihoodScore
 * @param {string} likelihoodCategory
 * @param {number} impactScore
 * @param {string} impactCategory
 * @returns {HTMLElement}
 */
export function createRiskFactors(
  likelihoodScore,
  likelihoodCategory,
  impactScore,
  impactCategory,
) {
  const section = document.createElement("div");
  section.className = "risk-factors";

  const heading = document.createElement("div");
  heading.className = "risk-factors__heading";
  heading.textContent = "Faktor Risiko";

  const row = document.createElement("div");
  row.className = "risk-factors__row";

  row.append(
    createFactorCard("Kemungkinan", likelihoodScore, likelihoodCategory),
    createFactorCard("Dampak", impactScore, impactCategory),
  );

  section.append(heading, row);

  return section;
}
