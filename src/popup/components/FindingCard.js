const SEVERITY_LABEL = {
  CRITICAL: "Kritis",
  HIGH: "Tinggi",
  MEDIUM: "Sedang",
  LOW: "Rendah",
};

export function createFindingCard(finding) {
  const card = document.createElement("div");
  card.className = "finding-card";

  const header = document.createElement("div");
  header.className = "finding-card__header";
  header.setAttribute("role", "button");
  header.setAttribute("tabindex", "0");
  header.setAttribute("aria-expanded", "false");

  const dot = document.createElement("span");
  dot.className = "finding-card__severity-dot";

  const severityKey = String(finding.severity ?? "LOW").toUpperCase();
  const severity = severityKey.toLowerCase();

  dot.style.background = `var(--risk-${severity})`;

  const title = document.createElement("span");
  title.className = "finding-card__title";
  title.textContent = finding.title ?? "Temuan tidak diketahui";

  const severityLabel = document.createElement("span");
  severityLabel.className = "finding-card__severity-label";
  severityLabel.style.color = `var(--risk-${severity})`;
  severityLabel.textContent = SEVERITY_LABEL[severityKey] ?? severityKey;

  console.log("FINDING CARD:", {
    title: finding.title,
    severity: finding.severity,
    description: finding.description,
    matchedText: finding.matchedText,
  });

  header.append(dot, title, severityLabel);
  header.append(dot, title);

  if (finding.count > 1) {
    const count = document.createElement("span");

    count.className = "finding-card__count";
    count.textContent = `${finding.count}×`;

    header.appendChild(count);
  }

  header.appendChild(severityLabel);

  const body = document.createElement("div");
  body.className = "finding-card__body";

  const description = document.createElement("div");
  description.textContent = finding.description ?? "Tidak ada penjelasan.";
  body.appendChild(description);

  if (finding.matchedText) {
    const matched = document.createElement("div");
    matched.className = "finding-card__matched";
    matched.textContent = `Cuplikan: ${finding.matchedText}`;
    body.appendChild(matched);
  }

  if (typeof finding.confidence === "number") {
    const confidence = document.createElement("div");
    confidence.className = "finding-card__confidence";
    confidence.textContent = `Tingkat keyakinan: ${Math.round(finding.confidence * 100)}%`;
    body.appendChild(confidence);
  }

  header.addEventListener("click", () => {
    const expanded = card.classList.toggle("finding-card--expanded");
    header.setAttribute("aria-expanded", String(expanded));
  });

  card.append(header, body);

  return card;
}
