/**
 * FindingCard.js
 *
 * Fungsi: Membangun satu kartu temuan (CSP warning ATAU script finding)
 * yang bisa di-klik untuk expand/collapse detail penjelasannya (FR-06:
 * "berikan penjelasan mengapa berbahaya"). Dibuat generik agar bisa
 * dipakai untuk kedua jenis temuan tanpa duplikasi komponen.
 */

const SEVERITY_LABEL = {
  CRITICAL: 'Kritis',
  HIGH: 'Tinggi',
  MEDIUM: 'Sedang',
  LOW: 'Rendah',
};

/**
 * @param {{ title: string, severity: string, description: string, confidence?: number }} finding
 *   - title: judul singkat, mis. "unsafe-inline pada script-src" atau "eval() terdeteksi"
 *   - severity: salah satu Severity
 *   - description: penjelasan lengkap mengapa ini berisiko
 *   - confidence: 0.0-1.0, opsional (hanya ada pada temuan script, bukan CSP warning) -
 *     ditampilkan sebagai persentase agar pengguna tahu seberapa yakin sistem
 *     terhadap temuan ini (implementasi Temuan #2 - Confidence Score, memisahkan
 *     dampak/severity dari keyakinan/confidence, mengikuti OWASP Risk Rating Methodology)
 * @returns {HTMLElement} elemen kartu, sudah termasuk event listener toggle
 */
export function createFindingCard(finding) {
  const card = document.createElement('div');
  card.className = 'finding-card';

  const header = document.createElement('button');
  header.className = 'finding-card__header';
  header.type = 'button';
  header.setAttribute('aria-expanded', 'false');

  const dot = document.createElement('span');
  dot.className = 'finding-card__severity-dot';
  dot.style.background = `var(--risk-${finding.severity.toLowerCase()})`;

  const title = document.createElement('span');
  title.className = 'finding-card__title';
  title.textContent = finding.title;

  const severityLabel = document.createElement('span');
  severityLabel.className = 'finding-card__severity-label';
  severityLabel.style.color = `var(--risk-${finding.severity.toLowerCase()})`;
  severityLabel.textContent = SEVERITY_LABEL[finding.severity] ?? finding.severity;

  header.append(dot, title, severityLabel);

  const body = document.createElement('div');
  body.className = 'finding-card__body';

  const descriptionEl = document.createElement('div');
  descriptionEl.textContent = finding.description;
  body.appendChild(descriptionEl);

  if (typeof finding.confidence === 'number') {
    const confidenceEl = document.createElement('div');
    confidenceEl.className = 'finding-card__confidence';
    confidenceEl.textContent = `Tingkat keyakinan: ${Math.round(finding.confidence * 100)}%`;
    body.appendChild(confidenceEl);
  }

  header.addEventListener('click', () => {
    const isExpanded = card.classList.toggle('finding-card--expanded');
    header.setAttribute('aria-expanded', String(isExpanded));
  });

  card.append(header, body);
  return card;
}
