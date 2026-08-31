/**
 * ScoreBadge.js
 *
 * Fungsi: Membangun elemen "signature" popup ini — gauge lingkaran (SVG arc)
 * yang menunjukkan skor akhir 0-100, plus pill teks level risiko di
 * bawahnya. Seluruh elemen dibuat via DOM API (createElementNS/createElement),
 * BUKAN innerHTML, sesuai NFR-02 (extension tidak boleh punya celah yang
 * sama dengan yang ia audit di situs lain).
 *
 * Parameter & return value didokumentasikan per fungsi di bawah.
 */

const RADIUS = 54;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const RISK_LABEL = {
  CRITICAL: 'Kritis',
  HIGH: 'Berisiko Tinggi',
  MEDIUM: 'Sedang',
  LOW: 'Aman',
};

/**
 * Membuat elemen SVG dengan namespace yang benar (createElementNS wajib
 * untuk elemen SVG, berbeda dari createElement biasa).
 *
 * @param {string} tag - nama tag SVG, mis. "circle"
 * @param {object} attrs - pasangan atribut yang di-set via setAttribute
 * @returns {SVGElement}
 */
function svgEl(tag, attrs) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attrs)) {
    el.setAttribute(key, value);
  }
  return el;
}

/**
 * Membangun keseluruhan komponen ScoreBadge (gauge + angka + pill risiko).
 *
 * @param {number} score - skor akhir 0-100
 * @param {string} riskLevel - salah satu RiskLevel ("LOW"|"MEDIUM"|"HIGH"|"CRITICAL")
 * @returns {HTMLElement} elemen <div class="score-section"> siap di-append ke DOM
 */
export function createScoreBadge(score, riskLevel) {
  const container = document.createElement('div');
  container.className = 'score-section';

  const gaugeWrapper = document.createElement('div');
  gaugeWrapper.className = 'score-gauge';

  const svg = svgEl('svg', { viewBox: '0 0 128 128', width: '128', height: '128' });

  const track = svgEl('circle', {
    class: 'score-gauge__track',
    cx: 64, cy: 64, r: RADIUS,
  });

  const clampedScore = Math.max(0, Math.min(100, score));
  const offset = CIRCUMFERENCE * (1 - clampedScore / 100);

  const arc = svgEl('circle', {
    class: 'score-gauge__arc',
    cx: 64, cy: 64, r: RADIUS,
    // PENTING: stroke-dasharray/dashoffset di-set sebagai atribut SVG biasa
    // (bukan lewat "style"), karena setAttribute('style', ...) diblokir oleh
    // CSP style-src 'self' yang kita kunci di manifest.json (Tahap 10).
    // Atribut presentasi SVG seperti ini TIDAK dianggap "inline style" oleh CSP.
    'stroke-dasharray': CIRCUMFERENCE,
    'stroke-dashoffset': offset,
  });
  // Warna stroke di-set via direct property assignment (arc.style.stroke = ...),
  // BUKAN via setAttribute('style', ...) — ini yang membedakan CSP-safe vs
  // diblokir. Lihat MDN: "styles properties set directly on the element's
  // style property will not be blocked" oleh CSP style-src.
  arc.style.stroke = `var(--risk-${riskLevel.toLowerCase()})`;

  svg.append(track, arc);

  const label = document.createElement('div');
  label.className = 'score-gauge__label';

  const number = document.createElement('div');
  number.className = 'score-gauge__number font-mono';
  number.textContent = String(clampedScore);

  const suffix = document.createElement('div');
  suffix.className = 'score-gauge__suffix';
  suffix.textContent = '/ 100';

  label.append(number, suffix);
  gaugeWrapper.append(svg, label);

  const pill = document.createElement('div');
  pill.className = 'risk-pill';
  pill.style.color = `var(--risk-${riskLevel.toLowerCase()})`;
  pill.style.background = `var(--risk-${riskLevel.toLowerCase()}-soft)`;
  pill.textContent = RISK_LABEL[riskLevel] ?? riskLevel;

  container.append(gaugeWrapper, pill);
  return container;
}
