/**
 * RiskLevel.js
 *
 * Fungsi: Mendefinisikan enum tingkat risiko yang dipakai secara konsisten
 * di seluruh domain layer (CSPAnalyzer, ScriptAnalyzer, RiskCalculator) dan
 * presentation layer (UIRenderer, untuk menentukan warna badge).
 *
 * Alur kerja: Diimpor sebagai konstanta, tidak pernah dibuat instance baru.
 * Menggunakan Object.freeze agar immutable (mencegah mutasi tidak sengaja
 * di tempat lain dalam kode).
 */

export const RiskLevel = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
});

/**
 * Severity dipakai untuk temuan individual (per-finding), sedikit berbeda
 * konteks dengan RiskLevel yang dipakai untuk skor akhir agregat.
 * Dipisah agar tidak tercampur maknanya saat dibaca ulang di masa depan.
 */
export const Severity = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
});

/**
 * Kategori Likelihood (khusus 3 tingkat, TIDAK ada CRITICAL — sesuai OWASP
 * Risk Rating Methodology, "likelihood" murni probabilitas 0-1, dibagi 3
 * pita: Low/Medium/High, berbeda dari Impact yang punya 4 pita termasuk
 * Critical karena mengukur besaran dampak, bukan probabilitas).
 */
export const LikelihoodCategory = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
});

/** Kategori Impact — 4 tingkat, sama seperti Severity. */
export const ImpactCategory = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
});

/**
 * Menentukan RiskLevel berdasarkan skor akhir (0-100) dan ambang batas
 * yang dikonfigurasi. Fungsi generik — dipakai untuk bucketing Likelihood
 * MAUPUN Impact, bukan cuma RiskLevel akhir (nama dipertahankan untuk
 * backward-compat dengan kode yang sudah ada).
 *
 * PENTING (kontrak implisit): key di objek `thresholds` HARUS ditulis di
 * config JSON dengan urutan `maxScore` MENAIK (ascending) — fungsi ini
 * mengecek key sesuai urutan iterasi objek (insertion order di JS untuk
 * string key), bukan mengurutkan ulang secara otomatis. Lihat
 * likelihoodThresholds/impactThresholds di weights.json sebagai contoh
 * urutan yang benar.
 *
 * @param {number} score - skor 0-100
 * @param {object} thresholds - objek dengan key kategori dan {maxScore},
 *   HARUS terurut ascending berdasarkan maxScore
 * @returns {string} nama kategori (key thresholds) yang cocok
 */
export function riskLevelFromScore(score, thresholds) {
  const categories = Object.keys(thresholds);
  for (const category of categories) {
    if (score <= thresholds[category].maxScore) return category;
  }
  return categories[categories.length - 1];
}

/**
 * Alias eksplisit dari riskLevelFromScore, dipakai khusus untuk kategorisasi
 * Likelihood/Impact di model skoring baru (implementasi framing OWASP Risk
 * Rating Methodology) — nama fungsi lebih jelas maksudnya di titik pemanggilan.
 *
 * @param {number} score - skor 0-100
 * @param {object} thresholds - objek dengan key kategori dan {maxScore}
 * @returns {string}
 */
export function categoryFromScore(score, thresholds) {
  return riskLevelFromScore(score, thresholds);
}
