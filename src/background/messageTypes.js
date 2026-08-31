/**
 * messageTypes.js
 *
 * Fungsi: Mendefinisikan kontrak pesan yang bertukar antar tiga context
 * eksekusi Manifest V3 (popup, background/service worker, content script).
 * Menggunakan enum eksplisit (bukan string bebas) untuk mencegah bug
 * silent-fail akibat typo tipe pesan — sesuai desain di Tahap 2.6.
 */

export const MessageType = Object.freeze({
  /** Popup -> Background: minta hasil analisis untuk tab aktif */
  REQUEST_ANALYSIS: 'REQUEST_ANALYSIS',
  /** Background -> Popup: hasil analisis (FinalReport) */
  ANALYSIS_RESULT: 'ANALYSIS_RESULT',
  /** Background -> Content script: minta scan DOM dijalankan */
  SCAN_DOM: 'SCAN_DOM',
  /** Content script -> Background: hasil scan DOM */
  DOM_SCAN_RESULT: 'DOM_SCAN_RESULT',
  /** Popup -> Background: minta riwayat analisis suatu domain */
  REQUEST_HISTORY: 'REQUEST_HISTORY',
  /** Background -> Popup: daftar riwayat analisis */
  HISTORY_RESULT: 'HISTORY_RESULT',
  /** Generik: menandakan terjadi error di sisi background */
  ANALYSIS_ERROR: 'ANALYSIS_ERROR',
});
