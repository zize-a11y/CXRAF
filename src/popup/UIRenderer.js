/**
 * UIRenderer.js
 *
 * Fungsi: Presentation layer class yang merangkai komponen (ScoreBadge,
 * FindingCard, ThemeToggle) menjadi tampilan popup lengkap berdasarkan
 * FinalReport. Satu-satunya class yang menyentuh elemen root #app secara
 * langsung — PopupController tidak pernah memanipulasi DOM sendiri.
 *
 * PRINSIP KEAMANAN (NFR-02): seluruh method di file ini membangun elemen
 * via document.createElement/textContent, TIDAK PERNAH memakai innerHTML,
 * insertAdjacentHTML, atau document.write — karena ironis jika tool
 * pendeteksi XSS sendiri rentan terhadap pola yang sama.
 */

import { createScoreBadge } from './components/ScoreBadge.js';
import { createFindingCard } from './components/FindingCard.js';
import { createThemeToggle } from './components/ThemeToggle.js';

export class UIRenderer {
  /** @param {HTMLElement} rootEl - elemen container utama, mis. document.getElementById('app') */
  constructor(rootEl) {
    this.root = rootEl;
  }

  /** Mengosongkan root sebelum render ulang (dipanggil di awal tiap render method). */
  _clear() {
    while (this.root.firstChild) this.root.removeChild(this.root.firstChild);
  }

  /**
   * Menampilkan state loading saat menunggu hasil analisis dari background.
   * @returns {void}
   */
  renderLoading() {
    this._clear();
    const el = document.createElement('div');
    el.className = 'loading-state';
    el.textContent = 'Menganalisis halaman…';
    this.root.appendChild(el);
  }

  /**
   * Menampilkan pesan error jika analisis gagal (mis. halaman chrome://
   * yang tidak bisa di-inject content script).
   * @param {string} message
   * @returns {void}
   */
  renderError(message) {
    this._clear();
    const el = document.createElement('div');
    el.className = 'loading-state';
    el.textContent = `Analisis tidak dapat dijalankan: ${message}`;
    this.root.appendChild(el);
  }

  /**
   * Menerapkan tema ke root <html>. Dipisah dari toggleTheme() di
   * PopupController supaya UIRenderer tetap fokus hanya urusan render,
   * bukan penyimpanan preferensi.
   * @param {string} theme - "dark" | "light"
   * @returns {void}
   */
  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  /**
   * Render utama: header domain + toggle tema, gauge skor, chip ringkasan,
   * daftar temuan, daftar rekomendasi, dan footer aksi.
   *
   * @param {import('../models/FinalReport.js').FinalReport} report
   * @param {{ theme: string, onThemeToggle: (t: string) => void,
   *           onHistoryClick: () => void, onExportClick: () => void }} options
   * @returns {void}
   */
  renderReport(report, { theme, onThemeToggle, onHistoryClick, onExportClick }) {
    this._clear();

    const children = [
      this._buildHeader(report.domain, theme, onThemeToggle),
      createScoreBadge(report.finalScore, report.riskLevel),
    ];

    if (report.truncated) {
      children.push(this._buildTruncatedNotice());
    }

    children.push(
      this._buildChipRow(report),
      this._buildFindingsSection(report),
      this._buildRecommendationsSection(report),
      this._buildFooter(onHistoryClick, onExportClick)
    );

    this.root.append(...children);
  }

  /** @private */
  _buildTruncatedNotice() {
    const notice = document.createElement('div');
    notice.className = 'empty-state';
    notice.style.margin = '0 16px 12px';
    notice.style.color = 'var(--risk-medium)';
    notice.style.borderColor = 'var(--risk-medium)';
    notice.textContent = 'Halaman ini memiliki jumlah script/atribut yang sangat banyak — sebagian tidak dianalisis demi menjaga performa.';
    return notice;
  }

  /** @private */
  _buildHeader(domain, theme, onThemeToggle) {
    const header = document.createElement('div');
    header.className = 'app-header';

    const domainWrap = document.createElement('div');
    domainWrap.className = 'app-header__domain';

    const dot = document.createElement('span');
    dot.className = 'app-header__dot';

    const domainText = document.createElement('span');
    domainText.className = 'app-header__domain-text';
    domainText.textContent = domain || 'Halaman tidak dikenal';

    domainWrap.append(dot, domainText);

    const toggle = createThemeToggle(theme, (nextTheme) => {
      this.applyTheme(nextTheme);
      onThemeToggle(nextTheme);
      header.replaceWith(this._buildHeader(domain, nextTheme, onThemeToggle));
    });

    header.append(domainWrap, toggle);
    return header;
  }

  /** @private */
  _buildChipRow(report) {
    const row = document.createElement('div');
    row.className = 'chip-row';

    const chips = [
      { label: 'Skor CSP', value: report.cspScore },
      { label: 'Warning', value: report.cspWarnings.length },
      { label: 'Script Berisiko', value: report.scriptFindings.length },
    ];

    for (const c of chips) {
      const chip = document.createElement('div');
      chip.className = 'chip';

      const value = document.createElement('div');
      value.className = 'chip__value font-mono';
      value.textContent = String(c.value);

      const label = document.createElement('div');
      label.className = 'chip__label';
      label.textContent = c.label;

      chip.append(value, label);
      row.appendChild(chip);
    }
    return row;
  }

  /** @private */
  _buildFindingsSection(report) {
    const section = document.createElement('div');
    section.className = 'section';

    const title = document.createElement('h2');
    title.className = 'section__title';
    title.textContent = 'Temuan';

    const list = document.createElement('div');
    list.className = 'section__list';

    const allFindings = [
      ...report.cspWarnings.map((w) => ({
        title: w.keyword === '-' ? `Directive "${w.directive}" bermasalah` : `${w.keyword} pada ${w.directive}`,
        severity: w.severity,
        description: w.explanation,
      })),
      ...report.scriptFindings.map((f) => ({
        title: f.sinkId.startsWith('event-handler:') ? `Atribut ${f.sinkId.split(':')[1]} inline` : `Sink "${f.sinkId}" terdeteksi`,
        severity: f.severity,
        description: `${f.description} — cuplikan: ${f.matchedText}`,
        confidence: f.confidence,
      })),
    ];

    if (allFindings.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'Tidak ada temuan berisiko pada halaman ini.';
      list.appendChild(empty);
    } else {
      for (const finding of allFindings) {
        list.appendChild(createFindingCard(finding));
      }
    }

    section.append(title, list);
    return section;
  }

  /** @private */
  _buildRecommendationsSection(report) {
    const section = document.createElement('div');
    section.className = 'section';

    const title = document.createElement('h2');
    title.className = 'section__title';
    title.textContent = 'Rekomendasi';

    if (report.recommendations.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'Tidak ada rekomendasi — konfigurasi sudah baik.';
      section.append(title, empty);
      return section;
    }

    const sorted = [...report.recommendations].sort((a, b) => {
      const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
      return order[a.priority] - order[b.priority];
    });

    for (const rec of sorted) {
      const item = document.createElement('div');
      item.className = 'recommendation-item';

      const priorityBar = document.createElement('span');
      priorityBar.className = 'recommendation-item__priority';
      priorityBar.style.background =
        rec.priority === 'HIGH' ? 'var(--risk-high)' : rec.priority === 'LOW' ? 'var(--risk-low)' : 'var(--risk-medium)';

      const text = document.createElement('span');
      text.textContent = rec.suggestion;

      item.append(priorityBar, text);
      section.appendChild(item);
    }
    return section;
  }

  /**
   * Menampilkan daftar riwayat analisis untuk domain aktif (UC-08).
   *
   * @param {import('../models/FinalReport.js').FinalReport[]} history
   * @param {() => void} onBack - kembali ke tampilan laporan terakhir
   * @returns {void}
   */
  renderHistory(history, onBack) {
    this._clear();

    const section = document.createElement('div');
    section.className = 'section';
    section.style.paddingTop = '16px';

    const title = document.createElement('h2');
    title.className = 'section__title';
    title.textContent = 'Riwayat Analisis';

    const list = document.createElement('div');
    list.className = 'section__list';

    if (history.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'Belum ada riwayat untuk domain ini.';
      list.appendChild(empty);
    } else {
      for (const entry of history) {
        const row = document.createElement('div');
        row.className = 'finding-card';
        row.style.padding = '8px 10px';

        const date = new Date(entry.timestamp).toLocaleString('id-ID');
        const line1 = document.createElement('div');
        line1.className = 'finding-card__title';
        line1.textContent = `${date} — Skor ${entry.finalScore} (${entry.riskLevel})`;

        row.appendChild(line1);
        list.appendChild(row);
      }
    }

    const backBtn = document.createElement('button');
    backBtn.className = 'footer-btn';
    backBtn.type = 'button';
    backBtn.textContent = '← Kembali ke hasil analisis';
    backBtn.style.margin = '12px 16px 0';
    backBtn.addEventListener('click', onBack);

    section.append(title, list);
    this.root.append(section, backBtn);
  }

  /** @private */
  _buildFooter(onHistoryClick, onExportClick) {
    const footer = document.createElement('div');
    footer.className = 'app-footer';

    const historyBtn = document.createElement('button');
    historyBtn.className = 'footer-btn';
    historyBtn.type = 'button';
    historyBtn.textContent = 'Riwayat';
    historyBtn.addEventListener('click', onHistoryClick);

    const exportBtn = document.createElement('button');
    exportBtn.className = 'footer-btn footer-btn--primary';
    exportBtn.type = 'button';
    exportBtn.textContent = 'Ekspor JSON';
    exportBtn.addEventListener('click', onExportClick);

    footer.append(historyBtn, exportBtn);
    return footer;
  }
}
