/**
 * PopupController.js
 *
 * Fungsi: Presentation layer controller yang menjadi orkestrator SISI popup
 * (bukan sisi background — jangan tertukar dengan AnalysisOrchestrator).
 * Tanggung jawabnya: mengambil info tab aktif, meminta analisis ke
 * background lewat message passing, dan mendelegasikan seluruh rendering
 * ke UIRenderer (controller ini TIDAK PERNAH menyentuh DOM secara langsung).
 */

import { MessageType } from '../background/messageTypes.js';

export class PopupController {
  /**
   * @param {import('./UIRenderer.js').UIRenderer} uiRenderer
   * @param {import('../services/StorageService.js').StorageService} storageService
   */
  constructor(uiRenderer, storageService) {
    this.uiRenderer = uiRenderer;
    this.storageService = storageService;
    /** @type {import('../models/FinalReport.js').FinalReport|null} */
    this._lastReport = null;
    this._domain = '';
  }

  /**
   * Dipanggil sekali saat popup dibuka (DOMContentLoaded). Menerapkan tema
   * tersimpan, lalu memulai proses analisis tab aktif.
   * @returns {Promise<void>}
   */
  async init() {
    const preferences = await this.storageService.getPreferences();
    this.uiRenderer.applyTheme(preferences.theme);

    this.uiRenderer.renderLoading();
    await this.onPopupOpen();
  }

  /**
   * Mengambil tab aktif, mengirim REQUEST_ANALYSIS ke background, lalu
   * merender hasilnya (atau error jika gagal, mis. halaman chrome://).
   * @returns {Promise<void>}
   */
  async onPopupOpen() {
    const tab = await this._getActiveTab();
    if (!tab || !tab.url || !tab.url.startsWith('http')) {
      this.uiRenderer.renderError('halaman ini bukan halaman web biasa (http/https).');
      return;
    }

    this._domain = new URL(tab.url).hostname;

    try {
      const report = await this.requestAnalysis(tab.id, this._domain);
      this._lastReport = report;
      this._renderCurrentReport();
    } catch (error) {
      this.uiRenderer.renderError(error.message);
    }
  }

  /**
   * Mengirim pesan REQUEST_ANALYSIS ke background dan menunggu balasannya.
   *
   * @param {number} tabId
   * @param {string} domain
   * @returns {Promise<import('../models/FinalReport.js').FinalReport>}
   */
  requestAnalysis(tabId, domain) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { type: MessageType.REQUEST_ANALYSIS, tabId, domain },
        (response) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (response?.type === MessageType.ANALYSIS_ERROR) {
            reject(new Error(response.payload.message));
            return;
          }
          resolve(response.payload);
        }
      );
    });
  }

  /** @private @returns {void} */
  _renderCurrentReport() {
    this.uiRenderer.renderReport(this._lastReport, {
      theme: document.documentElement.getAttribute('data-theme') || 'dark',
      onThemeToggle: (nextTheme) => this._handleThemeToggle(nextTheme),
      onHistoryClick: () => this._handleHistoryClick(),
      onExportClick: () => this._handleExportClick(),
    });
  }

  /** @private @param {string} nextTheme @returns {Promise<void>} */
  async _handleThemeToggle(nextTheme) {
    const preferences = await this.storageService.getPreferences();
    await this.storageService.savePreferences({ ...preferences, theme: nextTheme });
  }

  /** @private @returns {Promise<void>} */
  async _handleHistoryClick() {
    const history = await this._requestHistory(this._domain);
    this.uiRenderer.renderHistory(history, () => this._renderCurrentReport());
  }

  /**
   * @private
   * @param {string} domain
   * @returns {Promise<import('../models/FinalReport.js').FinalReport[]>}
   */
  _requestHistory(domain) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: MessageType.REQUEST_HISTORY, domain },
        (response) => resolve(response?.payload ?? [])
      );
    });
  }

  /**
   * Mengekspor laporan aktif sebagai file JSON (FR-12). Memakai Blob +
   * anchor sementara, TIDAK memerlukan permission "downloads" tambahan.
   * @private
   * @returns {void}
   */
  _handleExportClick() {
    if (!this._lastReport) return;

    const blob = new Blob([JSON.stringify(this._lastReport, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);

    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `csp-xss-report-${this._domain}-${Date.now()}.json`;
    anchor.click();

    URL.revokeObjectURL(url);
  }

  /**
   * Mengambil tab aktif pada window saat ini.
   * @private
   * @returns {Promise<chrome.tabs.Tab|undefined>}
   */
  _getActiveTab() {
    return new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0]));
    });
  }
}
