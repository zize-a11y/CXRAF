/**
 * MessageRouter.js
 *
 * Fungsi: Application layer class yang menerima pesan dari popup (via
 * chrome.runtime.onMessage) dan merutekannya ke use case yang sesuai
 * (AnalysisOrchestrator atau StorageService). Dipisah dari
 * AnalysisOrchestrator agar orchestrator tidak perlu tahu apa-apa soal
 * chrome.runtime API (Separation of Concern).
 *
 * Alur kerja: didaftarkan sekali di background/index.js sebagai listener
 * tunggal untuk chrome.runtime.onMessage, lalu handleMessage() menentukan
 * use case mana yang dipanggil berdasarkan message.type.
 */

import { MessageType } from './messageTypes.js';

export class MessageRouter {
  /**
   * @param {import('./AnalysisOrchestrator.js').AnalysisOrchestrator} orchestrator
   * @param {import('../services/StorageService.js').StorageService} storageService
   */
  constructor(orchestrator, storageService) {
    this.orchestrator = orchestrator;
    this.storageService = storageService;
  }

  /**
   * Handler utama, didaftarkan langsung ke chrome.runtime.onMessage.
   * Mengembalikan `true` untuk pesan yang ditangani secara async, sesuai
   * kontrak chrome.runtime.onMessage agar `sendResponse` tetap valid
   * dipanggil setelah handler ini return.
   *
   * @param {{type: string, tabId?: number, domain?: string}} message
   * @param {chrome.runtime.MessageSender} sender
   * @param {(response: object) => void} sendResponse
   * @returns {boolean} true jika sendResponse akan dipanggil secara asynchronous
   */
  handleMessage(message, sender, sendResponse) {
    switch (message.type) {
      case MessageType.REQUEST_ANALYSIS:
        this._handleRequestAnalysis(message, sendResponse);
        return true;

      case MessageType.REQUEST_HISTORY:
        this._handleRequestHistory(message, sendResponse);
        return true;

      default:
        // Pesan dengan tipe tidak dikenal diabaikan secara sengaja (bukan error),
        // karena bisa saja berasal dari context lain yang tidak relevan.
        return false;
    }
  }

  /**
   * @param {{tabId: number, domain: string}} message
   * @param {(response: object) => void} sendResponse
   * @returns {Promise<void>}
   */
  async _handleRequestAnalysis(message, sendResponse) {
    try {
      const report = await this.orchestrator.runAnalysis(message.tabId, message.domain);
      sendResponse({ type: MessageType.ANALYSIS_RESULT, payload: report });
    } catch (error) {
      sendResponse({ type: MessageType.ANALYSIS_ERROR, payload: { message: error.message } });
    }
  }

  /**
   * @param {{domain: string}} message
   * @param {(response: object) => void} sendResponse
   * @returns {Promise<void>}
   */
  async _handleRequestHistory(message, sendResponse) {
    try {
      const history = await this.storageService.getHistory(message.domain);
      sendResponse({ type: MessageType.HISTORY_RESULT, payload: history });
    } catch (error) {
      sendResponse({ type: MessageType.ANALYSIS_ERROR, payload: { message: error.message } });
    }
  }
}
