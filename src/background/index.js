/**
 * index.js (background/service worker)
 *
 * Fungsi: Composition root — satu-satunya tempat seluruh class di-instansiasi
 * dan dirangkai dengan dependency injection manual. Tidak ada logic bisnis
 * di file ini, murni "wiring".
 *
 * PENTING soal service worker MV3: service worker bisa dimatikan dan
 * di-restart Chrome kapan saja (non-persisten). Karena itu inisialisasi
 * (loadConfig, dst) dibungkus dalam Promise `readyPromise` yang di-await
 * oleh listener onMessage setiap kali dipanggil — bukan diasumsikan sudah
 * selesai dari sekali jalan di awal. Biaya re-inisialisasi kecil karena
 * hanya baca file JSON lokal (bukan network request).
 */

import { ConfigService } from '../services/ConfigService.js';
import { CSPHeaderService } from '../services/CSPHeaderService.js';
import { StorageService } from '../services/StorageService.js';
import {
  CSPAnalyzer,
  ScriptAnalyzer,
  SourceSinkTracer,
  ScoreEngine,
  RiskCalculator,
  AnalyzerRegistry,
} from '../../packages/xss-risk-core/index.js';
import { AnalysisOrchestrator } from './AnalysisOrchestrator.js';
import { MessageRouter } from './MessageRouter.js';
import { MessageType } from './messageTypes.js';

const cspHeaderService = new CSPHeaderService();
const storageService = new StorageService();
cspHeaderService.listenHeaders();

/**
 * Meminta content script menjalankan scan DOM pada tab tertentu.
 * Dibungkus sebagai fungsi sederhana (bukan class) dan disuntikkan ke
 * AnalysisOrchestrator, agar orchestrator tidak perlu tahu detail
 * chrome.tabs.sendMessage.
 *
 * @param {number} tabId
 * @returns {Promise<{scriptEntries: object[], metaCSP: string|null}>}
 */
function requestDomScan(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: MessageType.SCAN_DOM }, (response) => {
      if (chrome.runtime.lastError) {
        // Wajar terjadi mis. pada halaman chrome:// yang tidak bisa di-inject content script
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response ?? { scriptEntries: [], metaCSP: null });
    });
  });
}

/**
 * Membangun seluruh dependency chain sekali, dipanggil lazy saat pesan
 * pertama masuk (lihat komentar di atas soal service worker non-persisten).
 *
 * @returns {Promise<MessageRouter>}
 */
async function buildMessageRouter() {
  const configService = new ConfigService();
  const { cspRules, sinkPatterns, weights } = await configService.loadAll();

  const scoreEngine = new ScoreEngine(weights);
  const tracer = new SourceSinkTracer(sinkPatterns);
  const riskCalculator = new RiskCalculator(scoreEngine, weights);

  // PERBAIKAN TEMUAN #5: analyzer didaftarkan via registry, bukan
  // di-passing satu-satu sebagai parameter bernama ke AnalysisOrchestrator.
  // Menambah analyzer baru (mis. CORSAnalyzer di masa depan) HANYA perlu
  // menambah satu baris register() di sini — AnalysisOrchestrator.js
  // TIDAK PERLU diubah sama sekali.
  const registry = new AnalyzerRegistry();
  registry.register('csp', new CSPAnalyzer(cspRules, scoreEngine), 'csp');
  registry.register('script', new ScriptAnalyzer(sinkPatterns, tracer), 'script');

  const orchestrator = new AnalysisOrchestrator({
    cspHeaderService,
    requestDomScan,
    registry,
    riskCalculator,
    storageService,
  });

  return new MessageRouter(orchestrator, storageService);
}

/** @type {Promise<MessageRouter>|null} */
let routerPromise = null;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!routerPromise) routerPromise = buildMessageRouter();

  routerPromise
    .then((router) => router.handleMessage(message, sender, sendResponse))
    .catch((error) => {
      sendResponse({ type: MessageType.ANALYSIS_ERROR, payload: { message: error.message } });
    });

  return true; // seluruh response bersifat asynchronous
});
