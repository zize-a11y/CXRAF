/**
 * ScriptAnalyzer.js
 *
 * Fungsi: Domain layer class yang memindai kumpulan ScriptEntry (inline
 * script dan atribut event handler yang sudah diekstrak oleh
 * DOMScannerService di infrastructure layer) untuk menemukan pola sink
 * berbahaya (eval, innerHTML, dll) dan memicu SourceSinkTracer untuk
 * analisis alur source-to-sink sederhana.
 *
 * PENTING: Sama seperti CSPAnalyzer, file ini murni pure logic — TIDAK
 * mengimpor `chrome.*` maupun DOM API apapun. Input berupa array of
 * plain object (ScriptEntry), bukan objek DOM asli, sehingga bisa diuji
 * dengan Jest tanpa jsdom/browser environment.
 *
 * Bentuk ScriptEntry yang diharapkan:
 *   { type: 'inline-script' | 'event-handler', code: string,
 *     attribute?: string, tagName?: string }
 *
 * Alur kerja:
 *   1. Untuk tiap entry, jalankan detectSinks() terhadap `code`-nya.
 *   2. Jika entry berupa event-handler, tambahkan finding tersendiri untuk
 *      penggunaan atribut itu sendiri (mis. onclick) via detectEventHandlers().
 *   3. Jalankan SourceSinkTracer.trace() per entry untuk analisis DOM-based XSS.
 *   4. Kembalikan ScriptResult gabungan.
 */

import { IAnalyzer } from './IAnalyzer.js';
import { createScriptResult } from '../models/ScriptResult.js';

/**
 * Batas jumlah ScriptEntry yang diproses dalam satu kali analisis. Nilai ini
 * BUKAN angka sembarang — ditentukan dari benchmark cold-start (lihat
 * docs/optimization-report.md, Tahap 13), karena service worker MV3 bersifat
 * non-persisten sehingga setiap popup dibuka berpotensi menjalankan kode
 * dalam kondisi "cold" (belum di-JIT-warm oleh eksekusi sebelumnya) —
 * skenario yang lebih realistis daripada benchmark loop berulang.
 *
 * Hasil ukur: 800 entri ~43ms cold pada input ekstrem 8000 entri (truncated),
 * menyisakan margin ~57ms dari budget 100ms (NFR-01) untuk overhead
 * message-passing antar context yang tidak terukur di sandbox non-browser.
 * Halaman dengan >800 inline script + event handler adalah anomali —
 * halaman wajar jarang mendekati angka ini.
 */
const DEFAULT_MAX_ENTRIES = 800;

export class ScriptAnalyzer extends IAnalyzer {
  /**
   * @param {object} sinkPatterns - isi sink-patterns.json
   * @param {import('../tracer/SourceSinkTracer.js').SourceSinkTracer} tracer
   * @param {number} [maxEntries] - override cap default, terutama untuk kebutuhan testing
   */
  constructor(sinkPatterns, tracer, maxEntries = DEFAULT_MAX_ENTRIES) {
    super();
    this.sinkPatterns = sinkPatterns;
    this.tracer = tracer;
    this.maxEntries = maxEntries;
    // Compile regex sekali di constructor, bukan setiap kali analyze()
    // dipanggil, demi performa (NFR-01: overhead < 100ms per halaman).
    this._compiledSinks = sinkPatterns.sinks.map((s) => ({
      ...s,
      regex: new RegExp(s.pattern, 'i'),
    }));
  }

  /**
   * Memindai satu potongan kode terhadap seluruh pola sink yang dikenal.
   *
   * @param {string} code
   * @param {string} location - "inline-script" | "event-handler", untuk konteks tampilan
   * @returns {import('../../models/ScriptResult.js').SinkFinding[]}
   */
  detectSinks(code, location = 'inline-script') {
    if (!code) return [];
    const findings = [];

    for (const sink of this._compiledSinks) {
      const match = code.match(sink.regex);
      if (match) {
        findings.push({
          sinkId: sink.id,
          severity: sink.baseSeverity,
          confidence: sink.baseConfidence,
          description: sink.description,
          matchedText: this._excerpt(code, match.index),
          location,
        });
      }
    }
    return findings;
  }

  /**
   * Memeriksa apakah entry adalah event handler attribute (onclick, onerror,
   * dst) dan menambahkan finding tersendiri untuk pemakaian atribut itu,
   * terlepas dari isi kodenya mengandung sink atau tidak — karena inline
   * event handler attribute sendiri adalah indikator risiko (FR-04).
   *
   * @param {{attribute?: string}} entry
   * @returns {import('../../models/ScriptResult.js').SinkFinding[]}
   */
  detectEventHandlers(entry) {
    if (!entry.attribute) return [];
    const isKnownHandler = this.sinkPatterns.eventHandlerAttributes.includes(
      entry.attribute.toLowerCase()
    );
    if (!isKnownHandler) return [];

    return [{
      sinkId: `event-handler:${entry.attribute}`,
      severity: this.sinkPatterns.eventHandlerBaseSeverity,
      confidence: this.sinkPatterns.eventHandlerBaseConfidence,
      description: `Atribut "${entry.attribute}" adalah inline event handler yang dapat dieksploitasi jika CSP tidak melarang unsafe-inline.`,
      matchedText: `${entry.attribute}="${this._excerpt(entry.code || '', 0)}"`,
      location: 'event-handler',
    }];
  }

  /**
   * Entry point utama analyzer ini (implementasi kontrak IAnalyzer).
   *
   * PENTING (implementasi Temuan #2 - Confidence Score): korelasi antara
   * SinkFinding dan TraceResult dilakukan PER ENTRY (bukan menggabung dulu
   * baru mencari korelasi di akhir), supaya tidak salah mengorelasikan sink
   * di satu <script> dengan source di <script> lain yang tidak berhubungan.
   * Jika satu entry punya sink DAN source yang berkorelasi (dari
   * SourceSinkTracer), confidence finding tersebut dinaikkan ke nilai
   * traceConfidence yang lebih tinggi (bukti taint > sekadar pattern match).
   *
   * @param {Array<{type: string, code: string, attribute?: string, tagName?: string}>} scriptEntries
   * @returns {import('../../models/ScriptResult.js').ScriptResult}
   */
  analyze(scriptEntries) {
    const allFindings = [];
    const allTraceResults = [];

    const totalReceived = scriptEntries?.length ?? 0;
    const truncated = totalReceived > this.maxEntries;
    const entriesToProcess = truncated ? scriptEntries.slice(0, this.maxEntries) : (scriptEntries || []);

    for (const entry of entriesToProcess) {
      const location = entry.type === 'event-handler' ? 'event-handler' : 'inline-script';

      const entryFindings = [
        ...this.detectSinks(entry.code, location),
        ...(entry.type === 'event-handler' ? this.detectEventHandlers(entry) : []),
      ];
      const entryTraceResults = this.tracer.trace(entry.code || '');

      this._correlateConfidence(entryFindings, entryTraceResults);

      allFindings.push(...entryFindings);
      allTraceResults.push(...entryTraceResults);
    }

    return createScriptResult({
      findings: allFindings,
      traceResults: allTraceResults,
      truncated,
      totalEntriesReceived: totalReceived,
    });
  }

  /**
   * Menaikkan confidence suatu SinkFinding jika ditemukan TraceResult yang
   * berkorelasi (sinkId sama) DALAM ENTRY YANG SAMA. Confidence finding
   * diambil dari nilai TERBESAR antara baseConfidence sink itu sendiri dan
   * confidence korelasi trace — bukan dijumlahkan, agar tidak melebihi 1.0
   * dan lebih mudah dijustifikasi ("gunakan bukti terkuat yang tersedia").
   *
   * @param {import('../../models/ScriptResult.js').SinkFinding[]} entryFindings - dimutasi in-place
   * @param {import('../../models/ScriptResult.js').TraceResult[]} entryTraceResults
   * @returns {void}
   */
  _correlateConfidence(entryFindings, entryTraceResults) {
    if (entryTraceResults.length === 0) return;

    for (const finding of entryFindings) {
      const correlatedTrace = entryTraceResults.find((t) => t.sinkId === finding.sinkId);
      if (correlatedTrace && correlatedTrace.confidence > finding.confidence) {
        finding.confidence = correlatedTrace.confidence;
        finding.correlatedWithSource = true;
      }
    }
  }

  /**
   * Mengambil potongan kode pendek di sekitar posisi match, untuk
   * ditampilkan ke pengguna tanpa membanjiri UI dengan kode penuh.
   *
   * @param {string} code
   * @param {number} index
   * @returns {string}
   */
  _excerpt(code, index) {
    const start = Math.max(0, index - 10);
    const end = Math.min(code.length, index + 40);
    const prefix = start > 0 ? '…' : '';
    const suffix = end < code.length ? '…' : '';
    return `${prefix}${code.slice(start, end).trim()}${suffix}`;
  }
}
