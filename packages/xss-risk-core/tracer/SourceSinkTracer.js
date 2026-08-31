/**
 * SourceSinkTracer.js
 *
 * Fungsi: Melakukan analisis STATIS dan HEURISTIK (bukan taint-tracking
 * runtime penuh — lihat batasan scope di Tahap 1) untuk mendeteksi
 * kemungkinan aliran data dari "source" (mis. location.hash, yang dapat
 * dikontrol penyerang) ke "sink" (mis. innerHTML) tanpa sanitasi di antaranya.
 *
 * Dua level deteksi yang diimplementasikan (sesuai batasan skripsi):
 *   1. DIRECT  : source dan sink muncul dalam satu statement yang sama,
 *                mis. `element.innerHTML = location.hash;`
 *   2. INDIRECT (1 hop): source ditampung ke variabel terlebih dahulu,
 *                lalu variabel tersebut dipakai di sink pada statement lain,
 *                mis. `var x = location.hash; ... element.innerHTML = x;`
 *
 * PERBAIKAN TEMUAN #4 (review arsitektur — Source-Sink Analysis): batas
 * "statement" SEBELUMNYA ditentukan dengan `code.split(';')` naif, yang
 * SALAH memecah kode setiap kali karakter `;` muncul di dalam string
 * literal (mis. `const x = "a;b"; eval(x);` akan terpecah jadi 3 statement
 * palsu, merusak korelasi source-sink). Sekarang batas statement ditentukan
 * oleh `_splitStatements()` — tokenizer buatan sendiri yang menelusuri kode
 * karakter demi karakter dan SADAR akan boundary string literal ('...'),
 * string literal ("..."), template literal (`...`) termasuk ekspresi
 * interpolasi `${...}` di dalamnya, dan komentar (// serta /* *​/).
 *
 * KENAPA BUKAN AST PARSER SUNGGUHAN (mis. Acorn): dipertimbangkan dan
 * dicoba, tapi DITOLAK karena package npm seperti Acorn memakai bare
 * module specifier (`import ... from 'acorn'`) yang TIDAK bisa di-resolve
 * oleh browser tanpa import map atau bundler — sedangkan browser extension
 * ini sengaja dibangun TANPA bundler (lihat batasan awal proyek). Memaksa
 * dependency semacam ini berisiko GAGAL TOTAL saat extension di-load ke
 * Chrome tanpa cara aman untuk diuji ulang di sandbox pengembangan ini.
 * Tokenizer buatan sendiri ini adalah kompromi yang disengaja: bebas
 * dependency (aman di SEMUA konteks — extension, CLI, test), sambil tetap
 * memperbaiki kelemahan konkret yang ditemukan di review. AST parsing
 * sungguhan didokumentasikan sebagai future work yang butuh build step
 * (esbuild/Vite) — lihat docs/architecture.md.
 *
 * KETERBATASAN YANG MASIH ADA (jujur, bukan diklaim sempurna): tokenizer
 * ini TIDAK membedakan regex literal (mis. `/a;b/`) dari operator
 * pembagian — karakter `;` di dalam regex literal masih bisa salah
 * dianggap boundary. Ini kasus yang jauh lebih jarang muncul di sink
 * pattern yang relevan (eval, innerHTML, dst jarang berdampingan dengan
 * regex literal kompleks dalam satu statement) dibanding kasus string
 * literal yang sudah diperbaiki, sehingga risiko sisa ini dianggap dapat
 * diterima untuk skala penelitian S1 — didokumentasikan di sini, bukan
 * disembunyikan.
 *
 * KETERBATASAN LAIN (tetap ada, tidak berubah dari sebelumnya): tracer
 * ini tidak menelusuri lebih dari satu hop assignment, tidak memahami
 * sanitasi (mis. DOMPurify.sanitize()) sehingga bisa menghasilkan false
 * positive jika sanitasi sudah diterapkan — ini dijelaskan sebagai
 * "indikasi", bukan "kepastian" eksploitasi (FR-05/FR-06).
 */

export class SourceSinkTracer {
  /**
   * @param {object} sinkPatterns - isi sink-patterns.json (berisi sourcePatterns, sinks, traceConfidence)
   */
  constructor(sinkPatterns) {
    this.sourcePatterns = sinkPatterns.sourcePatterns.map((s) => ({
      ...s,
      regex: new RegExp(s.pattern, 'i'),
    }));
    this.sinkPatterns = sinkPatterns.sinks.map((s) => ({
      ...s,
      regex: new RegExp(s.pattern, 'i'),
    }));
    // Confidence korelasi DIRECT vs INDIRECT (implementasi Temuan #2).
    // Fallback disediakan agar tidak crash jika config lama belum
    // menyertakan field ini (backward-compatible).
    this.traceConfidence = sinkPatterns.traceConfidence ?? { direct: 0.9, indirect: 0.65 };
  }

  /**
   * Menjalankan pelacakan source-sink terhadap satu potongan kode.
   *
   * @param {string} code
   * @returns {import('../models/ScriptResult.js').TraceResult[]}
   */
  trace(code) {
    if (!code) return [];
    const results = [];

    const statements = this._splitStatements(code);
    const variableSources = this._collectVariableSources(statements);

    for (const statement of statements) {
      for (const sink of this.sinkPatterns) {
        if (!sink.regex.test(statement)) continue;

        // Level 1: deteksi DIRECT — source langsung di statement yang sama
        for (const source of this.sourcePatterns) {
          if (source.regex.test(statement)) {
            results.push({
              sourceId: source.id,
              sinkId: sink.id,
              tainted: true,
              confidence: this.traceConfidence.direct,
              explanation: `Data dari "${source.description}" tampak langsung dialirkan ke sink "${sink.id}" tanpa sanitasi yang terlihat.`,
            });
          }
        }

        // Level 2: deteksi INDIRECT — variabel yang sebelumnya diisi dari source
        for (const [varName, source] of variableSources.entries()) {
          const usesVariable = new RegExp(`\\b${this._escapeRegex(varName)}\\b`).test(statement);
          if (usesVariable) {
            results.push({
              sourceId: source.id,
              sinkId: sink.id,
              tainted: true,
              confidence: this.traceConfidence.indirect,
              explanation: `Variabel "${varName}" diisi dari "${source.description}" lalu dipakai pada sink "${sink.id}" tanpa sanitasi yang terlihat.`,
            });
          }
        }
      }
    }

    return this._dedupe(results);
  }

  /**
   * Memecah kode menjadi daftar "statement" berdasarkan karakter `;`,
   * TAPI dengan tokenizer sadar-syntax yang mengabaikan `;` yang muncul
   * di dalam string literal ('...', "..."), template literal (`...`,
   * termasuk ekspresi interpolasi ${...} di dalamnya), dan komentar
   * (// baris tunggal, /* blok *​/). Ini perbaikan inti Temuan #4 —
   * lihat komentar di atas file ini untuk detail lengkap.
   *
   * @param {string} code
   * @returns {string[]}
   */
  _splitStatements(code) {
    const statements = [];
    let current = '';
    // Stack posisi "mode" saat ini. Setiap entry: { type, braceDepth? }
    // type: 'string-single' | 'string-double' | 'template' | 'template-expr'
    const stack = [];
    const top = () => stack[stack.length - 1];

    let i = 0;
    const n = code.length;

    while (i < n) {
      const ch = code[i];
      const mode = top()?.type ?? 'normal';

      // --- Di dalam string literal '...' atau "..." ---
      if (mode === 'string-single' || mode === 'string-double') {
        current += ch;
        if (ch === '\\' && i + 1 < n) {
          current += code[i + 1];
          i += 2;
          continue;
        }
        if ((mode === 'string-single' && ch === "'") || (mode === 'string-double' && ch === '"')) {
          stack.pop();
        }
        i++;
        continue;
      }

      // --- Di dalam template literal `...` ---
      if (mode === 'template') {
        current += ch;
        if (ch === '\\' && i + 1 < n) {
          current += code[i + 1];
          i += 2;
          continue;
        }
        if (ch === '`') {
          stack.pop();
          i++;
          continue;
        }
        if (ch === '$' && code[i + 1] === '{') {
          current += '{';
          stack.push({ type: 'template-expr', braceDepth: 1 });
          i += 2;
          continue;
        }
        i++;
        continue;
      }

      // --- Di dalam ekspresi interpolasi ${...} pada template literal ---
      if (mode === 'template-expr') {
        if (ch === "'") { stack.push({ type: 'string-single' }); current += ch; i++; continue; }
        if (ch === '"') { stack.push({ type: 'string-double' }); current += ch; i++; continue; }
        if (ch === '`') { stack.push({ type: 'template' }); current += ch; i++; continue; }
        if (ch === '{') { top().braceDepth++; current += ch; i++; continue; }
        if (ch === '}') {
          top().braceDepth--;
          current += ch;
          if (top().braceDepth === 0) stack.pop(); // kembali ke mode 'template'
          i++;
          continue;
        }
        current += ch;
        i++;
        continue;
      }

      // --- Mode normal (di luar string/template) ---
      if (ch === "'") { stack.push({ type: 'string-single' }); current += ch; i++; continue; }
      if (ch === '"') { stack.push({ type: 'string-double' }); current += ch; i++; continue; }
      if (ch === '`') { stack.push({ type: 'template' }); current += ch; i++; continue; }

      if (ch === '/' && code[i + 1] === '/') {
        while (i < n && code[i] !== '\n') i++; // buang komentar baris, tidak ikut jadi bagian statement
        continue;
      }
      if (ch === '/' && code[i + 1] === '*') {
        i += 2;
        while (i < n && !(code[i] === '*' && code[i + 1] === '/')) i++;
        i += 2; // lewati '*/'
        continue;
      }

      if (ch === ';') {
        statements.push(current.trim());
        current = '';
        i++;
        continue;
      }

      current += ch;
      i++;
    }

    if (current.trim()) statements.push(current.trim());
    return statements.filter(Boolean);
  }

  /**
   * Mengumpulkan variabel yang di-assign langsung dari suatu source pattern,
   * untuk mendukung deteksi indirect (1 hop) di atas.
   *
   * @param {string[]} statements
   * @returns {Map<string, {id: string, description: string}>}
   */
  _collectVariableSources(statements) {
    const map = new Map();
    const assignPattern = /(?:let|const|var)\s+(\w+)\s*=\s*(.+)/;

    for (const statement of statements) {
      const match = statement.match(assignPattern);
      if (!match) continue;
      const [, varName, rhs] = match;

      for (const source of this.sourcePatterns) {
        if (source.regex.test(rhs)) {
          map.set(varName, { id: source.id, description: source.description });
        }
      }
    }
    return map;
  }

  /**
   * Menghapus duplikat hasil trace (kombinasi sourceId+sinkId yang sama
   * bisa muncul berkali-kali jika ada banyak statement serupa). Jika ada
   * duplikat dengan confidence BERBEDA (mis. satu statement menghasilkan
   * korelasi INDIRECT, statement lain menghasilkan DIRECT untuk pasangan
   * source-sink yang sama), yang dipertahankan adalah confidence TERTINGGI
   * — bukan sekadar yang pertama ditemukan — supaya bukti terkuat yang
   * tersedia tidak hilang begitu saja karena urutan iterasi statement.
   *
   * @param {import('../../models/ScriptResult.js').TraceResult[]} results
   * @returns {import('../../models/ScriptResult.js').TraceResult[]}
   */
  _dedupe(results) {
    const bestByKey = new Map();
    for (const r of results) {
      const key = `${r.sourceId}::${r.sinkId}`;
      const existing = bestByKey.get(key);
      if (!existing || r.confidence > existing.confidence) {
        bestByKey.set(key, r);
      }
    }
    return [...bestByKey.values()];
  }

  /**
   * Meng-escape karakter spesial regex pada nama variabel sebelum dipakai
   * membangun RegExp dinamis (mencegah error jika nama variabel mengandung
   * karakter tidak lazim).
   *
   * @param {string} str
   * @returns {string}
   */
  _escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}
