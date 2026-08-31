/**
 * ScriptAnalyzer.test.js
 *
 * Menguji deteksi sink berbahaya (eval, innerHTML, dll), deteksi atribut
 * event handler, dan pelacakan source-sink (direct & indirect 1-hop) —
 * memakai fixture malicious-scripts.json agar skenario konsisten dengan
 * dokumentasi pengujian di BAB IV.
 */

import { readFileSync } from 'fs';
import { ScriptAnalyzer, SourceSinkTracer } from 'xss-risk-core';

const sinkPatterns = JSON.parse(readFileSync(new URL('../../packages/xss-risk-core/config/sink-patterns.json', import.meta.url)));
const fixture = JSON.parse(readFileSync(new URL('../fixtures/malicious-scripts.json', import.meta.url)));

describe('ScriptAnalyzer', () => {
  /** @type {ScriptAnalyzer} */
  let analyzer;

  beforeEach(() => {
    const tracer = new SourceSinkTracer(sinkPatterns);
    analyzer = new ScriptAnalyzer(sinkPatterns, tracer);
  });

  describe.each(fixture.entries)('skenario: $name', ({ entry, expectedSinkIds, expectedTraceSourceId }) => {
    test('menghasilkan sinkId yang sesuai ekspektasi', () => {
      const result = analyzer.analyze([entry]);
      const sinkIds = result.findings.map((f) => f.sinkId);
      expect(sinkIds.sort()).toEqual([...expectedSinkIds].sort());
    });

    if (expectedTraceSourceId) {
      test('SourceSinkTracer mendeteksi source yang relevan', () => {
        const result = analyzer.analyze([entry]);
        const sourceIds = result.traceResults.map((t) => t.sourceId);
        expect(sourceIds).toContain(expectedTraceSourceId);
      });
    }
  });

  test('menggabungkan findings dari banyak entry sekaligus', () => {
    const entries = fixture.entries.map((e) => e.entry);
    const result = analyzer.analyze(entries);
    const totalExpected = fixture.entries.reduce((sum, e) => sum + e.expectedSinkIds.length, 0);
    expect(result.findings).toHaveLength(totalExpected);
  });

  test('criticalCount dan highCount pada ScriptResult terhitung benar', () => {
    const result = analyzer.analyze([{ type: 'inline-script', code: 'eval(x); el.innerHTML = y;' }]);
    expect(result.criticalCount).toBe(1); // eval
    expect(result.highCount).toBe(1); // innerHTML
  });

  /**
   * TEST PEMBUKTIAN (implementasi Temuan #2 - Confidence Score):
   * membuktikan bahwa confidence finding TANPA korelasi source-sink sama
   * dengan baseConfidence dari config (tidak ada bukti tambahan), sedangkan
   * finding YANG berkorelasi dengan source (DIRECT taint) confidence-nya
   * dinaikkan ke traceConfidence.direct — dan ditandai correlatedWithSource.
   */
  describe('confidence score (Temuan #2)', () => {
    test('finding TANPA korelasi source memakai baseConfidence sink apa adanya', () => {
      // eval() berdiri sendiri, tanpa source apapun di statement yang sama
      const result = analyzer.analyze([{ type: 'inline-script', code: 'eval(someLocalVariable);' }]);
      const evalFinding = result.findings.find((f) => f.sinkId === 'eval');

      const expectedBaseConfidence = sinkPatterns.sinks.find((s) => s.id === 'eval').baseConfidence;
      expect(evalFinding.confidence).toBe(expectedBaseConfidence);
      expect(evalFinding.correlatedWithSource).toBeUndefined();
    });

    test('finding YANG berkorelasi DIRECT dengan source, confidence dinaikkan ke traceConfidence.direct', () => {
      const result = analyzer.analyze([{ type: 'inline-script', code: 'eval(location.hash);' }]);
      const evalFinding = result.findings.find((f) => f.sinkId === 'eval');

      expect(evalFinding.confidence).toBe(sinkPatterns.traceConfidence.direct);
      expect(evalFinding.correlatedWithSource).toBe(true);
      // Pastikan confidence TERKOREKSI naik dibanding baseConfidence murni
      const baseConfidence = sinkPatterns.sinks.find((s) => s.id === 'eval').baseConfidence;
      expect(evalFinding.confidence).toBeGreaterThan(baseConfidence);
    });

    test('korelasi TIDAK menyeberang antar entry berbeda (source di entry A tidak boleh menaikkan confidence sink di entry B)', () => {
      const entries = [
        { type: 'inline-script', code: 'var x = location.hash;' }, // source saja, tidak ada sink
        { type: 'inline-script', code: 'eval(unrelatedVariable);' }, // sink saja, tidak berhubungan dengan entry pertama
      ];
      const result = analyzer.analyze(entries);
      const evalFinding = result.findings.find((f) => f.sinkId === 'eval');

      // Harus TETAP baseConfidence, bukan ikut naik karena ada source di entry lain
      const baseConfidence = sinkPatterns.sinks.find((s) => s.id === 'eval').baseConfidence;
      expect(evalFinding.confidence).toBe(baseConfidence);
      expect(evalFinding.correlatedWithSource).toBeUndefined();
    });

    test('averageConfidence pada ScriptResult mencerminkan confidence gabungan seluruh findings', () => {
      const result = analyzer.analyze([{ type: 'inline-script', code: 'eval(location.hash);' }]);
      expect(result.averageConfidence).toBe(sinkPatterns.traceConfidence.direct);
    });
  });
});

describe('SourceSinkTracer', () => {
  /** @type {SourceSinkTracer} */
  let tracer;

  beforeEach(() => {
    tracer = new SourceSinkTracer(sinkPatterns);
  });

  test('mendeteksi DIRECT taint: source dan sink di statement yang sama', () => {
    const results = tracer.trace('el.innerHTML = location.hash;');
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      sourceId: 'location-hash',
      sinkId: 'inner-html',
      tainted: true,
      confidence: sinkPatterns.traceConfidence.direct,
    });
  });

  test('mendeteksi INDIRECT taint (1 hop): variabel diisi dari source lalu dipakai di sink', () => {
    const results = tracer.trace('var x = location.hash; eval(x);');
    const found = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'eval');
    expect(found).toBeDefined();
    expect(found.confidence).toBe(sinkPatterns.traceConfidence.indirect);
  });

  test('PEMBUKTIAN: confidence DIRECT > confidence INDIRECT secara konsisten', () => {
    expect(sinkPatterns.traceConfidence.direct).toBeGreaterThan(sinkPatterns.traceConfidence.indirect);
  });

  test('tidak menghasilkan taint palsu pada kode yang tidak berhubungan', () => {
    const results = tracer.trace('const a = 1; const b = 2; console.log(a + b);');
    expect(results).toHaveLength(0);
  });

  test('hasil trace di-dedupe, tidak ada duplikat sourceId+sinkId', () => {
    const results = tracer.trace('eval(location.hash); eval(location.hash);');
    expect(results).toHaveLength(1);
  });

  test('PEMBUKTIAN: dedupe mempertahankan confidence TERTINGGI antar duplikat (bukan sekadar yang pertama ditemukan)', () => {
    // Statement ke-2 ("eval(x)") menghasilkan korelasi INDIRECT (variabel x
    // diisi dari location.hash) untuk pasangan (location-hash, eval) —
    // pushed LEBIH DULU ke array hasil. Statement ke-3 ("eval(location.hash)")
    // menghasilkan korelasi DIRECT untuk pasangan YANG SAMA — pushed BELAKANGAN.
    // Kalau dedupe naif memilih "yang pertama ditemukan", hasilnya salah
    // (confidence rendah INDIRECT yang bertahan). Dedupe yang benar harus
    // memilih confidence tertinggi (DIRECT), terlepas urutan kemunculan.
    const results = tracer.trace('var x = location.hash; eval(x); eval(location.hash);');
    const match = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'eval');

    expect(match).toBeDefined();
    expect(match.confidence).toBe(sinkPatterns.traceConfidence.direct); // bukan indirect yang lebih rendah
  });

  /**
   * TEST PEMBUKTIAN (implementasi Temuan #4 dari review arsitektur):
   * kasus PERSIS yang ditunjukkan sebagai kelemahan di laporan review —
   * semicolon DI DALAM string literal yang berada pada statement YANG SAMA
   * dengan sink dan source. Dengan `code.split(';')` naif (versi lama),
   * kode ini akan terpecah jadi 2 fragmen ('el.innerHTML = "prefix' dan
   * '" + location.hash'), sehingga sink (innerHTML) dan source
   * (location.hash) berakhir di fragmen BERBEDA — korelasi DIRECT gagal
   * total walau keduanya sebenarnya satu statement logis yang sama.
   */
  describe('tokenizer sadar-syntax (Temuan #4)', () => {
    test('semicolon di dalam string literal TIDAK memecah statement secara salah', () => {
      const results = tracer.trace('el.innerHTML = "prefix;suffix" + location.hash;');
      const match = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'inner-html');

      expect(match).toBeDefined();
      expect(match.confidence).toBe(sinkPatterns.traceConfidence.direct);
    });

    test('semicolon di dalam template literal (termasuk sebelum ekspresi interpolasi) TIDAK memecah statement', () => {
      // eslint-disable-next-line no-template-curly-in-string
      const results = tracer.trace('el.innerHTML = `prefix;${location.hash}`;');
      const match = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'inner-html');

      expect(match).toBeDefined();
      expect(match.confidence).toBe(sinkPatterns.traceConfidence.direct);
    });

    test('semicolon di dalam single-quote string TIDAK memecah statement', () => {
      const results = tracer.trace("el.innerHTML = 'a;b' + location.hash;");
      const match = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'inner-html');

      expect(match).toBeDefined();
    });

    test('komentar baris tunggal (//) tidak ikut dianggap bagian statement', () => {
      const results = tracer.trace('eval(location.hash); // ini komentar; dengan semicolon di dalamnya');
      const match = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'eval');
      expect(match).toBeDefined();
    });

    test('komentar blok (/* */) tidak ikut dianggap bagian statement', () => {
      const results = tracer.trace('eval(/* a;b;c */ location.hash);');
      const match = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'eval');
      expect(match).toBeDefined();
    });

    test('escape quote di dalam string tidak salah dianggap penutup string', () => {
      // String berisi tanda kutip ter-escape: "a\"b;c" - tanpa penanganan
      // escape yang benar, parser akan salah anggap string berakhir
      // sebelum \", memecah sisanya secara salah.
      const results = tracer.trace('el.innerHTML = "a\\"b;c" + location.hash;');
      const match = results.find((r) => r.sourceId === 'location-hash' && r.sinkId === 'inner-html');
      expect(match).toBeDefined();
    });

    test('statement yang benar-benar terpisah (dipisah ; asli di luar string) tetap terdeteksi sebagai INDIRECT, bukan DIRECT', () => {
      const results = tracer.trace('var x = location.hash; el.innerHTML = "aman;tanpa-source";');
      // sink ada di statement kedua, source ada di statement pertama (variabel x),
      // TAPI variabel x TIDAK dipakai di statement kedua -> tidak boleh ada korelasi
      const match = results.find((r) => r.sinkId === 'inner-html');
      expect(match).toBeUndefined();
    });
  });
});

describe('ScriptAnalyzer - cap performa (Tahap 13)', () => {
  test('memproses seluruh entry jika jumlahnya di bawah cap', () => {
    const tracer = new SourceSinkTracer(sinkPatterns);
    const analyzer = new ScriptAnalyzer(sinkPatterns, tracer, 5); // cap kecil untuk testing
    const entries = Array.from({ length: 3 }, () => ({ type: 'inline-script', code: 'eval(x);' }));

    const result = analyzer.analyze(entries);
    expect(result.truncated).toBe(false);
    expect(result.totalEntriesReceived).toBe(3);
    expect(result.findings).toHaveLength(3);
  });

  test('memotong entry dan menandai truncated=true jika melebihi cap', () => {
    const tracer = new SourceSinkTracer(sinkPatterns);
    const analyzer = new ScriptAnalyzer(sinkPatterns, tracer, 5); // cap kecil untuk testing
    const entries = Array.from({ length: 20 }, () => ({ type: 'inline-script', code: 'eval(x);' }));

    const result = analyzer.analyze(entries);
    expect(result.truncated).toBe(true);
    expect(result.totalEntriesReceived).toBe(20);
    expect(result.findings).toHaveLength(5); // hanya 5 entry pertama yang diproses
  });

  test('menggunakan DEFAULT_MAX_ENTRIES (800) jika tidak di-override', () => {
    const tracer = new SourceSinkTracer(sinkPatterns);
    const analyzer = new ScriptAnalyzer(sinkPatterns, tracer); // tanpa override, pakai default
    const entries = Array.from({ length: 10 }, () => ({ type: 'inline-script', code: 'const a = 1;' }));

    const result = analyzer.analyze(entries);
    expect(result.truncated).toBe(false); // 10 entries jauh di bawah 800
  });
});
