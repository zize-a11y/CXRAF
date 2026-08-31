/**
 * AnalyzerRegistry.test.js
 *
 * Menguji extension point inti dari perbaikan Temuan #5: registrasi,
 * pengambilan, dan pencegahan duplikasi nama analyzer.
 */

import { AnalyzerRegistry } from 'xss-risk-core';

describe('AnalyzerRegistry', () => {
  /** @type {AnalyzerRegistry} */
  let registry;

  beforeEach(() => {
    registry = new AnalyzerRegistry();
  });

  test('register() menambahkan analyzer, count() mencerminkan jumlahnya', () => {
    registry.register('csp', { analyze: () => {} }, 'csp');
    expect(registry.count()).toBe(1);

    registry.register('script', { analyze: () => {} }, 'script');
    expect(registry.count()).toBe(2);
  });

  test('getAll() mengembalikan seluruh entry dalam urutan pendaftaran', () => {
    const cspAnalyzer = { analyze: () => 'csp-result' };
    const scriptAnalyzer = { analyze: () => 'script-result' };
    registry.register('csp', cspAnalyzer, 'csp');
    registry.register('script', scriptAnalyzer, 'script');

    const all = registry.getAll();
    expect(all).toHaveLength(2);
    expect(all[0]).toMatchObject({ name: 'csp', analyzer: cspAnalyzer, inputKey: 'csp' });
    expect(all[1]).toMatchObject({ name: 'script', analyzer: scriptAnalyzer, inputKey: 'script' });
  });

  test('get() mengembalikan analyzer berdasarkan nama', () => {
    const cspAnalyzer = { analyze: () => {} };
    registry.register('csp', cspAnalyzer, 'csp');

    expect(registry.get('csp')).toBe(cspAnalyzer);
  });

  test('get() mengembalikan undefined untuk nama yang tidak terdaftar', () => {
    expect(registry.get('tidak-ada')).toBeUndefined();
  });

  test('register() menolak nama yang sudah terdaftar (mencegah override tidak sengaja)', () => {
    registry.register('csp', { analyze: () => {} }, 'csp');
    expect(() => registry.register('csp', { analyze: () => {} }, 'csp')).toThrow(/sudah terdaftar/);
  });

  /**
   * TEST PEMBUKTIAN: registry mendukung analyzer APAPUN yang memenuhi
   * kontrak minimal (method analyze()), termasuk instance yang bukan
   * turunan class IAnalyzer sungguhan — membuktikan extension point ini
   * tidak terkunci pada implementasi spesifik, hanya kontraknya saja
   * (duck typing, konsisten dengan JavaScript, dan konsisten dengan
   * bagaimana AnalysisOrchestrator memanggilnya generik).
   */
  test('PEMBUKTIAN: mendukung analyzer pihak ketiga apapun asal punya method analyze()', () => {
    class CustomThirdPartyAnalyzer {
      analyze(input) {
        return { customField: `diproses: ${input}` };
      }
    }

    registry.register('custom', new CustomThirdPartyAnalyzer(), 'custom-input');
    const analyzer = registry.get('custom');
    expect(analyzer.analyze('test')).toEqual({ customField: 'diproses: test' });
  });
});
