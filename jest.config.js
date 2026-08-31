/**
 * jest.config.js
 *
 * Konfigurasi Jest untuk project berbasis ES Modules native (package.json
 * "type": "module"). Menggunakan transform kosong karena Node.js sudah
 * mendukung ESM langsung — dijalankan lewat flag
 * --experimental-vm-modules (lihat script "test" di package.json).
 */

export default {
  testEnvironment: 'node',
  transform: {},
  testMatch: ['**/tests/**/*.test.js'],
  collectCoverageFrom: [
    'packages/xss-risk-core/**/*.js',
    'src/background/AnalysisOrchestrator.js',
  ],
};
