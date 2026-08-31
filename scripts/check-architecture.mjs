#!/usr/bin/env node
/**
 * check-architecture.mjs
 *
 * Fungsi: Validasi otomatis prinsip Clean Architecture — memastikan
 * package `packages/xss-risk-core` (domain layer / core engine, dipisah
 * dari extension sejak implementasi Temuan #5 review arsitektur) TIDAK
 * PERNAH menyentuh chrome.* API secara langsung. Jika ada pelanggaran,
 * script keluar dengan exit code 1 (bisa dipasang di CI atau dijalankan
 * manual sebelum commit).
 *
 * Kenapa ini penting untuk skripsi: ini adalah BUKTI OTOMATIS, bukan
 * janji di dokumen, bahwa xss-risk-core benar-benar framework-agnostic —
 * prasyarat mutlak supaya package ini valid dipakai dari THREE konteks
 * berbeda (extension, CLI bulk-test, unit test) tanpa modifikasi.
 *
 * Cara pakai: node scripts/check-architecture.mjs
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';

const DOMAIN_LAYER_DIR = join(process.cwd(), 'packages', 'xss-risk-core');
const FORBIDDEN_PATTERN = /\bchrome\s*\.\s*\w+/;

/**
 * Mengumpulkan seluruh file .js secara rekursif di dalam suatu direktori.
 * @param {string} dir
 * @returns {string[]}
 */
function collectJsFiles(dir) {
  const results = [];
  for (const name of readdirSync(dir)) {
    const fullPath = join(dir, name);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      results.push(...collectJsFiles(fullPath));
    } else if (name.endsWith('.js')) {
      results.push(fullPath);
    }
  }
  return results;
}

const files = collectJsFiles(DOMAIN_LAYER_DIR);
const violations = [];

for (const file of files) {
  const content = readFileSync(file, 'utf-8');
  const lines = content.split('\n');
  lines.forEach((line, idx) => {
    if (FORBIDDEN_PATTERN.test(line) && !line.trim().startsWith('*') && !line.trim().startsWith('//')) {
      violations.push({ file, line: idx + 1, content: line.trim() });
    }
  });
}

if (violations.length > 0) {
  console.error(`❌ Pelanggaran arsitektur ditemukan (${violations.length}):`);
  for (const v of violations) {
    console.error(`   ${v.file}:${v.line} -> ${v.content}`);
  }
  console.error('\npackages/xss-risk-core tidak boleh mengimpor/memanggil chrome.* API.');
  process.exit(1);
} else {
  console.log(`✅ xss-risk-core bersih — ${files.length} file diperiksa, 0 pelanggaran chrome.* API.`);
  process.exit(0);
}
