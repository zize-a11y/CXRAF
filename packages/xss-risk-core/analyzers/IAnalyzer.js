/**
 * IAnalyzer.js
 *
 * Fungsi: Mendefinisikan kontrak (interface) yang harus dipenuhi oleh
 * setiap analyzer (CSPAnalyzer, ScriptAnalyzer, dan analyzer baru di masa
 * depan seperti CORSAnalyzer). JavaScript tidak punya keyword `interface`
 * native, sehingga kontrak ini diimplementasikan sebagai abstract class
 * yang melempar error jika method tidak di-override — ini memberi jaminan
 * runtime bahwa subclass benar-benar mengimplementasikan method wajib.
 *
 * Prinsip SOLID yang didukung: Open/Closed Principle (OCP) — menambah
 * analyzer baru tidak perlu mengubah AnalysisOrchestrator, cukup
 * implementasi class ini dan daftarkan di dependency injection.
 *
 * Alur kerja: AnalysisOrchestrator memanggil method `analyze(input)` tanpa
 * perlu tahu detail implementasi CSPAnalyzer atau ScriptAnalyzer di baliknya
 * (Dependency Inversion Principle).
 */

export class IAnalyzer {
  /**
   * Menjalankan analisis terhadap input tertentu.
   *
   * @param {object} input - bentuk input berbeda tergantung jenis analyzer
   *   (string header CSP untuk CSPAnalyzer, array ScriptEntry untuk ScriptAnalyzer)
   * @returns {object} hasil analisis (CSPResult atau ScriptResult)
   * @throws {Error} jika dipanggil langsung dari IAnalyzer tanpa override
   */
  analyze(input) {
    throw new Error(
      'IAnalyzer.analyze() harus di-override oleh subclass. ' +
      'Class ini tidak boleh diinstansiasi langsung.'
    );
  }
}
