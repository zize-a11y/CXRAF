/**
 * ThemeToggle.js
 *
 * Fungsi: Membangun tombol toggle tema (dark/light, FR-11). Komponen ini
 * TIDAK menyimpan state sendiri — hanya memanggil callback onToggle yang
 * disuntikkan dari PopupController, yang bertanggung jawab menyimpan
 * preferensi via StorageService dan menerapkan atribut [data-theme] di <html>.
 */

const ICON = { dark: '🌙', light: '☀️' };

/**
 * @param {string} currentTheme - "dark" | "light"
 * @param {(nextTheme: string) => void} onToggle - dipanggil saat tombol diklik
 * @returns {HTMLButtonElement}
 */
export function createThemeToggle(currentTheme, onToggle) {
  const button = document.createElement('button');
  button.className = 'theme-toggle';
  button.type = 'button';
  button.setAttribute('aria-label', 'Ganti tema tampilan');
  button.textContent = ICON[currentTheme] ?? ICON.dark;

  button.addEventListener('click', () => {
    const next = currentTheme === 'dark' ? 'light' : 'dark';
    onToggle(next);
  });

  return button;
}
