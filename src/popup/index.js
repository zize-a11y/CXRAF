/**
 * index.js (popup)
 *
 * Fungsi: Entry point popup, composition root khusus presentation layer.
 * Menunggu DOMContentLoaded, lalu menginstansiasi UIRenderer + StorageService
 * dan menyuntikkannya ke PopupController.
 */

import { PopupController } from './PopupController.js';
import { UIRenderer } from './UIRenderer.js';
import { StorageService } from '../services/StorageService.js';

document.addEventListener('DOMContentLoaded', () => {
  const rootEl = document.getElementById('app');
  const uiRenderer = new UIRenderer(rootEl);
  const storageService = new StorageService();

  const controller = new PopupController(uiRenderer, storageService);
  controller.init();
});
