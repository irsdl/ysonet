// Apply the saved preference before paint. Storage can be blocked in private contexts.
(() => {
  let theme = 'system';
  try { theme = localStorage.getItem('ysonet-theme') || 'system'; } catch (_) { /* Use system. */ }
  if (!['light', 'dark', 'system'].includes(theme)) theme = 'system';
  document.documentElement.dataset.theme = theme;
})();
