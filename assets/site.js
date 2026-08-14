(() => {
  const root = document.documentElement;
  const themeButton = document.querySelector('.theme-toggle');
  const themeIcon = themeButton?.querySelector('i');
  const modes = ['system', 'dark', 'light'];
  let mode = 'system';

  try { mode = localStorage.getItem('hecavex-theme') || 'system'; } catch {}

  function applyTheme(next) {
    mode = modes.includes(next) ? next : 'system';
    if (mode === 'system') root.removeAttribute('data-theme');
    else root.dataset.theme = mode;
    if (themeButton) themeButton.title = `Theme: ${mode}`;
    if (themeIcon) themeIcon.className = mode === 'light' ? 'fa-regular fa-sun' : mode === 'dark' ? 'fa-regular fa-moon' : 'fa-solid fa-display';
    try { localStorage.setItem('hecavex-theme', mode); } catch {}
  }

  applyTheme(mode);
  themeButton?.addEventListener('click', () => applyTheme(modes[(modes.indexOf(mode) + 1) % modes.length]));

  const menuButton = document.querySelector('.menu-toggle');
  const sidebar = document.querySelector('.sidebar');
  menuButton?.addEventListener('click', () => {
    const open = menuButton.getAttribute('aria-expanded') === 'true';
    menuButton.setAttribute('aria-expanded', String(!open));
    sidebar?.classList.toggle('is-open', !open);
  });

  const topbar = document.querySelector('.topbar');
  const searchToggle = document.querySelector('.search-toggle');
  const searchCancel = document.querySelector('.search-cancel');
  const globalSearch = document.querySelector('#global-q');
  searchToggle?.addEventListener('click', () => { topbar?.classList.add('search-open'); globalSearch?.focus(); });
  searchCancel?.addEventListener('click', () => topbar?.classList.remove('search-open'));

  const searchItems = [...document.querySelectorAll('[data-search-item]')];
  if (searchItems.length && globalSearch) {
    const params = new URLSearchParams(location.search);
    globalSearch.value = params.get('q') || '';
    const filter = () => {
      const query = globalSearch.value.trim().toLowerCase();
      searchItems.forEach((item) => { item.hidden = Boolean(query) && !item.textContent.toLowerCase().includes(query); });
    };
    globalSearch.closest('form')?.addEventListener('submit', (event) => { event.preventDefault(); filter(); });
    globalSearch.addEventListener('input', filter);
    filter();
  }

  const measurementToken = document.querySelector('meta[name="hecavex-measurement-token"]')?.content.trim();
  if (measurementToken && !measurementToken.startsWith('__') && navigator.doNotTrack !== '1' && window.doNotTrack !== '1') {
    const beacon = document.createElement('script');
    beacon.defer = true;
    beacon.src = 'https://static.cloudflareinsights.com/beacon.min.js';
    beacon.dataset.cfBeacon = JSON.stringify({ token: measurementToken });
    document.head.appendChild(beacon);
  }
})();
