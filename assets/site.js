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
    const nextMode = modes[(modes.indexOf(mode) + 1) % modes.length];
    if (themeButton) {
      themeButton.title = `Theme: ${mode}. Change to ${nextMode}.`;
      themeButton.setAttribute('aria-label', `Theme: ${mode}. Change to ${nextMode}.`);
    }
    if (themeIcon) themeIcon.className = mode === 'light' ? 'fa-regular fa-sun' : mode === 'dark' ? 'fa-regular fa-moon' : 'fa-solid fa-display';
    try { localStorage.setItem('hecavex-theme', mode); } catch {}
  }

  applyTheme(mode);
  themeButton?.addEventListener('click', () => applyTheme(modes[(modes.indexOf(mode) + 1) % modes.length]));

  const menuButton = document.querySelector('.menu-toggle');
  const sidebar = document.querySelector('.sidebar');
  const mobileNavigation = window.matchMedia('(max-width: 849px)');
  let menuReturnFocus = null;
  let menuOpen = false;
  let closeButton;
  let backdrop;

  if (menuButton && sidebar) {
    closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'mobile-nav-close';
    closeButton.setAttribute('aria-label', 'Close navigation');
    closeButton.innerHTML = '<i class="fa-solid fa-xmark" aria-hidden="true"></i>';
    sidebar.prepend(closeButton);

    backdrop = document.createElement('button');
    backdrop.type = 'button';
    backdrop.className = 'nav-backdrop';
    backdrop.setAttribute('aria-label', 'Close navigation');
    backdrop.hidden = true;
    document.body.append(backdrop);
  }

  function setMenuOpen(open, restoreFocus = true) {
    if (!menuButton || !sidebar) return;
    menuOpen = Boolean(open && mobileNavigation.matches);
    menuButton.setAttribute('aria-expanded', String(menuOpen));
    menuButton.setAttribute('aria-label', menuOpen ? 'Close navigation' : 'Open navigation');
    sidebar.classList.toggle('is-open', menuOpen);
    sidebar.toggleAttribute('inert', mobileNavigation.matches && !menuOpen);
    sidebar.setAttribute('aria-hidden', mobileNavigation.matches && !menuOpen ? 'true' : 'false');
    if (!mobileNavigation.matches) sidebar.removeAttribute('aria-hidden');
    document.body.classList.toggle('nav-open', menuOpen);
    if (backdrop) backdrop.hidden = !menuOpen;
    if (menuOpen) {
      menuReturnFocus = document.activeElement;
      closeButton?.focus();
    } else if (restoreFocus && menuReturnFocus instanceof HTMLElement) {
      menuReturnFocus.focus();
      menuReturnFocus = null;
    }
  }

  menuButton?.addEventListener('click', () => setMenuOpen(!menuOpen));
  closeButton?.addEventListener('click', () => setMenuOpen(false));
  backdrop?.addEventListener('click', () => setMenuOpen(false));
  sidebar?.querySelectorAll('nav a').forEach((link) => link.addEventListener('click', () => setMenuOpen(false, false)));
  document.addEventListener('keydown', (event) => {
    if (!menuOpen) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      setMenuOpen(false);
      return;
    }
    if (event.key !== 'Tab' || !sidebar) return;
    const focusable = [...sidebar.querySelectorAll('a[href], button:not([disabled]), summary, input, select, textarea, [tabindex]:not([tabindex="-1"])')]
      .filter((element) => !element.hidden && element.getClientRects().length);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });
  mobileNavigation.addEventListener('change', () => setMenuOpen(false, false));
  setMenuOpen(false, false);

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
