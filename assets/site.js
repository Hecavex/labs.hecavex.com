(() => {
  const menuButton = document.querySelector('.menu-toggle');
  const navigation = document.querySelector('.site-nav');
  const closeButton = navigation?.querySelector('.mobile-nav-close');
  const mobileNavigation = window.matchMedia('(max-width: 849px)');
  let menuReturnFocus = null;
  let menuOpen = false;

  const backdrop = document.createElement('button');
  backdrop.type = 'button';
  backdrop.className = 'nav-backdrop';
  backdrop.setAttribute('aria-label', 'Close navigation');
  backdrop.hidden = true;
  document.body.append(backdrop);

  function setMenuOpen(open, restoreFocus = true) {
    if (!menuButton || !navigation) return;
    const nextState = Boolean(open && mobileNavigation.matches);
    if (nextState && !menuOpen) menuReturnFocus = document.activeElement;
    menuOpen = nextState;
    menuButton.setAttribute('aria-expanded', String(menuOpen));
    menuButton.setAttribute('aria-label', menuOpen ? 'Close navigation' : 'Open navigation');
    navigation.classList.toggle('is-open', menuOpen);
    navigation.toggleAttribute('inert', mobileNavigation.matches && !menuOpen);
    if (mobileNavigation.matches) navigation.setAttribute('aria-hidden', String(!menuOpen));
    else navigation.removeAttribute('aria-hidden');
    document.body.classList.toggle('nav-open', menuOpen);
    backdrop.hidden = !menuOpen;
    if (menuOpen) closeButton?.focus();
    else if (restoreFocus && menuReturnFocus instanceof HTMLElement) {
      menuReturnFocus.focus();
      menuReturnFocus = null;
    }
  }

  menuButton?.addEventListener('click', () => setMenuOpen(!menuOpen));
  closeButton?.addEventListener('click', () => setMenuOpen(false));
  backdrop.addEventListener('click', () => setMenuOpen(false));
  navigation?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => setMenuOpen(false, false)));

  document.addEventListener('keydown', (event) => {
    if (!menuOpen || !navigation) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      setMenuOpen(false);
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = [...navigation.querySelectorAll('a[href], button:not([disabled]), summary, [tabindex]:not([tabindex="-1"])')]
      .filter((element) => !element.hidden && element.getClientRects().length);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  mobileNavigation.addEventListener('change', () => setMenuOpen(false, false));
  setMenuOpen(false, false);

  const networkSwitcher = document.querySelector('.network-switcher');
  document.addEventListener('click', (event) => {
    if (networkSwitcher?.open && !networkSwitcher.contains(event.target)) networkSwitcher.open = false;
  });

  const globalSearch = document.querySelector('#global-q');
  const searchItems = [...document.querySelectorAll('[data-search-item]')];
  if (searchItems.length && globalSearch) {
    const params = new URLSearchParams(location.search);
    globalSearch.value = params.get('q') || '';
    const filter = () => {
      const query = globalSearch.value.trim().toLowerCase();
      searchItems.forEach((item) => {
        item.hidden = Boolean(query) && !item.textContent.toLowerCase().includes(query);
      });
    };
    globalSearch.closest('form')?.addEventListener('submit', (event) => {
      event.preventDefault();
      filter();
    });
    globalSearch.addEventListener('input', filter);
    filter();
  }

})();
