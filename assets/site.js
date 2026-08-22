(() => {
  const mobileNavigation = document.querySelector('[data-mobile-navigation]');
  const menuSummary = mobileNavigation?.querySelector('summary');

  const updateMenuLabel = () => {
    menuSummary?.setAttribute(
      'aria-label',
      mobileNavigation?.open ? 'Close navigation menu' : 'Open navigation menu',
    );
  };

  mobileNavigation?.addEventListener('toggle', updateMenuLabel);
  mobileNavigation?.querySelectorAll('a[href]').forEach((link) => {
    link.addEventListener('click', () => {
      mobileNavigation.open = false;
    });
  });

  document.addEventListener('click', (event) => {
    if (mobileNavigation?.open && !mobileNavigation.contains(event.target)) {
      mobileNavigation.open = false;
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !mobileNavigation?.open) return;
    mobileNavigation.open = false;
    menuSummary?.focus({ preventScroll: true });
  });

  window.matchMedia('(min-width: 1161px)').addEventListener('change', (event) => {
    if (event.matches && mobileNavigation) mobileNavigation.open = false;
  });
  updateMenuLabel();

  const searchInputs = [...document.querySelectorAll('[data-shell-search]')];
  const searchItems = [...document.querySelectorAll('[data-search-item]')];
  if (searchInputs.length && searchItems.length) {
    const params = new URLSearchParams(location.search);
    const initialQuery = params.get('q') || '';

    const filter = (query) => {
      const normalized = query.trim().toLowerCase();
      searchInputs.forEach((input) => {
        if (input.value !== query) input.value = query;
      });
      searchItems.forEach((item) => {
        item.hidden = Boolean(normalized) && !item.textContent.toLowerCase().includes(normalized);
      });
    };

    searchInputs.forEach((input) => {
      input.value = initialQuery;
      input.addEventListener('input', () => filter(input.value));
      input.closest('form')?.addEventListener('submit', (event) => {
        event.preventDefault();
        filter(input.value);
      });
    });
    filter(initialQuery);
  }
})();
