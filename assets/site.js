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

  const documentToc = document.querySelector('.document-toc');
  const documentTocLinks = [...(documentToc?.querySelectorAll('a[href^="#"]') || [])];
  const documentSections = documentTocLinks
    .map((link) => ({ link, target: document.querySelector(link.getAttribute('href')) }))
    .filter(({ target }) => target);

  if (documentSections.length) {
    let tocFrame;
    const updateDocumentToc = () => {
      if (tocFrame) return;
      tocFrame = requestAnimationFrame(() => {
        tocFrame = undefined;
        const headerHeight = document.querySelector('.site-header')?.getBoundingClientRect().height || 0;
        const activationLine = headerHeight + Math.min(72, window.innerHeight * .12);
        let currentIndex = 0;
        documentSections.forEach(({ target }, index) => {
          if (target.getBoundingClientRect().top <= activationLine) currentIndex = index;
        });
        if (window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 4) {
          currentIndex = documentSections.length - 1;
        }
        documentSections.forEach(({ link }, index) => {
          if (index === currentIndex) link.setAttribute('aria-current', 'location');
          else link.removeAttribute('aria-current');
        });
      });
    };

    window.addEventListener('scroll', updateDocumentToc, { passive: true });
    window.addEventListener('resize', updateDocumentToc, { passive: true });
    window.addEventListener('hashchange', updateDocumentToc);
    window.addEventListener('pageshow', updateDocumentToc);
    updateDocumentToc();
  }
})();
