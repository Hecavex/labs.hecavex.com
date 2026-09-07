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
  const shellSearchSubscribers = new Set();
  let shellQuery = new URLSearchParams(location.search).get('q') || '';

  const publishShellSearch = (query) => {
    shellQuery = query;
    const normalized = query.trim().toLowerCase();
    searchInputs.forEach((input) => {
      if (input.value !== query) input.value = query;
    });
    searchItems.forEach((item) => {
      item.hidden = Boolean(normalized) && !item.textContent.toLowerCase().includes(normalized);
    });
    shellSearchSubscribers.forEach((subscriber) => subscriber(query));
  };

  // Workspace scripts subscribe after site.js has loaded. Calling a new
  // subscriber immediately prevents the initial ?q= value from being lost.
  window.HECAVEX_LABS = Object.freeze({
    bindCopiedView(fields, container, update, extra = {}) {
      const restore = () => {
        if (!location.hash.startsWith('#view=')) return;
        let values;
        try { values = new URLSearchParams(decodeURIComponent(location.hash.slice(6))); } catch { return; }
        for (const [name, control] of Object.entries(fields)) {
          const value = values.get(name) || '';
          control.value = control.tagName === 'SELECT' && ![...control.options].some((option) => option.value === value) ? '' : value;
        }
        extra.restore?.(values);
        update();
      };
      const panel = document.createElement('p');
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'button';
      button.textContent = 'Copy filtered view';
      const status = document.createElement('span');
      status.className = 'meta';
      status.setAttribute('role', 'status');
      status.textContent = ' Includes search text only when copied. Review before sharing.';
      panel.append(button, status);
      container.after(panel);
      button.addEventListener('click', async () => {
        const values = new URLSearchParams();
        for (const [name, control] of Object.entries(fields)) if (control.value) values.set(name, control.value);
        extra.save?.(values);
        const url = new URL(location.pathname, location.origin);
        url.hash = `view=${encodeURIComponent(values.toString())}`;
        try {
          await navigator.clipboard.writeText(url.href);
          status.textContent = ' View copied. Search text is kept in the fragment, not the HTTP request.';
        } catch {
          status.textContent = ' Select and copy this link: ';
          const input = document.createElement('input');
          input.readOnly = true;
          input.value = url.href;
          input.setAttribute('aria-label', 'Filtered view link');
          status.append(input);
          input.focus();
          input.select();
        }
      });
      window.addEventListener('hashchange', restore);
      restore();
    },
    bindShellSearch(subscriber) {
      if (typeof subscriber !== 'function') return () => {};
      shellSearchSubscribers.add(subscriber);
      subscriber(shellQuery);
      return () => shellSearchSubscribers.delete(subscriber);
    }
  });

  searchInputs.forEach((input) => {
    input.value = shellQuery;
    input.addEventListener('input', () => publishShellSearch(input.value));
    input.closest('form')?.addEventListener('submit', (event) => {
      event.preventDefault();
      publishShellSearch(input.value);
    });
  });
  publishShellSearch(shellQuery);

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
