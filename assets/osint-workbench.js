(() => {
  const list = document.querySelector('#resource-list');
  const search = document.querySelector('#global-q');
  const sectionFilter = document.querySelector('#section-filter');
  const accessFilter = document.querySelector('#access-filter');
  const formatFilter = document.querySelector('#format-filter');
  const empty = document.querySelector('#resource-empty');
  let sections = [];

  const create = (name, text, className) => {
    const node = document.createElement(name);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };

  function toolCard(tool) {
    const article = create('article', undefined, 'source-card');
    const top = create('div', undefined, 'source-card-top');
    const heading = create('div');
    heading.append(create('h4', tool.name));
    const link = create('a', 'Open tool ↗', 'button small');
    link.href = tool.url;
    link.rel = 'noopener';
    top.append(heading, link);

    const badges = create('div', undefined, 'source-badges');
    badges.append(create('span', tool.access.replaceAll('-', ' '), 'badge derived'));
    tool.format.split('/').forEach((format) => badges.append(create('span', format, 'badge')));

    const details = create('dl', undefined, 'source-details');
    [['Use it when', tool.use_when], ['Why it helps', tool.why], ['Do not overclaim', tool.caution]].forEach(([term, value]) => {
      details.append(create('dt', term), create('dd', value));
    });
    article.append(top, badges, details);
    return article;
  }

  function matches(tool, sectionId, query) {
    const searchable = [tool.name, tool.use_when, tool.why, tool.caution, tool.access, tool.format].join(' ').toLowerCase();
    return (!query || searchable.includes(query))
      && (sectionFilter.value === 'all' || sectionFilter.value === sectionId)
      && (accessFilter.value === 'all' || accessFilter.value === tool.access)
      && (formatFilter.value === 'all' || tool.format.split('/').includes(formatFilter.value));
  }

  function render() {
    const query = search?.value.trim().toLowerCase() || '';
    const groups = [];
    let visible = 0;
    sections.forEach((section) => {
      const tools = section.tools.filter((tool) => matches(tool, section.id, query));
      if (!tools.length) return;
      visible += tools.length;
      const group = create('section', undefined, 'source-section');
      const header = create('header', undefined, 'source-section-head');
      const title = create('div');
      title.append(create('p', section.id.replaceAll('-', ' '), 'eyebrow'), create('h3', section.name), create('p', section.description));
      header.append(title, create('span', `${tools.length} tools`, 'meta'));
      const grid = create('div', undefined, 'source-grid');
      grid.append(...tools.map(toolCard));
      group.append(header, grid);
      groups.push(group);
    });
    list.replaceChildren(...groups);
    const total = sections.reduce((sum, section) => sum + section.tools.length, 0);
    document.querySelector('#resource-count').textContent = `${visible} of ${total} tools`;
    empty.hidden = visible !== 0;
  }

  function addOption(select, value, label) {
    const option = create('option', label);
    option.value = value;
    select.append(option);
  }

  async function initialise() {
    try {
      const response = await fetch('/data/osint-resources.json', { credentials: 'same-origin' });
      if (!response.ok) throw new Error(`Resource request failed with ${response.status}`);
      const data = await response.json();
      sections = data.sections;
      const tools = sections.flatMap((section) => section.tools);
      document.querySelector('#resource-total').textContent = String(tools.length);
      document.querySelector('#section-total').textContent = String(sections.length);
      sections.forEach((section) => addOption(sectionFilter, section.id, section.name));
      [...new Set(tools.map((tool) => tool.access))].sort().forEach((access) => addOption(accessFilter, access, access.replaceAll('-', ' ')));
      render();
    } catch (error) {
      document.querySelector('#resource-count').textContent = 'Source data unavailable';
      empty.textContent = 'The source directory could not be loaded. Use the JSON dataset link or report the problem.';
      empty.hidden = false;
      console.error(error);
    }
  }

  [sectionFilter, accessFilter, formatFilter].forEach((control) => control.addEventListener('change', render));
  search?.addEventListener('input', render);
  search?.closest('form')?.addEventListener('submit', (event) => { event.preventDefault(); render(); });
  document.querySelector('#clear-filters').addEventListener('click', () => {
    if (search) search.value = '';
    sectionFilter.value = 'all';
    accessFilter.value = 'all';
    formatFilter.value = 'all';
    render();
  });
  initialise();
})();
