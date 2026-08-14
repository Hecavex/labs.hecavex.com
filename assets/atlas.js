(() => {
  const list = document.querySelector('#atlas-records');
  const empty = document.querySelector('#atlas-empty');
  const count = document.querySelector('#atlas-count');
  const search = document.querySelector('#atlas-search');
  const globalSearch = document.querySelector('#global-q');
  const country = document.querySelector('#atlas-country');
  const type = document.querySelector('#atlas-type');
  const year = document.querySelector('#atlas-year');
  const mappingList = document.querySelector('#atlas-mapping-list');
  let records = [];

  const element = (name, className, text) => {
    const node = document.createElement(name);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  const normalise = (value) => String(value ?? '').toLowerCase();
  const recordYear = (record) => String(record.date).slice(0, 4);

  function sourceLabel(url) {
    try { return new URL(url).hostname.replace(/^www\./, ''); }
    catch { return 'Primary source'; }
  }

  function renderRecord(record) {
    const article = element('article', 'atlas-record');
    article.dataset.search = normalise([record.title, record.summary, record.country, record.type, record.sector, record.actor, record.attribution].join(' '));

    const date = element('div', 'atlas-date');
    date.append(element('strong', '', record.date), document.createElement('br'), document.createTextNode(record.country));

    const body = element('div');
    body.append(element('span', `badge ${record.confidence === 'official-attribution' ? 'official' : 'observed'}`, record.confidence.replaceAll('-', ' ')));
    body.append(element('h3', '', record.title));
    body.append(element('p', '', record.summary));

    const tags = element('div', 'atlas-tags');
    [record.type, record.sector, record.actor].filter(Boolean).forEach((value) => tags.append(element('span', 'atlas-tag', value)));
    body.append(tags);

    const links = element('p', 'meta');
    const source = element('a', '', `Source: ${sourceLabel(record.source)} ↗`);
    source.href = record.source;
    source.rel = 'noopener';
    links.append(source);
    (record.apt_refs || []).forEach((reference) => {
      links.append(document.createTextNode(' · '));
      const link = element('a', '', `${reference.label} ↗`);
      link.href = reference.url;
      links.append(link);
    });
    body.append(links);
    article.append(date, body);
    return article;
  }

  function populateSelect(select, values) {
    [...new Set(values)].sort().forEach((value) => {
      const option = element('option', '', value.replaceAll('-', ' '));
      option.value = value;
      select.append(option);
    });
  }

  function update() {
    const query = normalise(search.value.trim());
    const filters = { country: country.value, type: type.value, year: year.value };
    let visible = 0;
    [...list.children].forEach((article, index) => {
      const record = records[index];
      const matches = (!query || article.dataset.search.includes(query))
        && (!filters.country || normalise(record.country) === filters.country)
        && (!filters.type || record.type === filters.type)
        && (!filters.year || recordYear(record) === filters.year);
      article.hidden = !matches;
      if (matches) visible += 1;
    });
    count.textContent = `${visible} of ${records.length} observations`;
    empty.hidden = visible !== 0;
    document.querySelectorAll('[data-country-button]').forEach((button) => button.classList.toggle('active', button.dataset.countryButton === country.value));
  }

  function renderMappings() {
    const mappings = new Map();
    records.flatMap((record) => record.apt_refs || []).forEach((reference) => mappings.set(reference.url, reference));
    mappingList.replaceChildren();
    mappings.forEach((reference) => {
      const card = element('div', 'mapping-card');
      const label = element('p', 'meta', reference.type);
      const heading = element('h3');
      const link = element('a', '', `${reference.label} ↗`);
      link.href = reference.url;
      heading.append(link);
      card.append(label, heading);
      mappingList.append(card);
    });
    document.querySelector('#atlas-mappings').textContent = String(mappings.size);
  }

  async function initialise() {
    try {
      const response = await fetch('/data/baltic-threat-atlas.json', { credentials: 'same-origin' });
      if (!response.ok) throw new Error(`Dataset request failed with ${response.status}`);
      const data = await response.json();
      records = data.records;
      list.replaceChildren(...records.map(renderRecord));
      populateSelect(type, records.map((record) => record.type));
      populateSelect(year, records.map(recordYear));
      document.querySelector('#atlas-total').textContent = String(records.length);
      document.querySelector('#atlas-attributions').textContent = String(records.filter((record) => record.confidence === 'official-attribution').length);
      ['lithuania', 'latvia', 'estonia'].forEach((name) => { document.querySelector(`#count-${name}`).textContent = String(records.filter((record) => normalise(record.country) === name).length); });
      renderMappings();
      update();
    } catch (error) {
      list.replaceChildren(element('div', 'empty', 'The Atlas dataset could not be loaded. Download the JSON or report the problem.'));
      count.textContent = 'Dataset unavailable';
      console.error(error);
    }
  }

  [search, country, type, year].forEach((control) => control.addEventListener(control === search ? 'input' : 'change', update));
  document.querySelectorAll('[data-country-button]').forEach((button) => button.addEventListener('click', () => { country.value = country.value === button.dataset.countryButton ? '' : button.dataset.countryButton; update(); }));
  globalSearch?.addEventListener('input', () => { search.value = globalSearch.value; update(); });
  globalSearch?.closest('form')?.addEventListener('submit', (event) => { event.preventDefault(); search.value = globalSearch.value; update(); });
  initialise();
})();
