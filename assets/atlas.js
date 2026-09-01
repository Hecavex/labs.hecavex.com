(() => {
  const list = document.querySelector('#atlas-records');
  const empty = document.querySelector('#atlas-empty');
  const count = document.querySelector('#atlas-count');
  const search = document.querySelector('#atlas-search');
  const country = document.querySelector('#atlas-country');
  const type = document.querySelector('#atlas-type');
  const year = document.querySelector('#atlas-year');
  const mappingList = document.querySelector('#atlas-mapping-list');
  const actorContextList = document.querySelector('#atlas-actor-context');
  const actorContextCount = document.querySelector('#atlas-context-count');
  let records = [];
  let recordsLoaded = false;

  const element = (name, className, text) => {
    const node = document.createElement(name);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  const normalise = (value) => String(value ?? '').toLowerCase();
  const recordYear = (record) => String(record.date).slice(0, 4);

  // Atlas dates have different levels of precision. Treat a year, quarter or
  // month as the start of that period so every record has one comparable key.
  function recordDateValue(record) {
    const value = String(record.date ?? '').trim();
    let match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
    if (match) return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));

    match = /^(\d{4})-(\d{2})$/.exec(value);
    if (match) return Date.UTC(Number(match[1]), Number(match[2]) - 1, 1);

    match = /^(\d{4})-Q([1-4])$/.exec(value);
    if (match) return Date.UTC(Number(match[1]), (Number(match[2]) - 1) * 3, 1);

    match = /^(\d{4})$/.exec(value);
    if (match) return Date.UTC(Number(match[1]), 0, 1);

    return Number.NEGATIVE_INFINITY;
  }

  function newestFirst(left, right) {
    const dateDifference = recordDateValue(right) - recordDateValue(left);
    if (dateDifference !== 0) return dateDifference;

    const leftId = String(left.id ?? '');
    const rightId = String(right.id ?? '');
    return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
  }

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
    // site.js publishes an initial ?q= value as soon as this workspace
    // subscribes. The dataset fetch may still be in flight at that point, so
    // retain the query in the input and defer record filtering until the
    // placeholder has been replaced with actual Atlas records.
    if (!recordsLoaded) return;

    const query = normalise(search.value.trim());
    const filters = { country: country.value, type: type.value, year: year.value };
    let visible = 0;
    [...list.querySelectorAll('.atlas-record')].forEach((article, index) => {
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
    document.querySelectorAll('[data-country-button]').forEach((button) => {
      const active = button.dataset.countryButton === country.value;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
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

  function renderActorContext(actors) {
    const sortedActors = [...actors].sort((left, right) => left.name.localeCompare(right.name));
    actorContextList.replaceChildren(...sortedActors.map((actor) => {
      const card = element('article', 'card');
      const top = element('div', 'atlas-tags');
      top.append(
        element('span', 'badge derived', actor.category.replaceAll('-', ' ')),
        element('span', 'atlas-tag', actor.status.replaceAll('-', ' ')),
        element('span', 'atlas-tag', actor.context_scope === 'baltic-linked' ? 'Baltic observation linked' : 'Europe context only'),
      );

      const heading = element('h3');
      const link = element('a', '', `${actor.name} ↗`);
      link.href = actor.apt_url;
      heading.append(link);

      const mappingIds = actor.baltic_observation_ids || [];
      const boundary = mappingIds.length
        ? `${mappingIds.length} explicit Baltic observation${mappingIds.length === 1 ? '' : 's'} mapped`
        : 'No Baltic observation mapped';

      card.append(
        top,
        heading,
        element('p', '', actor.summary),
        element('p', '', actor.europe_relevance),
        element('p', 'meta', `${actor.confidence} confidence · reviewed ${actor.last_reviewed} · source record ${actor.source_record_version} · ${boundary}`),
      );
      return card;
    }));
    const balticLinked = sortedActors.filter((actor) => actor.context_scope === 'baltic-linked').length;
    actorContextCount.textContent = `${sortedActors.length} Europe-context actors · ${balticLinked} with explicit Baltic mappings`;
    document.querySelector('#atlas-context-total').textContent = String(sortedActors.length);
  }

  async function initialise() {
    try {
      const response = await fetch('/data/atlas/records.json?v=20260901-1', { credentials: 'same-origin' });
      if (!response.ok) throw new Error(`Dataset request failed with ${response.status}`);
      const data = await response.json();
      records = [...data.records].sort(newestFirst);
      list.replaceChildren(...records.map(renderRecord));
      recordsLoaded = true;
      populateSelect(type, records.map((record) => record.type));
      populateSelect(year, records.map(recordYear));
      document.querySelector('#atlas-total').textContent = String(records.length);
      document.querySelector('#atlas-attributions').textContent = String(records.filter((record) => record.confidence === 'official-attribution').length);
      ['lithuania', 'latvia', 'estonia'].forEach((name) => { document.querySelector(`#count-${name}`).textContent = String(records.filter((record) => normalise(record.country) === name).length); });
      renderMappings();
      renderActorContext(data.actor_context || []);
      const contextSource = data.actor_context_source;
      const contextRelease = document.querySelector('#atlas-context-release');
      if (contextSource && contextRelease) {
        contextRelease.textContent = '';
        const sourceLink = element('a', '', `Source release: APT Notes ${contextSource.dataset_version} ↗`);
        sourceLink.href = contextSource.url;
        sourceLink.rel = 'noopener';
        contextRelease.append(sourceLink);
      }
      update();
    } catch (error) {
      list.replaceChildren(element('div', 'empty', 'The Atlas dataset could not be loaded. Download the JSON or report the problem.'));
      count.textContent = 'Dataset unavailable';
      console.error(error);
    }
  }

  [search, country, type, year].forEach((control) => control.addEventListener(control === search ? 'input' : 'change', update));
  document.querySelectorAll('[data-country-button]').forEach((button) => button.addEventListener('click', () => { country.value = country.value === button.dataset.countryButton ? '' : button.dataset.countryButton; update(); }));
  window.HECAVEX_LABS?.bindShellSearch((query) => {
    search.value = query;
    update();
  });
  initialise();
})();
