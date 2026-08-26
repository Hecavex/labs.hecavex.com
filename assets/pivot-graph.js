(() => {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.querySelector('#graph-svg');
  const ledger = document.querySelector('#claim-ledger');
  const search = document.querySelector('#global-q');
  const selector = document.querySelector('#case-selector');
  let catalogue;
  let selectedCase;
  let data;

  const createSvg = (name, attrs = {}) => {
    const node = document.createElementNS(NS, name);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    return node;
  };

  const create = (name, text, className) => {
    const node = document.createElement(name);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };

  function edgePoints(source, target) {
    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const sourceScale = 1 / Math.max(Math.abs(dx) / 74, Math.abs(dy) / 31);
    const targetScale = 1 / Math.max(Math.abs(dx) / 82, Math.abs(dy) / 38);
    return { x1: source.x + dx * sourceScale, y1: source.y + dy * sourceScale, x2: target.x - dx * targetScale, y2: target.y - dy * targetScale };
  }

  function selectNode(node) {
    document.querySelectorAll('.graph-node').forEach((item) => item.classList.toggle('active', item.dataset.id === node.id));
    document.querySelector('#node-title').textContent = node.label;
    document.querySelector('#node-class').textContent = node.class;
    document.querySelector('#node-confidence').textContent = node.confidence;
    document.querySelector('#node-detail').textContent = node.meaning;
    const link = create('a', `${node.evidence_label} ↗`);
    link.href = node.evidence;
    link.rel = 'noopener';
    document.querySelector('#node-evidence').replaceChildren(link);
  }

  function renderGraph() {
    svg.replaceChildren();
    const title = createSvg('title', { id: 'graph-title' });
    title.textContent = `${selectedCase.title} evidence graph`;
    const description = createSvg('desc', { id: 'graph-desc' });
    description.textContent = 'Observed artefacts lead to reproducible derivations, bounded assessments and explicit limitations.';
    svg.append(title, description);

    const defs = createSvg('defs');
    const markerId = `arrow-${selectedCase.id}`;
    const marker = createSvg('marker', { id: markerId, viewBox: '0 0 10 10', refX: '8', refY: '5', markerWidth: '6', markerHeight: '6', orient: 'auto-start-reverse' });
    marker.append(createSvg('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: 'currentColor' }));
    defs.append(marker);
    svg.append(defs);

    const byId = Object.fromEntries(data.nodes.map((node) => [node.id, node]));
    data.edges.forEach((edge) => {
      const points = edgePoints(byId[edge.source], byId[edge.target]);
      svg.append(createSvg('line', { class: 'graph-edge', ...points, 'marker-end': `url(#${markerId})` }));
      const label = createSvg('text', { class: 'graph-edge-label', x: String((points.x1 + points.x2) / 2), y: String((points.y1 + points.y2) / 2 - 7), 'text-anchor': 'middle' });
      label.textContent = edge.relationship;
      svg.append(label);
    });

    data.nodes.forEach((node) => {
      const group = createSvg('g', { class: 'graph-node', 'data-id': node.id, 'data-class': node.class, role: 'button', tabindex: '0', 'aria-label': `${node.label}, ${node.class}` });
      group.append(createSvg('rect', { x: String(node.x - 76), y: String(node.y - 31), width: '152', height: '62' }));
      const text = createSvg('text', { x: String(node.x), y: String(node.y - 4), 'text-anchor': 'middle' });
      node.short_label.forEach((line, index) => {
        const tspan = createSvg('tspan', { x: String(node.x), dy: index === 0 ? '0' : '17' });
        tspan.textContent = line;
        text.append(tspan);
      });
      group.append(text);
      group.addEventListener('click', () => selectNode(node));
      group.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          selectNode(node);
        }
      });
      svg.append(group);
    });
    selectNode(data.nodes[0]);
  }

  function filterLedger() {
    if (!data) return;
    const query = search?.value.trim().toLowerCase() || '';
    let visible = 0;
    [...ledger.children].forEach((row) => {
      row.hidden = Boolean(query) && !row.dataset.search.includes(query);
      if (!row.hidden) visible += 1;
    });
    document.querySelector('#ledger-count').textContent = `${visible} of ${data.nodes.length} claims`;
  }

  function renderLedger() {
    ledger.replaceChildren(...data.nodes.map((node) => {
      const row = create('tr');
      row.dataset.search = [node.label, node.class, node.confidence, node.meaning].join(' ').toLowerCase();
      const object = create('td');
      const button = create('button', node.label, 'button small');
      button.type = 'button';
      button.addEventListener('click', () => {
        selectNode(node);
        document.querySelector('#graph').scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
      object.append(button);
      const kind = create('td');
      kind.append(create('span', node.class, `badge ${node.class === 'assessment' ? 'assessed' : node.class}`));
      const evidence = create('td');
      const link = create('a', `${node.evidence_label} ↗`);
      link.href = node.evidence;
      link.rel = 'noopener';
      evidence.append(link);
      row.append(object, kind, create('td', node.confidence), evidence);
      return row;
    }));
    filterLedger();
  }

  function renderSelector() {
    selector.replaceChildren(...catalogue.cases.map((caseItem) => {
      const button = create('button', undefined, 'case-card');
      button.type = 'button';
      button.dataset.caseId = caseItem.id;
      button.setAttribute('aria-pressed', String(caseItem.id === selectedCase?.id));
      const top = create('span', undefined, 'case-card-top');
      top.append(create('span', caseItem.status, 'badge derived'), create('span', caseItem.updated, 'case-date'));
      button.append(top, create('strong', caseItem.short_title), create('span', caseItem.summary, 'case-card-summary'));
      const tags = create('span', undefined, 'case-tags');
      caseItem.tags.forEach((tag) => tags.append(create('span', tag)));
      button.append(tags);
      button.addEventListener('click', () => loadCase(caseItem.id, true).catch(showError));
      return button;
    }));
  }

  function updateCaseHeader() {
    document.querySelector('#case-title').textContent = selectedCase.title;
    document.querySelector('#case-summary').textContent = selectedCase.summary;
    document.querySelector('#case-meta').textContent = `${selectedCase.id.toUpperCase()} · ${selectedCase.status.toUpperCase()} · UPDATED ${selectedCase.updated}`;
    document.querySelector('#case-research-link').href = selectedCase.research;
    document.querySelector('#case-json-link').href = selectedCase.graph;
    document.querySelector('#case-boundary').textContent = data.case.boundary;
    document.querySelector('#graph-case-label').textContent = selectedCase.title;
    document.querySelector('#case-node-count').textContent = String(data.nodes.length);
    document.querySelector('#case-edge-count').textContent = String(data.edges.length);
    renderSelector();
  }

  async function loadCase(caseId, updateHistory = false) {
    selectedCase = catalogue.cases.find((caseItem) => caseItem.id === caseId) || catalogue.cases[0];
    document.querySelector('#node-title').textContent = 'Loading case…';
    document.querySelector('#node-detail').textContent = 'Retrieving the selected graph.';
    const response = await fetch(selectedCase.graph, { credentials: 'same-origin' });
    if (!response.ok) throw new Error(`Graph request failed with ${response.status}`);
    data = await response.json();
    if (data.case.id !== selectedCase.id) throw new Error(`Catalogue and graph case IDs differ for ${selectedCase.id}`);
    if (search) search.value = '';
    updateCaseHeader();
    renderGraph();
    renderLedger();
    if (updateHistory) {
      const url = new URL(window.location.href);
      url.searchParams.set('case', selectedCase.id);
      window.history.pushState({ caseId: selectedCase.id }, '', url);
    }
  }

  function showError(error) {
    document.querySelector('#node-title').textContent = 'Case data unavailable';
    document.querySelector('#node-detail').textContent = 'Download the case catalogue or report the problem.';
    console.error(error);
  }

  async function initialise() {
    try {
      const response = await fetch('/data/pivots/cases.json', { credentials: 'same-origin' });
      if (!response.ok) throw new Error(`Case catalogue request failed with ${response.status}`);
      catalogue = await response.json();
      if (!catalogue.cases.length) throw new Error('No approved public cases are available');
      document.querySelector('#case-total').textContent = String(catalogue.cases.length);
      await loadCase(new URL(window.location.href).searchParams.get('case'), false);
    } catch (error) {
      document.querySelector('#case-title').textContent = 'Case catalogue unavailable';
      showError(error);
    }
  }

  search?.addEventListener('input', filterLedger);
  search?.closest('form')?.addEventListener('submit', (event) => { event.preventDefault(); filterLedger(); });
  window.addEventListener('popstate', () => {
    if (catalogue) loadCase(new URL(window.location.href).searchParams.get('case'), false).catch(showError);
  });
  initialise();
})();
