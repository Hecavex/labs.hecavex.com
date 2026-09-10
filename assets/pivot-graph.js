(() => {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.querySelector('#graph-svg');
  const ledger = document.querySelector('#claim-ledger');
  const selector = document.querySelector('#case-selector');
  let catalogue;
  let selectedCase;
  let data;
  let shellQuery = '';
  const graphWidth = 1100;
  const graphLeft = 105;
  const graphRight = graphWidth - 105;
  const nodeWidth = 170;
  const nodeHeight = 66;

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
    const sourceScale = 1 / Math.max(Math.abs(dx) / (nodeWidth / 2), Math.abs(dy) / (nodeHeight / 2));
    const targetScale = sourceScale;
    return { x1: source.x + dx * sourceScale, y1: source.y + dy * sourceScale, x2: target.x - dx * targetScale, y2: target.y - dy * targetScale };
  }

  function layoutNodes(nodes) {
    const positions = nodes.map((node) => node.x);
    const minimum = Math.min(...positions);
    const maximum = Math.max(...positions);
    const span = maximum - minimum;
    return nodes.map((node) => ({
      ...node,
      x: span ? graphLeft + ((node.x - minimum) / span) * (graphRight - graphLeft) : graphWidth / 2
    }));
  }

  function wrapEdgeLabel(value, maximumLength = 18) {
    const words = value.trim().split(/\s+/);
    const lines = [];
    words.forEach((word) => {
      const current = lines.at(-1);
      if (current && `${current} ${word}`.length <= maximumLength) lines[lines.length - 1] = `${current} ${word}`;
      else lines.push(word);
    });
    return lines;
  }

  function appendEdgeLabel(edge, points) {
    const x = (points.x1 + points.x2) / 2;
    const y = (points.y1 + points.y2) / 2 - 8;
    const lines = wrapEdgeLabel(edge.relationship);
    const group = createSvg('g', { class: 'graph-edge-label-group', 'aria-hidden': 'true' });
    const label = createSvg('text', { class: 'graph-edge-label', x: String(x), y: String(y - ((lines.length - 1) * 6)), 'text-anchor': 'middle' });
    lines.forEach((line, index) => {
      const tspan = createSvg('tspan', { x: String(x), dy: index === 0 ? '0' : '12' });
      tspan.textContent = line;
      label.append(tspan);
    });
    group.append(label);
    svg.append(group);
    const box = label.getBBox();
    const background = createSvg('rect', {
      class: 'graph-edge-label-bg',
      x: String(box.x - 5),
      y: String(box.y - 3),
      width: String(box.width + 10),
      height: String(box.height + 6),
      rx: '2'
    });
    group.insertBefore(background, label);
  }

  const claimAnchor = (node) => `claim-${selectedCase.id}-${node.id}`;
  function selectNode(node, updateHistory = true) {
    document.querySelectorAll('.graph-node').forEach((item) => item.classList.toggle('active', item.dataset.id === node.id));
    document.querySelector('#node-title').textContent = node.label;
    document.querySelector('#node-class').textContent = node.class;
    document.querySelector('#node-confidence').textContent = node.confidence;
    document.querySelector('#node-detail').textContent = node.meaning;
    const link = create('a', `${node.evidence_label} ↗`);
    link.href = node.evidence;
    link.rel = 'noopener';
    const permalink = new URL(location.href);
    permalink.searchParams.set('case', selectedCase.id);
    permalink.searchParams.set('node', node.id);
    permalink.hash = claimAnchor(node);
    const copy = create('button', 'Copy claim link', 'button small');
    copy.type = 'button';
    const direct = create('a', 'Claim permalink');
    direct.href = permalink.href;
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(permalink.href); copy.textContent = 'Claim link copied'; }
      catch { copy.textContent = 'Use Claim permalink to copy the address'; }
    });
    document.querySelector('#node-evidence').replaceChildren(link, document.createTextNode(' '), direct, document.createTextNode(' '), copy);
    if (node.artifact) {
      const artifact = create('a', node.artifact_locator || 'Released artifact');
      artifact.href = node.artifact;
      document.querySelector('#node-evidence').append(create('br'), artifact);
    }
    if (updateHistory) history.pushState({ caseId: selectedCase.id, nodeId: node.id }, '', permalink);
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

    const nodes = layoutNodes(data.nodes);
    const byId = Object.fromEntries(nodes.map((node) => [node.id, node]));
    data.edges.forEach((edge) => {
      const points = edgePoints(byId[edge.source], byId[edge.target]);
      svg.append(createSvg('line', { class: 'graph-edge', ...points, 'marker-end': `url(#${markerId})` }));
      appendEdgeLabel(edge, points);
    });

    nodes.forEach((node) => {
      const group = createSvg('g', { class: 'graph-node', 'data-id': node.id, 'data-class': node.class, role: 'button', tabindex: '0', 'aria-label': `${node.label}, ${node.class}` });
      group.append(createSvg('rect', { x: String(node.x - (nodeWidth / 2)), y: String(node.y - (nodeHeight / 2)), width: String(nodeWidth), height: String(nodeHeight) }));
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
    selectNode(data.nodes[0], false);
  }

  function filterLedger() {
    if (!data) return;
    const query = shellQuery.trim().toLowerCase();
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
      row.id = claimAnchor(node);
      row.tabIndex = -1;
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
    const reproduction = document.querySelector('#case-reproducibility');
    if (reproduction) {
      reproduction.replaceChildren(create('summary', 'What can be reproduced from this case?'));
      const scope = selectedCase.reproducibility;
      if (scope) {
        for (const [label, value] of [['Preserved inputs', scope.preserved_inputs], ['Repeatable transformations', scope.transformations], ['Source-attributed conclusions', scope.source_attributed_conclusions], ['Unavailable or unverified', scope.unavailable], ['Analytical cutoff', scope.analytical_cutoff], ['Packaging date (not new analysis)', selectedCase.package_updated || 'No separate packaging revision recorded']]) reproduction.append(create('p', `${label}: ${Array.isArray(value) ? value.join(' / ') : value}`));
      } else reproduction.append(create('p', 'A case-specific reproduction boundary is not recorded. Consult the published investigation before reuse.'));
    }
    if (data.case.package_note) {
      const boundary = document.querySelector('#case-boundary');
      const note = create('span', ` Package ${data.case.package_version}: ${data.case.package_note} `);
      boundary.append(note);
      if (data.case.package_errata) {
        const link = create('a', 'Packaging errata');
        link.href = data.case.package_errata;
        boundary.append(link);
      }
    }
    document.querySelector('#graph-case-label').textContent = selectedCase.title;
    document.querySelector('#case-node-count').textContent = String(data.nodes.length);
    document.querySelector('#case-edge-count').textContent = String(data.edges.length);
    renderSelector();
  }

  let caseRequest = 0;
  let caseController;
  async function loadCase(caseId, updateHistory = false) {
    const request = ++caseRequest;
    caseController?.abort();
    caseController = new AbortController();
    const requestedCase = caseId ? catalogue.cases.find((caseItem) => caseItem.id === caseId) : catalogue.cases[0];
    if (!requestedCase) throw new Error('Unknown case ID; choose a released case from the catalogue.');
    document.querySelector('#node-title').textContent = 'Loading case…';
    document.querySelector('#node-detail').textContent = 'Retrieving the selected graph.';
    try {
      const response = await fetch(requestedCase.graph, { credentials: 'same-origin', signal: caseController.signal });
      if (request !== caseRequest) return;
      if (!response.ok) throw new Error(`Graph request failed with ${response.status}`);
      const requestedData = await response.json();
      if (request !== caseRequest) return;
      if (requestedData.case.id !== requestedCase.id) throw new Error(`Catalogue and graph case IDs differ for ${requestedCase.id}`);
      selectedCase = requestedCase;
      data = requestedData;
    } catch (error) {
      if (request !== caseRequest || error.name === 'AbortError') return;
      throw error;
    }
    updateCaseHeader();
    renderGraph();
    renderLedger();
    if (updateHistory) {
      const url = new URL(window.location.href);
      url.searchParams.set('case', selectedCase.id);
      url.searchParams.delete('node');
      url.hash = '';
      window.history.pushState({ caseId: selectedCase.id }, '', url);
    }
    const nodeId = new URL(window.location.href).searchParams.get('node');
    if (nodeId) {
      const node = data.nodes.find((item) => item.id === nodeId);
      if (node) {
        selectNode(node, false);
        const row = document.getElementById(claimAnchor(node));
        row.hidden = false;
        row.focus();
        row.scrollIntoView({ block: 'center' });
      } else {
        document.querySelector('#node-title').textContent = 'Unknown claim';
        document.querySelector('#node-detail').textContent = 'This claim ID is not in the selected released case. Choose a node or a ledger row.';
        document.querySelector('#node-evidence').replaceChildren();
      }
    }
  }

  function showError(error) {
    ['case-title', 'case-summary', 'case-boundary', 'graph-case-label', 'ledger-count', 'case-node-count', 'case-edge-count'].forEach((id) => { document.getElementById(id).textContent = 'Case data unavailable'; });
    svg.replaceChildren();
    ledger.replaceChildren();
    document.querySelector('#node-evidence').replaceChildren();
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

  window.HECAVEX_LABS?.bindShellSearch((query) => {
    shellQuery = query;
    filterLedger();
  });
  window.addEventListener('popstate', () => {
    if (catalogue) loadCase(new URL(window.location.href).searchParams.get('case'), false).catch(showError);
  });
  initialise();
})();
