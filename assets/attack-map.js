(() => {
  'use strict';

  const DATA_URL = '/data/attack/intelligence/reviewed-evidence.json?v=20260901-2';
  const MAX_COMPARISON = 3;
  const elements = {
    sourceRelease: document.querySelector('#source-release'),
    actorTotal: document.querySelector('#actor-total'),
    mappingTotal: document.querySelector('#mapping-total'),
    techniqueTotal: document.querySelector('#technique-total'),
    campaignTotal: document.querySelector('#campaign-total'),
    frameworkNotice: document.querySelector('#framework-notice'),
    controls: document.querySelector('#evidence-controls'),
    search: document.querySelector('#evidence-search'),
    actor: document.querySelector('#actor-filter'),
    campaign: document.querySelector('#campaign-filter'),
    tactic: document.querySelector('#tactic-filter'),
    confidence: document.querySelector('#confidence-filter'),
    status: document.querySelector('#status-filter'),
    results: document.querySelector('#evidence-results'),
    resultCount: document.querySelector('#result-count'),
    comparisonCount: document.querySelector('#comparison-count'),
    comparison: document.querySelector('#comparison'),
    comparisonGrid: document.querySelector('#comparison-grid'),
    clearComparison: document.querySelector('#clear-comparison'),
    exportJson: document.querySelector('#export-json'),
    exportCsv: document.querySelector('#export-csv'),
    exportNavigator: document.querySelector('#export-navigator'),
    dialog: document.querySelector('#mapping-dialog'),
    dialogTitle: document.querySelector('#mapping-dialog-title'),
    dialogBody: document.querySelector('#mapping-dialog-body'),
    dialogClose: document.querySelector('#mapping-dialog-close')
  };

  const state = {
    data: null,
    actors: new Map(),
    rows: [],
    filtered: [],
    compared: new Set(),
    lastDialogTrigger: null
  };

  function el(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }

  function safeHttpsUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === 'https:' ? url.href : '';
    } catch {
      return '';
    }
  }

  function externalLink(label, value, className = '') {
    const url = safeHttpsUrl(value);
    if (!url) return el('span', className, label);
    const link = el('a', className, label);
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
  }

  function option(value, label) {
    const item = document.createElement('option');
    item.value = value;
    item.textContent = label;
    return item;
  }

  function normalized(value) {
    return String(value || '').toLocaleLowerCase('en');
  }

  function releaseDate(value) {
    if (!value) return 'date unavailable';
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return String(value).slice(0, 10);
    return new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeZone: 'UTC' }).format(date);
  }

  function flattenDataset(data) {
    state.actors = new Map(data.actors.map((actor) => [actor.id, actor]));
    state.rows = data.actors.flatMap((actor) => actor.evidence.map((evidence) => {
      const sourceText = evidence.sources.flatMap((source) => [source.title, source.publisher, source.id]).join(' ');
      return {
        ...evidence,
        actor,
        searchText: normalized([
          actor.name,
          actor.id,
          ...actor.aliases,
          evidence.technique,
          evidence.technique_id,
          evidence.campaign.name,
          evidence.campaign.id,
          evidence.notes,
          evidence.uncertainty,
          evidence.confidence_rationale,
          evidence.record_lifecycle?.state,
          ...evidence.tactics,
          sourceText
        ].join(' '))
      };
    }));
  }

  function fillSelect(select, values, allLabel) {
    select.replaceChildren(option('all', allLabel));
    values.forEach(({ value, label }) => select.append(option(value, label)));
  }

  function labelForValue(value) {
    return value ? value[0].toUpperCase() + value.slice(1) : value;
  }

  function uniqueOptions(rows, facet) {
    if (facet === 'campaign') {
      const campaigns = new Map();
      rows.forEach((row) => {
        if (row.campaign.id) campaigns.set(row.campaign.id, row.campaign.name);
      });
      return [...campaigns]
        .sort((left, right) => left[1].localeCompare(right[1]))
        .map(([value, label]) => ({ value, label }));
    }

    if (facet === 'tactic') {
      return [...new Set(rows.flatMap((row) => row.tactics))]
        .sort()
        .map((value) => ({ value, label: value }));
    }

    const preferredOrder = facet === 'confidence'
      ? ['high', 'moderate', 'low']
      : ['observed', 'reported', 'assessed', 'inferred', 'disputed', 'rejected'];
    const available = new Set(rows.map((row) => facet === 'status' ? row.mapping_status : row.confidence));
    return [
      ...preferredOrder.filter((value) => available.has(value)),
      ...[...available].filter((value) => !preferredOrder.includes(value)).sort()
    ].map((value) => ({ value, label: labelForValue(value) }));
  }

  function matchesFacet(row, facet, value) {
    if (value === 'all') return true;
    if (facet === 'actor') return row.actor.id === value;
    if (facet === 'campaign') return row.campaign.id === value;
    if (facet === 'tactic') return row.tactics.includes(value);
    if (facet === 'confidence') return row.confidence === value;
    return row.mapping_status === value;
  }

  function replaceDependentOptions(select, values, allLabel) {
    const requested = select.value;
    fillSelect(select, values, allLabel);
    select.value = values.some(({ value }) => value === requested) ? requested : 'all';
  }

  function reconcileDependentControls() {
    // Actor is the parent facet. Each following facet is built only from rows
    // compatible with the selections to its left, so stale combinations reset
    // to "all" in a predictable campaign -> tactic -> confidence -> status order.
    let compatibleRows = state.rows.filter((row) => matchesFacet(row, 'actor', elements.actor.value));
    const facets = [
      ['campaign', elements.campaign, 'All campaigns'],
      ['tactic', elements.tactic, 'All tactics'],
      ['confidence', elements.confidence, 'All confidence levels'],
      ['status', elements.status, 'All statuses']
    ];

    facets.forEach(([facet, select, allLabel]) => {
      replaceDependentOptions(select, uniqueOptions(compatibleRows, facet), allLabel);
      compatibleRows = compatibleRows.filter((row) => matchesFacet(row, facet, select.value));
    });
  }

  function configureControls() {
    fillSelect(
      elements.actor,
      [...state.actors.values()]
        .sort((left, right) => left.name.localeCompare(right.name))
        .map((actor) => ({ value: actor.id, label: actor.name })),
      'All reviewed actors'
    );
    reconcileDependentControls();
  }

  function setDatasetSummary() {
    const { summary, source_system: source, framework } = state.data;
    elements.actorTotal.textContent = summary.actors;
    elements.mappingTotal.textContent = summary.mappings;
    elements.techniqueTotal.textContent = summary.techniques;
    elements.campaignTotal.textContent = summary.campaigns;
    elements.sourceRelease.textContent = `APT Notes ${source.dataset_version} · ${releaseDate(source.released_at)} · ${source.release_id}`;
    elements.frameworkNotice.textContent = `${framework.notice} Labs pins this publication to Enterprise ATT&CK ${framework.version}.`;
  }

  function currentFilters() {
    return {
      query: normalized(elements.search.value.trim()),
      actor: elements.actor.value,
      campaign: elements.campaign.value,
      tactic: elements.tactic.value,
      confidence: elements.confidence.value,
      status: elements.status.value
    };
  }

  function applyFilters() {
    reconcileDependentControls();
    const filters = currentFilters();
    state.filtered = state.rows.filter((row) => {
      if (filters.query && !row.searchText.includes(filters.query)) return false;
      return ['actor', 'campaign', 'tactic', 'confidence', 'status']
        .every((facet) => matchesFacet(row, facet, filters[facet]));
    });
    renderRows();
  }

  function tag(value) {
    return el('span', `evidence-tag ${normalized(value).replace(/[^a-z0-9_-]/g, '-')}`, value);
  }

  function rowCell(label) {
    const cell = el('div', 'evidence-cell');
    cell.setAttribute('role', 'cell');
    cell.dataset.label = label;
    return cell;
  }

  function renderRow(row) {
    const record = el('article', 'evidence-row');
    record.setAttribute('role', 'row');
    record.dataset.evidenceId = row.id;

    const actorCell = rowCell('Actor and campaign');
    actorCell.append(externalLink(row.actor.name, row.actor.url, 'actor-link'));
    const campaign = row.campaign.id
      ? externalLink(row.campaign.name, row.campaign.url)
      : el('span', '', 'No campaign assigned');
    const campaignLine = el('small');
    campaignLine.append(campaign);
    actorCell.append(campaignLine);

    const techniqueCell = rowCell('Technique');
    techniqueCell.append(el('span', 'technique-id', row.technique_id));
    techniqueCell.append(externalLink(row.technique, row.attack_url, 'technique-link'));
    techniqueCell.append(el('small', '', row.tactics.join(' · ')));

    const evidenceCell = rowCell('Evidence');
    const tags = el('div', 'evidence-tags');
    tags.append(tag(row.mapping_status), tag(row.confidence));
    evidenceCell.append(tags);
    evidenceCell.append(el('small', '', `${row.sources.length} public source${row.sources.length === 1 ? '' : 's'}`));

    const timelineCell = rowCell('Timeline');
    timelineCell.append(el('span', 'timeline-value', `${row.first_observed} → ${row.last_observed}`));

    const actionsCell = rowCell('Actions');
    const actions = el('div', 'row-actions');
    const details = el('button', 'row-action', 'View evidence');
    details.type = 'button';
    details.dataset.openEvidence = row.id;
    const compare = el('button', 'row-action', state.compared.has(row.actor.id) ? 'Remove actor' : 'Compare actor');
    compare.type = 'button';
    compare.dataset.compareActor = row.actor.id;
    compare.setAttribute('aria-pressed', String(state.compared.has(row.actor.id)));
    if (state.compared.size >= MAX_COMPARISON && !state.compared.has(row.actor.id)) {
      compare.disabled = true;
      compare.title = 'Remove one selected actor before adding another.';
    }
    actions.append(details, compare);
    actionsCell.append(actions);

    record.append(actorCell, techniqueCell, evidenceCell, timelineCell, actionsCell);
    return record;
  }

  function renderRows() {
    elements.resultCount.textContent = `${state.filtered.length} of ${state.rows.length} mappings`;
    if (!state.filtered.length) {
      elements.results.replaceChildren(el('div', 'evidence-empty', 'No reviewed evidence matches these filters.'));
    } else {
      elements.results.replaceChildren(...state.filtered.map(renderRow));
    }
    [elements.exportJson, elements.exportCsv, elements.exportNavigator].forEach((button) => {
      button.disabled = state.filtered.length === 0;
    });
  }

  function mappingDefinition(label, value) {
    const wrapper = el('div');
    wrapper.append(el('span', '', label), el('strong', '', value));
    return wrapper;
  }

  function openDetails(row, trigger) {
    state.lastDialogTrigger = trigger;
    const summary = el('section', 'mapping-summary');
    const copy = el('div');
    copy.append(el('span', 'technique-id', row.technique_id));
    const heading = el('h3', '', `${row.actor.name}: ${row.technique}`);
    copy.append(heading, el('p', '', row.notes));
    const links = el('div', 'hero-actions');
    links.append(
      externalLink('Open actor dossier', row.actor.url, 'button primary'),
      externalLink('Open ATT&CK technique', row.attack_url, 'button'),
      externalLink('Open APT Notes technique', row.apt_notes_url, 'button')
    );
    if (row.campaign.url) links.append(externalLink('Open campaign', row.campaign.url, 'button'));
    copy.append(links);

    const metadata = el('div', 'mapping-meta');
    metadata.append(
      mappingDefinition('Evidence status', row.mapping_status),
      mappingDefinition('Confidence', row.confidence),
      mappingDefinition('Confidence basis', row.confidence_rationale),
      mappingDefinition('Upstream lifecycle', row.record_lifecycle.state),
      mappingDefinition('Correction state', row.record_lifecycle.correction_state),
      mappingDefinition('First observed', row.first_observed),
      mappingDefinition('Last observed', row.last_observed),
      mappingDefinition('Campaign', row.campaign.name),
      mappingDefinition('Actor review', row.actor.last_reviewed || 'Not recorded')
    );
    summary.append(copy, metadata);

    const uncertainty = el('section', 'mapping-uncertainty');
    uncertainty.append(el('strong', '', 'Uncertainty and reuse boundary'), el('span', '', row.uncertainty));

    const sources = el('section', 'mapping-sources');
    sources.append(el('h3', '', 'Public sources'));
    row.sources.forEach((source) => {
      const sourceRecord = el('article', 'source-record');
      const sourceCopy = el('div');
      sourceCopy.append(el('strong', '', source.title));
      sourceCopy.append(el('small', '', [source.publisher, source.published, source.source_type].filter(Boolean).join(' · ')));
      const sourceLinks = el('nav');
      sourceLinks.setAttribute('aria-label', `${source.title} links`);
      sourceLinks.append(
        externalLink('Primary publication', source.url),
        externalLink('APT Notes source record', source.apt_notes_url)
      );
      sourceRecord.append(sourceCopy, sourceLinks);
      sources.append(sourceRecord);
    });

    elements.dialogTitle.textContent = `${row.actor.name} · ${row.technique_id}`;
    elements.dialogBody.replaceChildren(summary, uncertainty, sources);
    elements.dialog.showModal();
    requestAnimationFrame(() => elements.dialogTitle.focus());
  }

  function actorComparisonCard(actor) {
    const card = el('article', 'comparison-card');
    const evidence = actor.evidence;
    const techniques = [...new Set(evidence.map((item) => `${item.technique_id} ${item.technique}`))];
    const campaigns = [...new Set(evidence.filter((item) => item.campaign.id).map((item) => item.campaign.name))];
    const sources = new Set(evidence.flatMap((item) => item.sources.map((source) => source.id)));
    card.append(el('p', 'eyebrow', `${actor.status} · ${actor.confidence} confidence`));
    card.append(externalLink(actor.name, actor.url, 'actor-link'));
    card.append(el('p', '', actor.summary));
    const facts = el('div', 'comparison-facts');
    facts.append(
      mappingDefinition('Mappings', evidence.length),
      mappingDefinition('Techniques', techniques.length),
      mappingDefinition('Sources', sources.size)
    );
    card.append(facts);
    card.append(el('strong', '', 'Mapped techniques'));
    const techniqueList = el('ul', 'comparison-list');
    techniques.slice(0, 8).forEach((item) => techniqueList.append(el('li', '', item)));
    if (techniques.length > 8) techniqueList.append(el('li', '', `+ ${techniques.length - 8} more`));
    card.append(techniqueList);
    card.append(el('strong', '', 'Named campaigns'));
    const campaignList = el('ul', 'comparison-list');
    (campaigns.length ? campaigns : ['No campaign assigned']).slice(0, 6).forEach((item) => campaignList.append(el('li', '', item)));
    if (campaigns.length > 6) campaignList.append(el('li', '', `+ ${campaigns.length - 6} more`));
    card.append(campaignList);
    return card;
  }

  function renderComparison() {
    elements.comparisonCount.textContent = state.compared.size;
    const actors = [...state.compared].map((id) => state.actors.get(id)).filter(Boolean);
    elements.comparison.hidden = actors.length < 2;
    elements.comparisonGrid.replaceChildren(...actors.map(actorComparisonCard));
    document.querySelectorAll('[data-compare-actor]').forEach((button) => {
      const selected = state.compared.has(button.dataset.compareActor);
      button.setAttribute('aria-pressed', String(selected));
      button.textContent = selected ? 'Remove actor' : 'Compare actor';
      button.disabled = state.compared.size >= MAX_COMPARISON && !selected;
      button.title = button.disabled ? 'Remove one selected actor before adding another.' : '';
    });
  }

  function toggleComparison(actorId) {
    if (state.compared.has(actorId)) state.compared.delete(actorId);
    else if (state.compared.size < MAX_COMPARISON) state.compared.add(actorId);
    renderComparison();
  }

  function serializableRows() {
    return state.filtered.map((row) => ({
      actor: { id: row.actor.id, name: row.actor.name, url: row.actor.url },
      id: row.id,
      technique_id: row.technique_id,
      technique: row.technique,
      tactics: row.tactics,
      framework_reference: row.framework_reference,
      mapping_status: row.mapping_status,
      confidence: row.confidence,
      confidence_rationale: row.confidence_rationale,
      record_lifecycle: row.record_lifecycle,
      campaign: row.campaign,
      first_observed: row.first_observed,
      last_observed: row.last_observed,
      notes: row.notes,
      uncertainty: row.uncertainty,
      attack_url: row.attack_url,
      sources: row.sources
    }));
  }

  function download(filename, mimeType, content) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportDate() {
    return String(state.data.source_system.released_at || state.data.generated_at || '').slice(0, 10) || 'current';
  }

  function exportJson() {
    const payload = {
      schema_version: '1.0.0',
      export_scope: 'current filters',
      source_release: state.data.source_system,
      framework: state.data.framework,
      result_count: state.filtered.length,
      records: serializableRows()
    };
    download(`hecavex-attack-evidence-${exportDate()}.json`, 'application/json', `${JSON.stringify(payload, null, 2)}\n`);
  }

  function csvCell(value) {
    const text = String(value ?? '');
    return `"${text.replace(/"/g, '""')}"`;
  }

  function exportCsv() {
    const headers = ['actor', 'actor_id', 'campaign', 'technique_id', 'technique', 'tactics', 'framework_version', 'framework_stix_id', 'mapping_status', 'confidence', 'confidence_rationale', 'lifecycle_state', 'correction_state', 'actor_version', 'campaign_version', 'technique_version', 'first_observed', 'last_observed', 'notes', 'uncertainty', 'source_urls'];
    const rows = state.filtered.map((row) => [
      row.actor.name,
      row.actor.id,
      row.campaign.name,
      row.technique_id,
      row.technique,
      row.tactics.join('; '),
      row.framework_reference.version,
      row.framework_reference.stix_id,
      row.mapping_status,
      row.confidence,
      row.confidence_rationale,
      row.record_lifecycle.state,
      row.record_lifecycle.correction_state,
      row.record_lifecycle.actor_version,
      row.record_lifecycle.campaign_version,
      row.record_lifecycle.technique_version,
      row.first_observed,
      row.last_observed,
      row.notes,
      row.uncertainty,
      row.sources.map((source) => source.url).join('; ')
    ]);
    const csv = [headers, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n');
    download(`hecavex-attack-evidence-${exportDate()}.csv`, 'text/csv;charset=utf-8', `\uFEFF${csv}\r\n`);
  }

  function exportNavigator() {
    const grouped = new Map();
    state.filtered.forEach((row) => {
      if (!grouped.has(row.technique_id)) grouped.set(row.technique_id, []);
      grouped.get(row.technique_id).push(row);
    });
    const scoreValue = { high: 100, moderate: 60, low: 30 };
    const techniques = [...grouped].sort().map(([techniqueID, rows]) => ({
      techniqueID,
      score: Math.max(...rows.map((row) => scoreValue[row.confidence] || 0)),
      comment: rows.map((row) => `${row.actor.name} · ${row.campaign.name}: ${row.notes}`).join('\n\n'),
      enabled: true,
      metadata: [
        { name: 'HECAVEX mappings', value: String(rows.length) },
        { name: 'Source release', value: state.data.source_system.release_id }
      ],
      links: [...new Map(rows.map((row) => [row.actor.url, { label: `${row.actor.name} dossier`, url: row.actor.url }])).values()]
    }));
    const layer = {
      name: 'HECAVEX reviewed ATT&CK evidence',
      versions: { attack: state.data.framework.version, navigator: '5.1.0', layer: '4.5' },
      domain: 'enterprise-attack',
      description: `Explicit source-backed mappings from ${state.data.source_system.release_id}. Scores encode published confidence only; they are not defensive coverage or actor prevalence.`,
      filters: { platforms: [] },
      sorting: 0,
      layout: { layout: 'side', aggregateFunction: 'average', showID: true, showName: true, showAggregateScores: false, countUnscored: false },
      hideDisabled: false,
      techniques,
      gradient: { colors: ['#8d969a', '#d2aa62', '#86b77e'], minValue: 0, maxValue: 100 },
      legendItems: [
        { label: 'Low published confidence', color: '#8d969a' },
        { label: 'Moderate published confidence', color: '#d2aa62' },
        { label: 'High published confidence', color: '#86b77e' }
      ],
      metadata: [
        { name: 'Publisher', value: 'HECAVEX' },
        { name: 'ATT&CK version pinned', value: state.data.framework.version },
        { name: 'ATT&CK version pinned at', value: state.data.framework.version_pinned_at },
        { name: 'Boundary', value: 'Reviewed evidence index; not coverage or prevalence' }
      ],
      links: [{ label: 'HECAVEX ATT&CK Evidence Explorer', url: 'https://labs.hecavex.com/attack-map/' }],
      showTacticRowBackground: false,
      tacticRowBackground: '#171b1d',
      selectTechniquesAcrossTactics: true,
      selectSubtechniquesWithParent: false
    };
    download(`hecavex-attack-navigator-${exportDate()}.json`, 'application/json', `${JSON.stringify(layer, null, 2)}\n`);
  }

  function showLoadError(error) {
    console.error(error);
    elements.results.replaceChildren(el('div', 'evidence-error', 'The reviewed evidence dataset could not be loaded. Use the Data catalogue for the canonical JSON or try again later.'));
    elements.resultCount.textContent = 'Dataset unavailable';
    [elements.exportJson, elements.exportCsv, elements.exportNavigator].forEach((button) => { button.disabled = true; });
  }

  function bindEvents() {
    elements.search.addEventListener('input', applyFilters);
    elements.controls.addEventListener('change', applyFilters);
    elements.controls.addEventListener('reset', () => requestAnimationFrame(applyFilters));
    elements.results.addEventListener('click', (event) => {
      const details = event.target.closest('[data-open-evidence]');
      if (details) {
        const row = state.rows.find((item) => item.id === details.dataset.openEvidence);
        if (row) openDetails(row, details);
        return;
      }
      const compare = event.target.closest('[data-compare-actor]');
      if (compare) toggleComparison(compare.dataset.compareActor);
    });
    elements.clearComparison.addEventListener('click', () => {
      state.compared.clear();
      renderComparison();
    });
    elements.exportJson.addEventListener('click', exportJson);
    elements.exportCsv.addEventListener('click', exportCsv);
    elements.exportNavigator.addEventListener('click', exportNavigator);
    elements.dialogClose.addEventListener('click', () => elements.dialog.close());
    elements.dialog.addEventListener('click', (event) => {
      if (event.target === elements.dialog) elements.dialog.close();
    });
    elements.dialog.addEventListener('close', () => {
      if (state.lastDialogTrigger?.isConnected) state.lastDialogTrigger.focus();
      state.lastDialogTrigger = null;
    });
    window.HECAVEX_LABS?.bindShellSearch((query) => {
      elements.search.value = query;
      if (state.data) applyFilters();
    });
  }

  async function init() {
    bindEvents();
    try {
      const response = await fetch(DATA_URL, { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error(`Evidence dataset request failed with HTTP ${response.status}`);
      const data = await response.json();
      if (data.schema_version !== '2.2.0' || !Array.isArray(data.actors)) throw new Error('Unsupported evidence dataset contract');
      state.data = data;
      flattenDataset(data);
      configureControls();
      setDatasetSummary();
      applyFilters();
      renderComparison();
    } catch (error) {
      showLoadError(error);
    }
  }

  init();
})();
