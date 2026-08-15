(() => {
  const matrix = document.querySelector('#attack-matrix');
  const search = document.querySelector('#global-q');
  const tacticFilter = document.querySelector('#tactic-filter');
  const confidenceFilter = document.querySelector('#confidence-filter');
  const behaviourFilter = document.querySelector('#behaviour-filter');
  const overlayFilter = document.querySelector('#overlay-filter');
  const platformFilter = document.querySelector('#platform-filter');
  const typeFilter = document.querySelector('#type-filter');
  const actorFilter = document.querySelector('#actor-filter');
  const modeFilter = document.querySelector('#view-mode');
  const empty = document.querySelector('#attack-empty');
  const dialog = document.querySelector('#evidence-dialog');
  let dataset;
  let catalogue;
  let mode = 'catalogue';
  let actorView = 'apt28';

  const create = (name, text, className) => {
    const node = document.createElement(name);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };

  const groupBy = (items, keyFor) => items.reduce((groups, item) => {
    const key = keyFor(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
    return groups;
  }, new Map());

  const actorById = (id) => dataset.actors.find((actor) => actor.id === id);
  const behaviourById = (id) => dataset.behaviours.find((behaviour) => behaviour.id === id);
  const branchById = (behaviour, id) => behaviour.branches.find((branch) => branch.id === id);

  function actorRecords(actorId) {
    const actor = actorById(actorId);
    return actor.evidence.map((record) => ({
      ...record,
      record_kind: 'actor',
      entity_id: actor.id,
      entity_name: actor.name,
      actor_id: actor.id,
      actor_name: actor.name
    }));
  }

  function behaviourRecords() {
    const behaviour = behaviourById(behaviourFilter.value);
    return behaviour.techniques.map((record) => ({
      ...record,
      record_kind: 'behaviour',
      entity_id: behaviour.id,
      entity_name: behaviour.name,
      actor_id: 'behaviour',
      actor_name: `${behaviour.name} model`,
      status: 'model',
      confidence: '',
      campaign: branchById(behaviour, record.branch)?.name || record.branch,
      first_observed: '',
      last_observed: ''
    }));
  }

  function catalogueRecords() {
    return catalogue.techniques.map((technique) => ({
      technique_id: technique.id,
      technique: technique.name,
      tactics: technique.tactics,
      record_kind: 'catalogue',
      entity_id: 'enterprise-attack',
      entity_name: `Enterprise ATT&CK ${catalogue.version}`,
      status: 'official',
      confidence: '',
      campaign: technique.parent ? `${technique.parent.id} ${technique.parent.name}` : 'Parent technique',
      notes: technique.description,
      caveat: '',
      attack_url: technique.url,
      platforms: technique.platforms,
      subtechnique: technique.subtechnique,
      parent: technique.parent,
      version: technique.version,
      modified: technique.modified,
      associations: {
        groups: technique.groups,
        campaigns: technique.campaigns,
        software: technique.software,
        mitigations: technique.mitigations,
        detections: technique.detections
      },
      sources: [{ title: `${technique.id} ${technique.name}`, publisher: 'MITRE ATT&CK', published: technique.modified, url: technique.url }]
    }));
  }

  function selectedRecords() {
    if (mode === 'catalogue') return catalogueRecords();
    if (mode === 'behaviour') {
      const records = behaviourRecords();
      return overlayFilter.value === 'none' ? records : records.concat(actorRecords(overlayFilter.value));
    }
    if (mode === 'compare') return dataset.actors.flatMap((actor) => actorRecords(actor.id));
    return actorRecords(actorView);
  }

  function filteredRecords() {
    const query = search?.value.trim().toLowerCase() || '';
    return selectedRecords().filter((record) => {
      const related = record.associations ? Object.values(record.associations).flat().flatMap((item) => [item.id, item.name]) : [];
      const haystack = [record.technique_id, record.technique, record.campaign, record.notes, record.caveat, record.role, record.branch, ...(record.platforms || []), ...related, ...record.sources.flatMap((source) => [source.publisher, source.title])].filter(Boolean).join(' ').toLowerCase();
      return (!query || haystack.includes(query))
        && (tacticFilter.value === 'all' || record.tactics.includes(tacticFilter.value))
        && (confidenceFilter.value === 'all' || ['behaviour', 'catalogue'].includes(record.record_kind) || record.confidence === confidenceFilter.value)
        && (mode !== 'catalogue' || platformFilter.value === 'all' || record.platforms.includes(platformFilter.value))
        && (mode !== 'catalogue' || typeFilter.value === 'all' || (typeFilter.value === 'subtechnique') === record.subtechnique);
    });
  }

  function viewSlug() {
    if (mode === 'catalogue') return 'enterprise-catalogue';
    if (mode === 'behaviour') return `${behaviourFilter.value}${overlayFilter.value === 'none' ? '' : `-vs-${overlayFilter.value}`}`;
    return mode === 'compare' ? 'apt28-vs-apt44' : actorView;
  }

  function updateUrl(technique) {
    const params = new URLSearchParams();
    if (mode !== 'catalogue') params.set('mode', mode);
    if (mode === 'actor') params.set('actor', actorView);
    if (mode === 'behaviour' && behaviourFilter.value !== 'phishing') params.set('behaviour', behaviourFilter.value);
    if (mode === 'behaviour' && overlayFilter.value !== 'none') params.set('overlay', overlayFilter.value);
    if (tacticFilter.value !== 'all') params.set('tactic', tacticFilter.value);
    if (mode !== 'behaviour' && confidenceFilter.value !== 'all') params.set('confidence', confidenceFilter.value);
    if (mode === 'catalogue' && platformFilter.value !== 'all') params.set('platform', platformFilter.value);
    if (mode === 'catalogue' && typeFilter.value !== 'all') params.set('type', typeFilter.value);
    if (search?.value.trim()) params.set('q', search.value.trim());
    if (technique) params.set('technique', technique);
    const query = params.toString();
    history.replaceState(null, '', `${location.pathname}${query ? `?${query}` : ''}`);
  }

  function recordClass(records) {
    if (records.some((record) => record.record_kind === 'catalogue')) return 'catalogue';
    const hasModel = records.some((record) => record.record_kind === 'behaviour');
    const actors = new Set(records.filter((record) => record.record_kind === 'actor').map((record) => record.actor_id));
    if (hasModel && actors.size) return 'overlap';
    if (hasModel) return 'baseline';
    return actors.size > 1 ? 'shared' : [...actors][0];
  }

  function techniqueButton(records) {
    const primary = records[0];
    const button = create('button', undefined, `attack-technique ${recordClass(records)}${primary.subtechnique ? ' subtechnique' : ''}`);
    button.type = 'button';
    button.dataset.technique = primary.technique_id;
    button.setAttribute('aria-label', `${primary.technique_id} ${primary.technique}. Open ${records.length} mapping${records.length === 1 ? '' : 's'}.`);
    button.append(create('span', primary.technique_id, 'technique-id'), create('strong', primary.technique));
    const meta = create('span', undefined, 'technique-meta');
    const labels = [...new Set(records.map((record) => record.record_kind === 'catalogue' ? (record.subtechnique ? 'sub-technique' : 'technique') : record.record_kind === 'behaviour' ? record.role : record.actor_name))];
    meta.append(create('span', labels.join(' + ')), create('span', `${records.length} ${records.length === 1 ? 'mapping' : 'mappings'}`));
    button.append(meta);
    button.addEventListener('click', () => openEvidence(primary.technique_id));
    return button;
  }

  function appendMetrics(summary, records, extraMetric) {
    const metrics = create('dl', undefined, 'attack-summary-metrics');
    const sources = new Set(records.flatMap((record) => record.sources.map((source) => source.url))).size;
    const items = [['Visible techniques', new Set(records.map((record) => record.technique_id)).size], extraMetric, ['Cited sources', sources]].filter(Boolean);
    items.forEach(([label, value]) => {
      const group = create('div');
      group.append(create('dt', label), create('dd', String(value)));
      metrics.append(group);
    });
    summary.append(metrics);
  }

  function renderSummary(records) {
    const summary = document.querySelector('#actor-summary');
    summary.replaceChildren();
    const text = create('div');
    if (mode === 'catalogue') {
      text.append(create('p', `OFFICIAL ENTERPRISE ATT&CK ${catalogue.version}`, 'eyebrow'), create('h3', 'Complete technique catalogue'), create('p', 'All active Enterprise techniques and sub-techniques from MITRE’s STIX release. Search also covers mapped groups, campaigns, software, mitigations, detection strategies and platforms.'));
      text.append(create('p', 'These are official ATT&CK knowledge-base relationships. They are not HECAVEX attribution findings and do not mean every related actor uses a technique in every operation.', 'attack-boundary'));
      summary.append(text);
      appendMetrics(summary, records, ['Sub-techniques', new Set(records.filter((record) => record.subtechnique).map((record) => record.technique_id)).size]);
      return;
    }
    if (mode === 'behaviour') {
      const behaviour = behaviourById(behaviourFilter.value);
      const overlay = overlayFilter.value === 'none' ? null : actorById(overlayFilter.value);
      text.append(create('p', overlay ? 'MODEL-TO-EVIDENCE COMPARISON' : 'BEHAVIOUR MODEL', 'eyebrow'), create('h3', overlay ? `${behaviour.name} compared with ${overlay.name}` : behaviour.name), create('p', behaviour.summary));
      const boundary = create('p', behaviour.boundary, 'attack-boundary');
      text.append(boundary);
      if (overlay) text.append(create('p', `Overlap means the ${overlay.name} profile contains a reviewed mapping for the same technique. It does not mean every ${overlay.name} phishing operation followed this entire model.`, 'attack-boundary'));
      summary.append(text);
      appendMetrics(summary, records, ['Model branches', behaviour.branches.length]);
      return;
    }
    if (mode === 'compare') {
      text.append(create('p', 'ACTOR COMPARISON', 'eyebrow'), create('h3', 'APT28 and APT44'), create('p', 'Shared cells mean both reviewed profiles contain a source-linked mapping. They do not establish coordination, shared infrastructure or a common operator.'));
      summary.append(text);
      appendMetrics(summary, records, ['Evidence records', records.length]);
      return;
    }
    const actor = actorById(actorView);
    text.append(create('p', actor.aliases.join(' · '), 'eyebrow'), create('h3', actor.name), create('p', actor.summary));
    const link = create('a', 'Open complete profile ↗', 'panel-link');
    link.href = actor.profile_url;
    text.append(link);
    summary.append(text);
    appendMetrics(summary, records, ['Evidence records', records.length]);
  }

  function renderLegend() {
    const legend = document.querySelector('#attack-legend');
    legend.replaceChildren();
    const entries = mode === 'catalogue'
      ? [['catalogue', 'Official ATT&CK catalogue']]
      : mode === 'behaviour'
      ? [['baseline', 'Behaviour model'], ...(overlayFilter.value === 'none' ? [] : [[overlayFilter.value, actorById(overlayFilter.value).name], ['overlap', 'Model + actor evidence']])]
      : mode === 'compare'
        ? [['apt28', 'APT28'], ['apt44', 'APT44'], ['shared', 'Both actors']]
        : [[actorView, actorById(actorView).name]];
    entries.forEach(([className, label]) => {
      const item = create('span');
      item.append(create('i', undefined, `legend-dot ${className}`), document.createTextNode(label));
      legend.append(item);
    });
  }

  function renderControls() {
    document.querySelector('#platform-control').hidden = mode !== 'catalogue';
    document.querySelector('#type-control').hidden = mode !== 'catalogue';
    document.querySelector('#behaviour-control').hidden = mode !== 'behaviour';
    document.querySelector('#overlay-control').hidden = mode !== 'behaviour';
    document.querySelector('#actor-control').hidden = mode !== 'actor';
    confidenceFilter.closest('label').hidden = ['behaviour', 'catalogue'].includes(mode);
    if (['behaviour', 'catalogue'].includes(mode)) confidenceFilter.value = 'all';
    [...modeFilter.querySelectorAll('button')].forEach((button) => {
      const active = button.dataset.mode === mode;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
      button.setAttribute('aria-selected', String(active));
    });
    [...actorFilter.querySelectorAll('button')].forEach((button) => {
      const active = button.dataset.actor === actorView;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    renderLegend();
  }

  function render() {
    const records = filteredRecords();
    const tactics = tacticFilter.value === 'all' ? catalogue.tactics.map((tactic) => tactic.name) : [tacticFilter.value];
    const columns = tactics.map((tactic) => {
      const column = create('section', undefined, 'attack-tactic');
      const tacticRecords = records.filter((record) => record.tactics.includes(tactic));
      const heading = create('header');
      heading.append(create('h3', tactic), create('span', `${new Set(tacticRecords.map((record) => record.technique_id)).size}`, 'meta'));
      const techniques = create('div', undefined, 'attack-techniques');
      const grouped = groupBy(tacticRecords, (record) => record.technique_id);
      [...grouped.entries()].sort((a, b) => a[1][0].technique.localeCompare(b[1][0].technique)).forEach(([, group]) => techniques.append(techniqueButton(group)));
      if (!tacticRecords.length) techniques.append(create('p', 'No mapping in this view', 'attack-none'));
      column.append(heading, techniques);
      return column;
    });
    matrix.replaceChildren(...columns);
    matrix.style.setProperty('--tactic-count', String(tactics.length));
    empty.hidden = records.length !== 0;
    document.querySelector('#mapping-count').textContent = `${records.length} mappings · ${new Set(records.map((record) => record.technique_id)).size} techniques`;
    renderSummary(records);
    renderControls();
    updateUrl();
  }

  function actorFacts(record) {
    return [['Actor', record.actor_name], ['Evidence status', record.status], ['Confidence', record.confidence], ['Campaign', record.campaign], ['Observed', [record.first_observed, record.last_observed].filter(Boolean).join(' → ') || 'Not stated']];
  }

  function behaviourFacts(record) {
    return [['Model', record.entity_name], ['Relationship', record.role], ['Branch', record.campaign], ['Stage', record.stage], ['Evidence type', 'Educational model']];
  }

  function catalogueFacts(record) {
    return [['ATT&CK release', catalogue.version], ['Technique type', record.subtechnique ? 'Sub-technique' : 'Parent technique'], ['Parent', record.parent ? `${record.parent.id} ${record.parent.name}` : 'None'], ['Platforms', record.platforms.join(', ') || 'Not specified'], ['Object version', record.version || 'Not stated'], ['Modified', record.modified || 'Not stated']];
  }

  function definitionList(record) {
    const list = create('dl', undefined, 'evidence-facts');
    const facts = record.record_kind === 'catalogue' ? catalogueFacts(record) : record.record_kind === 'behaviour' ? behaviourFacts(record) : actorFacts(record);
    facts.forEach(([term, value]) => {
      const group = create('div');
      group.append(create('dt', term), create('dd', value));
      list.append(group);
    });
    return list;
  }

  function openEvidence(techniqueId) {
    const records = selectedRecords().filter((record) => record.technique_id === techniqueId);
    if (!records.length) return;
    const primary = records[0];
    document.querySelector('#evidence-id').textContent = `${primary.technique_id} · ${primary.tactics.join(' · ')}`;
    document.querySelector('#evidence-title').textContent = primary.technique;
    const detail = document.querySelector('#evidence-detail');
    detail.replaceChildren();
    records.forEach((record) => {
      const article = create('article', undefined, `evidence-record ${recordClass([record])}`);
      article.append(definitionList(record), create('p', record.notes, 'evidence-note'));
      if (record.caveat) article.append(create('p', record.caveat, 'evidence-caveat'));
      if (record.record_kind === 'catalogue') {
        const related = create('div', undefined, 'catalogue-relations');
        const labels = { groups: 'Groups', campaigns: 'Campaigns', software: 'Software', mitigations: 'Mitigations', detections: 'Detection strategies' };
        Object.entries(record.associations).forEach(([key, items]) => {
          const section = create('section');
          section.append(create('h3', `${labels[key]} (${items.length})`));
          if (!items.length) section.append(create('p', 'No active relationship in this ATT&CK release.', 'meta'));
          else {
            const list = create('ul');
            items.forEach((item) => {
              const entry = create('li');
              const link = create('a', [item.id, item.name].filter(Boolean).join(' · '));
              link.href = item.url;
              link.rel = 'noopener';
              entry.append(link);
              list.append(entry);
            });
            section.append(list);
          }
          related.append(section);
        });
        article.append(related);
      }
      const sources = create('div', undefined, 'evidence-sources');
      sources.append(create('h3', `Sources (${record.sources.length})`));
      record.sources.forEach((source) => {
        const link = create('a');
        link.href = source.url;
        link.rel = 'noopener';
        link.append(create('strong', source.title), create('span', `${source.publisher} · ${source.published} ↗`));
        sources.append(link);
      });
      const attackLink = create('a', `Open ${record.technique_id} in MITRE ATT&CK ↗`, 'button small');
      attackLink.href = record.attack_url;
      attackLink.rel = 'noopener';
      article.append(sources, attackLink);
      detail.append(article);
    });
    updateUrl(techniqueId);
    dialog.showModal();
  }

  function closeEvidence() {
    dialog.close();
    updateUrl();
  }

  function download(name, type, body) {
    const url = URL.createObjectURL(new Blob([body], { type }));
    const link = create('a');
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
  }

  function csvExport() {
    const columns = ['mapping_type', 'entity', 'technique_id', 'technique', 'tactics', 'relationship', 'branch_or_campaign', 'confidence', 'notes', 'caveat', 'sources'];
    const quote = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;
    const rows = filteredRecords().map((record) => [record.record_kind, record.entity_name, record.technique_id, record.technique, record.tactics.join('|'), record.role || record.status, record.campaign, record.confidence, record.notes, record.caveat || '', record.sources.map((source) => source.url).join('|')].map(quote).join(','));
    download(`hecavex-attack-${viewSlug()}.csv`, 'text/csv;charset=utf-8', [columns.join(','), ...rows].join('\n'));
  }

  function navigatorExport() {
    const records = filteredRecords();
    const grouped = groupBy(records, (record) => record.technique_id);
    const techniques = [...grouped.entries()].map(([techniqueID, group]) => {
      const className = recordClass(group);
      const colors = { catalogue: '#7fa5cf', baseline: '#7fa5cf', apt28: '#63b3ed', apt44: '#e15a4f', shared: '#c7984c', overlap: '#c7984c' };
      return {
        techniqueID,
        color: colors[className],
        score: 100,
        comment: group.map((record) => `${record.entity_name}: ${record.notes}${record.caveat ? ` Caveat: ${record.caveat}` : ''}`).join('\n'),
        metadata: [
          { name: 'View', value: mode },
          { name: 'Entities', value: [...new Set(group.map((record) => record.entity_name))].join(', ') },
          { name: 'Mapping types', value: [...new Set(group.map((record) => record.record_kind))].join(', ') },
          { name: 'Dataset version', value: mode === 'catalogue' ? catalogue.version : dataset.updated }
        ],
        links: group.flatMap((record) => record.sources.map((source) => ({ label: source.publisher, url: source.url })))
      };
    });
    const layer = {
      name: `HECAVEX ${viewSlug().replaceAll('-', ' ')} ATT&CK view`,
      versions: { attack: catalogue.version, navigator: '5.2.0', layer: '4.5' },
      domain: 'enterprise-attack',
      description: `HECAVEX mappings reviewed on ${dataset.updated}. Behaviour models describe plausible branches; empty techniques are not evidence of absence.`,
      sorting: 0,
      layout: { layout: 'side', showID: true, showName: true, showAggregateScores: false, countUnscored: false, aggregateFunction: 'average', expandedSubtechniques: 'annotated' },
      hideDisabled: false,
      techniques
    };
    download(`hecavex-attack-${viewSlug()}-navigator.json`, 'application/json', `${JSON.stringify(layer, null, 2)}\n`);
  }

  function initialiseState() {
    const params = new URLSearchParams(location.search);
    if (['catalogue', 'behaviour', 'actor', 'compare'].includes(params.get('mode'))) mode = params.get('mode');
    if (['apt28', 'apt44'].includes(params.get('actor'))) {
      actorView = params.get('actor');
      if (!params.has('mode')) mode = 'actor';
    }
    if (dataset.behaviours.some((item) => item.id === params.get('behaviour'))) behaviourFilter.value = params.get('behaviour');
    if (['none', 'apt28', 'apt44'].includes(params.get('overlay'))) overlayFilter.value = params.get('overlay');
    if (catalogue.tactics.some((item) => item.name === params.get('tactic'))) tacticFilter.value = params.get('tactic');
    if (['high', 'moderate', 'low'].includes(params.get('confidence'))) confidenceFilter.value = params.get('confidence');
    if ([...platformFilter.options].some((option) => option.value === params.get('platform'))) platformFilter.value = params.get('platform');
    if (['parent', 'subtechnique'].includes(params.get('type'))) typeFilter.value = params.get('type');
    if (params.get('q') && search) search.value = params.get('q');
    render();
    const technique = params.get('technique');
    if (technique) openEvidence(technique);
  }

  async function initialise() {
    try {
      const [evidenceResponse, catalogueResponse] = await Promise.all([
        fetch('/data/attack-evidence.json', { credentials: 'same-origin' }),
        fetch('/data/enterprise-attack.json', { credentials: 'same-origin' })
      ]);
      if (!evidenceResponse.ok) throw new Error(`Evidence request failed with ${evidenceResponse.status}`);
      if (!catalogueResponse.ok) throw new Error(`Catalogue request failed with ${catalogueResponse.status}`);
      [dataset, catalogue] = await Promise.all([evidenceResponse.json(), catalogueResponse.json()]);
      catalogue.tactics.forEach((tactic) => {
        const option = create('option', tactic.name);
        option.value = tactic.name;
        tacticFilter.append(option);
      });
      [...new Set(catalogue.techniques.flatMap((technique) => technique.platforms))].sort().forEach((platform) => {
        const option = create('option', platform);
        option.value = platform;
        platformFilter.append(option);
      });
      dataset.behaviours.forEach((behaviour) => {
        const option = create('option', behaviour.name);
        option.value = behaviour.id;
        behaviourFilter.append(option);
      });
      const actorMappings = dataset.actors.flatMap((actor) => actor.evidence);
      const behaviourMappings = dataset.behaviours.flatMap((behaviour) => behaviour.techniques);
      const allMappings = actorMappings.concat(behaviourMappings);
      document.querySelector('#catalog-total').textContent = String(catalogue.techniques.length);
      document.querySelector('#tactic-total').textContent = String(catalogue.tactics.length);
      document.querySelector('#mapping-total').textContent = String(allMappings.length);
      document.querySelector('#source-total').textContent = String(new Set(allMappings.flatMap((record) => record.sources.map((source) => source.url))).size);
      document.querySelector('#mitre-notice').textContent = catalogue.notice;
      initialiseState();
    } catch (error) {
      document.querySelector('#mapping-count').textContent = 'Evidence data unavailable';
      empty.textContent = 'The evidence map could not be loaded. Use the JSON dataset link or report the problem.';
      empty.hidden = false;
      console.error(error);
    }
  }

  modeFilter.addEventListener('click', (event) => {
    const button = event.target.closest('[data-mode]');
    if (!button) return;
    mode = button.dataset.mode;
    render();
  });
  actorFilter.addEventListener('click', (event) => {
    const button = event.target.closest('[data-actor]');
    if (!button) return;
    actorView = button.dataset.actor;
    render();
  });
  [behaviourFilter, overlayFilter, tacticFilter, confidenceFilter, platformFilter, typeFilter].forEach((control) => control.addEventListener('change', render));
  search?.addEventListener('input', render);
  search?.closest('form')?.addEventListener('submit', (event) => { event.preventDefault(); render(); });
  document.querySelector('#clear-attack-filters').addEventListener('click', () => {
    mode = 'catalogue';
    actorView = 'apt28';
    behaviourFilter.value = 'phishing';
    overlayFilter.value = 'none';
    tacticFilter.value = 'all';
    confidenceFilter.value = 'all';
    platformFilter.value = 'all';
    typeFilter.value = 'all';
    if (search) search.value = '';
    render();
  });
  document.querySelector('#copy-view').addEventListener('click', async (event) => {
    updateUrl();
    const button = event.currentTarget;
    try {
      await navigator.clipboard.writeText(location.href);
      const original = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = original; }, 1400);
    } catch {
      window.prompt('Copy this view URL', location.href);
    }
  });
  document.querySelector('#export-csv').addEventListener('click', csvExport);
  document.querySelector('#export-navigator').addEventListener('click', navigatorExport);
  dialog.querySelector('.dialog-close').addEventListener('click', closeEvidence);
  dialog.addEventListener('click', (event) => { if (event.target === dialog) closeEvidence(); });
  dialog.addEventListener('close', updateUrl);
  initialise();
})();
