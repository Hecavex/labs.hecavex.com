(() => {
  const DATA_VERSION = '20260821-1';
  const STORAGE_READINESS = 'hecavex-attack-readiness-v1';
  const STORAGE_READINESS_META = 'hecavex-attack-readiness-meta-v1';
  const STORAGE_INCIDENT = 'hecavex-attack-incident-v1';
  const STORAGE_INCIDENT_META = 'hecavex-attack-incident-meta-v1';
  const STORAGE_OBSERVATION = 'hecavex-attack-observation-v1';
  const LOCAL_WORKSPACE_KEYS = [STORAGE_READINESS, STORAGE_READINESS_META, STORAGE_INCIDENT, STORAGE_INCIDENT_META, STORAGE_OBSERVATION];
  const $ = (selector, scope = document) => scope.querySelector(selector);
  const $$ = (selector, scope = document) => [...scope.querySelectorAll(selector)];
  const create = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const unique = (values) => [...new Set(values.filter(Boolean))];
  const showStorageWarning = (error) => {
    const warning = $('#local-storage-warning');
    if (warning) warning.hidden = false;
    console.warn('HECAVEX Labs could not use browser storage.', error);
  };
  const safeLoad = (key, fallback) => {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch (error) { showStorageWarning(error); return fallback; }
  };
  const save = (key, value) => {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; }
    catch (error) { showStorageWarning(error); return false; }
  };
  const download = (name, type, body) => {
    const url = URL.createObjectURL(new Blob([body], { type }));
    const link = create('a');
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
  };
  const validHttpUrl = (value) => !value || /^https?:\/\/[^\s]+$/i.test(value);
  const isoNow = () => new Date().toISOString();
  const localDateTimeValue = (date = new Date()) => {
    const pad = (value) => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  };
  const uuid = () => crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;

  let catalogue;
  let officialActorProcedures;
  let evidence;
  let operations;
  let detectionPackages;
  let governance;
  let engineeringPackages = [];
  let activeWorkflow = 'observation';
  let activeGroupId = '';
  let activeReadinessGroup = '';
  const storedObservation = safeLoad(STORAGE_OBSERVATION, { observation: '', assessment: null });
  let currentObservation = typeof storedObservation.observation === 'string' ? storedObservation.observation : '';
  let observationCandidates = [];
  let mappingAssessment = storedObservation.assessment && typeof storedObservation.assessment === 'object' ? storedObservation.assessment : null;
  let activeCapabilityId = '';
  const workflowProgress = {};
  let referenceLimit = 80;
  let groupLimit = 36;
  let incident = safeLoad(STORAGE_INCIDENT, []);
  let readiness = safeLoad(STORAGE_READINESS, {});
  let readinessMeta = safeLoad(STORAGE_READINESS_META, { workspace: 'Local capability review', scope: '', owner: '' });
  let incidentMeta = safeLoad(STORAGE_INCIDENT_META, { case_name: 'Local ATT&CK case', analyst: '', timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' });

  const WORKSPACES = {
    observation: { label: 'Analyse evidence', purpose: 'Turn a concrete observation into candidate ATT&CK mappings and validation questions.', journey: 'observation', steps: ['Describe evidence', 'Review candidates', 'Validate the mapping', 'Act or export'] },
    readiness: { label: 'Assess defensive coverage', purpose: 'Record whether telemetry, analytics, validation and response operations support the relevant behaviour.', journey: 'readiness', steps: ['Define scope', 'Inspect telemetry', 'Assess the analytic', 'Validate', 'Operationalise'] },
    intelligence: { label: 'Explore threat intelligence', purpose: 'Search official ATT&CK groups and aliases, then open the separate HECAVEX-reviewed evidence layer when available.', journey: 'intelligence', steps: ['Find the actor', 'Inspect aliases and sources', 'Review procedures', 'Use the intelligence'] },
    detection: { label: 'Detection engineering package', purpose: 'Translate a behaviour hypothesis into data requirements, analytic logic, tests and an operational handoff.', journey: 'readiness', steps: ['State hypothesis', 'Define data contract', 'Write logic', 'Test safely', 'Hand off'] },
    incident: { label: 'Incident timeline mapper', purpose: 'Record evidence as related claims, preserve uncertainty and export a portable case or Attack Flow.', journey: 'observation', steps: ['Record evidence', 'Relate events', 'Assess confidence', 'Export'] },
    phishing: { label: 'Phishing investigation model', purpose: 'Follow only the phishing branch supported by evidence and identify what must be collected next.', journey: 'observation', steps: ['Start with the lure', 'Choose the branch', 'Collect evidence', 'Map cautiously'] },
    reference: { label: 'Technique reference catalogue', purpose: 'Search official Enterprise ATT&CK techniques and relationships without turning catalogue data into a finding.', journey: 'intelligence', steps: ['Search', 'Inspect relationships', 'Confirm context', 'Export reference'] },
  };

  const techniqueById = (id) => catalogue.techniques.find((item) => item.id === id);
  const guideById = (id) => operations.guides.find((item) => item.technique_id === id);
  const actorById = (id) => evidence.actors.find((actor) => actor.id === id);
  const groupById = (id) => catalogue.groups.find((group) => group.id === id);
  const detectionByTechnique = (id) => engineeringPackages.find((item) => item.technique_id === id);
  const actorEvidenceFor = (id) => evidence.actors.flatMap((actor) => actor.evidence.filter((item) => item.technique_id === id).map((item) => ({ actor, item })));
  const normalise = (value) => String(value || '').toLowerCase().replace(/[^a-z0-9.]+/g, ' ').trim();

  function setStatus(message) {
    $('#workbench-status').textContent = message;
  }

  const FIELD_MESSAGES = {
    'observation-input': 'Enter a concrete observation of at least 12 characters, or choose one of the examples below.',
    'mapping-technique': 'Select the candidate technique you are assessing.',
    'mapping-evidence': 'State the concrete observations, fields or relationships supporting this mapping.',
    'mapping-gaps': 'Describe the missing evidence or collection gap that could change the assessment.',
    'mapping-alternative': 'Record at least one competing or benign explanation.',
    'incident-observation': 'Describe the observed evidence before adding a timeline entry.'
  };

  function fieldLabel(control) {
    return control.closest('label')?.querySelector(':scope > span')?.textContent.trim() || control.name || control.id || 'Field';
  }

  function clearFieldError(control, summary) {
    if (!control?.id) return;
    control.removeAttribute('aria-invalid');
    control.closest('label')?.classList.remove('field-error');
    document.getElementById(`${control.id}-error`)?.remove();
    const describedBy = (control.getAttribute('aria-describedby') || '').split(/\s+/).filter((id) => id && id !== `${control.id}-error`);
    if (describedBy.length) control.setAttribute('aria-describedby', describedBy.join(' '));
    else control.removeAttribute('aria-describedby');
    summary?.querySelector(`li[data-field="${control.id}"]`)?.remove();
    if (summary && !summary.querySelector('li')) summary.hidden = true;
  }

  function clearFormErrors(form, summary) {
    $$('[aria-invalid="true"]', form).forEach((control) => clearFieldError(control, summary));
    summary?.replaceChildren();
    if (summary) summary.hidden = true;
  }

  function nativeFormErrors(form, messages = FIELD_MESSAGES) {
    const errors = [];
    [...form.elements].filter((control) => control.matches?.('input:not([type="hidden"]), select, textarea')).forEach((control) => {
      const value = String(control.value || '').trim();
      let message = '';
      if (control.required && !value) message = messages[control.id] || 'Complete this field before continuing.';
      else if (control.minLength > 0 && value && value.length < control.minLength) message = messages[control.id] || `Enter at least ${control.minLength} characters.`;
      else if (control.type === 'url' && value && !validHttpUrl(value)) message = 'Enter a complete HTTP(S) URL beginning with https:// or http://.';
      if (message) errors.push({ control, message });
    });
    return errors;
  }

  function showFormErrors(form, summary, errors, heading = 'Complete the missing information') {
    clearFormErrors(form, summary);
    const uniqueErrors = errors.filter((error, index) => errors.findIndex((candidate) => candidate.control === error.control) === index);
    if (!uniqueErrors.length) return true;
    const title = create('strong', heading);
    const explanation = create('p', 'The highlighted fields explain exactly what is required before this action can continue.');
    const list = create('ul');
    uniqueErrors.forEach(({ control, message }) => {
      const label = control.closest('label');
      const messageId = `${control.id}-error`;
      control.setAttribute('aria-invalid', 'true');
      control.setAttribute('aria-describedby', unique([...(control.getAttribute('aria-describedby') || '').split(/\s+/), messageId]).join(' '));
      label?.classList.add('field-error');
      const inline = create('span', message, 'field-error-message'); inline.id = messageId; label?.append(inline);
      const item = create('li', `${fieldLabel(control)}: ${message}`); item.dataset.field = control.id; list.append(item);
    });
    summary.replaceChildren(title, explanation, list);
    summary.hidden = false;
    setStatus(`Cannot continue · ${uniqueErrors.map(({ control }) => fieldLabel(control)).join(', ')} missing or incomplete`);
    const first = uniqueErrors[0].control;
    first.closest('label')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    window.setTimeout(() => first.focus({ preventScroll: true }), 200);
    return false;
  }

  function validateStandardForm(form, summary, messages = FIELD_MESSAGES) {
    return showFormErrors(form, summary, nativeFormErrors(form, messages));
  }

  function bindValidationCleanup(form, summary) {
    ['input', 'change'].forEach((eventName) => form.addEventListener(eventName, (event) => {
      if (event.target.matches?.('input, select, textarea')) clearFieldError(event.target, summary);
    }));
  }

  function reveal(element, focusSelector = '') {
    if (!element) return false;
    element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    const focusTarget = focusSelector ? $(focusSelector, element) : null;
    if (focusTarget) window.setTimeout(() => focusTarget.focus({ preventScroll: true }), 350);
    return true;
  }

  function setJourneyProgress(index) {
    workflowProgress[activeWorkflow] = index;
    renderJourneySteps(index);
  }

  function renderJourneySteps(activeIndex = workflowProgress[activeWorkflow] || 0) {
    const list = $('#journey-steps');
    list.replaceChildren();
    WORKSPACES[activeWorkflow].steps.forEach((step, index) => {
      const item = create('li');
      if (index === activeIndex) item.className = 'active';
      const button = create('button');
      button.type = 'button';
      button.dataset.step = String(index);
      button.setAttribute('aria-current', index === activeIndex ? 'step' : 'false');
      button.append(create('span', String(index + 1).padStart(2, '0')), create('strong', step));
      button.addEventListener('click', () => activateJourneyStep(index));
      item.append(button);
      list.append(item);
    });
  }

  function requireObservationResults() {
    const value = $('#observation-input').value.trim();
    if (!value) {
      setStatus('Describe the evidence before reviewing candidates');
      reveal($('#observation-form'), '#observation-input');
      return false;
    }
    if (!observationCandidates.length || value !== currentObservation) renderObservation(value, false);
    return true;
  }

  function populateMappingCandidates(selectedId = '') {
    const select = $('#mapping-technique');
    select.replaceChildren();
    observationCandidates.forEach((candidate) => {
      const option = create('option', `${candidate.id} · ${candidate.name}`);
      option.value = candidate.id;
      select.append(option);
    });
    if (selectedId && observationCandidates.some((candidate) => candidate.id === selectedId)) select.value = selectedId;
  }

  function showObservationStage(index, selectedId = '', move = true) {
    if (index > 0 && !requireObservationResults()) return false;
    if (index > 1 && !observationCandidates.length) {
      setStatus('Review at least one candidate before validation');
      index = 1;
    }
    if (index === 2) populateMappingCandidates(selectedId || mappingAssessment?.technique_id || observationCandidates[0]?.id);
    if (index === 3 && !mappingAssessment) {
      setStatus('Save an analytical assessment before acting on it');
      index = 2;
      populateMappingCandidates(selectedId || observationCandidates[0]?.id);
    }
    $$('[data-observation-stage]').forEach((stage) => { stage.hidden = Number(stage.dataset.observationStage) !== index; });
    setJourneyProgress(index);
    const messages = ['Describe a concrete observation or choose an example', `Review ${observationCandidates.length} candidate mapping${observationCandidates.length === 1 ? '' : 's'} and select one to validate`, 'Document supporting evidence, gaps and a competing explanation', 'Export or operationalise the saved analytical assessment'];
    setStatus(messages[index]);
    const stage = $(`[data-observation-stage="${index}"]`);
    if (move) reveal(stage, index === 0 ? '#observation-input' : index === 2 ? '#mapping-technique' : '');
    return true;
  }

  function openFirstFilteredGroup(target = 'context') {
    const group = filteredGroups()[0];
    if (!group) {
      setStatus('No actor matches the current search');
      reveal($('.group-directory-controls'), '#group-search');
      return false;
    }
    openGroup(group.id, target);
    return true;
  }

  function activateJourneyStep(index) {
    if (activeWorkflow === 'observation') {
      if (index === 3 && !mappingAssessment) {
        showObservationStage(2);
        validateStandardForm($('#mapping-validation-form'), $('#mapping-errors'));
        return;
      }
      showObservationStage(index);
    } else if (activeWorkflow === 'intelligence') {
      showIntelligenceStage(index);
    } else if (activeWorkflow === 'readiness') {
      const currentStage = workflowProgress.readiness || 0;
      if (activeCapabilityId && index > currentStage && currentStage >= 1 && !validateCapabilityClaims(currentStage)) return;
      clearFormErrors($('#capability-form'), $('#capability-errors'));
      showReadinessStage(index);
    } else if (activeWorkflow === 'detection') {
      setJourneyProgress(index);
      const targets = ['.detection-package-head', '[data-detection-step="data"]', '[data-detection-step="logic"]', '[data-detection-step="validation"]', '[data-detection-step="handoff"]'];
      reveal($(targets[index], $('#detection-package')) || $('#detection-package'));
    } else if (activeWorkflow === 'incident') {
      setJourneyProgress(index);
      const targets = ['#incident-form', '#incident-parent', '#incident-status', '.incident-actions'];
      reveal($(targets[index]) || $('#panel-incident'), index === 0 ? '#incident-observation' : '');
    } else if (activeWorkflow === 'phishing') {
      setJourneyProgress(index);
      reveal(index === 0 ? $('#phishing-flow') : index === 1 ? $('#phishing-flow') : $('#phishing-detail'));
    } else if (activeWorkflow === 'reference') {
      setJourneyProgress(index);
      if (index === 0) reveal($('.reference-controls'), '#reference-search');
      else reveal($('#reference-results'));
    }
  }

  function updateUrl(values = {}) {
    const params = new URLSearchParams(location.search);
    if (activeWorkflow === 'observation') params.delete('workflow');
    else params.set('workflow', activeWorkflow);
    params.delete('actor');
    params.delete('group');
    if (values.actor) params.set('actor', values.actor);
    if (values.technique) params.set('technique', values.technique);
    else params.delete('technique');
    if (values.group) params.set('group', values.group);
    const query = params.toString();
    history.replaceState(null, '', `${location.pathname}${query ? `?${query}` : ''}${activeWorkflow === 'observation' ? '' : '#workbench'}`);
  }

  function switchWorkflow(name, focus = true) {
    if (!$(`[data-panel="${name}"]`)) return;
    activeWorkflow = name;
    $$('.operations-panel').forEach((panel) => { panel.hidden = panel.dataset.panel !== name; });
    $('#workspace-mode').value = name;
    $('#workbench-heading').textContent = WORKSPACES[name].label;
    $('#workbench-purpose').textContent = WORKSPACES[name].purpose;
    $$('.journey-card').forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.openWorkflow === WORKSPACES[name].journey)));
    renderJourneySteps(workflowProgress[name] || 0);
    if (name === 'observation') showObservationStage(workflowProgress.observation || 0, '', false);
    if (name === 'intelligence') { renderIntelligence(); showIntelligenceStage(workflowProgress.intelligence || 0, false); }
    if (name === 'readiness') { renderReadiness(); showReadinessStage(workflowProgress.readiness || 0, false); }
    if (name === 'detection') renderDetectionPackage();
    if (name === 'incident') renderIncident();
    if (name === 'phishing') renderPhishing();
    if (name === 'reference') renderReference();
    setStatus(`${WORKSPACES[name].label} active`);
    updateUrl();
    if (focus) $('#workbench').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function techniqueLink(id, label) {
    const button = create('button', label || id, 'technique-link');
    button.type = 'button';
    button.addEventListener('click', () => openTechnique(id));
    return button;
  }

  function listBlock(title, values, className = '') {
    const section = create('section', undefined, `operational-block ${className}`.trim());
    section.append(create('h4', title));
    const list = create('ul');
    values.forEach((value) => list.append(create('li', value)));
    section.append(list);
    return section;
  }

  function renderOperationalGuide(guide, score = null, matches = []) {
    const technique = techniqueById(guide.technique_id);
    const article = create('article', undefined, 'candidate-card curated');
    const header = create('header');
    const title = create('div');
    title.append(create('p', `${guide.technique_id} · ${technique?.tactics.join(' · ') || 'ATT&CK'}`, 'eyebrow'), create('h3', technique?.name || guide.technique_id));
    const badge = create('span', score === null ? 'CURATED GUIDE' : `${score} MATCH${score === 1 ? '' : 'ES'}`, 'candidate-badge');
    header.append(title, badge);
    article.append(header, create('p', guide.analyst_summary, 'candidate-summary'));
    if (matches.length) article.append(create('p', `Matched observation language: ${matches.join(', ')}`, 'match-reason'));
    const grid = create('div', undefined, 'operational-block-grid');
    grid.append(listBlock('Evidence required', guide.minimum_evidence), listBlock('Telemetry to inspect', guide.telemetry), listBlock('Benign overlap', guide.benign_overlap), listBlock('Next pivots', guide.pivots));
    article.append(grid);
    const actions = create('div', undefined, 'candidate-actions');
    actions.append(techniqueLink(guide.technique_id, 'Open complete technique view'));
    const validate = create('button', 'Select for validation', 'button primary');
    validate.type = 'button';
    validate.addEventListener('click', () => showObservationStage(2, guide.technique_id));
    actions.append(validate);
    const add = create('button', 'Add as suspected incident mapping', 'button small');
    add.type = 'button';
    add.addEventListener('click', () => prefillIncident(guide.technique_id));
    actions.append(add);
    article.append(actions);
    return article;
  }

  function scoreGuides(observation) {
    const text = normalise(observation);
    return operations.guides.map((guide) => {
      const matches = guide.triggers.filter((trigger) => text.includes(normalise(trigger)));
      const idMatch = text.includes(guide.technique_id.toLowerCase());
      return { guide, matches, score: matches.length + (idMatch ? 4 : 0) };
    }).filter((item) => item.score > 0).sort((a, b) => b.score - a.score || a.guide.technique_id.localeCompare(b.guide.technique_id));
  }

  function catalogueCandidates(observation) {
    const tokens = unique(normalise(observation).split(' ').filter((token) => token.length >= 4));
    if (!tokens.length) return [];
    return catalogue.techniques.map((technique) => {
      const target = normalise(`${technique.id} ${technique.name} ${technique.description}`);
      const matches = tokens.filter((token) => target.includes(token));
      return { technique, score: matches.length, matches };
    }).filter((item) => item.score > 0).sort((a, b) => b.score - a.score || a.technique.id.localeCompare(b.technique.id)).slice(0, 6);
  }

  function renderObservation(observation, moveToResults = true, preserveAssessment = false) {
    currentObservation = observation;
    const container = $('#observation-results');
    container.replaceChildren();
    const guided = scoreGuides(observation);
    if (guided.length) {
      const context = create('div', undefined, 'result-boundary');
      context.append(create('strong', `${guided.length} curated candidate${guided.length === 1 ? '' : 's'}`), create('span', 'Ranked by literal observation-language matches. Ranking is not confidence and does not confirm malicious intent.'));
      container.append(context);
      guided.slice(0, 4).forEach(({ guide, score, matches }) => container.append(renderOperationalGuide(guide, score, matches)));
    } else {
      const fallback = catalogueCandidates(observation);
      const boundary = create('div', undefined, 'result-boundary warning');
      boundary.append(create('strong', 'No curated operational guide matched'), create('span', fallback.length ? 'The following catalogue matches are terminology leads only. Review the official procedure and collect additional context.' : 'Use a more concrete process, command, identity action, message, file or network observation.'));
      container.append(boundary);
      fallback.forEach(({ technique, matches }) => {
        const card = create('article', undefined, 'candidate-card taxonomy');
        const heading = create('header');
        const title = create('div');
        title.append(create('p', `${technique.id} · ${technique.tactics.join(' · ')}`, 'eyebrow'), create('h3', technique.name));
        heading.append(title, create('span', 'TAXONOMY LEAD', 'candidate-badge muted'));
        card.append(heading, create('p', `Matched terms: ${matches.join(', ')}. This result has no HECAVEX procedure guide and should not be treated as a mapping.`, 'candidate-summary'), techniqueLink(technique.id, 'Inspect official context'));
        const validate = create('button', 'Select for validation', 'button small'); validate.type = 'button'; validate.addEventListener('click', () => showObservationStage(2, technique.id)); card.append(validate);
        container.append(card);
      });
    }
    observationCandidates = guided.length
      ? guided.slice(0, 4).map(({ guide }) => ({ id: guide.technique_id, name: techniqueById(guide.technique_id)?.name || guide.technique_id, guide: true }))
      : catalogueCandidates(observation).map(({ technique }) => ({ id: technique.id, name: technique.name, guide: false }));
    if (!preserveAssessment) {
      mappingAssessment = null;
      $('#mapping-status').value = 'plausible';
      $('#mapping-confidence').value = 'low';
      ['#mapping-evidence', '#mapping-gaps', '#mapping-alternative'].forEach((selector) => { $(selector).value = ''; });
    }
    save(STORAGE_OBSERVATION, { observation: currentObservation, assessment: mappingAssessment });
    setStatus(`${guided.length || catalogueCandidates(observation).length} candidate results`);
    if (moveToResults) showObservationStage(1);
  }

  function renderMappingOutput() {
    const container = $('#mapping-output');
    container.replaceChildren();
    if (!mappingAssessment) return;
    const technique = techniqueById(mappingAssessment.technique_id);
    const article = create('article', undefined, 'assessment-output-card');
    article.append(create('p', `${mappingAssessment.technique_id} · ${String(mappingAssessment.status).toUpperCase()} · ${String(mappingAssessment.confidence).toUpperCase()} CONFIDENCE`, 'eyebrow'), create('h3', technique?.name || mappingAssessment.technique_id));
    const statement = mappingAssessment.status === 'supported'
      ? `Available evidence supports mapping the observed behaviour to ${mappingAssessment.technique_id} ${technique?.name || ''} at ${mappingAssessment.confidence} confidence.`
      : mappingAssessment.status === 'rejected'
        ? `The candidate mapping to ${mappingAssessment.technique_id} ${technique?.name || ''} is rejected on the currently documented evidence.`
        : `${mappingAssessment.technique_id} ${technique?.name || ''} remains a plausible candidate, but the documented gaps prevent confirmation.`;
    article.append(create('p', statement, 'assessment-statement'));
    const evidenceGrid = create('div', undefined, 'operational-block-grid');
    evidenceGrid.append(listBlock('Supporting evidence', [mappingAssessment.evidence]), listBlock('Missing evidence', [mappingAssessment.gaps]), listBlock('Competing explanation', [mappingAssessment.alternative]), listBlock('Original observation', [mappingAssessment.observation]));
    article.append(evidenceGrid);
    const actions = create('div', undefined, 'assessment-actions');
    const exportButton = create('button', 'Export assessment JSON', 'button small'); exportButton.type = 'button'; exportButton.addEventListener('click', () => download(`hecavex-assessment-${mappingAssessment.technique_id.toLowerCase().replace('.', '-')}.json`, 'application/json', `${JSON.stringify({ schema_version: '1.0', type: 'hecavex-attack-assessment', exported: isoNow(), framework: { name: 'MITRE ATT&CK', version: catalogue.version }, assessment: mappingAssessment }, null, 2)}\n`));
    const incidentButton = create('button', 'Add to incident timeline', 'button primary'); incidentButton.type = 'button'; incidentButton.addEventListener('click', () => prefillIncident(mappingAssessment.technique_id));
    const pkg = detectionByTechnique(mappingAssessment.technique_id);
    actions.append(exportButton, incidentButton);
    if (pkg) { const detectionButton = create('button', pkg.starter ? 'Open engineering starter' : 'Open detection package', 'button small'); detectionButton.type = 'button'; detectionButton.addEventListener('click', () => { $('#detection-package-select').value = pkg.id; switchWorkflow('detection'); }); actions.append(detectionButton); }
    article.append(actions); container.append(article);
  }

  function saveMappingAssessment() {
    const techniqueId = $('#mapping-technique').value;
    if (!techniqueById(techniqueId)) throw new Error('Select a valid candidate technique.');
    mappingAssessment = {
      observation: currentObservation,
      technique_id: techniqueId,
      status: $('#mapping-status').value,
      confidence: $('#mapping-confidence').value,
      evidence: $('#mapping-evidence').value.trim(),
      gaps: $('#mapping-gaps').value.trim(),
      alternative: $('#mapping-alternative').value.trim(),
      assessed_at: isoNow()
    };
    if (!mappingAssessment.evidence || !mappingAssessment.gaps || !mappingAssessment.alternative) throw new Error('Document supporting evidence, gaps and a competing explanation.');
    save(STORAGE_OBSERVATION, { observation: currentObservation, assessment: mappingAssessment });
    renderMappingOutput();
    showObservationStage(3);
    setStatus(`${techniqueId} analytical assessment saved`);
  }

  function prefillIncident(techniqueId) {
    switchWorkflow('incident');
    const technique = techniqueById(techniqueId);
    $('#incident-technique').value = `${techniqueId} — ${technique?.name || ''}`;
    $('#incident-status').value = 'suspected';
    $('#incident-observation').focus();
  }

  function reviewedActorForGroup(group) {
    const groupNames = new Set([group.name, ...group.aliases].map((value) => normalise(value)));
    return evidence.actors.find((actor) => [actor.name, ...actor.aliases].some((value) => groupNames.has(normalise(value))));
  }

  function filteredGroups() {
    const query = normalise($('#group-search').value);
    const records = catalogue.groups.filter((group) => {
      if (!query) return true;
      const techniques = group.techniques.map((id) => techniqueById(id)?.name || id);
      return normalise(`${group.id} ${group.name} ${group.aliases.join(' ')} ${group.description} ${techniques.join(' ')}`).includes(query);
    });
    const sort = $('#group-sort').value;
    if (sort === 'modified') records.sort((a, b) => b.modified.localeCompare(a.modified) || a.name.localeCompare(b.name));
    else if (sort === 'techniques') records.sort((a, b) => b.techniques.length - a.techniques.length || a.name.localeCompare(b.name));
    else records.sort((a, b) => a.name.localeCompare(b.name));
    return records;
  }

  function renderGroupCatalogue(resetLimit = false) {
    if (resetLimit) groupLimit = 36;
    const records = filteredGroups();
    const container = $('#group-results');
    container.replaceChildren();
    $('#group-count').textContent = `${records.length} official group${records.length === 1 ? '' : 's'} · showing ${Math.min(groupLimit, records.length)}`;
    records.slice(0, groupLimit).forEach((group) => {
      const reviewed = reviewedActorForGroup(group);
      const article = create('article', undefined, `group-card${reviewed ? ' reviewed' : ''}`);
      const heading = create('div', undefined, 'group-card-heading');
      const title = create('div');
      const actorButton = create('button', group.name, 'group-title-button');
      actorButton.type = 'button';
      actorButton.setAttribute('aria-label', `Inspect ${group.name} aliases, sources and techniques`);
      actorButton.addEventListener('click', () => openGroup(group.id, 'context'));
      const actorHeading = create('h4');
      actorHeading.append(actorButton);
      title.append(create('p', `${group.id} · OFFICIAL ATT&CK GROUP`, 'eyebrow'), actorHeading);
      heading.append(title);
      if (reviewed) { const marker = create('span', 'HECAVEX REVIEWED', 'reviewed-marker'); marker.title = 'A separate HECAVEX-reviewed source layer is available'; heading.append(marker); }
      const aliases = group.aliases.length ? group.aliases.slice(0, 4).join(' · ') : 'No additional aliases listed';
      const summary = group.description.length > 180 ? `${group.description.slice(0, 177)}…` : group.description;
      article.append(heading, create('p', aliases, 'group-aliases'), create('p', summary, 'group-description'));
      const facts = create('div', undefined, 'group-card-facts');
      facts.append(create('span', `${group.procedures?.length || group.techniques.length} official procedures`), create('span', `updated ${group.modified}`));
      article.append(facts);
      const button = create('button', 'Inspect aliases, sources and use →', 'text-button');
      button.type = 'button'; button.addEventListener('click', () => openGroup(group.id, 'context')); article.append(button);
      container.append(article);
    });
    $('#group-more').hidden = records.length <= groupLimit;
    if (!records.length) container.append(create('p', 'No official ATT&CK group matches that search. Try an alias, group ID or technique name.', 'empty-message'));
  }

  function ensureGroupReadinessOption(group) {
    const select = $('#readiness-focus');
    $$('.temporary-group-focus', select).forEach((option) => option.remove());
    const option = create('option', `${group.name} mapped techniques (official reference)`, 'temporary-group-focus');
    option.value = `group:${group.id}`;
    select.append(option);
    activeReadinessGroup = group.id;
    select.value = option.value;
  }

  function setGroupDirectoryVisible(visible) {
    ['.panel-intro', '.group-directory-controls', '.reference-toolbar', '#group-results', '#group-more', '.reviewed-intelligence'].forEach((selector) => { const element = $(selector, $('#panel-intelligence')); if (element) element.hidden = !visible; });
    $('#group-workspace').hidden = visible;
  }

  function showIntelligenceStage(index, move = true) {
    if (index === 0) {
      setGroupDirectoryVisible(true);
      renderGroupCatalogue();
      setJourneyProgress(0);
      if (move) reveal($('.group-directory-controls'), '#group-search');
      return true;
    }
    if (!activeGroupId) {
      const query = $('#group-search').value.trim();
      const records = filteredGroups();
      if (!query) {
        setStatus('Search for an actor or alias before opening its intelligence record');
        setJourneyProgress(0);
        if (move) reveal($('.group-directory-controls'), '#group-search');
        return false;
      }
      const exact = records.filter((group) => [group.id, group.name, ...group.aliases].some((value) => normalise(value) === normalise(query)));
      if (exact.length === 1) activeGroupId = exact[0].id;
      else if (records.length !== 1) {
        setStatus(`Select one actor from the ${records.length} matching records`);
        setJourneyProgress(0);
        if (move) reveal($('#group-results'));
        return false;
      } else activeGroupId = records[0].id;
    }
    openGroup(activeGroupId, index === 1 ? 'context' : index === 2 ? 'procedures' : 'use', move);
    setStatus(index === 1 ? 'Inspect aliases, catalogue context and public sources' : index === 2 ? 'Review mapped and HECAVEX-reviewed procedures separately' : 'Choose how to use or export the intelligence record');
    return true;
  }

  function openGroup(id, target = 'context', move = true) {
    const group = groupById(id);
    if (!group) return;
    activeGroupId = id;
    const stepIndex = target === 'context' ? 1 : target === 'procedures' ? 2 : target === 'use' ? 3 : 1;
    setJourneyProgress(stepIndex);
    setGroupDirectoryVisible(false);
    const reviewed = reviewedActorForGroup(group);
    const workspace = $('#group-workspace');
    workspace.replaceChildren();
    const head = create('header', undefined, 'group-workspace-head');
    const identity = create('div'); identity.append(create('p', `${group.id} · OFFICIAL ENTERPRISE ATT&CK GROUP`, 'eyebrow'), create('h3', group.name));
    const back = create('button', 'Back to actor results', 'button small'); back.type = 'button'; back.addEventListener('click', () => { activeGroupId = ''; updateUrl(); showIntelligenceStage(0); });
    head.append(identity, back); workspace.append(head);
    const detail = create('div', undefined, 'group-workspace-detail');
    const boundary = create('div', undefined, 'technique-boundary');
    boundary.append(create('strong', 'Reference boundary'), create('span', 'This is MITRE ATT&CK catalogue data. Inclusion, aliases and mapped techniques do not establish current activity, attribution or HECAVEX validation.'));
    detail.append(boundary);

    const nav = create('nav', undefined, 'group-dialog-nav');
    nav.setAttribute('aria-label', `${group.name} profile sections`);
    [['context', 'Aliases & sources'], ['procedures', 'Procedures'], ['use', 'Use this intelligence']].forEach(([sectionId, label]) => {
      const button = create('button', label, 'button small');
      button.type = 'button';
      button.addEventListener('click', () => showIntelligenceStage(sectionId === 'context' ? 1 : sectionId === 'procedures' ? 2 : 3));
      nav.append(button);
    });
    detail.append(nav);

    const context = create('section', undefined, 'group-dialog-section');
    context.id = 'group-context';
    context.append(create('p', 'IDENTITY AND SOURCE RECORD', 'eyebrow'), create('h3', 'Aliases, catalogue context and public sources'));
    const facts = create('dl', undefined, 'evidence-facts');
    [['Aliases', group.aliases.join(', ') || 'None listed'], ['Mapped techniques', String(group.techniques.length)], ['Official procedures', String(group.procedures?.length || 0)], ['ATT&CK version', String(group.version || 'Not stated')], ['Last modified', group.modified]].forEach(([term, value]) => { const row = create('div'); row.append(create('dt', term), create('dd', value)); facts.append(row); });
    context.append(facts, create('p', group.description, 'group-full-description'));
    const official = create('a', 'Open official ATT&CK group page ↗', 'button small'); official.href = group.url; official.rel = 'noopener'; context.append(official);
    if (group.sources.length) {
      const sources = create('div', undefined, 'catalogue-relations'); const listSection = create('section'); listSection.append(create('h4', `Public references (${group.sources.length})`)); const list = create('ul');
      group.sources.slice(0, 20).forEach((source) => { const item = create('li'); const link = create('a', source.source); link.href = source.url; link.rel = 'noopener'; item.append(link); list.append(item); }); listSection.append(list); sources.append(listSection); context.append(sources);
    }
    detail.append(context);

    const procedures = create('section', undefined, 'group-dialog-section');
    procedures.id = 'group-procedures';
    procedures.append(create('p', 'PROCEDURE CONTEXT', 'eyebrow'), create('h3', `Official actor procedures (${group.procedures?.length || 0})`));
    if (reviewed) {
      const review = create('div', undefined, 'group-review-available');
      review.append(create('p', 'HECAVEX REVIEWED LAYER AVAILABLE', 'eyebrow'), create('h4', `${reviewed.evidence.length} source-linked procedure mappings`), create('p', reviewed.summary));
      reviewed.evidence.forEach((item) => {
        const claim = create('article', undefined, 'procedure-claim');
        const technique = techniqueById(item.technique_id);
        claim.append(create('p', `${item.technique_id} · ${String(item.status).toUpperCase()} · ${String(item.confidence).toUpperCase()} CONFIDENCE`, 'eyebrow'), create('h4', technique?.name || item.technique), create('p', item.notes));
        const sources = create('div', undefined, 'inline-sources'); item.sources.forEach((source) => { const link = create('a', `${source.publisher} · ${source.published} ↗`); link.href = source.url; link.rel = 'noopener'; sources.append(link); }); claim.append(sources); review.append(claim);
      });
      const reviewedActions = create('div', undefined, 'group-use-actions');
      const profileLink = create('a', `Open ${reviewed.name} in APT Notes ↗`, 'button small'); profileLink.href = reviewed.profile_url; profileLink.rel = 'noopener';
      reviewedActions.append(profileLink); review.append(reviewedActions); procedures.append(review);
    } else procedures.append(create('p', 'No HECAVEX-reviewed procedure layer is available for this group. The relationships below remain official ATT&CK reference data.', 'gap-note'));
    const officialProcedures = Array.isArray(group.procedures) ? group.procedures : [];
    if (officialProcedures.length) {
      const filter = create('div', undefined, 'group-procedure-controls');
      const filterLabel = create('label'); filterLabel.append(create('span', 'Filter this actor’s procedures'));
      const filterInput = create('input'); filterInput.type = 'search'; filterInput.placeholder = 'Technique, procedure text or source'; filterInput.setAttribute('aria-label', `Filter ${group.name} procedures`); filterLabel.append(filterInput); filter.append(filterLabel); procedures.append(filter);
      const procedureList = create('div', undefined, 'official-procedure-list'); procedures.append(procedureList);
      const moreProcedures = create('button', 'Show more procedures', 'button small load-more'); moreProcedures.type = 'button'; procedures.append(moreProcedures);
      let procedureLimit = 24;
      const renderProcedures = () => {
        const query = normalise(filterInput.value);
        const filtered = officialProcedures.filter((procedure) => {
          const technique = techniqueById(procedure.technique_id);
          return !query || normalise(`${procedure.technique_id} ${technique?.name || ''} ${procedure.description || ''} ${(procedure.sources || []).map((source) => source.source).join(' ')}`).includes(query);
        });
        procedureList.replaceChildren();
        filtered.slice(0, procedureLimit).forEach((procedure) => {
          const technique = techniqueById(procedure.technique_id);
          const claim = create('article', undefined, 'procedure-claim official-procedure');
          const heading = create('div', undefined, 'official-procedure-head');
          const title = create('div'); title.append(create('p', `${procedure.technique_id} · OFFICIAL ATT&CK RELATIONSHIP`, 'eyebrow'), create('h4', technique?.name || procedure.technique_id));
          heading.append(title, techniqueLink(procedure.technique_id, 'Open technique context')); claim.append(heading);
          claim.append(create('p', procedure.description || 'The official relationship has no procedure description. Use the linked ATT&CK record and sources as reference, not as a complete analytical claim.'));
          const sourceList = create('div', undefined, 'inline-sources');
          (procedure.sources || []).forEach((source) => { const link = create('a', `${source.source} ↗`); link.href = source.url; link.rel = 'noopener'; sourceList.append(link); });
          if (sourceList.childElementCount) claim.append(sourceList);
          procedureList.append(claim);
        });
        if (!filtered.length) procedureList.append(create('p', 'No procedure matches this filter.', 'empty-message'));
        moreProcedures.hidden = filtered.length <= procedureLimit;
        moreProcedures.textContent = `Show more procedures (${Math.max(0, filtered.length - procedureLimit)} remaining)`;
      };
      filterInput.addEventListener('input', () => { procedureLimit = 24; renderProcedures(); });
      moreProcedures.addEventListener('click', () => { procedureLimit += 24; renderProcedures(); });
      renderProcedures();
    } else {
      procedures.append(create('p', 'No source-linked official procedure description is available. The mapped techniques below remain catalogue relationships.', 'gap-note'));
      const techniqueList = create('div', undefined, 'group-technique-list'); group.techniques.forEach((techniqueId) => { const technique = techniqueById(techniqueId); techniqueList.append(techniqueLink(techniqueId, `${techniqueId} · ${technique?.name || ''}`)); }); procedures.append(techniqueList);
    }
    detail.append(procedures);

    const use = create('section', undefined, 'group-dialog-section group-use');
    use.id = 'group-use';
    use.append(create('p', 'ANALYST ACTIONS', 'eyebrow'), create('h3', 'Use the reference without turning it into attribution'), create('p', 'Carry the mapped techniques into a defensive review, search their catalogue relationships, or export this source record. Validate current activity independently.'));
    const actions = create('div', undefined, 'group-use-actions');
    const assess = create('button', 'Assess mapped techniques', 'button primary'); assess.type = 'button'; assess.addEventListener('click', () => { ensureGroupReadinessOption(group); activeCapabilityId = ''; workflowProgress.readiness = 1; switchWorkflow('readiness'); renderReadiness(); showReadinessStage(1); });
    const explore = create('button', 'Explore technique relationships', 'button small'); explore.type = 'button'; explore.addEventListener('click', () => { $('#reference-search').value = group.name; switchWorkflow('reference'); renderReference(true); });
    const exportActor = create('button', 'Export actor reference JSON', 'button small'); exportActor.type = 'button'; exportActor.addEventListener('click', () => download(`${group.id.toLowerCase()}-${normalise(group.name).replace(/ /g, '-')}.json`, 'application/json', `${JSON.stringify({ boundary: 'Official ATT&CK reference data; not an attribution assessment.', group }, null, 2)}\n`));
    actions.append(assess, explore, exportActor); use.append(actions); detail.append(use); workspace.append(detail);

    updateUrl({ group: id });
    setStatus(target === 'context' ? 'Inspect aliases, catalogue context and public sources' : target === 'procedures' ? 'Review mapped and HECAVEX-reviewed procedures separately' : 'Choose how to use or export the intelligence record');
    if (move) window.setTimeout(() => reveal($(`#group-${target}`) || context), 50);
  }

  function renderIntelligence() {
    renderGroupCatalogue();
    const value = $('#intel-actor').value;
    const platform = $('#intel-platform').value;
    const actors = value === 'compare' ? evidence.actors : [actorById(value)];
    const records = actors.flatMap((actor) => actor.evidence.map((item) => ({ actor, item, technique: techniqueById(item.technique_id) })));
    const filtered = records.filter((record) => platform === 'all' || record.technique?.platforms.includes(platform));
    const summary = $('#intel-summary');
    summary.replaceChildren();
    const sources = new Set(filtered.flatMap((record) => record.item.sources.map((source) => source.url)));
    [['Reviewed relationships', filtered.length], ['Unique techniques', new Set(filtered.map((record) => record.item.technique_id)).size], ['Public sources', sources.size]].forEach(([label, amount]) => {
      const stat = create('div'); stat.append(create('strong', String(amount)), create('span', label)); summary.append(stat);
    });
    const container = $('#intel-results');
    container.replaceChildren();
    actors.forEach((actor) => { if (!actor?.review) return; const review = create('div', undefined, 'result-boundary'); review.append(create('strong', `${actor.name} review boundary`), create('span', `${actor.review.scope} Reviewed ${actor.review.last_reviewed}; next review ${actor.review.review_due}.`)); container.append(review); });
    const grouped = new Map();
    filtered.forEach((record) => {
      if (!grouped.has(record.item.technique_id)) grouped.set(record.item.technique_id, []);
      grouped.get(record.item.technique_id).push(record);
    });
    [...grouped.entries()].sort((a, b) => a[0].localeCompare(b[0])).forEach(([id, group]) => {
      const article = create('article', undefined, `intel-record${group.length > 1 ? ' shared' : ''}`);
      const technique = group[0].technique;
      const head = create('header');
      const title = create('div'); title.append(create('p', `${id} · ${technique?.tactics.join(' · ')}`, 'eyebrow'), create('h3', technique?.name || group[0].item.technique));
      head.append(title, create('span', group.map((record) => record.actor.name).join(' + '), 'candidate-badge'));
      article.append(head);
      group.forEach(({ actor, item }) => {
        const procedure = create('section', undefined, 'procedure-claim');
        procedure.append(create('h4', `${actor.name} · ${item.campaign}`), create('p', item.notes), create('p', `${item.status.toUpperCase()} · ${item.confidence.toUpperCase()} CONFIDENCE · ${item.first_observed} → ${item.last_observed}`, 'meta'));
        const lineage = create('dl', undefined, 'claim-lineage');
        [['Evidence class', item.status], ['Mapping basis', 'Public procedure reporting'], ['Sources', String(item.sources.length)], ['Reviewed', evidence.updated]].forEach(([term, answer]) => { const fact = create('div'); fact.append(create('dt', term), create('dd', answer)); lineage.append(fact); });
        procedure.append(lineage);
        const sourceList = create('div', undefined, 'inline-sources');
        item.sources.forEach((source) => { const link = create('a', `${source.publisher} · ${source.published} ↗`); link.href = source.url; link.rel = 'noopener'; sourceList.append(link); });
        procedure.append(sourceList); article.append(procedure);
      });
      const guide = guideById(id);
      if (guide) {
        const questions = create('div', undefined, 'intel-operationalise');
        questions.append(listBlock('Collection questions', guide.minimum_evidence.slice(0, 3)), listBlock('Detection and hunt pivots', guide.pivots.slice(0, 3)));
        article.append(questions);
      } else article.append(create('p', 'No curated operational guide yet. Preserve the source procedure and use the official ATT&CK object as reference—not as a ready-made detection requirement.', 'gap-note'));
      article.append(techniqueLink(id, 'Open technique context'));
      container.append(article);
    });
  }

  function focusTechniqueIds() {
    const focus = $('#readiness-focus').value;
    if (focus === 'all-guides') return operations.guides.map((guide) => guide.technique_id);
    if (focus === 'phishing') return unique(operations.phishing_flow.nodes.flatMap((node) => node.techniques));
    if (focus.startsWith('group:')) return groupById(focus.slice(6))?.techniques || [];
    return actorById(focus)?.evidence.map((item) => item.technique_id) || [];
  }

  function readinessKey(id) {
    return `${$('#readiness-environment').value}:${$('#readiness-focus').value}:${id}`;
  }

  function blankCapability() {
    return { not_applicable: false, telemetry: 'not-assessed', analytic: 'none', validation: 'untested', operations: 'unowned', owner: '', rule_id: '', repository: '', sensors: '', required_fields: '', last_test: '', test_method: '', runbook: '', review_due: '', notes: '', updated: '' };
  }

  function capabilityRecord(id) {
    const key = readinessKey(id);
    const stored = readiness[key];
    if (!stored) return blankCapability();
    if (!stored.telemetry && stored.state) {
      const migrated = blankCapability();
      if (stored.state === 'no-telemetry') migrated.telemetry = 'absent';
      if (stored.state === 'telemetry') migrated.telemetry = 'ready';
      if (stored.state === 'analytic') Object.assign(migrated, { telemetry: 'ready', analytic: 'deployed' });
      if (stored.state === 'validated') Object.assign(migrated, { telemetry: 'ready', analytic: 'deployed', validation: 'passed' });
      if (stored.state === 'operational') Object.assign(migrated, { telemetry: 'healthy', analytic: 'deployed', validation: 'passed', operations: 'operational' });
      if (stored.state === 'not-applicable') migrated.not_applicable = true;
      migrated.notes = stored.note || '';
      readiness[key] = migrated;
      save(STORAGE_READINESS, readiness);
      return migrated;
    }
    return { ...blankCapability(), ...stored };
  }

  function derivedCapabilityState(record) {
    if (record.not_applicable) return 'not-applicable';
    const untouched = record.telemetry === 'not-assessed' && record.analytic === 'none' && record.validation === 'untested' && record.operations === 'unowned' && !record.owner && !record.rule_id && !record.sensors && !record.notes;
    if (untouched) return 'not-assessed';
    if (record.telemetry === 'not-assessed') return 'not-assessed';
    if (record.telemetry === 'absent') return 'no-telemetry';
    if (record.telemetry === 'partial' || record.analytic === 'none' || record.analytic === 'draft') return 'telemetry';
    if (record.validation !== 'passed') return 'analytic';
    if (record.operations !== 'operational') return 'validated';
    return 'operational';
  }

  function capabilityDimensions(record) {
    const dimensions = [
      ['telemetry', 'Telemetry', record.telemetry, { 'not-assessed': 'Not assessed', absent: 'Absent', partial: 'Partial', ready: 'Ready', healthy: 'Healthy' }, { 'not-assessed': 'pending', absent: 'gap', partial: 'warning', ready: 'good', healthy: 'good' }],
      ['analytic', 'Analytic', record.analytic, { none: 'None', draft: 'Draft', deployed: 'Deployed' }, { none: 'pending', draft: 'warning', deployed: 'good' }],
      ['validation', 'Validation', record.validation, { untested: 'Untested', failed: 'Failed', passed: 'Passed', stale: 'Stale' }, { untested: 'pending', failed: 'gap', passed: 'good', stale: 'warning' }],
      ['operations', 'Operations', record.operations, { unowned: 'Unowned', owned: 'Owner assigned', runbook: 'Runbook ready', operational: 'Alert path tested' }, { unowned: 'pending', owned: 'progress', runbook: 'progress', operational: 'good' }]
    ];
    if (record.not_applicable) return dimensions.map(([id, label]) => ({ id, label, value: 'Not applicable', tone: 'pending' }));
    return dimensions.map(([id, label, value, labels, tones]) => ({ id, label, value: labels[value] || value, tone: tones[value] || 'pending' }));
  }

  function capabilityStateReason(record) {
    if (record.not_applicable) return 'Explicitly excluded from the documented scope.';
    if (record.telemetry === 'not-assessed') return 'Telemetry has not been assessed, so later selections cannot establish coverage.';
    if (record.telemetry === 'absent') return 'Required telemetry is absent.';
    if (record.telemetry === 'partial') return 'Telemetry exists but collection or field quality remains incomplete.';
    if (record.analytic === 'none') return 'Telemetry is available, but no analytic is recorded.';
    if (record.analytic === 'draft') return 'The analytic is still a draft.';
    if (record.validation === 'failed') return 'Validation failed; the analytic cannot advance.';
    if (record.validation === 'untested') return 'The analytic is recorded but has not been tested.';
    if (record.validation === 'stale') return 'Previous validation is stale and must be repeated.';
    if (record.operations === 'unowned') return 'Validation passed, but no operational owner is assigned.';
    if (record.operations === 'owned') return 'An owner is assigned; the runbook and alert path remain incomplete.';
    if (record.operations === 'runbook') return 'The runbook exists; test the alert path before claiming operational readiness.';
    return 'Telemetry, analytic, validation and alert handling are recorded as operational.';
  }

  function appendCapabilityDimensions(container, record) {
    capabilityDimensions(record).forEach((dimension) => {
      const item = create('div', undefined, `capability-dimension dimension-${dimension.tone}`);
      item.append(create('span', dimension.label), create('strong', dimension.value));
      container.append(item);
    });
  }

  function stateLabel(id) {
    return operations.readiness_states.find((item) => item.id === id)?.label || id;
  }

  function renderReadiness() {
    const environment = $('#readiness-environment').value;
    const techniques = focusTechniqueIds().map(techniqueById).filter(Boolean).filter((technique) => environment === 'all' || technique.platforms.includes(environment));
    const body = $('#readiness-body');
    body.replaceChildren();
    techniques.forEach((technique) => {
      const guide = guideById(technique.id);
      const current = capabilityRecord(technique.id);
      const derived = derivedCapabilityState(current);
      const card = create('article', undefined, 'readiness-card');
      const header = create('header', undefined, 'readiness-card-head');
      const name = create('div', undefined, 'readiness-technique');
      name.append(create('p', `${technique.id} · ${technique.tactics.join(' · ')}`, 'eyebrow'), create('h3', technique.name));
      const packageRecord = detectionByTechnique(technique.id);
      const packageLabel = packageRecord ? create('span', packageRecord.starter ? 'ENGINEERING CANDIDATE' : 'VALIDATION-READY PACKAGE', 'package-marker') : null;
      header.append(name); if (packageLabel) header.append(packageLabel);
      const bodyGrid = create('div', undefined, 'readiness-card-body');
      const why = create('section'); why.append(create('h4', 'Why it matters'), create('p', guide?.analyst_summary || 'This relationship comes from the selected official actor reference. Review its procedure sources before defining a capability requirement.'));
      const telemetry = create('section'); telemetry.append(create('h4', 'Minimum telemetry'));
      const telemetryList = create('ul');
      (guide?.telemetry || ['Review ATT&CK detection strategies and identify environment-specific events and fields.']).slice(0, 3).forEach((item) => telemetryList.append(create('li', item)));
      telemetry.append(telemetryList);
      bodyGrid.append(why, telemetry);
      const capability = create('div', undefined, 'readiness-capability');
      const aggregate = create('div', undefined, 'readiness-aggregate'); aggregate.append(create('span', stateLabel(derived), `capability-state state-${derived}`), create('p', capabilityStateReason(current)));
      const dimensions = create('div', undefined, 'capability-dimension-grid'); appendCapabilityDimensions(dimensions, current);
      const ownership = create('div', undefined, 'readiness-owner'); ownership.append(create('strong', current.owner || 'Unassigned'), create('span', current.review_due ? `Review ${current.review_due}` : 'No review due', 'meta'));
      const edit = create('button', current.updated ? 'Edit record' : 'Create record', 'button small'); edit.type = 'button'; edit.addEventListener('click', () => openCapability(technique.id));
      capability.append(aggregate, dimensions, ownership, edit);
      card.append(header, bodyGrid, capability); body.append(card);
    });
    renderReadinessSummary(techniques);
    setStatus(`${techniques.length} readiness decisions in scope`);
  }

  function renderReadinessSummary(techniques) {
    const summary = $('#readiness-summary');
    summary.replaceChildren();
    const counts = new Map(operations.readiness_states.map((state) => [state.id, 0]));
    techniques.forEach((technique) => { const state = derivedCapabilityState(capabilityRecord(technique.id)); counts.set(state, counts.get(state) + 1); });
    const meaningful = ['not-assessed', 'no-telemetry', 'telemetry', 'analytic', 'validated', 'operational'];
    meaningful.forEach((id) => {
      const state = operations.readiness_states.find((item) => item.id === id);
      const item = create('div', undefined, `readiness-metric state-${id}`); item.append(create('strong', String(counts.get(id))), create('span', state.label)); summary.append(item);
    });
  }

  function prepareCapabilityEditor() {
    const form = $('#capability-form');
    if (form && form.parentElement !== $('#capability-form-host')) $('#capability-form-host').append(form);
  }

  function setReadinessSections(stage) {
    const panel = $('#panel-readiness');
    const scopeVisible = stage === 0;
    const tableVisible = stage === 1 && !activeCapabilityId;
    $('.panel-intro', panel).hidden = false;
    $('.workspace-meta', panel).hidden = !scopeVisible;
    $('.readiness-controls', panel).hidden = false;
    $('#readiness-summary').hidden = !tableVisible;
    $('#readiness-body').hidden = !tableVisible;
    $('#capability-editor').hidden = stage < 1 || !activeCapabilityId;
  }

  function highlightCapabilityStage(stage) {
    $$('.capability-form label').forEach((label) => { label.classList.remove('active-capability-field'); label.hidden = !label.classList.contains('checkbox-control'); });
    const selectors = {
      1: ['#capability-telemetry', '#capability-sensors', '#capability-fields-required'],
      2: ['#capability-analytic', '#capability-rule', '#capability-repository'],
      3: ['#capability-validation', '#capability-last-test', '#capability-test-method'],
      4: ['#capability-operations', '#capability-owner', '#capability-runbook', '#capability-review', '#capability-notes']
    };
    (selectors[stage] || []).forEach((selector) => { const label = $(selector)?.closest('label'); if (label) { label.hidden = false; label.classList.add('active-capability-field'); } });
    const guidance = {
      1: 'Telemetry claim: identify the actual sensors, event sources and required fields. Do not infer collection from a product licence.',
      2: 'Analytic claim: record the implemented rule, its durable repository link and current ownership.',
      3: 'Validation claim: document when and how representative positive and benign cases were tested, plus the observed result.',
      4: 'Operational claim: assign the alert owner, runbook, review date and known gaps before treating the capability as operational.'
    };
    $('#capability-stage-guidance').textContent = guidance[stage] || '';
    const focus = $(selectors[stage]?.[0] || '#capability-telemetry');
    if (focus) window.setTimeout(() => focus.focus({ preventScroll: true }), 150);
  }

  function showReadinessStage(index, move = true) {
    if (index > 1 && !activeCapabilityId) {
      setStatus('Choose a technique and create or edit its capability record first');
      index = 1;
    }
    setJourneyProgress(index);
    setReadinessSections(index);
    const messages = ['Define the environment, owner, platform and threat focus', 'Choose a technique and inspect whether its minimum telemetry exists', 'Record the analytic, repository and rule ownership', 'Record the validation method, result and date', 'Assign operational ownership, runbook and review date'];
    setStatus(messages[index]);
    if (index === 0 && move) reveal($('.workspace-meta'), '#readiness-workspace');
    else if (index === 1 && !activeCapabilityId && move) reveal($('#readiness-body'));
    else if (activeCapabilityId) { if (move) reveal($('#capability-editor')); highlightCapabilityStage(index); }
    return index;
  }

  function openCapability(id, stage = 1) {
    activeCapabilityId = id;
    const technique = techniqueById(id);
    const record = capabilityRecord(id);
    $('#capability-inline-id').textContent = `${id} · ${technique?.tactics.join(' · ') || 'ATT&CK'}`;
    $('#capability-inline-title').textContent = technique?.name || id;
    $('#capability-id').textContent = `${id} · ${technique?.tactics.join(' · ') || 'ATT&CK'}`;
    $('#capability-title').textContent = technique?.name || id;
    $('#capability-key').value = id;
    $('#capability-na').checked = Boolean(record.not_applicable);
    $('#capability-telemetry').value = record.telemetry;
    $('#capability-analytic').value = record.analytic;
    $('#capability-validation').value = record.validation;
    $('#capability-operations').value = record.operations;
    $('#capability-owner').value = record.owner;
    $('#capability-rule').value = record.rule_id;
    $('#capability-repository').value = record.repository;
    $('#capability-sensors').value = record.sensors;
    $('#capability-fields-required').value = record.required_fields;
    $('#capability-last-test').value = record.last_test;
    $('#capability-test-method').value = record.test_method;
    $('#capability-runbook').value = record.runbook;
    $('#capability-review').value = record.review_due;
    $('#capability-notes').value = record.notes;
    clearFormErrors($('#capability-form'), $('#capability-errors'));
    $('#delete-capability').hidden = !record.updated;
    renderCapabilityProgress(record);
    showReadinessStage(stage);
  }

  function capabilityFromForm() {
    return {
      not_applicable: $('#capability-na').checked,
      telemetry: $('#capability-telemetry').value,
      analytic: $('#capability-analytic').value,
      validation: $('#capability-validation').value,
      operations: $('#capability-operations').value,
      owner: $('#capability-owner').value.trim(),
      rule_id: $('#capability-rule').value.trim(),
      repository: $('#capability-repository').value.trim(),
      sensors: $('#capability-sensors').value.trim(),
      required_fields: $('#capability-fields-required').value.trim(),
      last_test: $('#capability-last-test').value,
      test_method: $('#capability-test-method').value.trim(),
      runbook: $('#capability-runbook').value.trim(),
      review_due: $('#capability-review').value,
      notes: $('#capability-notes').value.trim()
    };
  }

  function capabilityClaimErrors(stage = 0) {
    const record = capabilityFromForm();
    const errors = [];
    const applies = (claimStage) => !stage || stage === claimStage;
    const requireValue = (claimStage, selector, value, message) => {
      if (applies(claimStage) && !value) errors.push({ control: $(selector), message, stage: claimStage });
    };

    if (record.not_applicable) {
      requireValue(4, '#capability-notes', record.notes, 'Explain why this technique is not applicable to the documented environment or threat scope.');
      return errors;
    }

    if (applies(1) && ['partial', 'ready', 'healthy'].includes(record.telemetry)) {
      requireValue(1, '#capability-sensors', record.sensors, 'Name the actual sensors or event sources supporting this telemetry claim.');
      requireValue(1, '#capability-fields-required', record.required_fields, 'List the fields required to correlate and test the behaviour.');
    }
    if (applies(2) && ['draft', 'deployed'].includes(record.analytic)) {
      requireValue(2, '#capability-rule', record.rule_id, 'Record the rule or analytic identifier supporting this claim.');
      if (record.analytic === 'deployed') requireValue(2, '#capability-repository', record.repository, 'Add the durable HTTP(S) repository permalink for the deployed analytic.');
    }
    if (applies(2) && record.repository && !validHttpUrl(record.repository)) errors.push({ control: $('#capability-repository'), message: 'Enter a complete HTTP(S) repository permalink beginning with https:// or http://.', stage: 2 });
    if (applies(3) && record.validation !== 'untested') {
      requireValue(3, '#capability-last-test', record.last_test, 'Record when the representative validation was last performed.');
      requireValue(3, '#capability-test-method', record.test_method, 'Describe the validation method and observed result.');
    }
    if (applies(4) && record.operations !== 'unowned') requireValue(4, '#capability-owner', record.owner, 'Assign the team or analyst responsible for this capability.');
    if (applies(4) && ['runbook', 'operational'].includes(record.operations)) requireValue(4, '#capability-runbook', record.runbook, 'Add the HTTP(S) runbook used by the alert-handling path.');
    if (applies(4) && record.operations === 'operational') requireValue(4, '#capability-review', record.review_due, 'Set the next review date for this operational capability.');
    if (applies(4) && record.runbook && !validHttpUrl(record.runbook)) errors.push({ control: $('#capability-runbook'), message: 'Enter a complete HTTP(S) runbook URL beginning with https:// or http://.', stage: 4 });
    return errors;
  }

  function validateCapabilityClaims(stage = 0) {
    const label = stage ? `${WORKSPACES.readiness.steps[stage]} cannot continue` : 'Capability record cannot be saved';
    const errors = capabilityClaimErrors(stage);
    if (!stage && errors.length && errors[0].stage) {
      setJourneyProgress(errors[0].stage);
      setReadinessSections(errors[0].stage);
      highlightCapabilityStage(errors[0].stage);
    }
    return showFormErrors($('#capability-form'), $('#capability-errors'), errors, label);
  }

  function renderCapabilityProgress(record = capabilityFromForm()) {
    const container = $('#capability-progress'); if (!container) return;
    container.replaceChildren();
    const dimensions = create('div', undefined, 'capability-dimension-grid'); appendCapabilityDimensions(dimensions, record);
    const state = derivedCapabilityState(record);
    const claimErrors = capabilityClaimErrors();
    const summary = create('p', undefined, `capability-progress-summary${claimErrors.length ? ' is-incomplete' : ''}`);
    if (claimErrors.length) {
      const missing = unique(claimErrors.map(({ control }) => fieldLabel(control)));
      summary.append(create('strong', 'Incomplete claim: '), document.createTextNode(`${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} still required before this ${stateLabel(state).toLowerCase()} claim can be saved.`));
    } else {
      summary.append(create('strong', `${stateLabel(state)}: `), document.createTextNode(capabilityStateReason(record)));
    }
    container.append(dimensions, summary);
  }

  function saveCapabilityFromForm() {
    const id = $('#capability-key').value;
    const currentStage = Math.max(1, workflowProgress.readiness || 1);
    if (!validateCapabilityClaims()) return false;
    const record = capabilityFromForm();
    record.updated = isoNow(); readiness[readinessKey(id)] = record;
    save(STORAGE_READINESS, readiness); $('#delete-capability').hidden = false; renderReadiness(); renderCapabilityProgress(record); showReadinessStage(currentStage, false);
    const state = derivedCapabilityState(record); setStatus(`${id} saved · ${stateLabel(state)}. ${capabilityStateReason(record)}`);
    return true;
  }

  function readinessPayload() {
    return { schema_version: '2.0', type: 'hecavex-attack-readiness', exported: isoNow(), framework: { name: 'MITRE ATT&CK', domain: 'Enterprise', version: catalogue.version }, metadata: readinessMeta, records: readiness };
  }

  function starterDetectionPackage(guide) {
    const technique = techniqueById(guide.technique_id);
    const testPrefix = guide.technique_id.replace(/[^A-Z0-9]/g, '');
    return {
      id: `HXD-${guide.technique_id}-STARTER`,
      technique_id: guide.technique_id,
      title: `${technique?.name || guide.technique_id} engineering starter`,
      status: 'analyst starter · requires local design and validation',
      starter: true,
      scope: {
        platforms: technique?.platforms || ['Environment specific'],
        behaviour: guide.analyst_summary,
        not_covered: ['A deployable product query', 'Proof that required telemetry exists locally', 'Validation against the organisation’s benign baseline']
      },
      hypothesis: guide.analyst_summary,
      official_detection: {
        strategy_id: 'ATT&CK CONTEXT',
        strategy_name: technique?.name || guide.technique_id,
        url: technique?.url || `https://attack.mitre.org/techniques/${guide.technique_id.replace('.', '/')}/`,
        analytic_id: 'Open technique and detection relationships',
        description: 'Use the official technique and its current detection relationships as input. The starter does not claim that a portable analytic exists.',
        log_sources: guide.telemetry.map((source, index) => ({ component_id: `LOCAL-${String(index + 1).padStart(2, '0')}`, component: `Telemetry requirement ${index + 1}`, source, channel: 'Map to local schema' }))
      },
      data_requirements: [{
        source: 'Minimum defensible evidence',
        acceptable_sensors: guide.telemetry,
        required_fields: guide.minimum_evidence,
        quality_checks: ['Confirm timestamps, identity and asset identifiers can be correlated', 'Measure field population, truncation and ingestion delay', 'Record blind spots before claiming coverage']
      }],
      analytic_logic: {
        required: guide.minimum_evidence,
        elevating_context: guide.pivots,
        lowering_context: guide.benign_overlap,
        decision: 'Translate the behaviour into the local event model, then require enough related context to distinguish the adversary-relevant claim from the documented benign overlap.'
      },
      benign_baseline: guide.benign_overlap,
      known_blind_spots: ['The listed evidence is not collected or cannot be joined', 'A product field is assumed equivalent without schema validation', 'Testing covers only a single happy path'],
      safe_validation_cases: [
        { id: `${testPrefix}-P01`, class: 'positive', title: 'Representative approved behaviour', procedure: 'Use an isolated test system or approved simulation to reproduce the smallest harmless behaviour that should satisfy the analytic hypothesis.', expected: ['Required events and fields are present', 'Correlation survives normal ingestion delay', 'The analytic result contains enough context for triage'] },
        { id: `${testPrefix}-N01`, class: 'negative', title: 'Documented benign overlap', procedure: `Exercise or replay a representative benign case such as: ${guide.benign_overlap[0] || 'approved administrative activity'}.`, expected: ['Telemetry remains available for hunting', 'The analytic does not create an unjustified high-severity result', 'Any suppression is narrow and documented'] },
        { id: `${testPrefix}-R01`, class: 'resilience', title: 'Missing or degraded context', procedure: 'Repeat the test with one expected field or related event unavailable in the validation dataset.', expected: ['The failure mode is visible', 'The result does not silently become confirmed coverage', 'The gap is assigned for remediation'] }
      ],
      acceptance_criteria: ['Required telemetry and fields are measured in the intended scope', 'Positive and benign cases behave as expected', 'An analyst can explain why the result fired', 'Ownership, review date and response path are recorded'],
      triage: guide.pivots,
      response: guide.response,
      lifecycle: { package_owner: 'Local detection team', package_status: 'starter reference', created: detectionPackages.updated, last_reviewed: detectionPackages.updated, review_due: 'Set during local implementation', attack_version: catalogue.version, technique_version: technique?.version || 'current catalogue' },
      references: [{ title: `MITRE ATT&CK ${guide.technique_id} ${technique?.name || ''}`.trim(), url: technique?.url || `https://attack.mitre.org/techniques/${guide.technique_id.replace('.', '/')}/` }]
    };
  }

  function buildEngineeringPackages() {
    const authoredIds = new Set(detectionPackages.packages.map((pkg) => pkg.technique_id));
    engineeringPackages = [...detectionPackages.packages, ...operations.guides.filter((guide) => !authoredIds.has(guide.technique_id)).map(starterDetectionPackage)];
  }

  function renderDetectionPackage() {
    const selected = $('#detection-package-select').value || engineeringPackages[0]?.id;
    const pkg = engineeringPackages.find((item) => item.id === selected);
    const container = $('#detection-package'); container.replaceChildren();
    if (!pkg) { container.append(create('p', 'No engineering package is available.', 'gap-note')); return; }
    const header = create('article', undefined, 'detection-package-head');
    const title = create('div'); title.append(create('p', `${pkg.id} · ${pkg.technique_id}`, 'eyebrow'), create('h3', pkg.title), create('p', pkg.hypothesis));
    if (pkg.starter) title.append(create('p', 'STARTER PACKAGE · COMPLETE THE DATA CONTRACT, LOGIC AND TESTS FOR YOUR ENVIRONMENT', 'starter-boundary'));
    const facts = create('dl', undefined, 'package-facts');
    [['Status', pkg.status], ['Platform', pkg.scope.platforms.join(', ')], ['ATT&CK', pkg.lifecycle.attack_version], ['Review due', pkg.lifecycle.review_due]].forEach(([term, value]) => { const fact = create('div'); fact.append(create('dt', term), create('dd', value)); facts.append(fact); });
    header.append(title, facts); container.append(header);

    const strategy = create('section', undefined, 'detection-section');
    const strategyTitle = create('div'); strategyTitle.append(create('p', 'OFFICIAL DETECTION FOUNDATION', 'eyebrow'), create('h3', `${pkg.official_detection.strategy_id} · ${pkg.official_detection.strategy_name}`), create('p', pkg.official_detection.description));
    const strategyLink = create('a', `${pkg.official_detection.analytic_id} in MITRE ATT&CK ↗`, 'button small'); strategyLink.href = pkg.official_detection.url; strategyLink.rel = 'noopener'; strategyTitle.append(strategyLink); strategy.append(strategyTitle);
    const logs = create('div', undefined, 'log-source-grid');
    pkg.official_detection.log_sources.forEach((item) => { const card = create('article'); card.append(create('p', `${item.component_id} · ${item.channel}`, 'eyebrow'), create('h4', item.component), create('p', item.source)); logs.append(card); });
    strategy.append(logs); container.append(strategy);

    const data = create('section', undefined, 'detection-section'); data.dataset.detectionStep = 'data'; data.append(create('p', 'DATA CONTRACT', 'eyebrow'), create('h3', 'Required observables and quality gates'));
    const requirements = create('div', undefined, 'data-requirements');
    pkg.data_requirements.forEach((requirement) => { const card = create('article'); card.append(create('h4', requirement.source), listBlock('Acceptable sensors', requirement.acceptable_sensors), listBlock('Required fields', requirement.required_fields), listBlock('Quality checks', requirement.quality_checks)); requirements.append(card); });
    data.append(requirements); container.append(data);

    const analytic = create('section', undefined, 'detection-section'); analytic.dataset.detectionStep = 'logic'; analytic.append(create('p', 'PRODUCT-INDEPENDENT LOGIC', 'eyebrow'), create('h3', 'Context before severity'));
    const analyticGrid = create('div', undefined, 'operational-block-grid'); analyticGrid.append(listBlock('Required', pkg.analytic_logic.required), listBlock('Elevating context', pkg.analytic_logic.elevating_context), listBlock('Lowering context', pkg.analytic_logic.lowering_context), listBlock('Known blind spots', pkg.known_blind_spots)); analytic.append(analyticGrid, create('p', pkg.analytic_logic.decision, 'evidence-note')); container.append(analytic);

    const validation = create('section', undefined, 'detection-section'); validation.dataset.detectionStep = 'validation'; validation.append(create('p', 'VALIDATION PLAN', 'eyebrow'), create('h3', 'Positive, negative and resilience tests'));
    const cases = create('div', undefined, 'validation-grid');
    pkg.safe_validation_cases.forEach((test) => { const card = create('article', undefined, `validation-case case-${test.class}`); card.append(create('p', `${test.id} · ${test.class}`, 'eyebrow'), create('h4', test.title), create('p', test.procedure), listBlock('Expected evidence', test.expected)); cases.append(card); });
    validation.append(cases, listBlock('Acceptance criteria', pkg.acceptance_criteria)); container.append(validation);

    const handoff = create('section', undefined, 'detection-section detection-handoff'); handoff.dataset.detectionStep = 'handoff'; handoff.append(create('p', 'SOC HANDOFF', 'eyebrow'), create('h3', 'The alert is not the finish line'));
    const handoffGrid = create('div', undefined, 'operational-block-grid'); handoffGrid.append(listBlock('Triage', pkg.triage), listBlock('Response', pkg.response), listBlock('Benign baseline', pkg.benign_baseline), listBlock('Not covered', pkg.scope.not_covered)); handoff.append(handoffGrid); container.append(handoff);

    const refs = create('div', undefined, 'source-links');
    pkg.references.forEach((reference) => { const link = create('a'); link.href = reference.url; link.rel = 'noopener'; link.append(create('strong', reference.title), create('span', 'PRIMARY OR PROJECT SOURCE ↗')); refs.append(link); });
    container.append(refs); setStatus(`${pkg.id} detection package active`);
  }

  function parseTechnique(value) {
    const id = value.match(/T\d{4}(?:\.\d{3})?/i)?.[0].toUpperCase();
    if (id && techniqueById(id)) return techniqueById(id);
    const normalised = normalise(value);
    return catalogue.techniques.find((item) => normalise(item.name) === normalised) || null;
  }

  function renderIncident() {
    const container = $('#incident-timeline');
    container.replaceChildren();
    syncIncidentParentOptions();
    if (!incident.length) {
      const empty = create('div', undefined, 'empty'); empty.append(create('strong', 'No local case entries.'), create('span', 'Add evidence even when no technique can yet be assigned.')); container.append(empty); return;
    }
    [...incident].sort((a, b) => String(a.time).localeCompare(String(b.time))).forEach((entry) => {
      const article = create('article', undefined, `incident-entry status-${entry.status}`);
      const marker = create('span', entry.status.toUpperCase(), 'incident-status');
      const content = create('div');
      content.append(create('p', `${entry.time || 'TIME UNKNOWN'} · ${entry.asset || 'ASSET UNKNOWN'}`, 'eyebrow'), create('h3', entry.observation));
      if (entry.technique_id) {
        const technique = techniqueById(entry.technique_id);
        const mapping = create('p', undefined, 'incident-mapping'); mapping.append(techniqueLink(entry.technique_id, entry.technique_id), document.createTextNode(` ${technique?.name || ''}`)); content.append(mapping);
      } else content.append(create('p', 'No ATT&CK mapping assigned', 'incident-mapping unmapped'));
      if (entry.parent_id) {
        const parent = incident.find((item) => item.id === entry.parent_id);
        if (parent) content.append(create('p', `${String(entry.relation || 'follows').toUpperCase()} · ${parent.observation}`, 'incident-relation'));
      }
      if (entry.note) content.append(create('p', entry.note));
      const remove = create('button', 'Remove', 'text-button'); remove.type = 'button'; remove.addEventListener('click', () => {
        incident = incident.filter((item) => item.id !== entry.id).map((item) => item.parent_id === entry.id ? { ...item, parent_id: '', relation: '' } : item);
        save(STORAGE_INCIDENT, incident);
        renderIncident();
      });
      article.append(marker, content, remove); container.append(article);
    });
    setStatus(`${incident.length} local incident entries`);
  }

  function syncIncidentParentOptions() {
    const select = $('#incident-parent'); if (!select) return;
    const current = select.value; select.replaceChildren();
    const none = create('option', 'No relationship'); none.value = ''; select.append(none);
    incident.forEach((entry, index) => { const option = create('option', `${index + 1} · ${entry.observation.slice(0, 70)}`); option.value = entry.id; select.append(option); });
    if ([...select.options].some((option) => option.value === current)) select.value = current;
  }

  function incidentPayload() {
    return { schema_version: '2.0', type: 'hecavex-attack-incident', exported: isoNow(), framework: { name: 'MITRE ATT&CK', domain: 'Enterprise', version: catalogue.version }, boundary: operations.boundary, metadata: incidentMeta, entries: incident };
  }

  function attackFlowPayload() {
    const eligible = incident.filter((entry) => ['confirmed', 'suspected'].includes(entry.status));
    if (!eligible.length) throw new Error('Attack Flow export requires at least one confirmed or suspected action.');
    const created = isoNow();
    const extension = 'extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4';
    const actionIds = new Map(eligible.map((entry) => [entry.id, `attack-action--${uuid()}`]));
    const incoming = new Set();
    const effectRefs = new Map(eligible.map((entry) => [entry.id, []]));
    eligible.forEach((entry) => {
      if (!entry.parent_id || !actionIds.has(entry.parent_id)) return;
      if (entry.relation === 'enables') { effectRefs.get(entry.id).push(actionIds.get(entry.parent_id)); incoming.add(entry.parent_id); }
      else if (entry.relation !== 'parallel-to') { effectRefs.get(entry.parent_id).push(actionIds.get(entry.id)); incoming.add(entry.id); }
    });
    const actions = eligible.map((entry) => {
      const technique = techniqueById(entry.technique_id);
      const action = { type: 'attack-action', spec_version: '2.1', id: actionIds.get(entry.id), created, modified: created, name: entry.observation.slice(0, 120), description: entry.observation, confidence: entry.status === 'confirmed' ? 90 : 50, extensions: { [extension]: { extension_type: 'new-sdo' } } };
      if (entry.technique_id) { action.technique_id = entry.technique_id; action.external_references = [{ source_name: 'mitre-attack', external_id: entry.technique_id, url: technique?.url || `https://attack.mitre.org/techniques/${entry.technique_id.replace('.', '/')}/` }]; }
      if (effectRefs.get(entry.id).length) action.effect_refs = effectRefs.get(entry.id);
      return action;
    });
    const flowId = `attack-flow--${uuid()}`;
    const flow = { type: 'attack-flow', spec_version: '2.1', id: flowId, created, modified: created, name: incidentMeta.case_name || 'HECAVEX incident flow', description: `Exported from HECAVEX Labs. ${operations.boundary}`, scope: 'incident', start_refs: eligible.filter((entry) => !incoming.has(entry.id)).map((entry) => actionIds.get(entry.id)), extensions: { [extension]: { extension_type: 'new-sdo' } } };
    return { type: 'bundle', id: `bundle--${uuid()}`, objects: [flow, ...actions] };
  }

  function renderPhishing() {
    const flow = $('#phishing-flow');
    if (flow.childElementCount) return;
    const stages = unique(operations.phishing_flow.nodes.map((node) => node.stage));
    stages.forEach((stage) => {
      const column = create('section', undefined, 'phishing-stage');
      column.append(create('h3', stage));
      operations.phishing_flow.nodes.filter((node) => node.stage === stage).forEach((node) => {
        const card = create('button', undefined, 'phishing-node'); card.type = 'button'; card.dataset.node = node.id;
        card.append(create('span', node.techniques.join(' · '), 'meta'), create('strong', node.label), create('span', node.question));
        card.addEventListener('click', () => showPhishingNode(node.id)); column.append(card);
      });
      flow.append(column);
    });
    showPhishingNode('lure');
  }

  function showPhishingNode(id) {
    const node = operations.phishing_flow.nodes.find((item) => item.id === id);
    $$('.phishing-node').forEach((button) => button.classList.toggle('active', button.dataset.node === id));
    const detail = $('#phishing-detail'); detail.replaceChildren();
    detail.append(create('p', node.stage.toUpperCase(), 'eyebrow'), create('h3', node.label), create('p', node.question, 'phishing-question'), listBlock('Collect before mapping', node.collect));
    const techniques = create('div', undefined, 'phishing-techniques');
    techniques.append(create('h4', 'Candidate techniques'));
    node.techniques.forEach((techniqueId) => { const technique = techniqueById(techniqueId); techniques.append(techniqueLink(techniqueId, `${techniqueId} · ${technique?.name || ''}`)); });
    detail.append(techniques);
    if (node.next.length) {
      const next = create('div', undefined, 'phishing-next'); next.append(create('h4', 'Continue only if evidence supports it'));
      node.next.forEach((nextId) => { const target = operations.phishing_flow.nodes.find((item) => item.id === nextId); const button = create('button', `${target.label} →`, 'text-button'); button.type = 'button'; button.addEventListener('click', () => showPhishingNode(nextId)); next.append(button); });
      detail.append(next);
    }
  }

  function filteredReference() {
    const query = normalise($('#reference-search').value);
    const tactic = $('#reference-tactic').value;
    const platform = $('#reference-platform').value;
    const type = $('#reference-type').value;
    return catalogue.techniques.filter((technique) => {
      const related = Object.values({ groups: technique.groups, campaigns: technique.campaigns, software: technique.software }).flat().flatMap((item) => [item.id, item.name]);
      const haystack = normalise(`${technique.id} ${technique.name} ${technique.description} ${technique.platforms.join(' ')} ${related.join(' ')}`);
      return (!query || haystack.includes(query)) && (tactic === 'all' || technique.tactics.includes(tactic)) && (platform === 'all' || technique.platforms.includes(platform)) && (type === 'all' || (type === 'subtechnique') === technique.subtechnique);
    });
  }

  function renderReference(resetLimit = false) {
    if (resetLimit) referenceLimit = 80;
    const records = filteredReference();
    $('#reference-count').textContent = `${records.length} techniques · showing ${Math.min(referenceLimit, records.length)}`;
    const container = $('#reference-results'); container.replaceChildren();
    records.slice(0, referenceLimit).forEach((technique) => {
      const article = create('article', undefined, `reference-card${technique.subtechnique ? ' subtechnique' : ''}`);
      const heading = create('header'); const title = create('div'); title.append(create('p', `${technique.id} · ${technique.tactics.join(' · ')}`, 'eyebrow'), create('h3', technique.name));
      heading.append(title, create('span', technique.subtechnique ? 'SUB-TECHNIQUE' : 'TECHNIQUE', 'candidate-badge muted'));
      const description = technique.description.length > 280 ? `${technique.description.slice(0, 277)}…` : technique.description;
      const relations = create('p', `${technique.groups.length} groups · ${technique.campaigns.length} campaigns · ${technique.software.length} software · ${technique.detections.length} detection strategies`, 'meta');
      article.append(heading, create('p', description), relations, techniqueLink(technique.id, 'Open operational context')); container.append(article);
    });
    $('#reference-more').hidden = records.length <= referenceLimit;
    setStatus(`${records.length} reference techniques`);
  }

  function renderGovernance() {
    const container = $('#governance-summary'); container.replaceChildren();
    const head = create('div', undefined, 'governance-head'); head.append(create('div', undefined));
    head.firstChild.append(create('p', 'LIFECYCLE GOVERNANCE', 'eyebrow'), create('h3', `${governance.framework.name} ${governance.framework.version}`), create('p', 'Curated layers have independent scope, owners and review clocks. Framework refreshes do not silently turn reference data into HECAVEX findings.'));
    const history = create('details'); const summary = create('summary', 'Visible change history'); history.append(summary);
    const historyList = create('ul'); governance.change_history.forEach((entry) => historyList.append(create('li', `${entry.date} · ${entry.version} · ${entry.summary}`))); history.append(historyList); head.append(history); container.append(head);
    const layers = create('div', undefined, 'governance-layers');
    governance.curated_layers.forEach((layer) => {
      const card = create('article');
      const review = /^\d{4}-\d{2}-\d{2}$/.test(layer.last_reviewed) ? `reviewed ${layer.last_reviewed}` : layer.last_reviewed;
      card.append(create('p', `${layer.records} RECORDS · V${layer.version}`, 'eyebrow'), create('h4', layer.label), create('p', layer.scope), create('p', `${layer.owner} · ${review} · due ${layer.review_due}`, 'meta'));
      layers.append(card);
    });
    container.append(layers);
  }

  function relationshipSection(title, items) {
    const section = create('section'); section.append(create('h3', `${title} (${items.length})`));
    if (!items.length) section.append(create('p', 'No active relationship in this ATT&CK release.', 'meta'));
    else {
      const list = create('ul');
      items.slice(0, 30).forEach((item) => { const row = create('li'); const link = create('a', [item.id, item.name].filter(Boolean).join(' · ')); link.href = item.url; link.rel = 'noopener'; row.append(link); list.append(row); });
      section.append(list);
      if (items.length > 30) section.append(create('p', `${items.length - 30} additional relationships are available in the source dataset.`, 'meta'));
    }
    return section;
  }

  function openTechnique(id) {
    const technique = techniqueById(id);
    if (!technique) return;
    if (activeWorkflow === 'observation' || activeWorkflow === 'intelligence') setJourneyProgress(2);
    if (activeWorkflow === 'reference') setJourneyProgress(1);
    $('#evidence-id').textContent = `${technique.id} · ${technique.tactics.join(' · ')}`;
    $('#evidence-title').textContent = technique.name;
    const detail = $('#evidence-detail'); detail.replaceChildren();
    const boundary = create('div', undefined, 'technique-boundary');
    boundary.append(create('strong', guideById(id) ? 'Operational guide available' : 'Reference object only'), create('span', guideById(id) ? 'The guide below adds evidence requirements, telemetry and benign overlap. It still requires analyst confirmation.' : 'No HECAVEX operational guide has been curated for this technique. Official ATT&CK relationships are context, not an incident finding.'));
    detail.append(boundary);
    const facts = create('dl', undefined, 'evidence-facts');
    [['Type', technique.subtechnique ? 'Sub-technique' : 'Parent technique'], ['Parent', technique.parent ? `${technique.parent.id} ${technique.parent.name}` : 'None'], ['Platforms', technique.platforms.join(', ') || 'Not specified'], ['Object version', technique.version], ['Modified', technique.modified]].forEach(([term, value]) => { const group = create('div'); group.append(create('dt', term), create('dd', value)); facts.append(group); });
    detail.append(facts, create('p', technique.description, 'evidence-note'));
    const guide = guideById(id);
    if (guide) {
      const operational = create('section', undefined, 'dialog-operational');
      operational.append(create('p', 'HECAVEX ANALYST GUIDE', 'eyebrow'), create('h3', 'Use it only when the evidence supports it'), create('p', guide.analyst_summary));
      const grid = create('div', undefined, 'operational-block-grid'); grid.append(listBlock('Minimum evidence', guide.minimum_evidence), listBlock('Telemetry', guide.telemetry), listBlock('Benign overlap', guide.benign_overlap), listBlock('Investigation pivots', guide.pivots), listBlock('Response considerations', guide.response)); operational.append(grid); detail.append(operational);
    }
    const packageRecord = detectionByTechnique(id);
    if (packageRecord) {
      const packageSection = create('section', undefined, 'dialog-operational detection-available'); packageSection.append(create('p', 'DETECTION ENGINEERING PACKAGE', 'eyebrow'), create('h3', packageRecord.title), create('p', packageRecord.hypothesis));
      const openPackage = create('button', `Open ${packageRecord.id}`, 'button small'); openPackage.type = 'button'; openPackage.addEventListener('click', () => { $('#evidence-dialog').close(); $('#detection-package-select').value = packageRecord.id; switchWorkflow('detection'); }); packageSection.append(openPackage); detail.append(packageSection);
    }
    const reviewed = actorEvidenceFor(id);
    if (reviewed.length) {
      const section = create('section', undefined, 'dialog-reviewed'); section.append(create('p', 'HECAVEX REVIEWED INTELLIGENCE', 'eyebrow'), create('h3', `${reviewed.length} source-linked actor relationship${reviewed.length === 1 ? '' : 's'}`));
      reviewed.forEach(({ actor, item }) => { const claim = create('article', undefined, 'procedure-claim'); claim.append(create('h4', `${actor.name} · ${item.campaign}`), create('p', item.notes), create('p', `${item.status} · ${item.confidence} confidence · ${item.first_observed} → ${item.last_observed}`, 'meta')); const lineage = create('p', `PUBLIC REPORTING · ${item.sources.length} SOURCE${item.sources.length === 1 ? '' : 'S'} · REVIEWED ${evidence.updated}`, 'meta'); claim.append(lineage); item.sources.forEach((source) => { const link = create('a', `${source.publisher} · ${source.published} ↗`); link.href = source.url; link.rel = 'noopener'; claim.append(link); }); section.append(claim); }); detail.append(section);
    }
    const relationships = create('div', undefined, 'catalogue-relations');
    relationships.append(relationshipSection('Groups', technique.groups), relationshipSection('Campaigns', technique.campaigns), relationshipSection('Software', technique.software), relationshipSection('Mitigations', technique.mitigations), relationshipSection('Detection strategies', technique.detections)); detail.append(relationships);
    const official = create('a', `Open ${technique.id} in MITRE ATT&CK ↗`, 'button small'); official.href = technique.url; official.rel = 'noopener'; detail.append(official);
    updateUrl({ technique: id });
    if (!$('#evidence-dialog').open) $('#evidence-dialog').showModal();
  }

  function exportReferenceCsv() {
    const quote = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;
    const columns = ['technique_id', 'technique', 'tactics', 'platforms', 'type', 'groups', 'campaigns', 'software', 'mitigations', 'detections', 'url'];
    const rows = filteredReference().map((item) => [item.id, item.name, item.tactics.join('|'), item.platforms.join('|'), item.subtechnique ? 'sub-technique' : 'parent', item.groups.length, item.campaigns.length, item.software.length, item.mitigations.length, item.detections.length, item.url].map(quote).join(','));
    download('hecavex-attack-reference.csv', 'text/csv;charset=utf-8', [columns.join(','), ...rows].join('\n'));
  }

  function exportNavigator() {
    const records = filteredReference();
    const layer = {
      name: 'HECAVEX filtered Enterprise ATT&CK reference',
      versions: { attack: catalogue.version, navigator: '5.2.0', layer: '4.5' },
      domain: 'enterprise-attack',
      description: 'Reference selection exported from HECAVEX Labs. Inclusion is not a finding, priority or coverage assertion.',
      sorting: 0,
      layout: { layout: 'side', showID: true, showName: true, showAggregateScores: false, countUnscored: false, aggregateFunction: 'average', expandedSubtechniques: 'annotated' },
      hideDisabled: false,
      techniques: records.map((item) => ({ techniqueID: item.id, color: '#7fa5cf', comment: 'Reference selection only.', links: [{ label: 'MITRE ATT&CK', url: item.url }] }))
    };
    download('hecavex-attack-reference-navigator.json', 'application/json', `${JSON.stringify(layer, null, 2)}\n`);
  }

  function renderSources() {
    const container = $('#operations-sources');
    operations.sources.forEach((source) => { const link = create('a'); link.href = source.url; link.rel = 'noopener'; link.append(create('strong', source.title), create('span', `${source.publisher} ↗`)); container.append(link); });
  }

  function bindEvents() {
    bindValidationCleanup($('#observation-form'), $('#observation-errors'));
    bindValidationCleanup($('#mapping-validation-form'), $('#mapping-errors'));
    bindValidationCleanup($('#capability-form'), $('#capability-errors'));
    bindValidationCleanup($('#incident-form'), $('#incident-errors'));
    $$('[data-open-workflow]').forEach((button) => button.addEventListener('click', (event) => { event.preventDefault(); switchWorkflow(button.dataset.openWorkflow); }));
    $('#workspace-mode').addEventListener('change', () => switchWorkflow($('#workspace-mode').value, false));
    $('#observation-form').addEventListener('submit', (event) => { event.preventDefault(); if (!validateStandardForm(event.currentTarget, $('#observation-errors'))) return; renderObservation($('#observation-input').value.trim()); });
    $$('.quick-observations button').forEach((button) => button.addEventListener('click', () => { $('#observation-input').value = button.dataset.example; clearFormErrors($('#observation-form'), $('#observation-errors')); renderObservation(button.dataset.example); }));
    $('#mapping-validation-form').addEventListener('submit', (event) => { event.preventDefault(); if (!validateStandardForm(event.currentTarget, $('#mapping-errors'))) return; saveMappingAssessment(); });
    $$('[data-stage-back]').forEach((button) => button.addEventListener('click', () => { const [workflow, stage] = button.dataset.stageBack.split(':'); if (workflow === 'observation') showObservationStage(Number(stage)); }));
    $('#group-search').addEventListener('input', () => renderGroupCatalogue(true));
    $('#group-sort').addEventListener('change', () => renderGroupCatalogue(true));
    $('#group-more').addEventListener('click', () => { groupLimit += 36; renderGroupCatalogue(); });
    $('.reviewed-intelligence').addEventListener('toggle', () => { if (activeWorkflow === 'intelligence' && $('.reviewed-intelligence').open) setJourneyProgress(2); });
    $('#intel-actor').addEventListener('change', () => { renderIntelligence(); updateUrl({ actor: $('#intel-actor').value }); });
    $('#intel-platform').addEventListener('change', renderIntelligence);
    $('#readiness-environment').addEventListener('change', () => { activeCapabilityId = ''; renderReadiness(); showReadinessStage(1); });
    $('#readiness-focus').addEventListener('change', () => { activeCapabilityId = ''; renderReadiness(); showReadinessStage(1); });
    [['#readiness-workspace', 'workspace'], ['#readiness-scope', 'scope'], ['#readiness-owner', 'owner']].forEach(([selector, field]) => $(selector).addEventListener('change', () => { readinessMeta[field] = $(selector).value.trim(); save(STORAGE_READINESS_META, readinessMeta); }));
    $('#export-readiness').addEventListener('click', () => download('hecavex-attack-readiness.json', 'application/json', `${JSON.stringify(readinessPayload(), null, 2)}\n`));
    $('#reset-readiness').addEventListener('click', () => {
      const prefix = `${$('#readiness-environment').value}:${$('#readiness-focus').value}:`;
      if (window.confirm('Reset capability records in the current platform and threat-focus view?')) { Object.keys(readiness).filter((key) => key.startsWith(prefix)).forEach((key) => delete readiness[key]); save(STORAGE_READINESS, readiness); renderReadiness(); }
    });
    $('#capability-form').addEventListener('submit', (event) => { event.preventDefault(); saveCapabilityFromForm(); });
    $('#capability-form').addEventListener('input', () => activeCapabilityId && renderCapabilityProgress());
    $('#capability-form').addEventListener('change', () => activeCapabilityId && renderCapabilityProgress());
    $('#close-capability-editor').addEventListener('click', () => { activeCapabilityId = ''; showReadinessStage(1); });
    $('.capability-close').addEventListener('click', () => $('#capability-dialog').close());
    $('#capability-dialog').addEventListener('click', (event) => { if (event.target === $('#capability-dialog')) $('#capability-dialog').close(); });
    $('#delete-capability').addEventListener('click', () => { const id = $('#capability-key').value; delete readiness[readinessKey(id)]; save(STORAGE_READINESS, readiness); activeCapabilityId = ''; renderReadiness(); showReadinessStage(1); });
    $('#detection-package-select').addEventListener('change', () => { workflowProgress.detection = 0; renderDetectionPackage(); renderJourneySteps(0); });
    $('#export-detection-package').addEventListener('click', () => { const pkg = engineeringPackages.find((item) => item.id === $('#detection-package-select').value); if (pkg) download(`${pkg.id}.json`, 'application/json', `${JSON.stringify({ schema_version: detectionPackages.schema_version, boundary: pkg.starter ? 'Analyst starter only. Complete and validate locally before operational use.' : detectionPackages.boundary, package: pkg }, null, 2)}\n`); });
    $('#open-detection-technique').addEventListener('click', () => { const pkg = engineeringPackages.find((item) => item.id === $('#detection-package-select').value); if (pkg) openTechnique(pkg.technique_id); });
    [['#incident-case', 'case_name'], ['#incident-analyst', 'analyst']].forEach(([selector, field]) => $(selector).addEventListener('change', () => { incidentMeta[field] = $(selector).value.trim(); save(STORAGE_INCIDENT_META, incidentMeta); }));
    $('#incident-form').addEventListener('submit', (event) => {
      event.preventDefault(); if (!validateStandardForm(event.currentTarget, $('#incident-errors'))) return; const technique = parseTechnique($('#incident-technique').value);
      incident.push({ id: uuid(), time: $('#incident-time').value, timezone: incidentMeta.timezone, asset: $('#incident-asset').value.trim(), observation: $('#incident-observation').value.trim(), technique_id: technique?.id || '', status: $('#incident-status').value, note: $('#incident-note').value.trim(), parent_id: $('#incident-parent').value, relation: $('#incident-parent').value ? $('#incident-relation').value : '' });
      save(STORAGE_INCIDENT, incident); clearFormErrors(event.currentTarget, $('#incident-errors')); event.currentTarget.reset(); $('#incident-time').value = localDateTimeValue(); renderIncident();
    });
    $('#export-incident').addEventListener('click', () => download('hecavex-incident-attack-map.json', 'application/json', `${JSON.stringify(incidentPayload(), null, 2)}\n`));
    $('#export-attack-flow').addEventListener('click', () => { try { download('hecavex-incident-attack-flow.json', 'application/json', `${JSON.stringify(attackFlowPayload(), null, 2)}\n`); } catch (error) { window.alert(error.message); } });
    $('#clear-incident').addEventListener('click', () => { if (window.confirm('Clear this browser-local incident timeline?')) { incident = []; save(STORAGE_INCIDENT, incident); renderIncident(); } });
    $('#clear-local-workspaces').addEventListener('click', () => {
      if (!window.confirm('Clear every browser-local ATT&CK workspace on this device? Export anything you need first.')) return;
      try {
        LOCAL_WORKSPACE_KEYS.forEach((key) => localStorage.removeItem(key));
        window.location.reload();
      } catch (error) { showStorageWarning(error); }
    });
    [$('#reference-search'), $('#reference-tactic'), $('#reference-platform'), $('#reference-type')].forEach((control) => control.addEventListener(control.tagName === 'INPUT' ? 'input' : 'change', () => renderReference(true)));
    $('#reference-more').addEventListener('click', () => { referenceLimit += 80; renderReference(); });
    $('#export-csv').addEventListener('click', exportReferenceCsv); $('#export-navigator').addEventListener('click', exportNavigator);
    const globalSearch = $('#global-q');
    globalSearch?.closest('form')?.addEventListener('submit', (event) => {
      event.preventDefault();
      const query = globalSearch.value.trim();
      const actorMatch = query && catalogue.groups.some((group) => normalise(`${group.id} ${group.name} ${group.aliases.join(' ')}`).includes(normalise(query)));
      if (actorMatch) { $('#group-search').value = query; switchWorkflow('intelligence'); renderGroupCatalogue(true); }
      else { $('#reference-search').value = query; switchWorkflow('reference'); renderReference(true); }
    });
    $('.dialog-close').addEventListener('click', () => $('#evidence-dialog').close());
    $('#evidence-dialog').addEventListener('click', (event) => { if (event.target === $('#evidence-dialog')) $('#evidence-dialog').close(); });
    $('#evidence-dialog').addEventListener('close', () => activeWorkflow === 'intelligence' && activeGroupId ? updateUrl({ group: activeGroupId }) : updateUrl());
  }

  function populateControls() {
    const platforms = unique(catalogue.techniques.flatMap((technique) => technique.platforms)).sort();
    platforms.forEach((platform) => {
      ['#intel-platform', '#reference-platform'].forEach((selector) => { const option = create('option', platform); option.value = platform; $(selector).append(option); });
      const readinessOption = create('option', platform); readinessOption.value = platform; $('#readiness-environment').append(readinessOption);
    });
    const allEnvironment = create('option', 'All platforms'); allEnvironment.value = 'all'; $('#readiness-environment').prepend(allEnvironment); $('#readiness-environment').value = platforms.includes('Windows') ? 'Windows' : 'all';
    const reviewedSelect = $('#intel-actor'); reviewedSelect.replaceChildren();
    evidence.actors.forEach((actor) => {
      const option = create('option', actor.name); option.value = actor.id; reviewedSelect.append(option);
      const readinessOption = create('option', `${actor.name} · HECAVEX-reviewed evidence`); readinessOption.value = actor.id; $('#readiness-focus').append(readinessOption);
    });
    if (evidence.actors.length > 1) { const compare = create('option', `Compare ${evidence.actors.map((actor) => actor.name).join(' and ')}`); compare.value = 'compare'; reviewedSelect.append(compare); }
    $('#reviewed-profile-count').textContent = `${evidence.actors.length} profile${evidence.actors.length === 1 ? '' : 's'}`;
    catalogue.tactics.forEach((tactic) => { const option = create('option', tactic.name); option.value = tactic.name; $('#reference-tactic').append(option); });
    catalogue.techniques.forEach((technique) => { const option = create('option'); option.value = `${technique.id} — ${technique.name}`; $('#technique-options').append(option); });
    engineeringPackages.forEach((pkg) => { const option = create('option', `${pkg.starter ? 'ENGINEERING CANDIDATE' : 'VALIDATION-READY'} · ${pkg.technique_id} · ${pkg.title}`); option.value = pkg.id; $('#detection-package-select').append(option); });
  }

  function populateWorkspaceMeta() {
    $('#readiness-workspace').value = String(readinessMeta.workspace || 'Local capability review').slice(0, 80);
    $('#readiness-scope').value = String(readinessMeta.scope || '').slice(0, 120);
    $('#readiness-owner').value = String(readinessMeta.owner || '').slice(0, 120);
    $('#incident-case').value = String(incidentMeta.case_name || 'Local ATT&CK case').slice(0, 100);
    $('#incident-analyst').value = String(incidentMeta.analyst || '').slice(0, 120);
    $('#incident-timezone').value = String(incidentMeta.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC').slice(0, 100);
  }

  function restoreObservationWorkspace() {
    if (!currentObservation) return;
    const restoredAssessment = mappingAssessment;
    $('#observation-input').value = currentObservation;
    renderObservation(currentObservation, false, true);
    if (restoredAssessment && restoredAssessment.observation === currentObservation && techniqueById(restoredAssessment.technique_id)) {
      mappingAssessment = restoredAssessment;
      populateMappingCandidates(restoredAssessment.technique_id);
      $('#mapping-status').value = restoredAssessment.status || 'plausible';
      $('#mapping-confidence').value = restoredAssessment.confidence || 'low';
      $('#mapping-evidence').value = restoredAssessment.evidence || '';
      $('#mapping-gaps').value = restoredAssessment.gaps || '';
      $('#mapping-alternative').value = restoredAssessment.alternative || '';
      renderMappingOutput();
      workflowProgress.observation = 3;
    } else workflowProgress.observation = 1;
  }

  async function initialise() {
    try {
      const responses = await Promise.all(['/data/attack/catalogue/enterprise.json', '/data/attack/intelligence/official-actor-procedures.json', '/data/attack/intelligence/reviewed-evidence.json', '/data/attack/operations/guides.json', '/data/attack/detections/packages.json', '/data/attack/governance/governance.json'].map((url) => fetch(`${url}?v=${DATA_VERSION}`, { credentials: 'same-origin' })));
      if (responses.some((response) => !response.ok)) throw new Error(`Dataset request failed: ${responses.map((response) => response.status).join(', ')}`);
      [catalogue, officialActorProcedures, evidence, operations, detectionPackages, governance] = await Promise.all(responses.map((response) => response.json()));
      const proceduresByGroup = new Map(officialActorProcedures.groups.map((group) => [group.id, group.procedures]));
      catalogue.groups.forEach((group) => { group.procedures = proceduresByGroup.get(group.id) || []; });
      buildEngineeringPackages();
      $('#catalog-total').textContent = String(catalogue.techniques.length); $('#group-total').textContent = String(catalogue.groups.length); $('#procedure-total').textContent = catalogue.groups.reduce((total, group) => total + (group.procedures?.length || 0), 0).toLocaleString('en-US'); $('#guide-total').textContent = String(operations.guides.length); $('#package-total').textContent = String(detectionPackages.packages.length); $('#reviewed-total').textContent = String(evidence.actors.length); $('#mitre-notice').textContent = catalogue.notice;
      populateControls(); populateWorkspaceMeta(); prepareCapabilityEditor(); restoreObservationWorkspace(); renderSources(); renderGovernance(); bindEvents(); $('#incident-time').value = localDateTimeValue();
      const params = new URLSearchParams(location.search); let workflow = params.get('workflow') || 'observation';
      if (params.get('actor')) { const validActorIds = [...evidence.actors.map((actor) => actor.id), 'compare']; workflow = 'intelligence'; $('#intel-actor').value = validActorIds.includes(params.get('actor')) ? params.get('actor') : evidence.actors[0]?.id || ''; }
      if (params.get('group')) workflow = 'intelligence';
      switchWorkflow(workflow, false);
      if (params.get('actor')) { $('.reviewed-intelligence').open = true; setJourneyProgress(2); updateUrl({ actor: $('#intel-actor').value }); }
      if (params.get('technique')) openTechnique(params.get('technique').toUpperCase());
      else if (params.get('group')) openGroup(params.get('group').toUpperCase());
      $('#workspace-mode').disabled = false;
    } catch (error) {
      setStatus('Workbench data unavailable');
      const boundary = create('div', undefined, 'result-boundary warning'); boundary.append(create('strong', 'The workbench could not load its local datasets.'), create('span', 'Use the source-data links below or report the problem to HECAVEX.')); $('#observation-results').replaceChildren(boundary); console.error(error);
    }
  }

  initialise();
})();
