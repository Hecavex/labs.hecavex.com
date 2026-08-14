(() => {
  const answers = {};
  const questions = [...document.querySelectorAll('[data-question]')];
  const awareAt = document.querySelector('#aware-at');
  const caseReference = document.querySelector('#case-reference');
  const title = document.querySelector('#result-title');
  const badge = document.querySelector('#result-badge');
  const body = document.querySelector('#result-body');
  let currentOutcome = {};

  const create = (name, text, className) => {
    const node = document.createElement(name);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };

  function awarenessDate() {
    if (!awareAt.value) return null;
    const parsed = new Date(`${awareAt.value}:00Z`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function deadline(hours) {
    const date = awarenessDate();
    if (!date) return null;
    date.setUTCHours(date.getUTCHours() + hours);
    return date.toISOString().replace('.000Z', 'Z');
  }

  function setStatus(statusTitle, statusLabel, statusClass) {
    title.textContent = statusTitle;
    badge.textContent = statusLabel;
    badge.className = `badge ${statusClass}`;
  }

  function addParagraph(text) { body.append(create('p', text)); }

  function addDeadlines() {
    const grid = create('div', undefined, 'deadline-grid');
    const values = [
      ['24-hour ceiling', deadline(24) || 'Set awareness time'],
      ['72-hour ceiling', deadline(72) || 'Set awareness time']
    ];
    values.forEach(([label, value]) => {
      const card = create('div', undefined, 'deadline');
      card.append(create('strong', value), create('span', label));
      grid.append(card);
    });
    body.append(grid);
  }

  function addActions(actions) {
    const list = create('ol', undefined, 'action-list');
    actions.forEach((action) => list.append(create('li', action)));
    body.append(list);
  }

  function render() {
    body.replaceChildren();
    const unresolved = questions.filter((question) => !answers[question.dataset.question]).map((question) => question.dataset.question);
    const tracks = [];
    if (answers.exploitation === 'yes') tracks.push('actively exploited vulnerability');
    if (answers['severe-data'] === 'yes' || answers['severe-code'] === 'yes') tracks.push('severe incident');

    currentOutcome = {
      generated_at: new Date().toISOString(),
      case_reference: caseReference.value || null,
      awareness_utc: awarenessDate()?.toISOString() || null,
      answers: { ...answers },
      unresolved,
      tracks,
      indicative_deadlines: { early_warning_24h: deadline(24), notification_72h: deadline(72) },
      disclaimer: 'Preparation aid only. Not a legal determination.'
    };

    if (unresolved.length) {
      setStatus('Classification incomplete', `${unresolved.length} unresolved`, 'derived');
      addParagraph(`Resolve: ${unresolved.join(', ')}. Preserve the awareness time and the evidence used for each answer.`);
      currentOutcome.status = 'incomplete';
      return;
    }

    if (answers.role === 'no' || answers.market === 'no') {
      setStatus('Possible scope exclusion', 'validate scope', 'derived');
      addParagraph('At least one scope answer is No. Document the product, operator role, market placement and legal basis before treating the reporting duty as excluded.');
      addActions(['Record the scope rationale and evidence.', 'Obtain legal validation.', 'Reassess immediately if product or role facts change.']);
      currentOutcome.status = 'possible-scope-exclusion';
      return;
    }

    if (answers.role === 'unknown' || answers.market === 'unknown') {
      setStatus('Scope requires escalation', 'scope unknown', 'derived');
      addParagraph('The trigger cannot be closed while operator role or product scope remains unknown.');
      addActions(['Assign ownership for the scope decision.', 'Preserve the awareness record while scope is resolved.', 'Do not wait for perfect facts before preparing a possible early warning.']);
      currentOutcome.status = 'scope-unknown';
      return;
    }

    const triggerUnknown = [answers.exploitation, answers['severe-data'], answers['severe-code']].includes('unknown');
    if (!tracks.length && triggerUnknown) {
      setStatus('Trigger evidence gap', 'investigate now', 'derived');
      addParagraph('No trigger is confirmed, but one or more Article 14 criteria remain unknown. Treat each unknown as a time-sensitive evidence task.');
      addActions(['Define what evidence would resolve each unknown.', 'Assign an owner and next update time.', 'Preserve logs, product telemetry and the decision record.']);
      currentOutcome.status = 'trigger-unknown';
      return;
    }

    if (!tracks.length) {
      setStatus('No trigger identified', 'document rationale', 'observed');
      addParagraph('These answers do not identify either Article 14 reporting track. This is not a legal safe harbour. Preserve the rationale and reassess when facts change.');
      currentOutcome.status = 'no-trigger-identified';
      return;
    }

    setStatus('Prepare Article 14 workstreams', `${tracks.length} track${tracks.length > 1 ? 's' : ''}`, 'assessed');
    addParagraph(`Current answers support preparation for: ${tracks.join(' and ')}.`);
    addDeadlines();
    addActions([
      'Record the awareness timestamp, decision owner and evidence supporting every classification.',
      'Prepare the early warning now. The 24-hour period is a ceiling, not a waiting period.',
      'Prepare the applicable 72-hour notification in parallel.',
      'Identify the coordinating CSIRT and current ENISA Single Reporting Platform workflow.',
      'Open the user-communication and final-report workstreams; their content and deadlines differ by track.'
    ]);
    if (triggerUnknown) addParagraph('At least one other trigger criterion remains unknown and may add another reporting track.');
    currentOutcome.status = 'prepare-reporting';
  }

  questions.forEach((question) => question.querySelectorAll('.choice').forEach((button) => button.addEventListener('click', () => {
    question.querySelectorAll('.choice').forEach((candidate) => candidate.classList.remove('active'));
    button.classList.add('active');
    answers[question.dataset.question] = button.dataset.answer;
    render();
  })));

  [awareAt, caseReference].forEach((control) => control.addEventListener('input', render));

  document.querySelector('#reset').addEventListener('click', () => {
    Object.keys(answers).forEach((key) => delete answers[key]);
    document.querySelectorAll('.choice').forEach((button) => button.classList.remove('active'));
    awareAt.value = '';
    caseReference.value = '';
    render();
  });

  document.querySelector('#copy-summary').addEventListener('click', async () => {
    const summary = [title.textContent, body.textContent.replace(/\s+/g, ' ').trim(), 'Preparation aid only. Not legal advice.'].join('\n\n');
    try { await navigator.clipboard.writeText(summary); document.querySelector('#copy-summary').textContent = 'Copied'; }
    catch { document.querySelector('#copy-summary').textContent = 'Copy unavailable'; }
    setTimeout(() => { document.querySelector('#copy-summary').textContent = 'Copy summary'; }, 1800);
  });

  document.querySelector('#export-json').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(currentOutcome, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cra-article-14-triage-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  });

  render();
})();
