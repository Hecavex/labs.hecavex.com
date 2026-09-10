/* A deterministic answer key for fictional records, never a production detector. */
(() => {
  'use strict';
  const outcomes = {
    'tracking-ambiguous': { conclusion: 'A tracking request is present; a recipient action is not established.', next: 'Check whether an email security service or image proxy made the request. Do not infer a human open from the request alone.', stop: 'Without reliable recipient attribution, stop the identity-specific chain. No compromise or actor identity is established.' },
    'bounded-follow-up': { conclusion: 'One recipient-confirmed open and later failed sign-in are temporally associated.', next: 'Check the recipient and time window against authorised identity, mailbox and endpoint telemetry. Examine routine authentication errors and unrelated activity as alternatives.', stop: 'A failed sign-in is not successful access. Do not label an account compromised, or attribute the activity, from this association.' },
    'benign-alternative': { conclusion: 'The observed mailbox reads have an approved-client explanation in this fixture.', next: 'Confirm that the client baseline and authorisation are still valid and review unexpected deviations.', stop: 'This explanation applies to these records only. It does not prove that the account or environment is clean.' },
    'stop-insufficient': { conclusion: 'The provided telemetry cannot answer the question.', next: 'Record the missing telemetry and retention period. Request only authorised, relevant observations before proceeding.', stop: 'No observation is not evidence of no activity. Do not record a successful defensive test.' }
  };
  function evaluate(sample) {
    if (!sample || !Array.isArray(sample.events) || !Array.isArray(sample.available_telemetry)) throw new TypeError('Expected explicit telemetry availability and events');
    const kinds = new Set(['mail-image', 'identity', 'mailbox']);
    if (sample.available_telemetry.some(kind => !kinds.has(kind))) throw new TypeError('Unsupported telemetry type');
    for (const event of sample.events) {
      if (!kinds.has(event.type) || !sample.available_telemetry.includes(event.type) || typeof event.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(event.at) || !Number.isFinite(Date.parse(event.at)) || typeof event.identity !== 'string' || !/^[a-z0-9._-]+@[a-z0-9.-]+\.test$/i.test(event.identity)) throw new TypeError('Malformed or non-synthetic event');
      if (event.type === 'mail-image' && !['security-proxy', 'recipient-confirmed', 'unknown'].includes(event.initiator)) throw new TypeError('Image initiator must be explicit');
      if (new Date(event.at).toISOString().replace('.000Z', 'Z') !== event.at) throw new TypeError('Invalid calendar date');
      if (event.type === 'identity' && event.outcome !== 'failed-sign-in') throw new TypeError('Unsupported identity event');
      if (event.type === 'mailbox' && !['approved', 'unknown'].includes(event.client_baseline)) throw new TypeError('Mailbox baseline must be explicit');
    }
    const opens = sample.events.filter(event => event.type === 'mail-image');
    const identities = sample.events.filter(event => event.type === 'identity');
    const reads = sample.events.filter(event => event.type === 'mailbox');
    const joins = opens.filter(open => open.initiator === 'recipient-confirmed' && identities.some(event => event.identity === open.identity && Date.parse(event.at) >= Date.parse(open.at) && Date.parse(event.at) - Date.parse(open.at) <= 3600000)).length;
    const decision = joins ? 'bounded-follow-up' : opens.length ? 'tracking-ambiguous' : reads.length && reads.every(event => event.client_baseline === 'approved') ? 'benign-alternative' : 'stop-insufficient';
    return { decision, counts: { images: opens.length, identity_events: identities.length, mailbox_reads: reads.length, recipient_time_joins: joins }, ...outcomes[decision], boundary: 'Synthetic exercise only; no detection efficacy, compromise or actor attribution established.' };
  }
  if (typeof module === 'object' && module.exports) module.exports = { evaluate };
  if (typeof document === 'undefined') return;
  const form = document.querySelector('#analytical-exercise');
  if (!form) return;
  const select = form.querySelector('select');
  const button = form.querySelector('button');
  const result = document.querySelector('#exercise-result');
  const input = document.querySelector('#exercise-input');
  let dataset;
  const showInput = () => { const { expected, ...observations } = dataset.cases.find(item => item.id === select.value); input.textContent = JSON.stringify(observations, null, 2); result.textContent = 'Choose your interpretation, then reveal the worked answer. The complete answer key is also in the downloadable fixture.'; };
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!dataset) return;
    const answer = evaluate(dataset.cases.find(item => item.id === select.value));
    result.replaceChildren();
    for (const [label, value] of [['Intermediate artifact', JSON.stringify(answer.counts)], ['Conclusion', answer.conclusion], ['Next authorised check', answer.next], ['Stopping rule', answer.stop], ['Boundary', answer.boundary]]) {
      const line = document.createElement('p');
      const heading = document.createElement('strong');
      heading.textContent = label + ': ';
      line.append(heading, document.createTextNode(value));
      result.append(line);
    }
  });
  select.addEventListener('change', showInput);
  fetch('/data/attack/exercises/source-to-hypothesis.json', { credentials: 'same-origin' }).then(response => { if (!response.ok) throw new Error('Fixture unavailable'); return response.json(); }).then(value => {
    if (value.kind !== 'synthetic-analytical-exercise' || value.schema_version !== '1.0.0' || !value.cases.length) throw new Error('Unsupported fixture');
    value.cases.forEach(evaluate);
    dataset = value;
    select.replaceChildren(...dataset.cases.map(item => { const option = document.createElement('option'); option.value = item.id; option.textContent = item.title; return option; }));
    select.disabled = false; button.disabled = false; showInput();
  }).catch(() => { result.textContent = 'The interactive fixture could not be loaded. Use the static worked example and downloadable JSON; no result is inferred.'; });
})();
