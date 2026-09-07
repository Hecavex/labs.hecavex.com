const { readFileSync } = require('node:fs');
const { strict: assert } = require('node:assert');
const vm = require('node:vm');
const source = readFileSync(require('node:path').join(__dirname, '../assets/pivot-graph.js'), 'utf8');
const loadingCode = source.slice(source.indexOf('  let caseRequest ='), source.indexOf('  function showError'));
const requests = [];
const rendered = [];
const errors = [];
const nodes = new Map();
const context = vm.createContext({
  AbortController, URL,
  catalogue: { cases: [{ id: 'old', graph: '/old.json' }, { id: 'new', graph: '/new.json' }] },
  selectedCase: null, data: null,
  document: { querySelector(id) { if (!nodes.has(id)) nodes.set(id, {}); return nodes.get(id); } },
  window: { location: { href: 'https://labs.hecavex.com/pivot-graph/' }, history: { pushState(state) { rendered.push(`url:${state.caseId}`); } } },
  updateCaseHeader() { rendered.push(`${context.selectedCase.id}:${context.data.case.id}`); },
  renderGraph() {}, renderLedger() {},
  fetch(url, options) { return new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })); }
});
vm.runInContext(loadingCode, context);
const response = (id) => ({ ok: true, json: async () => ({ case: { id } }) });
(async () => {
  const old = context.loadCase('old', true).catch((error) => errors.push(error));
  const latest = context.loadCase('new', true);
  assert.equal(requests[0].options.signal.aborted, true);
  requests[1].resolve(response('new'));
  await latest;
  requests[0].resolve(response('old')); // Transport deliberately ignores cancellation.
  await old;
  assert.deepEqual(rendered, ['new:new', 'url:new']);
  const obsolete = context.loadCase('old');
  const current = context.loadCase('new');
  requests[2].reject(new Error('Late failure from old selection'));
  requests[3].resolve(response('new'));
  await Promise.all([obsolete, current]);
  assert.equal(errors.length, 0);
  const back = context.loadCase('old', false);
  requests[4].resolve(response('old'));
  await back;
  assert.equal(rendered.at(-1), 'old:old');
  assert.equal(rendered.filter((value) => value.startsWith('url:')).length, 1);
  const invalid = context.loadCase('new');
  requests[5].resolve(response('old'));
  await assert.rejects(invalid, /case IDs differ/);
  assert.equal(context.data.case.id, 'old');
  console.log('Pivot race regressions passed: reverse responses, stale failures, history restoration and mismatched payload.');
})().catch((error) => { console.error(error); process.exitCode = 1; });
