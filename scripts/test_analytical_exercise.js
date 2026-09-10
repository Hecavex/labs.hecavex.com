const assert = require('node:assert/strict');
const fs = require('node:fs');
const { evaluate } = require('../assets/analytical-exercise.js');
const fixture = JSON.parse(fs.readFileSync('data/attack/exercises/source-to-hypothesis.json', 'utf8'));
for (const sample of fixture.cases) {
  const before = JSON.stringify(sample);
  assert.equal(evaluate(sample).decision, sample.expected);
  assert.equal(JSON.stringify(sample), before, 'Input records must not be mutated');
  assert.match(evaluate(sample).boundary, /no detection efficacy/);
}
const joined = structuredClone(fixture.cases[1]);
assert.equal(evaluate(joined).counts.recipient_time_joins, 1);
joined.events[1].identity = 'different@example.test';
assert.equal(evaluate(joined).decision, 'tracking-ambiguous');
joined.events[1].identity = joined.events[0].identity;
joined.events[1].at = '2026-09-01T07:59:00Z';
assert.equal(evaluate(joined).counts.recipient_time_joins, 0);
joined.events[1].at = '2026-09-01T09:01:00Z';
assert.equal(evaluate(joined).counts.recipient_time_joins, 0);
joined.events[0].initiator = 'security-proxy';
joined.events[1].at = '2026-09-01T08:20:00Z';
assert.equal(evaluate(joined).decision, 'tracking-ambiguous');
for (const identity of ['real@example.com', '<script>@example.test', '=CMD@example.test']) {
  const hostile = structuredClone(fixture.cases[0]); hostile.events[0].identity = identity;
  assert.throws(() => evaluate(hostile), /Malformed/);
}
assert.throws(() => evaluate({events: [], available_telemetry: ['future']}), /Unsupported/);
assert.throws(() => evaluate({events: fixture.cases[0].events, available_telemetry: []}), /Malformed/);
assert.throws(() => evaluate({events: []}), /explicit/);
console.log('Synthetic worked exercise: four decisions, identity/time joins, proxy alternative, missing telemetry and hostile input guards passed.');
