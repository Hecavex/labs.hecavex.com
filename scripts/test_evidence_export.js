'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const api = require('../assets/evidence-export.js');
const raw = fs.readFileSync('data/attack/intelligence/reviewed-evidence.json');
const data = JSON.parse(raw);
const pin = require('./upstream-release.json');
const context = { ...pin, source_dataset_sha256: crypto.createHash('sha256').update(raw).digest('hex'), source_dataset_url: 'https://labs.hecavex.com/data/attack/intelligence/reviewed-evidence.json' };
const ids = data.actors.flatMap(actor => actor.evidence.map(record => record.id));
const exportedAt = '2030-01-02T03:04:05.000Z';
const filters = { actor: 'all', query: '' };
const payload = api.createEnvelope(data, ids, filters, context, exportedAt);
assert.equal(payload.records.length, 59);
assert.deepEqual(payload.selection.record_ids, ids);
assert.equal(JSON.stringify(data), JSON.stringify(JSON.parse(raw)));
for (const actor of data.actors) {
  const { evidence, ...actorContext } = actor;
  for (const record of evidence) {
    const exported = payload.records.find(item => item.id === record.id);
    assert.deepEqual(exported, { ...record, actor: actorContext });
    assert.equal(exported.claim_review.reviewed_at, record.claim_review.reviewed_at);
    assert(!('evidence' in exported.actor));
  }
}
const subset = api.createEnvelope(data, ids.slice(0, 2).reverse(), { actor: 'apt28' }, context, exportedAt);
assert.deepEqual(subset.records.map(record => record.id), ids.slice(0, 2).reverse());
assert.equal(subset.result_count, 2);
assert.equal(subset.source_release.released_at, data.source_system.released_at);
assert.notEqual(subset.source_release.released_at, subset.exported_at);
for (const invalid of [[], ['missing'], [ids[0], ids[0]]]) assert.throws(() => api.createEnvelope(data, invalid, filters, context));
assert.throws(() => api.createEnvelope(data, ids, filters, null));
assert.throws(() => api.createEnvelope(data, ids, filters, { ...context, release_id: 'wrong' }));
assert.throws(() => api.createEnvelope(data, ids, filters, { ...context, revision: 'main' }));

function parseCsv(input) {
  const rows = []; let row = [], value = '', quoted = false;
  const text = input.replace(/^\uFEFF/, '');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { if (quoted && text[i + 1] === '"') { value += '"'; i++; } else quoted = !quoted; }
    else if (!quoted && c === ',') { row.push(value); value = ''; }
    else if (!quoted && c === '\r' && text[i + 1] === '\n') { row.push(value); rows.push(row); row = []; value = ''; i++; }
    else value += c;
  }
  assert.equal(quoted, false); assert.equal(value, ''); assert.equal(row.length, 0);
  const [headers, ...records] = rows;
  return records.map(cells => { assert.equal(cells.length, headers.length); return Object.fromEntries(headers.map((key, index) => [key, cells[index]])); });
}
for (const record of parseCsv(api.toCsv(payload))) {
  assert.deepEqual(JSON.parse(record.record_json), payload.records.find(item => item.id === record.evidence_id));
  assert.deepEqual(JSON.parse(record.source_metadata_json), payload.source_dataset_metadata);
  assert.deepEqual(JSON.parse(record.source_locators_json), JSON.parse(record.record_json).source_locators);
  assert.deepEqual(JSON.parse(record.selection_json), payload.selection);
  assert.equal(record.upstream_revision, context.revision);
}

const malicious = structuredClone(data);
const changed = malicious.actors[0].evidence[0];
changed.future_field = { nested: ['never silently drop', 'Lietuviškai \"įrodymas\"\nnext line'] };
changed.notes = '=HYPERLINK("https://example.test", "danger")\n<script>alert(1)</script>\n```sh\ncode\n```\n[click](javascript:alert(1))';
changed.source_locators[0].locator = '</script><img src=x onerror=alert(1)>\n# heading';
changed.sources[0].title = '<img src=x> [bad](data:text/html,evil)';
changed.sources[0].url = 'javascript:alert(1)';
const hostile = api.createEnvelope(malicious, [changed.id], { query: '+malicious\nLietuviškai' }, context, exportedAt);
assert.deepEqual(hostile.records[0].future_field, changed.future_field);
const conflicting = structuredClone(malicious);
conflicting.actors[0].evidence[0].actor = { future: 'source-owned context' };
assert.throws(() => api.createEnvelope(conflicting, [changed.id], filters, context), /No fields were discarded/);
const csv = parseCsv(api.toCsv(hostile))[0];
assert.equal(csv.notes, "'" + changed.notes);
assert.deepEqual(JSON.parse(csv.record_json).notes, changed.notes);
assert.deepEqual(JSON.parse(csv.record_json).future_field, changed.future_field);
for (const value of ['=1+1', '+SUM(A1)', '-1+1', '@SUM(A1)', '  =1', '\tplain', '\nplain', '\u200b=1', '\u202e=1', '\uFEFF=1']) assert(api.csvCell(value).startsWith('"\''));
for (const value of ['123', 'Lithuania', 'T1114.002']) assert.equal(api.csvCell(value), '"' + value + '"');
const md = api.toMarkdown(hostile);
assert(!md.includes('<script>') && !md.includes('<img') && !md.includes('```'));
assert(!md.includes('](javascript:') && !md.includes('](<javascript:'));
assert(md.includes('URL not linked'));
assert(md.includes('Independent claim review date: Not recorded'));
assert(md.includes('Only the explicitly filtered records'));
assert(md.includes(api.markdownText(changed.id)));
for (const url of ['javascript:alert(1)', 'data:text/html,hello', 'http://example.test', 'https://user:password@example.test', 'https://example.test/\nhello', 'https://example.test/a b']) assert(api.markdownLink('source', url).includes('URL not linked'));
assert.equal(api.markdownLink('source', 'https://example.test/(test)?x=1#p'), '[source](<https://example.test/%28test%29?x=1#p>)');
assert.match(api.toMarkdown(payload), /Locator checked at \(not claim review\)/);
console.log('Evidence exports: 59-record lossless JSON/CSV round-trip, bounded selection, dates, future fields, Markdown and spreadsheet safety passed.');
