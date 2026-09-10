import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const [target, profile] = process.argv.slice(2);
const { chromium } = await import(pathToFileURL(path.resolve(process.env.PLAYWRIGHT_MODULE || '.browser-check/node_modules/playwright-core/index.mjs')).href);
let server;
let base = target;
if (!/^https?:/.test(target)) {
  const root = path.resolve(target);
  server = http.createServer((request, response) => {
    const route = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const filename = path.resolve(root, '.' + route + (route.endsWith('/') ? 'index.html' : ''));
    if (!filename.startsWith(root + path.sep) || !fs.existsSync(filename) || !fs.statSync(filename).isFile()) { response.writeHead(404); response.end(); return; }
    const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm', '.svg': 'image/svg+xml' };
    response.setHeader('Content-Type', mime[path.extname(filename)] || 'application/octet-stream');
    fs.createReadStream(filename).pipe(response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = 'http://127.0.0.1:' + server.address().port + '/';
}
const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome', headless: true });
try {
  const page = await browser.newPage();
  const failures = [];
  page.on('pageerror', error => failures.push(error.message));
  await page.addInitScript(() => {
    window.cspViolations = [];
    document.addEventListener('securitypolicyviolation', event => window.cspViolations.push(event.violatedDirective));
  });
  if (profile === 'apt') {
    for (const q of ['APT28', 'Microsoft', 'quarkflibbertigibbet']) {
      await page.goto(new URL('search/?q=' + q, base).href);
      await page.waitForFunction(() => document.querySelector('#search-status').textContent.startsWith('Showing'));
      let count = await page.locator('.search-result-row').count();
      while (await page.locator('#search-more').isVisible()) {
        await page.locator('#search-more').click();
        await page.waitForFunction(old => document.querySelectorAll('.search-result-row').length > old, count);
        count = await page.locator('.search-result-row').count();
      }
      const links = await page.locator('.search-result-row h2 a').evaluateAll(nodes => nodes.map(node => node.href));
      assert.equal(new Set(links).size, count);
      assert.equal(await page.locator('#search-status').innerText(), 'Showing ' + count + ' of ' + count + ' results');
      if (q === 'Microsoft') assert(count > 30); else if (q === 'APT28') assert(count > 0); else assert.equal(count, 0);
      assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    }
  } else if (profile === 'labs') {
    const sourceResponse = await page.request.get(new URL('data/attack/intelligence/reviewed-evidence.json', base).href);
    const sourceBytes = await sourceResponse.body();
    const evidenceData = JSON.parse(sourceBytes.toString('utf8'));
    const expectedActor = evidenceData.actors.find(actor => actor.id === 'apt28');
    async function downloadedText(button) {
      const promise = page.waitForEvent('download');
      await page.locator(button).click();
      const download = await promise;
      const stream = await download.createReadStream();
      const chunks = [];
      for await (const chunk of stream) chunks.push(chunk);
      return Buffer.concat(chunks).toString('utf8');
    }
    for (const width of [320, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(new URL('attack-map/?actor=apt28', base).href);
      await page.waitForFunction(() => !document.querySelector('#export-json').disabled);
      assert.equal(await page.locator('#actor-filter').inputValue(), 'apt28');
      await page.locator('[data-compare-actor="apt28"]').first().click();
      const full = JSON.parse(await downloadedText('#export-json'));
      assert.equal(full.result_count, expectedActor.evidence.length);
      assert.deepEqual(full.selection.record_ids, expectedActor.evidence.map(record => record.id));
      assert.equal(full.build_context.source_dataset_sha256, createHash('sha256').update(sourceBytes).digest('hex'));
      assert.equal(full.source_release.release_id, evidenceData.source_system.release_id);
      assert.match(await page.locator('#export-scope').innerText(), /Actor comparison does not change/);
      const evidence = expectedActor.evidence[0];
      await page.locator('#evidence-search').fill(evidence.technique_id);
      const filtered = JSON.parse(await downloadedText('#export-json'));
      const expected = expectedActor.evidence.filter(record => record.technique_id === evidence.technique_id);
      assert.deepEqual(filtered.selection.record_ids, expected.map(record => record.id));
      assert.equal(filtered.selection.filters.query, evidence.technique_id);
      const { evidence: allEvidence, ...actorContext } = expectedActor;
      assert.deepEqual(filtered.records, expected.map(record => ({ ...record, actor: actorContext })));
      const csv = await downloadedText('#export-csv');
      assert(csv.includes('record_json') && csv.includes('source_locators_json') && csv.includes(evidence.id));
      const markdown = await downloadedText('#export-markdown');
      assert(markdown.includes('Independent claim review date: Not recorded'));
      assert(markdown.includes(evidence.notes.slice(0, 15)));
      assert(markdown.includes(filtered.build_context.revision));
      assert(markdown.includes('Only the explicitly filtered records'));
      await page.locator('#evidence-search').fill('no-such-evidence-zzzz');
      for (const button of ['#export-json', '#export-csv', '#export-markdown', '#export-navigator']) assert(await page.locator(button).isDisabled());
      assert.match(await page.locator('#export-scope').innerText(), /0 current filtered records/);
      await page.locator('#reset-filters').click();
      await page.waitForFunction(() => document.querySelector('#actor-filter').value === 'all' && !document.querySelector('#export-json').disabled);
      assert.equal(JSON.parse(await downloadedText('#export-json')).result_count, evidenceData.summary.mappings);
      const firstView = 'attack-map/#view=' + encodeURIComponent('actor=apt28&q=' + evidence.technique_id);
      await page.goto(new URL(firstView, base).href);
      await page.waitForFunction(id => document.querySelector('#evidence-search').value === id, evidence.technique_id);
      assert.deepEqual(JSON.parse(await downloadedText('#export-json')).selection.record_ids, expected.map(record => record.id));
      await page.goto(new URL('attack-map/#view=' + encodeURIComponent('actor=apt44'), base).href);
      await page.waitForFunction(() => document.querySelector('#actor-filter').value === 'apt44');
      await page.goBack();
      await page.waitForFunction(id => document.querySelector('#evidence-search').value === id && document.querySelector('#actor-filter').value === 'apt28', evidence.technique_id);
      assert.deepEqual(JSON.parse(await downloadedText('#export-json')).selection.record_ids, expected.map(record => record.id));
      await page.goForward();
      await page.waitForFunction(() => document.querySelector('#actor-filter').value === 'apt44');
      assert(JSON.parse(await downloadedText('#export-json')).records.every(record => record.actor.id === 'apt44'));
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    }
    // Stale HTML paired with a newer JSON must not publish a false immutable hash.
    await page.route('**/data/attack/intelligence/reviewed-evidence.json?*', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ...evidenceData, export_test: 'different source bytes' }) }));
    await page.goto(new URL('attack-map/', base).href);
    await page.waitForFunction(() => document.querySelector('#export-scope').textContent.includes('could not be verified'));
    assert(await page.locator('#export-json').isDisabled());
    assert(await page.locator('#export-markdown').isDisabled());
    assert((await page.locator('.evidence-row').count()) > 0);
    await page.unroute('**/data/attack/intelligence/reviewed-evidence.json?*');
    await page.goto(new URL('attack-map/?actor=apt28', base).href);
    await page.waitForFunction(() => !/Loading/.test(document.querySelector('#result-count').textContent));
    assert.equal(await page.locator('#actor-filter').inputValue(), 'apt28');
    assert(await page.locator('#evidence-results').innerText().then(text => text.includes('APT28')));
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    await page.goto(new URL('baltic-threat-atlas/', base).href);
    await page.waitForFunction(() => document.querySelector('#atlas-count').textContent.includes('observations'));
    await page.locator('#atlas-search').fill('846');
    assert.equal(await page.locator('#atlas-records > article:visible').count(), 1);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    const recordId = await page.locator('#atlas-records > article:visible').getAttribute('id');
    const atlasData = await page.request.get(new URL('data/atlas/records.json', base).href).then(response => response.json());
    const recordCountry = atlasData.records.find(record => record.id === recordId).country.toLowerCase();
    const permalink = await page.locator('#atlas-records > article:visible .observation-link').getAttribute('href');
    await page.locator('#atlas-records > article:visible .observation-link').click();
    await page.waitForFunction(id => document.activeElement?.id === id, recordId);
    assert.equal(await page.locator('#atlas-search').inputValue(), '');
    assert.match(await page.locator('#atlas-link-status').innerText(), /Filters cleared/i);
    assert.equal(await page.locator('[data-linked-observation]').getAttribute('id'), recordId);
    await page.goBack();
    await page.waitForFunction(() => document.querySelector('#atlas-search').value === '846');
    assert.equal(await page.locator('#atlas-records > article:visible').count(), 1);
    assert.equal(await page.locator('[data-linked-observation]').count(), 0);
    await page.goForward();
    await page.waitForFunction(id => document.activeElement?.id === id, recordId);
    assert.equal(await page.locator('#atlas-search').inputValue(), '');

    for (const width of [320, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(new URL(`baltic-threat-atlas/?q=does-not-match#observation=${encodeURIComponent(recordId)}`, base).href);
      await page.waitForFunction(id => document.activeElement?.id === id, recordId);
      assert.equal(await page.locator('#atlas-search').inputValue(), '');
      assert.match(await page.locator('#atlas-link-status').innerText(), /Filters cleared/i);
      assert(await page.locator('[data-linked-observation]').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
      await page.locator('#atlas-search').fill('846');
      await page.waitForFunction(() => location.hash === '');
      assert.equal(await page.evaluate(() => location.hash), '');
      assert.equal(await page.locator('[data-linked-observation]').count(), 0);
    }
    await page.goto(new URL(`baltic-threat-atlas/#${encodeURIComponent(recordId)}`, base).href);
    await page.waitForFunction(id => document.activeElement?.id === id, recordId);
    await page.goto(new URL('baltic-threat-atlas/#observation=missing-observation-id', base).href);
    await page.waitForFunction(() => document.querySelector('#atlas-link-status').textContent.includes('not in the published'));
    assert.equal(await page.locator('[data-linked-observation]').count(), 0);
    await page.goto(new URL('baltic-threat-atlas/#observation=%E0%A4%A', base).href);
    await page.waitForFunction(() => document.querySelector('#atlas-link-status').textContent.includes('malformed'));

    await page.goto(new URL('baltic-threat-atlas/#view=' + encodeURIComponent('q=846&country=' + recordCountry), base).href);
    await page.waitForFunction(() => document.querySelector('#atlas-search').value === '846');
    assert.equal(await page.locator('#atlas-country').inputValue(), recordCountry);
    assert.equal(await page.locator('#atlas-records > article:visible').count(), 1);
    await page.locator('#atlas-records > article:visible .observation-link').click();
    await page.waitForFunction(id => document.activeElement?.id === id, recordId);
    await page.goBack();
    await page.waitForFunction(country => document.querySelector('#atlas-country').value === country, recordCountry);
    assert.equal(await page.locator('#atlas-search').inputValue(), '846');
    assert.equal(await page.locator('#atlas-records > article:visible').count(), 1);
    assert.deepEqual(await page.evaluate(() => window.cspViolations), []);

    const noJs = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 320, height: 900 } });
    for (const width of [320, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(new URL('attack-map/?actor=apt31#worked-exercise', base).href);
      await page.waitForFunction(() => !document.querySelector('#exercise-case').disabled);
      const exerciseCases = [['proxy-only', 'a recipient action is not established'], ['recipient-follow-up', 'temporally associated'], ['approved-client', 'approved-client explanation'], ['missing-telemetry', 'cannot answer the question']];
      for (const [id, expected] of exerciseCases) {
        await page.locator('#exercise-case').selectOption(id);
        await page.locator('#analytical-exercise button').focus();
        await page.keyboard.press('Enter');
        assert((await page.locator('#exercise-result').innerText()).includes(expected));
        assert((await page.locator('#exercise-result').innerText()).includes('Stopping rule:'));
        if (id === 'proxy-only' && process.env.SCREENSHOT_DIR) {
          fs.mkdirSync(process.env.SCREENSHOT_DIR, { recursive: true });
          await page.locator('#worked-exercise').screenshot({ path: path.join(process.env.SCREENSHOT_DIR, `worked-exercise-${width}.png`) });
        }
      }
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.locator('[data-open-evidence]').first().click();
      assert((await page.locator('#mapping-dialog').innerText()).includes('ai-assisted-source-comparison'));
      assert((await page.locator('#mapping-dialog').innerText()).includes('Not recorded'));
      await page.keyboard.press('Escape');
      await page.goto(new URL('pivot-graph/?case=github-python-loader-2024', base).href);
      await page.waitForFunction(() => document.querySelector('#case-reproducibility').textContent.includes('final stage is unavailable'));
      await page.locator('#case-reproducibility summary').focus();
      await page.keyboard.press('Enter');
      assert((await page.locator('#case-reproducibility').innerText()).includes('Complete original bytes'));
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      assert.deepEqual(await page.evaluate(() => window.cspViolations), []);
    }
    await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
    await page.goto(new URL('attack-map/#worked-exercise', base).href);
    await page.waitForFunction(() => !document.querySelector('#exercise-case').disabled);
    await page.locator('#analytical-exercise button').focus();
    await page.keyboard.press('Enter');
    assert((await page.locator('#exercise-result').innerText()).includes('Stopping rule:'));
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.emulateMedia({ forcedColors: 'none', reducedMotion: 'no-preference' });
    try {
      const staticPage = await noJs.newPage();
      await staticPage.goto(permalink);
      assert(await staticPage.locator('noscript a[href="/data/atlas/records.json"]').isVisible());
      assert.equal(await staticPage.locator('#atlas-records').isVisible(), false);
      assert(await staticPage.locator('main > noscript').innerText().then(text => text.includes('JavaScript')));
      await staticPage.goto(new URL('attack-map/?actor=apt28', base).href);
      assert(await staticPage.locator('noscript a[href="/data/attack/intelligence/reviewed-evidence.json"]').isVisible());
      assert.equal(await staticPage.locator('#export-json').isVisible(), false);
      assert.equal(await staticPage.locator('#export-scope').isVisible(), false);
      assert(await staticPage.locator('#worked-exercise').isVisible());
      assert((await staticPage.locator('#worked-exercise').innerText()).includes('Complete static worked example'));
      assert(await staticPage.locator('a[href="/data/attack/exercises/source-to-hypothesis.json"]').isVisible());
    } finally { await noJs.close(); }
  } else throw new Error('Unknown smoke profile');
  assert.deepEqual(failures, []);
  console.log(profile + ' served-release browser smoke passed');
} finally {
  await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
}
