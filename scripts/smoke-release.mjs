import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
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
  } else throw new Error('Unknown smoke profile');
  assert.deepEqual(failures, []);
  console.log(profile + ' served-release browser smoke passed');
} finally {
  await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
}
