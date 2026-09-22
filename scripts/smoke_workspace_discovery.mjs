import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { browserForChecks, servedTarget } from './browser_support.mjs';

const preview = await servedTarget(process.argv[2] || '.');
const browser = await browserForChecks().catch(async error => { await preview.close(); throw error; });
const routes = ['', 'lt/', 'lt/metodika/', 'baltic-threat-atlas/', 'pivot-graph/', 'attack-map/', 'changes/', 'about/', 'methodology/', 'licence/', 'security/', 'osint-workbench/', '404.html'];
const widths = [320, 390, 768, 1160, 1161, 1440, 1920];
let checked = 0;

try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  // This compatibility route intentionally leaves Labs. Validate the handoff
  // rather than applying Labs geometry assertions to the live Research site.
  const redirect = await page.request.get(new URL('data/', preview.base).href);
  assert.equal(redirect.status(), 200);
  assert.match(await redirect.text(), /http-equiv="refresh" content="0; url=https:\/\/hecavex\.com\/data\/"/);
  for (const width of widths) {
    await page.setViewportSize({ width, height: 1000 });
    for (const route of routes) {
      await page.goto(new URL(route, preview.base).href, { waitUntil: 'networkidle' });
      await page.evaluate(() => document.fonts.ready);
      const geometry = await page.evaluate(() => {
        const rect = selector => document.querySelector(selector)?.getBoundingClientRect();
        const hero = document.querySelector('.home-hero');
        return {
          overflow: document.documentElement.scrollWidth > innerWidth,
          networkHeight: rect('.network-bar')?.height,
          headerHeight: rect('.site-header')?.height,
          heroHeight: hero?.getBoundingClientRect().height,
          heroTopBorder: hero && getComputedStyle(hero).borderTopWidth,
          heroInset: hero && getComputedStyle(hero).paddingLeft,
          titleSize: parseFloat(getComputedStyle(document.querySelector('h1')).fontSize),
          titleFont: getComputedStyle(document.querySelector('h1')).fontFamily,
          displayFontLoaded: document.fonts.check('600 16px "Space Grotesk"', document.querySelector('h1').textContent),
          bodySize: parseFloat(getComputedStyle(document.body).fontSize),
          visibleNavSizes: [...document.querySelectorAll('.portfolio-navigation a, .product-navigation a')].filter(a => a.getBoundingClientRect().width > 0).map(a => parseFloat(getComputedStyle(a).fontSize)),
        };
      });
      const context = `${route || '/'} at ${width}`;
      assert.equal(geometry.overflow, false, `page overflow: ${context}`);
      assert.equal(geometry.networkHeight, 64, `network row: ${context}`);
      assert.equal(geometry.headerHeight, width > 1160 ? 116 : 64, `header geometry: ${context}`);
      assert(geometry.titleSize <= 52.01, `oversized title: ${context}`);
      assert(geometry.titleFont.startsWith('"Space Grotesk"'), `display type: ${context}`);
      assert(geometry.displayFontLoaded, `display font failed to load: ${context}`);
      assert.equal(geometry.bodySize, 16, `reading type: ${context}`);
      assert(geometry.visibleNavSizes.every(size => size >= 12), `small navigation: ${context}`);
      if (geometry.heroHeight !== undefined) {
        if (width > 680) assert(geometry.heroHeight >= 320, `desktop hero minimum: ${context}`);
        assert.equal(geometry.heroTopBorder, '0px', `framed hero: ${context}`);
        assert.equal(geometry.heroInset, '0px', `hero content edge: ${context}`);
      }
      if (process.env.SCREENSHOT_DIR && [390, 1440].includes(width) && ['', 'lt/', 'changes/', 'attack-map/'].includes(route)) {
        fs.mkdirSync(process.env.SCREENSHOT_DIR, { recursive: true });
        await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, `labs-${route.replaceAll('/', '-') || 'home'}-${width}.png`), fullPage: route === '' || route === 'lt/' });
      }
      checked++;
    }
  }

  for (const width of [320, 1440]) {
    await page.setViewportSize({ width, height: 1000 });
    for (const route of ['', 'lt/']) {
      await page.goto(new URL(route, preview.base).href);
      assert.equal(await page.locator('.workspace-row:visible').count(), 3);
      const initialUrl = page.url();
      await page.locator('#workspace-search').fill('ATT&CK');
      assert.equal(await page.locator('.workspace-row:visible').count(), 1);
      assert.equal(page.url(), initialUrl, 'typing must remain local');
      await page.locator('#workspace-search').fill('no-such-workspace');
      assert(await page.locator('[data-workspace-empty]').isVisible());
      assert.equal(await page.locator('.workspace-row:visible').count(), 0);
      await page.locator('[data-workspace-empty] button').focus();
      await page.keyboard.press('Enter');
      assert.equal(await page.locator('.workspace-row:visible').count(), 3);
      assert.equal(await page.evaluate(() => document.activeElement.id), 'workspace-search');
      assert.equal(await page.locator('[data-workspace-empty]').isVisible(), false);
      await page.goto(new URL(`${route}?q=ATT%26CK`, preview.base).href);
      assert.equal(await page.locator('.workspace-row:visible').count(), 1, 'initial query preserved');
    }
    if (width === 320) {
      await page.locator('.mobile-navigation summary').focus();
      await page.keyboard.press('Enter');
      assert(await page.locator('.mobile-navigation-panel').isVisible());
      await page.keyboard.press('Escape');
      assert.equal(await page.locator('.mobile-navigation-panel').isVisible(), false);
    }
  }

  await page.emulateMedia({ forcedColors: 'active', reducedMotion: 'reduce' });
  await page.goto(preview.base);
  await page.locator('#workspace-search').fill('no-match');
  await page.locator('[data-workspace-empty] button').focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('.workspace-row:visible').count(), 3);
  const noJs = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 320, height: 1000 } });
  try {
    const staticPage = await noJs.newPage();
    for (const route of ['', 'lt/']) {
      await staticPage.goto(new URL(route, preview.base).href);
      assert.equal(await staticPage.locator('.workspace-row:visible').count(), 3);
      assert.equal(await staticPage.locator('.workspace-filter').isVisible(), false);
      await staticPage.locator('.mobile-navigation summary').click();
      assert(await staticPage.locator('.mobile-navigation-panel').isVisible());
    }
  } finally { await noJs.close(); }
  assert.deepEqual(errors, []);
  console.log(`Labs overview and geometry passed: ${checked} route/viewport combinations and canonical Data handoff; EN/LT filtering, empty recovery, keyboard, forced colors, reduced motion, no-JS and query privacy.`);
} finally {
  await browser.close();
  await preview.close();
}
