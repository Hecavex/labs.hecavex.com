// Shared bounded browser harness. Application code never imports this module.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export async function browserForChecks() {
  const modulePath = process.env.PLAYWRIGHT_MODULE || '.browser-check/node_modules/playwright-core/index.mjs';
  const { chromium } = await import(pathToFileURL(path.resolve(modulePath)).href);
  return chromium.launch({ executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome', headless: true });
}

export async function servedTarget(target) {
  if (/^https?:/.test(target)) return { base: target, close: async () => {} };
  const root = path.resolve(target);
  const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png' };
  const server = http.createServer((request, response) => {
    let route;
    try { route = decodeURIComponent(new URL(request.url, 'http://localhost').pathname); }
    catch { response.writeHead(400); response.end(); return; }
    const filename = path.resolve(root, '.' + route + (route.endsWith('/') ? 'index.html' : ''));
    if (!filename.startsWith(root + path.sep) || !fs.existsSync(filename) || !fs.statSync(filename).isFile()) {
      response.writeHead(404); response.end(); return;
    }
    response.setHeader('Content-Type', mime[path.extname(filename)] || 'application/octet-stream');
    fs.createReadStream(filename).pipe(response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    base: `http://127.0.0.1:${server.address().port}/`,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}
