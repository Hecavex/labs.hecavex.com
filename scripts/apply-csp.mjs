import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

// Hash exact emitted inline scripts. No eval, inline event handlers or arbitrary script origins.
const root = process.argv[2] || 'dist';
let count = 0;
function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) { walk(filename); continue; }
    if (!filename.endsWith('.html')) continue;
    let html = fs.readFileSync(filename, 'utf8');
    html = html.replace(/<meta\s+http-equiv="Content-Security-Policy"[^>]*>\s*/gi, '');
    const hashes = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
      .filter((match) => !/\bsrc\s*=/.test(match[1]))
      .map((match) => `'sha256-${createHash('sha256').update(match[2].replace(/\r\n?/g, '\n')).digest('base64')}'`);
    const policy = `default-src 'none'; script-src 'self' 'wasm-unsafe-eval' https://static.cloudflareinsights.com ${[...new Set(hashes)].join(' ')}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://cloudflareinsights.com; worker-src 'self' blob:; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-src 'none'`;
    html = html.replace(/(<meta\s+charset=[^>]+>)/i, `$1<meta http-equiv="Content-Security-Policy" content="${policy}">`);
    if (!html.includes('http-equiv="Content-Security-Policy"')) throw new Error(`No charset insertion point: ${filename}`);
    fs.writeFileSync(filename, html);
    count++;
  }
}
walk(root);
console.log(`Applied script-hash CSP to ${count} HTML pages.`);
