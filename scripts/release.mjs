import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const [mode, target, profileOrDigest, revisionArg] = process.argv.slice(2);
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const profiles = {
  apt: ['index.html', 'search/index.html', 'actors/apt28/index.html', 'api/version.json', 'api/actors/apt28.json', 'pagefind/pagefind.js', 'scripts/search.js'],
  labs: ['index.html', 'attack-map/index.html', 'pivot-graph/index.html', 'baltic-threat-atlas/index.html', 'data/atlas/records.json', 'data/attack/intelligence/reviewed-evidence.json', 'data/pivots/cases.json']
};
if (mode === 'create') {
  const files = new Set(profiles[profileOrDigest]);
  if (!files.size) throw new Error('Unknown release profile');
  for (const file of [...files]) {
    if (!file.endsWith('.html')) continue;
    const html = fs.readFileSync(path.join(target, file), 'utf8');
    for (const match of html.matchAll(/(?:src|href)=["'](\/[^"'?#]+)(?:[?#][^"']*)?["']/g)) {
      if (/\.(?:js|css|woff2|svg|png|ico)$/.test(match[1])) files.add(match[1].slice(1));
    }
  }
  const revision = revisionArg || process.env.GITHUB_SHA || execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('An exact source revision is required');
  const manifest = { schema_version: '1.0.0', revision, profile: profileOrDigest, files: {} };
  for (const file of [...files].sort()) manifest.files[file] = digest(fs.readFileSync(path.join(target, file)));
  const bytes = JSON.stringify(manifest, null, 2) + '\n';
  fs.writeFileSync(path.join(target, 'publication-manifest.json'), bytes);
  const hash = digest(bytes);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, 'digest=' + hash + '\n');
  console.log(hash);
} else if (mode === 'verify') {
  if (!/^[a-f0-9]{64}$/.test(profileOrDigest || '') || !/^[a-f0-9]{40}$/.test(revisionArg || '')) throw new Error('Expected digest and revision are required');
  const base = new URL(target);
  if (!['https:', 'http:'].includes(base.protocol)) throw new Error('Unsupported URL');
  const get = async (file) => {
    const url = new URL(file, base);
    url.searchParams.set('release', revisionArg);
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(15000), headers: { 'Cache-Control': 'no-cache' } });
    if (!response.ok) throw new Error(file + ': HTTP ' + response.status);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > 2000000) throw new Error('Unexpected release file size');
    return bytes;
  };
  const attempts = Number(process.env.RELEASE_VERIFY_ATTEMPTS || 8);
  if (!Number.isInteger(attempts) || attempts < 1 || attempts > 8) throw new Error('Verification attempts must be 1-8');
  let error;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const bytes = await get('publication-manifest.json');
      if (digest(bytes) !== profileOrDigest) throw new Error('Served manifest differs from build artifact');
      const manifest = JSON.parse(bytes);
      if (manifest.revision !== revisionArg) throw new Error('Stale release revision');
      const entries = Object.entries(manifest.files);
      if (!entries.length || entries.length > 50) throw new Error('Unexpected manifest size');
      for (const [file, hash] of entries) {
        if (!/^[a-zA-Z0-9_./-]+$/.test(file) || file.includes('..') || file.startsWith('/')) throw new Error('Invalid release path');
        if (digest(await get(file)) !== hash) throw new Error('Served bytes differ: ' + file);
      }
      console.log('Verified live revision and ' + entries.length + ' artifact hashes: ' + revisionArg);
      error = null;
      break;
    } catch (caught) {
      error = caught;
      console.warn('Release verification attempt ' + (attempt + 1) + ': ' + caught.message);
      if (attempt < attempts - 1) await new Promise(resolve => setTimeout(resolve, 10000));
    }
  }
  if (error) throw error;
} else throw new Error('Usage: release.mjs create DIRECTORY apt|labs [REVISION] or verify BASE_URL DIGEST REVISION');
