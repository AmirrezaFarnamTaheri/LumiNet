import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const manifest = JSON.parse(readFileSync(new URL('../public/manifest.webmanifest', import.meta.url), 'utf8'));
const worker = readFileSync(new URL('../public/sw.js', import.meta.url), 'utf8');
const main = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');

assert.equal(manifest.name, 'LumiNet Control');
assert.equal(manifest.display, 'standalone');
assert.equal(manifest.start_url, './');
assert.match(worker, /url\.pathname\.includes\('\/api\/'\)/);
assert.match(worker, /request\.method !== 'GET'/);
assert.match(worker, /request\.mode === 'navigate'/);
assert.match(worker, /caches\.match\('\.\/index\.html'\)/);
assert.match(main, /navigator\.serviceWorker\.register\('\.\/sw\.js'/);

console.log('PWA characterization: 8 checks passed');
