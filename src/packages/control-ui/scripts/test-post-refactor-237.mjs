import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const cockpitPath = path.resolve('src/pages/NetworkCockpit.tsx');
const appPath = path.resolve('src/App.tsx');
const navPath = path.resolve('src/navigation.ts');
const layoutPath = path.resolve('src/AppLayout.tsx');

const cockpitSrc = fs.readFileSync(cockpitPath, 'utf8');
const appSrc = fs.readFileSync(appPath, 'utf8');
const navSrc = fs.readFileSync(navPath, 'utf8');
const layoutSrc = fs.readFileSync(layoutPath, 'utf8');

// Assertions
assert.ok(cockpitSrc.includes('export const NetworkCockpit'), 'NetworkCockpit must be exported');
assert.ok(cockpitSrc.includes('GLOBAL_NODES'), 'NetworkCockpit must define GLOBAL_NODES');
assert.ok(cockpitSrc.includes('CABLE_HOPS'), 'NetworkCockpit must define CABLE_HOPS');
assert.ok(cockpitSrc.includes('MIDDLEBOX INTERFERENCE DETECTED'), 'NetworkCockpit must render middlebox warning');
assert.ok(cockpitSrc.includes('latLngTo3D'), 'NetworkCockpit must implement 3D sphere coordinate projection');

assert.ok(appSrc.includes('path="cockpit"'), 'App.tsx must register cockpit route');
assert.ok(navSrc.includes("path: '/cockpit'"), 'navigation.ts must include /cockpit');
assert.ok(layoutSrc.includes("'/cockpit': Globe"), 'AppLayout.tsx must assign Globe icon to /cockpit');

console.log('test-post-refactor-237 (3D Network Cockpit): all assertions passed');
