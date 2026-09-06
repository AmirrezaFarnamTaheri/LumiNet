import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

const root = new URL('../', import.meta.url);
const rootPath = fileURLToPath(root);
const outDir = mkdtempSync(join(tmpdir(), 'luminet-routing-presets-'));

try {
  const compile = spawnSync(
    process.execPath,
    [join(rootPath, 'node_modules', 'typescript', 'bin', 'tsc'),
      resolve(rootPath, 'src', 'utils', 'routingPresets.ts'),
      resolve(rootPath, 'src', 'presets', 'seeds', 'iran_routing.json'),
      '--outDir', outDir,
      '--target', 'ES2023',
      '--module', 'commonjs',
      '--moduleResolution', 'bundler',
      '--resolveJsonModule',
      '--esModuleInterop',
      '--strict',
      '--skipLibCheck',
      '--ignoreConfig',
      '--rootDir', 'src'],
    { cwd: rootPath },
  );
  assert.equal(compile.status, 0, `tsc failed: ${compile.stderr?.toString()}`);

  const require2 = createRequire(pathToFileURL(join(outDir, 'noop.js')).href);
  const mod = require2(join(outDir, 'utils', 'routingPresets.js'));

  const presets = mod.listRoutingPresets();
  assert.ok(presets.length >= 1, 'expected at least the iran preset');
  const iran = mod.getRoutingPreset('iran');
  assert.ok(iran, 'iran preset missing');
  assert.equal(iran.id, 'iran');
  assert.ok(iran.ruleCount > 50, `iran ruleCount suspiciously low: ${iran.ruleCount}`);
  assert.equal(iran.hasDnsConfig, true);
  assert.ok(iran.outboundCounts.length >= 2, 'expected multiple outbounds');

  assert.equal(mod.getRoutingPreset('nope'), undefined);

  const line = mod.formatPresetLine(iran);
  assert.ok(line.startsWith(`${iran.ruleCount} rules —`), line);

  console.log('test-routing-presets: all assertions passed');
  console.log('iran:', line);
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
