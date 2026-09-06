import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = new URL('../', import.meta.url);
const rootPath = fileURLToPath(root);
const workDir = mkdtempSync(join(tmpdir(), 'luminet-transport-'));
const outDir = join(workDir, 'out');
const envTypes = join(workDir, 'import-meta-env.d.ts');

writeFileSync(envTypes, `
interface ImportMetaEnv {
  readonly VITE_LUMINET_API_URL?: string;
  readonly VITE_LUMINET_API_KEY?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
`);

try {
  const compile = spawnSync(
    process.execPath,
    [join(rootPath, 'node_modules', 'typescript', 'bin', 'tsc'),
      'src/api/ControlTransport.ts',
      envTypes,
      '--outDir', outDir,
      '--target', 'ES2023',
      '--module', 'ES2022',
      '--moduleResolution', 'bundler',
      '--strict',
      '--noUncheckedIndexedAccess',
      '--exactOptionalPropertyTypes',
      '--useUnknownInCatchVariables',
      '--skipLibCheck',
      '--ignoreConfig',
      '--lib', 'ES2023,DOM',
    ],
    { cwd: rootPath, encoding: 'utf8' },
  );
  if (compile.error || compile.status !== 0) {
    throw new Error(`TypeScript transport compilation failed: ${compile.error ?? ""} ${compile.stdout ?? ""}${compile.stderr ?? ""}`);
  }

  const moduleURL = pathToFileURL(join(outDir, 'ControlTransport.js')).href;

  globalThis.window = {
    go: {
      main: {
        AppBridge: {
          GetSessionConfig: async () => {
            throw new Error('unsafe session descriptor');
          },
        },
      },
    },
  };
  const failed = await import(`${moduleURL}?case=fail-closed`);
  await assert.rejects(
    () => failed.controlTransport.session(),
    /Desktop session discovery failed; refusing direct HTTP fallback\./,
  );

  globalThis.window = {
    go: {
      main: {
        AppBridge: {
          GetSessionConfig: async () => ({
            api_url: 'http://127.0.0.1:8470/',
            api_key: '  session-key  ',
          }),
        },
      },
    },
  };
  const valid = await import(`${moduleURL}?case=valid-wails-session`);
  assert.deepEqual(await valid.controlTransport.session(), {
    apiUrl: 'http://127.0.0.1:8470',
    apiKey: 'session-key',
    source: 'wails',
  });

  let diagnosticRequest;
  globalThis.fetch = async (input, init = {}) => {
    diagnosticRequest = { input: String(input), init };
    return new Response(JSON.stringify({ id: 'diag-7' }), {
      status: 202,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  const diagnosticID = await valid.controlTransport.executeDiagnosticRun('ping', '1.1.1.1');
  assert.equal(diagnosticID, 'diag-7');
  assert.equal(diagnosticRequest.input, 'http://127.0.0.1:8470/api/diagnostics');
  assert.equal(new Headers(diagnosticRequest.init.headers).get('X-API-Key'), 'session-key');
  assert.deepEqual(JSON.parse(diagnosticRequest.init.body), {
    type: 'ping',
    target: '1.1.1.1',
    options: {},
  });

  console.log('transport characterization: 3 checks passed');
} finally {
  delete globalThis.window;
  delete globalThis.fetch;
  rmSync(workDir, { recursive: true, force: true });
}
