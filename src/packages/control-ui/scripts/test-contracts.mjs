import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = new URL('../', import.meta.url);
const rootPath = fileURLToPath(root);
const outDir = mkdtempSync(join(tmpdir(), 'luminet-contracts-'));

try {
  const compile = spawnSync(
    process.execPath,
    [join(rootPath, 'node_modules', 'typescript', 'bin', 'tsc'),
      'src/api/contracts.ts',
      'src/api/qlog.ts',
      '--outDir', outDir,
      '--target', 'ES2023',
      '--module', 'ES2022',
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
    throw new Error(`TypeScript contract compilation failed: ${compile.error ?? ""} ${compile.stdout ?? ""}${compile.stderr ?? ""}`);
  }

  const contracts = await import(pathToFileURL(join(outDir, 'contracts.js')).href);
  const qlog = await import(pathToFileURL(join(outDir, 'qlog.js')).href);

  const status = contracts.parseSystemStatus({
    cpu_usage: 125,
    ram_usage: -10,
    used_ram_gb: -1,
    total_ram_gb: 32,
    disk_free_gb: 120,
  });
  assert.deepEqual(status, {
    cpuUsage: 100,
    ramUsage: 0,
    usedRamGb: 0,
    totalRamGb: 32,
    diskFreeGb: 120,
    configMutationRetry: { calls: 0, commits: 0, conflicts: 0, automaticRetries: 0, exhaustedRetries: 0 },
    remoteMutationRetry: { cooldownKeys: 0, activeScopes: 0, inFlight: 0, cooldownWaits: 0, inFlightWaits: 0, capacityStops: 0, rateLimits: 0, retrySleeps: 0, reconciled: 0 },
    websocketBackpressure: { broadcastDrops: 0, slowClientDisconnects: 0 },
  });

  const statusWithReliability = contracts.parseSystemStatus({
    cpu_usage: 10, ram_usage: 20, used_ram_gb: 2, total_ram_gb: 8, disk_free_gb: 50,
    config_mutation_retry: { calls: 5, commits: 4, conflicts: 2, automatic_retries: 1, exhausted_retries: 1 },
    remote_mutation_retry: { cooldown_keys: 1, active_scopes: 2, in_flight: 3, cooldown_waits: 4, in_flight_waits: 5, capacity_stops: 6, rate_limits: 7, retry_sleeps: 8, reconciled: 9 },
    websocket_backpressure: { broadcast_drops: 2, slow_client_disconnects: 3 },
  });
  assert.equal(statusWithReliability.configMutationRetry.automaticRetries, 1);
  assert.equal(statusWithReliability.websocketBackpressure.slowClientDisconnects, 3);
  assert.throws(() => contracts.parseSystemStatus({
    cpu_usage: 1, ram_usage: 1, used_ram_gb: 1, total_ram_gb: 1, disk_free_gb: 1,
    websocket_backpressure: { broadcast_drops: 'bad', slow_client_disconnects: 0 },
  }), /broadcast_drops must be a finite number/);

  assert.throws(
    () => contracts.parseSystemStatus({
      cpu_usage: Number.NaN,
      ram_usage: 10,
      used_ram_gb: 1,
      total_ram_gb: 2,
      disk_free_gb: 3,
    }),
    /system status\.cpu_usage must be a finite number/,
  );

  assert.deepEqual(
    contracts.parseTelemetryEvent({
      type: 'METRICS_UPDATE',
      data: { rx: -1, tx: 2048, latency: -5 },
    }),
    { type: 'METRICS_UPDATE', data: { rx: 0, tx: 2048, latency: 0 } },
  );

  assert.deepEqual(
    contracts.parseTelemetryEvent({
      type: 'METRICS_UPDATE',
      data: { rx: 1024, tx: 512, latency: null },
    }),
    { type: 'METRICS_UPDATE', data: { rx: 1024, tx: 512, latency: null } },
  );

  assert.deepEqual(
    contracts.parseTelemetryEvent({
      type: 'DIAGNOSTIC_LOG',
      data: { message: 'legacy', isComplete: false },
    }),
    { type: 'SYSTEM_EVENT', name: 'DIAGNOSTIC_LOG', data: { message: 'legacy', isComplete: false } },
  );

  assert.deepEqual(
    contracts.parseTelemetryEvent({ type: 'evasion_log', data: 'tunnel ready' }),
    { type: 'EVASION_LOG', data: 'tunnel ready' },
  );

  assert.deepEqual(
    contracts.parseDiagnosticStatus({
      status: 'completed',
      progress: 140,
      results: '{"metrics":{"results":[]}}',
    }),
    {
      status: 'completed',
      progress: 100,
      results: { metrics: { results: [] } },
    },
  );

  assert.throws(
    () => contracts.parseDiagnosticStatus({
      status: 'completed',
      progress: 100,
      results: '{invalid',
    }),
    /diagnostic results contains invalid JSON/,
  );

  assert.deepEqual(
    contracts.parsePerAppProxyConfig({ mode: 'off', packages: [], supported: false, enforced: false }),
    { mode: 'off', packages: [], supported: false, enforced: false },
  );

  assert.deepEqual(
    contracts.parsePerAppProxyConfig({ mode: 'off', packages: [], supported: false, enforced: false, reason: 'not implemented' }),
    { mode: 'off', packages: [], supported: false, enforced: false, reason: 'not implemented' },
  );

  const warp = contracts.parseWarpScanResults({
    status: 'success',
    results: [
      { Endpoint: '198.51.100.2:2408', RTT: 30_000_000, Error: null },
      { Endpoint: '198.51.100.1:2408', RTT: 10_000_000, Error: null },
      { Endpoint: '198.51.100.3:2408', RTT: 5_000_000, Error: 'timeout' },
    ],
  });
  assert.deepEqual(warp, [
    { endpoint: '198.51.100.1:2408', rttMilliseconds: 10 },
    { endpoint: '198.51.100.2:2408', rttMilliseconds: 30 },
  ]);


  assert.deepEqual(
    contracts.parsePortPreflight({ host: '127.0.0.1', port: 8470, address: '127.0.0.1:8470', available: true, message: 'free' }),
    { host: '127.0.0.1', port: 8470, address: '127.0.0.1:8470', available: true, message: 'free' },
  );

  assert.deepEqual(
    contracts.parseRuntimeEngines({ engines: [{ id: 'sstp', name: 'SSTP', description: 'system tunnel', running: false, socks_port: 0, mode: 'system-tunnel', available: false, availability_reason: 'sstpc not found' }] }),
    [{ id: 'sstp', name: 'SSTP', description: 'system tunnel', running: false, socksPort: 0, mode: 'system-tunnel', available: false, availabilityReason: 'sstpc not found' }],
  );

  const doctor = contracts.parseDoctorReport({
    timestamp: '2026-08-11T12:00:00Z', healthy: false, go_version: 'go1.26', goos: 'linux', goarch: 'amd64',
    checks: [{ name: 'db', ok: true, message: 'ready', latency_ns: 1200 }, { name: 'core', ok: false, message: 'degraded', latency_ns: 500 }],
  });
  assert.equal(doctor.healthy, false);
  assert.equal(doctor.checks.length, 2);
  assert.equal(doctor.checks[1].name, 'core');

  const updatePlan = contracts.parseUpdatePlan({
    key_id: 'primary', release_id: 'r42', version: '5.0.0', from_version: '4.0.0', rollback_version: '4.0.0',
    artifact_url: 'https://example.test/a', artifact_sha256: 'ab'.repeat(32), artifact_size: 123,
    published_at: '2026-08-11T10:00:00Z', expires_at: '2026-08-12T10:00:00Z', verified_at: '2026-08-11T11:00:00Z', apply_authorized: false,
  });
  assert.equal(updatePlan.releaseId, 'r42');
  assert.equal(updatePlan.applyAuthorized, false);

  const discovery = contracts.parseUpdateDiscovery({ envelope: { key_id: 'primary', payload: 'payload64', signature: 'signature64' }, plan: {
    key_id: 'primary', release_id: 'r42', version: '5.0.0', from_version: '4.0.0', rollback_version: '4.0.0',
    artifact_url: 'https://example.test/a', artifact_sha256: 'ab'.repeat(32), artifact_size: 123,
    published_at: '2026-08-11T10:00:00Z', expires_at: '2026-08-12T10:00:00Z', verified_at: '2026-08-11T11:00:00Z', apply_authorized: false,
  } });
  assert.equal(discovery.envelope.keyId, 'primary');
  assert.equal(discovery.plan.version, '5.0.0');

  const trace = qlog.parseTransportTrace(JSON.stringify({ traces: [{ events: [
    [0, 'transport', 'packet_sent', { size: 1200 }],
    [1.5, 'recovery', 'metrics_updated', { cwnd: 12000 }],
    [2.0, 'transport', 'packet_received', { size: 800 }],
  ] }] }));
  assert.equal(trace.format, 'qlog');
  assert.equal(trace.totalEvents, 3);
  assert.deepEqual(trace.categories[0], { name: 'transport', count: 2 });

  const tooManyTraceEvents = Array.from({ length: 100_001 }, () => [0, 'transport', 'packet']);
  assert.throws(() => qlog.parseTransportTrace(JSON.stringify({ traces: [{ events: tooManyTraceEvents }] })), /more than 100000 events/);

  const netlog = qlog.parseTransportTrace(JSON.stringify({
    constants: { logEventTypes: { URL_REQUEST: 42 }, logSourceType: { URL_REQUEST: 7 }, logEventPhase: { PHASE_BEGIN: 1 } },
    events: [{ time: '1.25', type: 42, phase: 1, source: { id: 1, type: 7 }, params: { url: 'https://example.test/' } }],
  }));
  assert.equal(netlog.format, 'netlog');
  assert.equal(netlog.totalEvents, 1);
  assert.equal(netlog.retainedEvents[0].category, 'URL_REQUEST');
  assert.equal(netlog.retainedEvents[0].name, 'URL_REQUEST · PHASE_BEGIN');
  assert.equal(netlog.retainedEvents[0].time, 1.25);

  const profile = contracts.parseSubscriptionProfile({
    id: 'profile-1', name: 'Primary', url: 'https://provider.example/sub', mirrors: ['https://mirror.example/sub'],
    last_source_url: 'https://mirror.example/sub', update_interval_hours: 6, active: true, remote_fetch_enabled: true,
    auto_refresh: true, node_count: 42, source_health: { consecutive_failures: 0 },
    source_health_by_url: { 'https://mirror.example/sub': { consecutive_failures: 1, last_error: 'temporary failure' } },
    subscription_info: { upload: 1024, download: 2048, total: 4096, expire: '2027-01-01T00:00:00Z', profile_title: 'Gold' },
    entitlement: { status: 'warning', quota_known: true, expiry_known: true, used_bytes: 3072, remaining_bytes: 1024, usage_percent: 75, seconds_until_expiry: 3600, warnings: ['expires_soon', 'expires_soon'] },
  });
  assert.equal(profile.sourceHealthByUrl['https://mirror.example/sub'].consecutiveFailures, 1);
  assert.equal(profile.subscriptionInfo.profileTitle, 'Gold');
  assert.equal(profile.entitlement.status, 'warning');
  assert.equal(profile.entitlement.remainingBytes, 1024);
  assert.deepEqual(profile.entitlement.warnings, ['expires_soon']);

  const legacyProfile = contracts.parseSubscriptionProfile({
    id: 'legacy', name: 'Legacy', url: 'https://provider.example/legacy', mirrors: [],
    update_interval_hours: 6, active: true, remote_fetch_enabled: false, auto_refresh: false,
    node_count: 0, source_health: { consecutive_failures: 0 }, source_health_by_url: {},
  });
  assert.deepEqual(legacyProfile.entitlement, {
    status: 'unknown', quotaKnown: false, expiryKnown: false, usedBytes: 0, remainingBytes: 0, usagePercent: 0, warnings: [],
  });

  console.log('contracts characterization: 30 checks passed');
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
