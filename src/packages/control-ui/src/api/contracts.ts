export type Decoder<T> = (value: unknown) => T;

export interface ConfigMutationRetryStats {
  calls: number;
  commits: number;
  conflicts: number;
  automaticRetries: number;
  exhaustedRetries: number;
}

export interface RemoteMutationRetryStats {
  cooldownKeys: number;
  activeScopes: number;
  inFlight: number;
  cooldownWaits: number;
  inFlightWaits: number;
  capacityStops: number;
  rateLimits: number;
  retrySleeps: number;
  reconciled: number;
}

export interface WebSocketBackpressureStats {
  broadcastDrops: number;
  slowClientDisconnects: number;
}

export interface SystemStatus {
  cpuUsage: number;
  ramUsage: number;
  usedRamGb: number;
  totalRamGb: number;
  diskFreeGb: number;
  configMutationRetry: ConfigMutationRetryStats;
  remoteMutationRetry: RemoteMutationRetryStats;
  websocketBackpressure: WebSocketBackpressureStats;
}

export interface GeoIPData {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  asn?: string;
}

interface PingResult {
  success: boolean;
  latencyMs: number;
  error?: string;
}

export interface MatrixResult {
  utls: string;
  fakeRepeat: number;
  enableFragment: boolean;
  pass: boolean;
  latencyMs: number;
  error?: string;
}

export interface DiagnosticStatus {
  status: 'pending' | 'running' | 'completed' | 'failed' | string;
  progress: number;
  results: unknown;
  error?: string;
}

interface LogsResponse {
  logs: string[];
}

export type TelemetryEvent =
  | {
      type: 'METRICS_UPDATE';
      data: { rx: number; tx: number; latency: number | null };
    }
  | {
      type: 'EVASION_LOG';
      data: string;
    }
  | {
      type: 'SYSTEM_EVENT';
      name: string;
      data: unknown;
    };

type UnknownRecord = Record<string, unknown>;

function asRecord(value: unknown, context: string): UnknownRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${context} must be a JSON object`);
  }
  return value as UnknownRecord;
}

function readString(record: UnknownRecord, key: string, context: string): string {
  const value = record[key];
  if (typeof value !== 'string') {
    throw new Error(`${context}.${key} must be a string`);
  }
  return value;
}

function readOptionalString(record: UnknownRecord, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' && value.trim() !== '' ? value : undefined;
}

function readNumber(record: UnknownRecord, key: string, context: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${context}.${key} must be a finite number`);
  }
  return value;
}

function readBoolean(record: UnknownRecord, key: string, context: string): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') {
    throw new Error(`${context}.${key} must be a boolean`);
  }
  return value;
}

function clampPercent(value: number): number {
  return Math.min(100, Math.max(0, value));
}

function readNonNegativeNumber(record: UnknownRecord, key: string, context: string): number {
  return Math.max(0, readNumber(record, key, context));
}

function optionalStatsRecord(record: UnknownRecord, key: string, context: string): UnknownRecord | null {
  const value = record[key];
  if (value === undefined || value === null) {
    return null;
  }
  return asRecord(value, `${context}.${key}`);
}

function parseConfigMutationRetryStats(record: UnknownRecord): ConfigMutationRetryStats {
  const context = 'system status.config_mutation_retry';
  return {
    calls: readNonNegativeNumber(record, 'calls', context),
    commits: readNonNegativeNumber(record, 'commits', context),
    conflicts: readNonNegativeNumber(record, 'conflicts', context),
    automaticRetries: readNonNegativeNumber(record, 'automatic_retries', context),
    exhaustedRetries: readNonNegativeNumber(record, 'exhausted_retries', context),
  };
}

function parseRemoteMutationRetryStats(record: UnknownRecord): RemoteMutationRetryStats {
  const context = 'system status.remote_mutation_retry';
  return {
    cooldownKeys: readNonNegativeNumber(record, 'cooldown_keys', context),
    activeScopes: readNonNegativeNumber(record, 'active_scopes', context),
    inFlight: readNonNegativeNumber(record, 'in_flight', context),
    cooldownWaits: readNonNegativeNumber(record, 'cooldown_waits', context),
    inFlightWaits: readNonNegativeNumber(record, 'in_flight_waits', context),
    capacityStops: readNonNegativeNumber(record, 'capacity_stops', context),
    rateLimits: readNonNegativeNumber(record, 'rate_limits', context),
    retrySleeps: readNonNegativeNumber(record, 'retry_sleeps', context),
    reconciled: readNonNegativeNumber(record, 'reconciled', context),
  };
}

function parseWebSocketBackpressureStats(record: UnknownRecord): WebSocketBackpressureStats {
  const context = 'system status.websocket_backpressure';
  return {
    broadcastDrops: readNonNegativeNumber(record, 'broadcast_drops', context),
    slowClientDisconnects: readNonNegativeNumber(record, 'slow_client_disconnects', context),
  };
}

const zeroConfigMutationRetryStats = (): ConfigMutationRetryStats => ({
  calls: 0, commits: 0, conflicts: 0, automaticRetries: 0, exhaustedRetries: 0,
});
const zeroRemoteMutationRetryStats = (): RemoteMutationRetryStats => ({
  cooldownKeys: 0, activeScopes: 0, inFlight: 0, cooldownWaits: 0, inFlightWaits: 0,
  capacityStops: 0, rateLimits: 0, retrySleeps: 0, reconciled: 0,
});
const zeroWebSocketBackpressureStats = (): WebSocketBackpressureStats => ({
  broadcastDrops: 0, slowClientDisconnects: 0,
});

export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim() !== '') {
    return error.message;
  }
  return fallback;
}

export function parseSystemStatus(value: unknown): SystemStatus {
  const record = asRecord(value, 'system status');
  const configMutationRetry = optionalStatsRecord(record, 'config_mutation_retry', 'system status');
  const remoteMutationRetry = optionalStatsRecord(record, 'remote_mutation_retry', 'system status');
  const websocketBackpressure = optionalStatsRecord(record, 'websocket_backpressure', 'system status');
  return {
    cpuUsage: clampPercent(readNumber(record, 'cpu_usage', 'system status')),
    ramUsage: clampPercent(readNumber(record, 'ram_usage', 'system status')),
    usedRamGb: Math.max(0, readNumber(record, 'used_ram_gb', 'system status')),
    totalRamGb: Math.max(0, readNumber(record, 'total_ram_gb', 'system status')),
    diskFreeGb: Math.max(0, readNumber(record, 'disk_free_gb', 'system status')),
    configMutationRetry: configMutationRetry ? parseConfigMutationRetryStats(configMutationRetry) : zeroConfigMutationRetryStats(),
    remoteMutationRetry: remoteMutationRetry ? parseRemoteMutationRetryStats(remoteMutationRetry) : zeroRemoteMutationRetryStats(),
    websocketBackpressure: websocketBackpressure ? parseWebSocketBackpressureStats(websocketBackpressure) : zeroWebSocketBackpressureStats(),
  };
}

export function parseGeoIPData(value: unknown): GeoIPData {
  const record = asRecord(value, 'GeoIP response');
  const asn = readOptionalString(record, 'asn');
  return {
    ip: readString(record, 'ip', 'GeoIP response'),
    country: readString(record, 'country', 'GeoIP response'),
    countryCode: readString(record, 'country_code', 'GeoIP response'),
    region: readString(record, 'region', 'GeoIP response'),
    city: readString(record, 'city', 'GeoIP response'),
    ...(asn ? { asn } : {}),
  };
}

export function parsePingResult(value: unknown): PingResult {
  const record = asRecord(value, 'ping response');
  const error = readOptionalString(record, 'error');
  return {
    success: readBoolean(record, 'success', 'ping response'),
    latencyMs: readNumber(record, 'latency_ms', 'ping response'),
    ...(error ? { error } : {}),
  };
}

function parseJSONIfString(value: unknown, context: string): unknown {
  if (typeof value !== 'string') {
    return value;
  }
  if (value.trim() === '') {
    return null;
  }
  try {
    return JSON.parse(value) as unknown;
  } catch (error) {
    throw new Error(`${context} contains invalid JSON: ${errorMessage(error, 'parse failed')}`);
  }
}

export function parseDiagnosticStatus(value: unknown): DiagnosticStatus {
  const record = asRecord(value, 'diagnostic status');
  const status = readString(record, 'status', 'diagnostic status');
  const progressValue = record.progress;
  const progress = typeof progressValue === 'number' && Number.isFinite(progressValue)
    ? clampPercent(progressValue)
    : 0;
  const error = readOptionalString(record, 'error');
  return {
    status,
    progress,
    results: parseJSONIfString(record.results, 'diagnostic results'),
    ...(error ? { error } : {}),
  };
}

export function parseMatrixResults(value: unknown): MatrixResult[] {
  const resultRecord = asRecord(value, 'diagnostic result');
  const metrics = asRecord(resultRecord.metrics, 'diagnostic result.metrics');
  const rows = metrics.results;
  if (!Array.isArray(rows)) {
    throw new Error('diagnostic result.metrics.results must be an array');
  }

  return rows.map((row, index) => {
    const record = asRecord(row, `matrix result[${index}]`);
    const error = readOptionalString(record, 'error');
    return {
      utls: readString(record, 'utls', `matrix result[${index}]`),
      fakeRepeat: readNumber(record, 'fake_repeat', `matrix result[${index}]`),
      enableFragment: readBoolean(record, 'enable_fragment', `matrix result[${index}]`),
      pass: readBoolean(record, 'pass', `matrix result[${index}]`),
      latencyMs: readNumber(record, 'latency_ms', `matrix result[${index}]`),
      ...(error ? { error } : {}),
    };
  });
}

export function parseLogsResponse(value: unknown): LogsResponse {
  const record = asRecord(value, 'logs response');
  if (!Array.isArray(record.logs) || !record.logs.every((entry) => typeof entry === 'string')) {
    throw new Error('logs response.logs must be an array of strings');
  }
  return { logs: record.logs.slice(-500) };
}

export function parseTelemetryEvent(value: unknown): TelemetryEvent {
  const record = asRecord(value, 'telemetry frame');
  const type = readString(record, 'type', 'telemetry frame');
  const data = record.data;

  if (type === 'METRICS_UPDATE') {
    const metrics = asRecord(data, 'METRICS_UPDATE.data');
    return {
      type,
      data: {
        rx: Math.max(0, readNumber(metrics, 'rx', 'METRICS_UPDATE.data')),
        tx: Math.max(0, readNumber(metrics, 'tx', 'METRICS_UPDATE.data')),
        latency: metrics.latency === null
          ? null
          : Math.max(0, readNumber(metrics, 'latency', 'METRICS_UPDATE.data')),
      },
    };
  }

  if (type === 'evasion_log') {
    if (typeof data !== 'string') {
      throw new Error('evasion_log.data must be a string');
    }
    return { type: 'EVASION_LOG', data };
  }

  return { type: 'SYSTEM_EVENT', name: type, data };
}

export function parsePerAppProxyConfig(value: unknown): {
  mode: string;
  packages: string[];
  supported: boolean;
  enforced: boolean;
  reason?: string;
} {
  const record = asRecord(value, 'per-app proxy response');
  if (!Array.isArray(record.packages) || !record.packages.every((entry) => typeof entry === 'string')) {
    throw new Error('per-app proxy response.packages must be an array of strings');
  }
  const supported = record.supported === undefined ? true : readBoolean(record, 'supported', 'per-app proxy response');
  const enforced = record.enforced === undefined ? supported : readBoolean(record, 'enforced', 'per-app proxy response');
  const reason = readOptionalString(record, 'reason');
  return {
    mode: readString(record, 'mode', 'per-app proxy response'),
    packages: record.packages,
    supported,
    enforced,
    ...(reason === undefined ? {} : { reason }),
  };
}

export function parseDNSConfig(value: unknown): { interface: string; servers: string[]; source: string } {
  const record = asRecord(value, 'DNS response');
  if (!Array.isArray(record.servers) || !record.servers.every((entry) => typeof entry === 'string')) {
    throw new Error('DNS response.servers must be an array of strings');
  }
  return {
    interface: readString(record, 'interface', 'DNS response'),
    servers: record.servers,
    source: readString(record, 'source', 'DNS response'),
  };
}


interface EvasionSettings {
  running: boolean;
  splitBytes: number;
  delayMs: number;
  mutateHost: boolean;
  fakePacketInject: boolean;
  wsUseUtls: boolean;
  wsFingerprint: string;
}

export interface WarpParams {
  ipv4: string;
  ipv6: string;
  reserved: number[];
  publicKey: string;
  privateKey: string;
  clientID: string;
}

export interface WarpScanResult {
  endpoint: string;
  rttMilliseconds: number;
}

export function parseEvasionSettings(value: unknown): EvasionSettings {
  const record = asRecord(value, 'evasion settings');
  return {
    running: readBoolean(record, 'running', 'evasion settings'),
    splitBytes: readNumber(record, 'split_bytes', 'evasion settings'),
    delayMs: readNumber(record, 'delay_ms', 'evasion settings'),
    mutateHost: readBoolean(record, 'mutate_host', 'evasion settings'),
    fakePacketInject: readBoolean(record, 'fake_packet_inject', 'evasion settings'),
    wsUseUtls: readBoolean(record, 'ws_use_utls', 'evasion settings'),
    wsFingerprint: readString(record, 'ws_fingerprint', 'evasion settings'),
  };
}

export function parseWarpParams(value: unknown): WarpParams {
  const record = asRecord(value, 'WARP profile');
  const reserved = record.reserved;
  if (!Array.isArray(reserved) || !reserved.every((item) => typeof item === 'number' && Number.isInteger(item))) {
    throw new Error('WARP profile.reserved must be an array of integers');
  }
  return {
    ipv4: readString(record, 'ipv4', 'WARP profile'),
    ipv6: readString(record, 'ipv6', 'WARP profile'),
    reserved,
    publicKey: readString(record, 'public_key', 'WARP profile'),
    privateKey: readString(record, 'private_key', 'WARP profile'),
    clientID: readString(record, 'client_id', 'WARP profile'),
  };
}

export function parseWarpScanResults(value: unknown): WarpScanResult[] {
  const record = asRecord(value, 'WARP scan response');
  if (readString(record, 'status', 'WARP scan response') !== 'success') {
    throw new Error('WARP scan did not report success');
  }
  if (!Array.isArray(record.results)) {
    throw new Error('WARP scan response.results must be an array');
  }

  const results: WarpScanResult[] = [];
  record.results.forEach((item, index) => {
    const row = asRecord(item, `WARP scan response.results[${index}]`);
    if (row.Error !== null && row.Error !== undefined) {
      return;
    }
    const endpoint = readString(row, 'Endpoint', `WARP scan response.results[${index}]`);
    const rttNanoseconds = readNumber(row, 'RTT', `WARP scan response.results[${index}]`);
    results.push({ endpoint, rttMilliseconds: Math.max(0, rttNanoseconds / 1_000_000) });
  });
  return results.sort((left, right) => left.rttMilliseconds - right.rttMilliseconds);
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface DoctorCheck {
  name: string;
  ok: boolean;
  message: string;
  latencyNs: number;
}

export interface DoctorReport {
  timestamp: string;
  healthy: boolean;
  checks: DoctorCheck[];
  goVersion: string;
  goos: string;
  goarch: string;
}

export interface DiagnosticPhase {
  number: number;
  name: string;
  description: string;
}

export interface RuntimeEngineStatus {
  id: string;
  name: string;
  description: string;
  running: boolean;
  socksPort: number;
  mode: string;
  available: boolean;
  binaryPath?: string;
  availabilityReason?: string;
}

export interface PortPreflightResult {
  host: string;
  port: number;
  address: string;
  available: boolean;
  message: string;
}

export interface UpdateEnvelope {
  keyId: string;
  payload: string;
  signature: string;
}

export interface UpdateDiscovery {
  envelope: UpdateEnvelope;
  plan: UpdatePlan;
}

export interface UpdatePlan {
  keyId: string;
  releaseId: string;
  version: string;
  fromVersion: string;
  rollbackVersion: string;
  artifactUrl: string;
  artifactSha256: string;
  artifactSize: number;
  publishedAt: string;
  expiresAt: string;
  verifiedAt: string;
  applyAuthorized: boolean;
}

export interface UpdateStageResult {
  plan: UpdatePlan;
  path: string;
  receiptPath: string;
  sha256: string;
  bytes: number;
  stagedAt: string;
  applyAuthorized: boolean;
  reused: boolean;
}

export type SubscriptionSourceFailureKind =
  | 'certificate_verification'
  | 'path_interference_suspected'
  | 'timeout'
  | 'canceled'
  | 'network_failure';

export interface SubscriptionSourceHealth {
  lastAttemptAt?: string;
  lastSuccessAt?: string;
  consecutiveFailures: number;
  nextEligibleAt?: string;
  lastError?: string;
  failureKind?: SubscriptionSourceFailureKind;
}

export interface SubscriptionInfo {
  upload: number;
  download: number;
  total: number;
  expire?: string;
  webPageUrl?: string;
  supportUrl?: string;
  profileTitle?: string;
  announcement?: string;
  refillDate?: string;
}

export interface SubscriptionEntitlement {
  status: string;
  quotaKnown: boolean;
  expiryKnown: boolean;
  usedBytes: number;
  remainingBytes: number;
  usagePercent: number;
  secondsUntilExpiry?: number;
  secondsUntilRefill?: number;
  warnings: string[];
}

export interface SubscriptionNode {
  id: string;
  protocol: string;
  name?: string;
  address: string;
  port: number;
  transport?: string;
  tls: boolean;
  sni?: string;
  hidden: boolean;
  runtimeActivatable: boolean;
  runtimeCores: string[];
  runtimeReason?: string;
}

export interface SubscriptionRuntimeStatus {
  active: boolean;
  profileId?: string;
  nodeId?: string;
  socksPort?: number;
}

export interface SubscriptionProfile {
  id: string;
  name: string;
  url: string;
  mirrors: string[];
  lastSourceUrl?: string;
  lastUpdated?: string;
  updateIntervalHours: number;
  active: boolean;
  remoteFetchEnabled: boolean;
  autoRefresh: boolean;
  nodeCount: number;
  sourceHealth: SubscriptionSourceHealth;
  sourceHealthByUrl: Record<string, SubscriptionSourceHealth>;
  subscriptionInfo?: SubscriptionInfo;
  entitlement: SubscriptionEntitlement;
}

export function parseDoctorReport(value: unknown): DoctorReport {
  const record = asRecord(value, 'doctor report');
  if (!Array.isArray(record.checks)) {
    throw new Error('doctor report.checks must be an array');
  }
  const checks = record.checks.map((item, index) => {
    const row = asRecord(item, `doctor report.checks[${index}]`);
    return {
      name: readString(row, 'name', `doctor report.checks[${index}]`),
      ok: readBoolean(row, 'ok', `doctor report.checks[${index}]`),
      message: readOptionalString(row, 'message') ?? '',
      latencyNs: Math.max(0, typeof row.latency_ns === 'number' && Number.isFinite(row.latency_ns) ? row.latency_ns : 0),
    };
  });
  return {
    timestamp: readString(record, 'timestamp', 'doctor report'),
    healthy: readBoolean(record, 'healthy', 'doctor report'),
    checks,
    goVersion: readString(record, 'go_version', 'doctor report'),
    goos: readString(record, 'goos', 'doctor report'),
    goarch: readString(record, 'goarch', 'doctor report'),
  };
}

export function parseDiagnosticPhases(value: unknown): DiagnosticPhase[] {
  const record = asRecord(value, 'diagnostic phases response');
  if (!Array.isArray(record.phases)) {
    throw new Error('diagnostic phases response.phases must be an array');
  }
  return record.phases.map((item, index) => {
    const phase = asRecord(item, `diagnostic phases[${index}]`);
    return {
      number: readNumber(phase, 'number', `diagnostic phases[${index}]`),
      name: readString(phase, 'name', `diagnostic phases[${index}]`),
      description: readString(phase, 'description', `diagnostic phases[${index}]`),
    };
  });
}

export function parseRuntimeEngines(value: unknown): RuntimeEngineStatus[] {
  const record = asRecord(value, 'runtime engines response');
  if (!Array.isArray(record.engines)) {
    throw new Error('runtime engines response.engines must be an array');
  }
  return record.engines.map((item, index) => {
    const engine = asRecord(item, `runtime engines[${index}]`);
    return {
      id: readString(engine, 'id', `runtime engines[${index}]`),
      name: readString(engine, 'name', `runtime engines[${index}]`),
      description: readString(engine, 'description', `runtime engines[${index}]`),
      running: readBoolean(engine, 'running', `runtime engines[${index}]`),
      socksPort: typeof engine.socks_port === 'number' && Number.isFinite(engine.socks_port) ? engine.socks_port : 0,
      mode: readOptionalString(engine, 'mode') ?? (engine.socks_port ? 'socks' : 'system-tunnel'),
      available: engine.available === undefined ? true : readBoolean(engine, 'available', `runtime engines[${index}]`),
      ...(readOptionalString(engine, 'binary_path') ? { binaryPath: readOptionalString(engine, 'binary_path')! } : {}),
      ...(readOptionalString(engine, 'availability_reason') ? { availabilityReason: readOptionalString(engine, 'availability_reason')! } : {}),
    };
  });
}

export function parsePortPreflight(value: unknown): PortPreflightResult {
  const record = asRecord(value, 'port preflight response');
  return {
    host: readString(record, 'host', 'port preflight response'),
    port: readNumber(record, 'port', 'port preflight response'),
    address: readString(record, 'address', 'port preflight response'),
    available: readBoolean(record, 'available', 'port preflight response'),
    message: readString(record, 'message', 'port preflight response'),
  };
}

function parseUpdatePlanRecord(record: UnknownRecord, context: string): UpdatePlan {
  return {
    keyId: readString(record, 'key_id', context),
    releaseId: readString(record, 'release_id', context),
    version: readString(record, 'version', context),
    fromVersion: readString(record, 'from_version', context),
    rollbackVersion: readString(record, 'rollback_version', context),
    artifactUrl: readString(record, 'artifact_url', context),
    artifactSha256: readString(record, 'artifact_sha256', context),
    artifactSize: Math.max(0, readNumber(record, 'artifact_size', context)),
    publishedAt: readString(record, 'published_at', context),
    expiresAt: readString(record, 'expires_at', context),
    verifiedAt: readString(record, 'verified_at', context),
    applyAuthorized: readBoolean(record, 'apply_authorized', context),
  };
}

export function parseUpdatePlan(value: unknown): UpdatePlan {
  return parseUpdatePlanRecord(asRecord(value, 'update plan'), 'update plan');
}

export function parseUpdateDiscovery(value: unknown): UpdateDiscovery {
  const record = asRecord(value, 'update discovery response');
  const envelope = asRecord(record.envelope, 'update discovery response.envelope');
  return {
    envelope: {
      keyId: readString(envelope, 'key_id', 'update discovery response.envelope'),
      payload: readString(envelope, 'payload', 'update discovery response.envelope'),
      signature: readString(envelope, 'signature', 'update discovery response.envelope'),
    },
    plan: parseUpdatePlanRecord(asRecord(record.plan, 'update discovery response.plan'), 'update discovery response.plan'),
  };
}

export function parseUpdateStage(value: unknown): UpdateStageResult {
  const record = asRecord(value, 'update stage response');
  return {
    plan: parseUpdatePlanRecord(asRecord(record.plan, 'update stage response.plan'), 'update stage response.plan'),
    path: readString(record, 'path', 'update stage response'),
    receiptPath: readString(record, 'receipt_path', 'update stage response'),
    sha256: readString(record, 'sha256', 'update stage response'),
    bytes: Math.max(0, readNumber(record, 'bytes', 'update stage response')),
    stagedAt: readString(record, 'staged_at', 'update stage response'),
    applyAuthorized: readBoolean(record, 'apply_authorized', 'update stage response'),
    reused: readBoolean(record, 'reused', 'update stage response'),
  };
}

function parseSourceFailureKind(value: unknown): SubscriptionSourceFailureKind | undefined {
  switch (value) {
    case 'certificate_verification':
    case 'path_interference_suspected':
    case 'timeout':
    case 'canceled':
    case 'network_failure':
      return value;
    default:
      return undefined;
  }
}

function parseSourceHealth(value: unknown, context: string): SubscriptionSourceHealth {
  const record = asRecord(value ?? {}, context);
  const lastAttemptAt = readOptionalString(record, 'last_attempt_at');
  const lastSuccessAt = readOptionalString(record, 'last_success_at');
  const nextEligibleAt = readOptionalString(record, 'next_eligible_at');
  const lastError = readOptionalString(record, 'last_error');
  const failureKind = parseSourceFailureKind(record.failure_kind);
  return {
    consecutiveFailures: typeof record.consecutive_failures === 'number' && Number.isFinite(record.consecutive_failures)
      ? Math.max(0, record.consecutive_failures)
      : 0,
    ...(lastAttemptAt ? { lastAttemptAt } : {}),
    ...(lastSuccessAt ? { lastSuccessAt } : {}),
    ...(nextEligibleAt ? { nextEligibleAt } : {}),
    ...(lastError ? { lastError } : {}),
    ...(failureKind ? { failureKind } : {}),
  };
}

function parseSubscriptionInfo(value: unknown, context: string): SubscriptionInfo | undefined {
  if (value === null || value === undefined) return undefined;
  const record = asRecord(value, context);
  const expire = readOptionalString(record, 'expire');
  const webPageUrl = readOptionalString(record, 'web_page_url');
  const supportUrl = readOptionalString(record, 'support_url');
  const profileTitle = readOptionalString(record, 'profile_title');
  const announcement = readOptionalString(record, 'announcement');
  const refillDate = readOptionalString(record, 'refill_date');
  return {
    upload: Math.max(0, typeof record.upload === 'number' && Number.isFinite(record.upload) ? record.upload : 0),
    download: Math.max(0, typeof record.download === 'number' && Number.isFinite(record.download) ? record.download : 0),
    total: Math.max(0, typeof record.total === 'number' && Number.isFinite(record.total) ? record.total : 0),
    ...(expire ? { expire } : {}),
    ...(webPageUrl ? { webPageUrl } : {}),
    ...(supportUrl ? { supportUrl } : {}),
    ...(profileTitle ? { profileTitle } : {}),
    ...(announcement ? { announcement } : {}),
    ...(refillDate ? { refillDate } : {}),
  };
}

function parseSubscriptionEntitlement(value: unknown, context: string): SubscriptionEntitlement {
  if (value === null || value === undefined) {
    return { status: 'unknown', quotaKnown: false, expiryKnown: false, usedBytes: 0, remainingBytes: 0, usagePercent: 0, warnings: [] };
  }
  const record = asRecord(value, context);
  const warnings = Array.isArray(record.warnings) && record.warnings.every((item) => typeof item === 'string')
    ? [...new Set(record.warnings)]
    : [];
  const secondsUntilExpiry = typeof record.seconds_until_expiry === 'number' && Number.isFinite(record.seconds_until_expiry)
    ? Math.max(0, Math.floor(record.seconds_until_expiry))
    : undefined;
  const secondsUntilRefill = typeof record.seconds_until_refill === 'number' && Number.isFinite(record.seconds_until_refill)
    ? Math.max(0, Math.floor(record.seconds_until_refill))
    : undefined;
  return {
    status: readOptionalString(record, 'status') ?? 'unknown',
    quotaKnown: record.quota_known === undefined ? false : readBoolean(record, 'quota_known', context),
    expiryKnown: record.expiry_known === undefined ? false : readBoolean(record, 'expiry_known', context),
    usedBytes: Math.max(0, typeof record.used_bytes === 'number' && Number.isFinite(record.used_bytes) ? record.used_bytes : 0),
    remainingBytes: Math.max(0, typeof record.remaining_bytes === 'number' && Number.isFinite(record.remaining_bytes) ? record.remaining_bytes : 0),
    usagePercent: clampPercent(typeof record.usage_percent === 'number' && Number.isFinite(record.usage_percent) ? record.usage_percent : 0),
    ...(secondsUntilExpiry !== undefined ? { secondsUntilExpiry } : {}),
    ...(secondsUntilRefill !== undefined ? { secondsUntilRefill } : {}),
    warnings,
  };
}

function parseSubscriptionProfileRecord(value: unknown, context: string): SubscriptionProfile {
  const record = asRecord(value, context);
  const mirrors = Array.isArray(record.mirrors) && record.mirrors.every((item) => typeof item === 'string')
    ? record.mirrors
    : [];
  const lastSourceUrl = readOptionalString(record, 'last_source_url');
  const lastUpdated = readOptionalString(record, 'last_updated');
  const rawSourceHealthByUrl = isRecord(record.source_health_by_url) ? record.source_health_by_url : {};
  const sourceHealthByUrl = Object.fromEntries(
    Object.entries(rawSourceHealthByUrl).map(([sourceUrl, health]) => [sourceUrl, parseSourceHealth(health, `${context}.source_health_by_url[${sourceUrl}]`)]),
  );
  const subscriptionInfo = parseSubscriptionInfo(record.subscription_info, `${context}.subscription_info`);
  const entitlement = parseSubscriptionEntitlement(record.entitlement, `${context}.entitlement`);
  return {
    id: readString(record, 'id', context),
    name: readString(record, 'name', context),
    url: readString(record, 'url', context),
    mirrors,
    ...(lastSourceUrl ? { lastSourceUrl } : {}),
    ...(lastUpdated ? { lastUpdated } : {}),
    updateIntervalHours: typeof record.update_interval_hours === 'number' && Number.isFinite(record.update_interval_hours)
      ? Math.max(0, record.update_interval_hours)
      : 0,
    active: record.active === undefined ? true : readBoolean(record, 'active', context),
    remoteFetchEnabled: record.remote_fetch_enabled === undefined ? false : readBoolean(record, 'remote_fetch_enabled', context),
    autoRefresh: record.auto_refresh === undefined ? false : readBoolean(record, 'auto_refresh', context),
    nodeCount: typeof record.node_count === 'number' && Number.isFinite(record.node_count) ? Math.max(0, record.node_count) : 0,
    sourceHealth: parseSourceHealth(record.source_health ?? {}, `${context}.source_health`),
    sourceHealthByUrl,
    ...(subscriptionInfo ? { subscriptionInfo } : {}),
    entitlement,
  };
}

export function parseSubscriptionNodes(value: unknown): SubscriptionNode[] {
  const record = asRecord(value, 'subscription nodes response');
  if (!Array.isArray(record.nodes)) throw new Error('subscription nodes response.nodes must be an array');
  return record.nodes.map((item, index) => {
    const node = asRecord(item, `subscription nodes[${index}]`);
    const name = readOptionalString(node, 'name');
    const transport = readOptionalString(node, 'transport');
    const sni = readOptionalString(node, 'sni');
    const runtimeReason = readOptionalString(node, 'runtime_reason');
    return {
      id: readString(node, 'id', `subscription nodes[${index}]`),
      protocol: readString(node, 'protocol', `subscription nodes[${index}]`),
      ...(name ? { name } : {}),
      address: readString(node, 'address', `subscription nodes[${index}]`),
      port: Math.max(0, readNumber(node, 'port', `subscription nodes[${index}]`)),
      ...(transport ? { transport } : {}),
      tls: node.tls === undefined ? false : readBoolean(node, 'tls', `subscription nodes[${index}]`),
      ...(sni ? { sni } : {}),
      hidden: node.hidden === undefined ? false : readBoolean(node, 'hidden', `subscription nodes[${index}]`),
      runtimeActivatable: node.runtime_activatable === undefined ? false : readBoolean(node, 'runtime_activatable', `subscription nodes[${index}]`),
      runtimeCores: Array.isArray(node.runtime_cores) ? node.runtime_cores.map((core, coreIndex) => {
        if (typeof core !== 'string') throw new Error(`subscription nodes[${index}].runtime_cores[${coreIndex}] must be a string`);
        return core;
      }) : [],
      ...(runtimeReason ? { runtimeReason } : {}),
    };
  });
}

export function parseSubscriptionRuntime(value: unknown): SubscriptionRuntimeStatus {
  const envelope = asRecord(value, 'subscription runtime response');
  const record = asRecord(envelope.runtime ?? {}, 'subscription runtime response.runtime');
  const active = record.active === undefined ? false : readBoolean(record, 'active', 'subscription runtime response.runtime');
  const profileId = readOptionalString(record, 'profile_id');
  const nodeId = readOptionalString(record, 'node_id');
  const socksPort = typeof record.socks_port === 'number' && Number.isFinite(record.socks_port)
    ? Math.max(0, Math.floor(record.socks_port))
    : undefined;
  return {
    active,
    ...(profileId ? { profileId } : {}),
    ...(nodeId ? { nodeId } : {}),
    ...(socksPort !== undefined ? { socksPort } : {}),
  };
}

export function parseSubscriptionProfiles(value: unknown): SubscriptionProfile[] {
  const record = asRecord(value, 'subscription profiles response');
  if (!Array.isArray(record.profiles)) {
    throw new Error('subscription profiles response.profiles must be an array');
  }
  return record.profiles.map((item, index) => parseSubscriptionProfileRecord(item, `subscription profiles[${index}]`));
}

export function parseSubscriptionProfile(value: unknown): SubscriptionProfile {
  return parseSubscriptionProfileRecord(value, 'subscription profile');
}
