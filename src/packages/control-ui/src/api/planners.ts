export interface ServiceIncidentPolicyPlan {
  transition: string;
  notify: boolean;
  incidentCallbackDue: boolean;
  persist: boolean;
  failureAgeSeconds: number;
  incidentRetentionDays: number;
  latencyRetentionHours: number;
  suppressionReasons: string[];
  invariants: string[];
  readOnly: boolean;
}

export interface DNSPolicyTransportPlan {
  id: string;
  kind: string;
  secure: boolean;
  fallbackTo?: string;
  truncationFallbackTo?: string;
  ecsPrivacyImpact: boolean;
}

export interface DNSResolutionPolicyPlan {
  transports: DNSPolicyTransportPlan[];
  primaryTransport: string;
  lookupFamilies: string[];
  cacheScope: string;
  rewriteTTLSeconds?: number;
  warnings: string[];
  invariants: string[];
  readOnly: boolean;
}

export interface MultiplexPolicyPlan {
  protocol: string;
  runtimeSupported: boolean;
  version: number;
  maxConnections: number;
  maxStreamsPerConnection: number;
  estimatedMaxConcurrentStreams: number;
  sessionSelection: string;
  padding: boolean;
  maxPaddingBytes?: number;
  bandwidthControlSupported: boolean;
  keepAliveDisabled: boolean;
  keepAliveIntervalMS: number;
  keepAliveTimeoutMS: number;
  maxFrameSize: number;
  maxReceiveBuffer: number;
  maxStreamBuffer: number;
  warnings: string[];
  invariants: string[];
  readOnly: boolean;
}

export interface RoutingArtifactRank {
  id: string;
  admitted: boolean;
  reason?: string;
  provenanceSHA256: string;
}

export interface RoutingArtifactPlan {
  artifacts: RoutingArtifactRank[];
  admitted: string[];
  rejected: string[];
  readOnly: boolean;
  fetches: boolean;
  installs: boolean;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return value;
}

function numberValue(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`${label} must be a finite number`);
  return value;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  return stringValue(value, label);
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new Error(`${label} must be an array of strings`);
  }
  return [...value];
}

export function parseServiceIncidentPolicyPlan(value: unknown): ServiceIncidentPolicyPlan {
  const source = record(value, 'service incident policy');
  return {
    transition: stringValue(source.transition, 'service incident policy.transition'),
    notify: booleanValue(source.notify, 'service incident policy.notify'),
    incidentCallbackDue: booleanValue(source.incident_callback_due, 'service incident policy.incident_callback_due'),
    persist: booleanValue(source.persist, 'service incident policy.persist'),
    failureAgeSeconds: typeof source.failure_age_seconds === 'number' ? numberValue(source.failure_age_seconds, 'service incident policy.failure_age_seconds') : 0,
    incidentRetentionDays: numberValue(source.incident_retention_days, 'service incident policy.incident_retention_days'),
    latencyRetentionHours: numberValue(source.latency_retention_hours, 'service incident policy.latency_retention_hours'),
    suppressionReasons: stringArray(source.suppression_reasons, 'service incident policy.suppression_reasons'),
    invariants: stringArray(source.invariants, 'service incident policy.invariants'),
    readOnly: booleanValue(source.read_only, 'service incident policy.read_only'),
  };
}

export function parseDNSResolutionPolicyPlan(value: unknown): DNSResolutionPolicyPlan {
  const source = record(value, 'DNS resolution policy');
  if (!Array.isArray(source.transports)) throw new Error('DNS resolution policy.transports must be an array');
  const transports = source.transports.map((item, index) => {
    const transport = record(item, `DNS resolution policy.transports[${index}]`);
    const fallbackTo = optionalString(transport.fallback_to, `DNS transport[${index}].fallback_to`);
    const truncationFallbackTo = optionalString(transport.truncation_fallback_to, `DNS transport[${index}].truncation_fallback_to`);
    return {
      id: stringValue(transport.id, `DNS transport[${index}].id`),
      kind: stringValue(transport.kind, `DNS transport[${index}].kind`),
      secure: booleanValue(transport.secure, `DNS transport[${index}].secure`),
      ...(fallbackTo !== undefined ? { fallbackTo } : {}),
      ...(truncationFallbackTo !== undefined ? { truncationFallbackTo } : {}),
      ecsPrivacyImpact: booleanValue(transport.ecs_privacy_impact, `DNS transport[${index}].ecs_privacy_impact`),
    } satisfies DNSPolicyTransportPlan;
  });
  const rewriteTTLSeconds = typeof source.rewrite_ttl_seconds === 'number' ? numberValue(source.rewrite_ttl_seconds, 'DNS resolution policy.rewrite_ttl_seconds') : undefined;
  return {
    transports,
    primaryTransport: stringValue(source.primary_transport, 'DNS resolution policy.primary_transport'),
    lookupFamilies: stringArray(source.lookup_families, 'DNS resolution policy.lookup_families'),
    cacheScope: stringValue(source.cache_scope, 'DNS resolution policy.cache_scope'),
    ...(rewriteTTLSeconds !== undefined ? { rewriteTTLSeconds } : {}),
    warnings: stringArray(source.warnings, 'DNS resolution policy.warnings'),
    invariants: stringArray(source.invariants, 'DNS resolution policy.invariants'),
    readOnly: booleanValue(source.read_only, 'DNS resolution policy.read_only'),
  };
}

export function parseMultiplexPolicyPlan(value: unknown): MultiplexPolicyPlan {
  const source = record(value, 'multiplex policy');
  return {
    protocol: stringValue(source.protocol, 'multiplex policy.protocol'),
    runtimeSupported: booleanValue(source.runtime_supported, 'multiplex policy.runtime_supported'),
    version: numberValue(source.version, 'multiplex policy.version'),
    maxConnections: numberValue(source.max_connections, 'multiplex policy.max_connections'),
    maxStreamsPerConnection: numberValue(source.max_streams_per_connection, 'multiplex policy.max_streams_per_connection'),
    estimatedMaxConcurrentStreams: typeof source.estimated_max_concurrent_streams === 'number' ? numberValue(source.estimated_max_concurrent_streams, 'multiplex policy.estimated_max_concurrent_streams') : 0,
    sessionSelection: stringValue(source.session_selection, 'multiplex policy.session_selection'),
    padding: booleanValue(source.padding, 'multiplex policy.padding'),
    ...(typeof source.max_padding_bytes === 'number' ? { maxPaddingBytes: numberValue(source.max_padding_bytes, 'multiplex policy.max_padding_bytes') } : {}),
    bandwidthControlSupported: booleanValue(source.bandwidth_control_supported, 'multiplex policy.bandwidth_control_supported'),
    keepAliveDisabled: booleanValue(source.keep_alive_disabled, 'multiplex policy.keep_alive_disabled'),
    keepAliveIntervalMS: numberValue(source.keep_alive_interval_ms, 'multiplex policy.keep_alive_interval_ms'),
    keepAliveTimeoutMS: numberValue(source.keep_alive_timeout_ms, 'multiplex policy.keep_alive_timeout_ms'),
    maxFrameSize: numberValue(source.max_frame_size, 'multiplex policy.max_frame_size'),
    maxReceiveBuffer: numberValue(source.max_receive_buffer, 'multiplex policy.max_receive_buffer'),
    maxStreamBuffer: numberValue(source.max_stream_buffer, 'multiplex policy.max_stream_buffer'),
    warnings: stringArray(source.warnings, 'multiplex policy.warnings'),
    invariants: stringArray(source.invariants, 'multiplex policy.invariants'),
    readOnly: booleanValue(source.read_only, 'multiplex policy.read_only'),
  };
}

export function parseRoutingArtifactPlan(value: unknown): RoutingArtifactPlan {
  const source = record(value, 'routing artifact plan');
  if (!Array.isArray(source.artifacts)) throw new Error('routing artifact plan.artifacts must be an array');
  const artifacts = source.artifacts.map((item, index) => {
    const artifact = record(item, `routing artifact plan.artifacts[${index}]`);
    const reason = optionalString(artifact.reason, `routing artifact[${index}].reason`);
    return {
      id: stringValue(artifact.id, `routing artifact[${index}].id`),
      admitted: booleanValue(artifact.admitted, `routing artifact[${index}].admitted`),
      ...(reason !== undefined ? { reason } : {}),
      provenanceSHA256: stringValue(artifact.provenance_sha256, `routing artifact[${index}].provenance_sha256`),
    } satisfies RoutingArtifactRank;
  });
  return {
    artifacts,
    admitted: stringArray(source.admitted, 'routing artifact plan.admitted'),
    rejected: stringArray(source.rejected, 'routing artifact plan.rejected'),
    readOnly: booleanValue(source.read_only, 'routing artifact plan.read_only'),
    fetches: booleanValue(source.fetches, 'routing artifact plan.fetches'),
    installs: booleanValue(source.installs, 'routing artifact plan.installs'),
  };
}

export interface EndpointDispatchRank {
  endpoint: string;
  score: number;
  quality: string;
  healthState: string;
  circuitOpen: boolean;
  loadPct?: number;
  eligible: boolean;
}

export interface EndpointDispatchPlan {
  ranked: EndpointDispatchRank[];
  dispatchOrder: string[];
  warmPool: number;
  preferredEndpoint?: string;
  selectionBasis: string[];
}

export function parseEndpointDispatchPlan(value: unknown): EndpointDispatchPlan {
  const source = record(value, 'endpoint dispatch plan');
  if (!Array.isArray(source.ranked)) throw new Error('endpoint dispatch plan.ranked must be an array');
  const preferredEndpoint = optionalString(source.preferred_endpoint, 'endpoint dispatch plan.preferred_endpoint');
  return {
    ranked: source.ranked.map((item, index) => {
      const rank = record(item, `endpoint dispatch plan.ranked[${index}]`);
      return {
        endpoint: stringValue(rank.endpoint, `endpoint rank[${index}].endpoint`),
        score: numberValue(rank.score, `endpoint rank[${index}].score`),
        quality: stringValue(rank.quality, `endpoint rank[${index}].quality`),
        healthState: typeof rank.health_state === 'string' ? rank.health_state : 'unknown',
        circuitOpen: Boolean(rank.circuit_open),
        ...(typeof rank.load_pct === 'number' ? { loadPct: numberValue(rank.load_pct, `endpoint rank[${index}].load_pct`) } : {}),
        eligible: Boolean(rank.eligible),
      };
    }),
    dispatchOrder: stringArray(source.dispatch_order, 'endpoint dispatch plan.dispatch_order'),
    warmPool: numberValue(source.warm_pool, 'endpoint dispatch plan.warm_pool'),
    ...(preferredEndpoint !== undefined ? { preferredEndpoint } : {}),
    selectionBasis: Array.isArray(source.selection_basis) ? stringArray(source.selection_basis, 'endpoint dispatch plan.selection_basis') : [],
  };
}

export interface DoHResolverPoolRank {
  id: string;
  url: string;
  priority: number;
  rttMs?: number;
  canaryStatus: string;
  circuitOpen: boolean;
  tier: string;
  reason?: string;
}

export interface DoHResolverPoolPlan {
  active: DoHResolverPoolRank[];
  reserve: DoHResolverPoolRank[];
  invalid: DoHResolverPoolRank[];
  fallbackOrder: string[];
  readOnly: boolean;
}

function parseDoHResolverRank(value: unknown, label: string): DoHResolverPoolRank {
  const rank = record(value, label);
  const rttMs = typeof rank.rtt_ms === 'number' ? numberValue(rank.rtt_ms, `${label}.rtt_ms`) : undefined;
  const reason = optionalString(rank.reason, `${label}.reason`);
  return {
    id: stringValue(rank.id, `${label}.id`),
    url: stringValue(rank.url, `${label}.url`),
    priority: numberValue(rank.priority, `${label}.priority`),
    ...(rttMs !== undefined ? { rttMs } : {}),
    canaryStatus: stringValue(rank.canary_status, `${label}.canary_status`),
    circuitOpen: booleanValue(rank.circuit_open, `${label}.circuit_open`),
    tier: stringValue(rank.tier, `${label}.tier`),
    ...(reason !== undefined ? { reason } : {}),
  };
}

export function parseDoHResolverPoolPlan(value: unknown): DoHResolverPoolPlan {
  const source = record(value, 'DoH resolver pool plan');
  const parseList = (key: 'active' | 'reserve' | 'invalid') => {
    const raw = source[key];
    if (!Array.isArray(raw)) throw new Error(`DoH resolver pool plan.${key} must be an array`);
    return raw.map((item, index) => parseDoHResolverRank(item, `DoH resolver pool plan.${key}[${index}]`));
  };
  return {
    active: parseList('active'),
    reserve: parseList('reserve'),
    invalid: parseList('invalid'),
    fallbackOrder: stringArray(source.fallback_order, 'DoH resolver pool plan.fallback_order'),
    readOnly: booleanValue(source.read_only, 'DoH resolver pool plan.read_only'),
  };
}

export interface L7SignatureAdmissionResult {
  name: string;
  expressionSHA256?: string;
  admitted: boolean;
  reason?: string;
}

export interface L7SignatureAdmissionPlan {
  results: L7SignatureAdmissionResult[];
  admitted: number;
  rejected: number;
  offlineOnly: boolean;
  installsClassifier: boolean;
}

export function parseL7SignatureAdmissionPlan(value: unknown): L7SignatureAdmissionPlan {
  const source = record(value, 'L7 signature admission plan');
  if (!Array.isArray(source.results)) throw new Error('L7 signature admission plan.results must be an array');
  return {
    results: source.results.map((item, index) => {
      const result = record(item, `L7 signature admission plan.results[${index}]`);
      const expressionSHA256 = optionalString(result.expression_sha256, `L7 signature result[${index}].expression_sha256`);
      const reason = optionalString(result.reason, `L7 signature result[${index}].reason`);
      return {
        name: stringValue(result.name, `L7 signature result[${index}].name`),
        ...(expressionSHA256 !== undefined ? { expressionSHA256 } : {}),
        admitted: booleanValue(result.admitted, `L7 signature result[${index}].admitted`),
        ...(reason !== undefined ? { reason } : {}),
      };
    }),
    admitted: numberValue(source.admitted, 'L7 signature admission plan.admitted'),
    rejected: numberValue(source.rejected, 'L7 signature admission plan.rejected'),
    offlineOnly: booleanValue(source.offline_only, 'L7 signature admission plan.offline_only'),
    installsClassifier: booleanValue(source.installs_classifier, 'L7 signature admission plan.installs_classifier'),
  };
}

export interface LocalRuleEvidence {
  action: string;
  kind: string;
  value: string;
  sourceLine: number;
  options: string[];
}

export interface LocalRuleSetPlan {
  format: string;
  rules: LocalRuleEvidence[];
  duplicateCount: number;
  ignoredCount: number;
  fetches: boolean;
  installs: boolean;
  invariants: string[];
}

export function parseLocalRuleSetPlan(value: unknown): LocalRuleSetPlan {
  const source = record(value, 'local rule-set plan');
  if (!Array.isArray(source.rules)) throw new Error('local rule-set plan.rules must be an array');
  return {
    format: stringValue(source.format, 'local rule-set plan.format'),
    rules: source.rules.map((item, index) => {
      const rule = record(item, `local rule-set plan.rules[${index}]`);
      return {
        action: stringValue(rule.action, `local rule[${index}].action`),
        kind: stringValue(rule.kind, `local rule[${index}].kind`),
        value: stringValue(rule.value, `local rule[${index}].value`),
        sourceLine: numberValue(rule.source_line, `local rule[${index}].source_line`),
        options: rule.options === undefined || rule.options === null ? [] : stringArray(rule.options, `local rule[${index}].options`),
      };
    }),
    duplicateCount: numberValue(source.duplicate_count, 'local rule-set plan.duplicate_count'),
    ignoredCount: numberValue(source.ignored_count, 'local rule-set plan.ignored_count'),
    fetches: booleanValue(source.fetches, 'local rule-set plan.fetches'),
    installs: booleanValue(source.installs, 'local rule-set plan.installs'),
    invariants: stringArray(source.invariants, 'local rule-set plan.invariants'),
  };
}

export interface RoutingPolicyShare {
  name: string;
  weight: number;
  sharePct: number;
}

export interface RoutingPolicyGroupPlan {
  mode: string;
  preferred?: string;
  dispatchOrder: string[];
  skipped: string[];
  shares: RoutingPolicyShare[];
  usesObservedState: boolean;
  performsNetworkIO: boolean;
  installsPolicy: boolean;
  invariants: string[];
}

export function parseRoutingPolicyGroupPlan(value: unknown): RoutingPolicyGroupPlan {
  const source = record(value, 'routing policy-group plan');
  const rawShares = source.shares === undefined || source.shares === null ? [] : source.shares;
  if (!Array.isArray(rawShares)) throw new Error('routing policy-group plan.shares must be an array');
  const preferred = optionalString(source.preferred, 'routing policy-group plan.preferred');
  return {
    mode: stringValue(source.mode, 'routing policy-group plan.mode'),
    ...(preferred !== undefined ? { preferred } : {}),
    dispatchOrder: stringArray(source.dispatch_order, 'routing policy-group plan.dispatch_order'),
    skipped: stringArray(source.skipped, 'routing policy-group plan.skipped'),
    shares: rawShares.map((item, index) => {
      const share = record(item, `routing policy-group plan.shares[${index}]`);
      return {
        name: stringValue(share.name, `routing policy-group share[${index}].name`),
        weight: numberValue(share.weight, `routing policy-group share[${index}].weight`),
        sharePct: numberValue(share.share_pct, `routing policy-group share[${index}].share_pct`),
      };
    }),
    usesObservedState: booleanValue(source.uses_observed_state, 'routing policy-group plan.uses_observed_state'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'routing policy-group plan.performs_network_io'),
    installsPolicy: booleanValue(source.installs_policy, 'routing policy-group plan.installs_policy'),
    invariants: stringArray(source.invariants, 'routing policy-group plan.invariants'),
  };
}

export interface TailnetTransactionPlan {
  operation: string;
  steps: string[];
  requiresETag: boolean;
  validationOnly: boolean;
  patchSemantics: boolean;
  replaceSemantics: boolean;
  sensitiveResult: boolean;
  credentialAccepted: boolean;
  makesAPIRequest: boolean;
  invariants: string[];
}

export function parseTailnetTransactionPlan(value: unknown): TailnetTransactionPlan {
  const source = record(value, 'tailnet transaction plan');
  return {
    operation: stringValue(source.operation, 'tailnet transaction plan.operation'),
    steps: stringArray(source.steps, 'tailnet transaction plan.steps'),
    requiresETag: booleanValue(source.requires_etag, 'tailnet transaction plan.requires_etag'),
    validationOnly: booleanValue(source.validation_only, 'tailnet transaction plan.validation_only'),
    patchSemantics: booleanValue(source.patch_semantics, 'tailnet transaction plan.patch_semantics'),
    replaceSemantics: booleanValue(source.replace_semantics, 'tailnet transaction plan.replace_semantics'),
    sensitiveResult: booleanValue(source.sensitive_result, 'tailnet transaction plan.sensitive_result'),
    credentialAccepted: booleanValue(source.credential_accepted, 'tailnet transaction plan.credential_accepted'),
    makesAPIRequest: booleanValue(source.makes_api_request, 'tailnet transaction plan.makes_api_request'),
    invariants: stringArray(source.invariants, 'tailnet transaction plan.invariants'),
  };
}

export interface BrowserNativeHostManifestPlan {
  name: string;
  description: string;
  allowedOrigins: string[];
  allowedExtensions: string[];
}

export interface BrowserProxyHandoffPlan {
  state: string;
  profileID: string;
  browserFamily: string;
  extensionID?: string;
  proxyHost: string;
  proxyPort: string;
  missingPermissions: string[];
  messageLimitBytes: number;
  nativeHost: BrowserNativeHostManifestPlan;
  nativeCommands: string[];
  proxyBypass: string[];
  reconnectBackoffMS: number[];
  registersHost: boolean;
  changesBrowserProxy: boolean;
  invariants: string[];
}

export function parseBrowserProxyHandoffPlan(value: unknown): BrowserProxyHandoffPlan {
  const source = record(value, 'browser proxy handoff plan');
  const nativeHost = record(source.native_host, 'browser proxy handoff plan.native_host');
  if (!Array.isArray(source.reconnect_backoff_ms) || !source.reconnect_backoff_ms.every((item) => typeof item === 'number' && Number.isFinite(item))) {
    throw new Error('browser proxy handoff plan.reconnect_backoff_ms must be an array of finite numbers');
  }
  const extensionID = optionalString(source.extension_id, 'browser proxy handoff plan.extension_id');
  return {
    state: stringValue(source.state, 'browser proxy handoff plan.state'),
    profileID: stringValue(source.profile_id, 'browser proxy handoff plan.profile_id'),
    browserFamily: stringValue(source.browser_family, 'browser proxy handoff plan.browser_family'),
    ...(extensionID !== undefined ? { extensionID } : {}),
    proxyHost: stringValue(source.proxy_host, 'browser proxy handoff plan.proxy_host'),
    proxyPort: stringValue(source.proxy_port, 'browser proxy handoff plan.proxy_port'),
    missingPermissions: stringArray(source.missing_permissions, 'browser proxy handoff plan.missing_permissions'),
    messageLimitBytes: numberValue(source.message_limit_bytes, 'browser proxy handoff plan.message_limit_bytes'),
    nativeHost: {
      name: stringValue(nativeHost.name, 'browser native host.name'),
      description: stringValue(nativeHost.description, 'browser native host.description'),
      allowedOrigins: nativeHost.allowed_origins === undefined || nativeHost.allowed_origins === null ? [] : stringArray(nativeHost.allowed_origins, 'browser native host.allowed_origins'),
      allowedExtensions: nativeHost.allowed_extensions === undefined || nativeHost.allowed_extensions === null ? [] : stringArray(nativeHost.allowed_extensions, 'browser native host.allowed_extensions'),
    },
    nativeCommands: stringArray(source.native_commands, 'browser proxy handoff plan.native_commands'),
    proxyBypass: stringArray(source.proxy_bypass, 'browser proxy handoff plan.proxy_bypass'),
    reconnectBackoffMS: [...source.reconnect_backoff_ms] as number[],
    registersHost: booleanValue(source.registers_host, 'browser proxy handoff plan.registers_host'),
    changesBrowserProxy: booleanValue(source.changes_browser_proxy, 'browser proxy handoff plan.changes_browser_proxy'),
    invariants: stringArray(source.invariants, 'browser proxy handoff plan.invariants'),
  };
}

export interface WorkerAffinityPlan {
  preferredWorker?: string;
  selectedWorker?: string;
  spillover: boolean;
  failOpen: boolean;
  hardDeadlineMS: number;
  restartBackoffMS: number[];
  startsProcess: boolean;
  protocolFraming: string;
  readyHandshake: string;
  correlatesRequestIDs: boolean;
  affinityQueueDepth: number;
  sharedQueueDepth: number;
  maxProtocolFrameBytes: number;
  readyTimeoutMS: number;
  callerCancellationFailOpen: boolean;
  workerContinuesAfterCancel: boolean;
  recycleOnProtocolError: boolean;
  coldFirstCallTelemetry: boolean;
  invariants: string[];
}

export function parseWorkerAffinityPlan(value: unknown): WorkerAffinityPlan {
  const source = record(value, 'worker affinity plan');
  if (!Array.isArray(source.restart_backoff_ms) || !source.restart_backoff_ms.every((item) => typeof item === 'number' && Number.isFinite(item))) {
    throw new Error('worker affinity plan.restart_backoff_ms must be an array of finite numbers');
  }
  const preferredWorker = optionalString(source.preferred_worker, 'worker affinity plan.preferred_worker');
  const selectedWorker = optionalString(source.selected_worker, 'worker affinity plan.selected_worker');
  return {
    ...(preferredWorker !== undefined ? { preferredWorker } : {}),
    ...(selectedWorker !== undefined ? { selectedWorker } : {}),
    spillover: booleanValue(source.spillover, 'worker affinity plan.spillover'),
    failOpen: booleanValue(source.fail_open, 'worker affinity plan.fail_open'),
    hardDeadlineMS: numberValue(source.hard_deadline_ms, 'worker affinity plan.hard_deadline_ms'),
    restartBackoffMS: [...source.restart_backoff_ms] as number[],
    startsProcess: booleanValue(source.starts_process, 'worker affinity plan.starts_process'),
    protocolFraming: stringValue(source.protocol_framing, 'worker affinity plan.protocol_framing'),
    readyHandshake: stringValue(source.ready_handshake, 'worker affinity plan.ready_handshake'),
    correlatesRequestIDs: booleanValue(source.correlates_request_ids, 'worker affinity plan.correlates_request_ids'),
    affinityQueueDepth: numberValue(source.affinity_queue_depth, 'worker affinity plan.affinity_queue_depth'),
    sharedQueueDepth: numberValue(source.shared_queue_depth, 'worker affinity plan.shared_queue_depth'),
    maxProtocolFrameBytes: numberValue(source.max_protocol_frame_bytes, 'worker affinity plan.max_protocol_frame_bytes'),
    readyTimeoutMS: numberValue(source.ready_timeout_ms, 'worker affinity plan.ready_timeout_ms'),
    callerCancellationFailOpen: booleanValue(source.caller_cancellation_fail_open, 'worker affinity plan.caller_cancellation_fail_open'),
    workerContinuesAfterCancel: booleanValue(source.worker_continues_after_cancel, 'worker affinity plan.worker_continues_after_cancel'),
    recycleOnProtocolError: booleanValue(source.recycle_on_protocol_error, 'worker affinity plan.recycle_on_protocol_error'),
    coldFirstCallTelemetry: booleanValue(source.cold_first_call_telemetry, 'worker affinity plan.cold_first_call_telemetry'),
    invariants: stringArray(source.invariants, 'worker affinity plan.invariants'),
  };
}

export interface WebSocketReadinessPlan {
  ready: boolean;
  tcpReachable: boolean;
  upgradeValid: boolean;
  connectionValid: boolean;
  acceptValid: boolean;
  tlsValid: boolean;
  reasons: string[];
  performsNetworkIO: boolean;
  invariants: string[];
}

export function parseWebSocketReadinessPlan(value: unknown): WebSocketReadinessPlan {
  const source = record(value, 'WebSocket readiness plan');
  return {
    ready: booleanValue(source.ready, 'WebSocket readiness plan.ready'),
    tcpReachable: booleanValue(source.tcp_reachable, 'WebSocket readiness plan.tcp_reachable'),
    upgradeValid: booleanValue(source.upgrade_valid, 'WebSocket readiness plan.upgrade_valid'),
    connectionValid: booleanValue(source.connection_valid, 'WebSocket readiness plan.connection_valid'),
    acceptValid: booleanValue(source.accept_valid, 'WebSocket readiness plan.accept_valid'),
    tlsValid: booleanValue(source.tls_valid, 'WebSocket readiness plan.tls_valid'),
    reasons: stringArray(source.reasons, 'WebSocket readiness plan.reasons'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'WebSocket readiness plan.performs_network_io'),
    invariants: stringArray(source.invariants, 'WebSocket readiness plan.invariants'),
  };
}

export interface GatewayCompositionService {
  id: string;
  role: string;
  dependsOn: string[];
  healthy: boolean;
}

export interface GatewayCompositionPlan {
  preset?: string;
  services: GatewayCompositionService[];
  startOrder: string[];
  stopOrder: string[];
  rollbackOrder: string[];
  unhealthy: string[];
  restartBackoffSeconds: number[];
  downloads: boolean;
  writesServiceConfig: boolean;
  invariants: string[];
}

export function parseGatewayCompositionPlan(value: unknown): GatewayCompositionPlan {
  const source = record(value, 'gateway composition plan');
  if (!Array.isArray(source.restart_backoff_seconds) || !source.restart_backoff_seconds.every((item) => typeof item === 'number' && Number.isFinite(item))) {
    throw new Error('gateway composition plan.restart_backoff_seconds must be an array of finite numbers');
  }
  if (!Array.isArray(source.services)) throw new Error('gateway composition plan.services must be an array');
  const preset = optionalString(source.preset, 'gateway composition plan.preset');
  return {
    ...(preset !== undefined ? { preset } : {}),
    services: source.services.map((item, index) => {
      const service = record(item, `gateway composition plan.services[${index}]`);
      return {
        id: stringValue(service.id, `gateway composition service[${index}].id`),
        role: stringValue(service.role, `gateway composition service[${index}].role`),
        dependsOn: service.depends_on === undefined || service.depends_on === null ? [] : stringArray(service.depends_on, `gateway composition service[${index}].depends_on`),
        healthy: booleanValue(service.healthy, `gateway composition service[${index}].healthy`),
      };
    }),
    startOrder: stringArray(source.start_order, 'gateway composition plan.start_order'),
    stopOrder: stringArray(source.stop_order, 'gateway composition plan.stop_order'),
    rollbackOrder: stringArray(source.rollback_order, 'gateway composition plan.rollback_order'),
    unhealthy: stringArray(source.unhealthy, 'gateway composition plan.unhealthy'),
    restartBackoffSeconds: [...source.restart_backoff_seconds] as number[],
    downloads: booleanValue(source.downloads, 'gateway composition plan.downloads'),
    writesServiceConfig: booleanValue(source.writes_service_config, 'gateway composition plan.writes_service_config'),
    invariants: stringArray(source.invariants, 'gateway composition plan.invariants'),
  };
}

export interface WireGuardIndexTranslationPlan {
  persistedNeedsRevalidation: number[];
  macRecomputeRequired: boolean;
  mutatesPackets: boolean;
  restoresMappings: boolean;
  readOnly: boolean;
  invariants: string[];
}

export function parseWireGuardIndexTranslationPlan(value: unknown): WireGuardIndexTranslationPlan {
  const source = record(value, 'WireGuard index translation plan');
  if (!Array.isArray(source.persisted_needs_revalidation) || !source.persisted_needs_revalidation.every((item) => typeof item === 'number' && Number.isFinite(item))) {
    throw new Error('WireGuard index translation plan.persisted_needs_revalidation must be numeric');
  }
  return {
    persistedNeedsRevalidation: [...source.persisted_needs_revalidation] as number[],
    macRecomputeRequired: booleanValue(source.mac_recompute_required, 'WireGuard index translation plan.mac_recompute_required'),
    mutatesPackets: booleanValue(source.mutates_packets, 'WireGuard index translation plan.mutates_packets'),
    restoresMappings: booleanValue(source.restores_mappings, 'WireGuard index translation plan.restores_mappings'),
    readOnly: booleanValue(source.read_only, 'WireGuard index translation plan.read_only'),
    invariants: stringArray(source.invariants, 'WireGuard index translation plan.invariants'),
  };
}

export interface SNIDecoyHandshakePlan {
  state: string;
  readyToInject: boolean;
  readyToRelay: boolean;
  expectedRealSeq: number;
  expectedServerACK: number;
  expectedThirdACK: number;
  expectedFakeSeq: number;
  performsNetworkIO: boolean;
  requiresRawPacketAuthority: boolean;
  reasons: string[];
  invariants: string[];
}

export function parseSNIDecoyHandshakePlan(value: unknown): SNIDecoyHandshakePlan {
  const source = record(value, 'SNI decoy handshake plan');
  return {
    state: stringValue(source.state, 'SNI decoy handshake plan.state'),
    readyToInject: booleanValue(source.ready_to_inject, 'SNI decoy handshake plan.ready_to_inject'),
    readyToRelay: booleanValue(source.ready_to_relay, 'SNI decoy handshake plan.ready_to_relay'),
    expectedRealSeq: numberValue(source.expected_real_seq, 'SNI decoy handshake plan.expected_real_seq'),
    expectedServerACK: numberValue(source.expected_server_ack, 'SNI decoy handshake plan.expected_server_ack'),
    expectedThirdACK: numberValue(source.expected_third_ack, 'SNI decoy handshake plan.expected_third_ack'),
    expectedFakeSeq: numberValue(source.expected_fake_seq, 'SNI decoy handshake plan.expected_fake_seq'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'SNI decoy handshake plan.performs_network_io'),
    requiresRawPacketAuthority: booleanValue(source.requires_raw_packet_authority, 'SNI decoy handshake plan.requires_raw_packet_authority'),
    reasons: stringArray(source.reasons, 'SNI decoy handshake plan.reasons'),
    invariants: stringArray(source.invariants, 'SNI decoy handshake plan.invariants'),
  };
}

export interface TunnelSafetyPlan {
  desiredState: string;
  effectiveProtectionState: string;
  observedState: string;
  lockdownRequired: boolean;
  firewallBlockConfirmed: boolean;
  dnsGuardConfirmed: boolean;
  requiredGuards: string[];
  missingOrFailedGuards: string[];
  reconnectAllowed: boolean;
  nextAction: string;
  reasons: string[];
  invariants: string[];
  readOnly: boolean;
  mutatesHostNetwork: boolean;
}

export function parseTunnelSafetyPlan(value: unknown): TunnelSafetyPlan {
  const source = record(value, 'tunnel safety plan');
  return {
    desiredState: stringValue(source.desired_state, 'tunnel safety plan.desired_state'),
    effectiveProtectionState: stringValue(source.effective_protection_state, 'tunnel safety plan.effective_protection_state'),
    observedState: stringValue(source.observed_state, 'tunnel safety plan.observed_state'),
    lockdownRequired: booleanValue(source.lockdown_required, 'tunnel safety plan.lockdown_required'),
    firewallBlockConfirmed: booleanValue(source.firewall_block_confirmed, 'tunnel safety plan.firewall_block_confirmed'),
    dnsGuardConfirmed: booleanValue(source.dns_guard_confirmed, 'tunnel safety plan.dns_guard_confirmed'),
    requiredGuards: stringArray(source.required_guards, 'tunnel safety plan.required_guards'),
    missingOrFailedGuards: stringArray(source.missing_or_failed_guards, 'tunnel safety plan.missing_or_failed_guards'),
    reconnectAllowed: booleanValue(source.reconnect_allowed, 'tunnel safety plan.reconnect_allowed'),
    nextAction: stringValue(source.next_action, 'tunnel safety plan.next_action'),
    reasons: stringArray(source.reasons, 'tunnel safety plan.reasons'),
    invariants: stringArray(source.invariants, 'tunnel safety plan.invariants'),
    readOnly: booleanValue(source.read_only, 'tunnel safety plan.read_only'),
    mutatesHostNetwork: booleanValue(source.mutates_host_network, 'tunnel safety plan.mutates_host_network'),
  };
}

export interface TLSInterceptionEvidencePlan {
  worstMatch: string;
  mismatchedComponents: string[];
  expectedGrade?: string;
  observedGrade?: string;
  gradeRegressed: boolean;
  pfsLost: boolean;
  weakCiphersDetected: boolean;
  suspicious: boolean;
  reasons: string[];
  invariants: string[];
  readOnly: boolean;
  performsNetworkIO: boolean;
  usesFingerprintDatabase: boolean;
  identifiesInterceptionProduct: boolean;
}

export function parseTLSInterceptionEvidencePlan(value: unknown): TLSInterceptionEvidencePlan {
  const source = record(value, 'TLS interception evidence plan');
  return {
    worstMatch: stringValue(source.worst_match, 'TLS interception evidence plan.worst_match'),
    mismatchedComponents: stringArray(source.mismatched_components, 'TLS interception evidence plan.mismatched_components'),
    ...(typeof source.expected_grade === 'string' ? { expectedGrade: source.expected_grade } : {}),
    ...(typeof source.observed_grade === 'string' ? { observedGrade: source.observed_grade } : {}),
    gradeRegressed: booleanValue(source.grade_regressed, 'TLS interception evidence plan.grade_regressed'),
    pfsLost: booleanValue(source.pfs_lost, 'TLS interception evidence plan.pfs_lost'),
    weakCiphersDetected: booleanValue(source.weak_ciphers_detected, 'TLS interception evidence plan.weak_ciphers_detected'),
    suspicious: booleanValue(source.suspicious, 'TLS interception evidence plan.suspicious'),
    reasons: stringArray(source.reasons, 'TLS interception evidence plan.reasons'),
    invariants: stringArray(source.invariants, 'TLS interception evidence plan.invariants'),
    readOnly: booleanValue(source.read_only, 'TLS interception evidence plan.read_only'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'TLS interception evidence plan.performs_network_io'),
    usesFingerprintDatabase: booleanValue(source.uses_fingerprint_database, 'TLS interception evidence plan.uses_fingerprint_database'),
    identifiesInterceptionProduct: booleanValue(source.identifies_interception_product, 'TLS interception evidence plan.identifies_interception_product'),
  };
}

export interface SplitTunnelEntryPlan {
  kind: string;
  identifier: string;
}

export interface SplitTunnelPlan {
  platform: string;
  mode: string;
  entries: SplitTunnelEntryPlan[];
  duplicateCount: number;
  portableEntryCount: number;
  platformBoundEntryCount: number;
  manifestSHA256: string;
  runtimeSupported: boolean;
  runtimeEnforced: boolean;
  requiresRuntimeOwner: boolean;
  warnings: string[];
  invariants: string[];
  readOnly: boolean;
}

export function parseSplitTunnelPlan(value: unknown): SplitTunnelPlan {
  const source = record(value, 'split tunnel plan');
  if (!Array.isArray(source.entries)) throw new Error('split tunnel plan.entries must be an array');
  return {
    platform: stringValue(source.platform, 'split tunnel plan.platform'),
    mode: stringValue(source.mode, 'split tunnel plan.mode'),
    entries: source.entries.map((item, index) => {
      const entry = record(item, `split tunnel plan.entries[${index}]`);
      return {
        kind: stringValue(entry.kind, `split tunnel entry[${index}].kind`),
        identifier: stringValue(entry.identifier, `split tunnel entry[${index}].identifier`),
      };
    }),
    duplicateCount: numberValue(source.duplicate_count, 'split tunnel plan.duplicate_count'),
    portableEntryCount: numberValue(source.portable_entry_count, 'split tunnel plan.portable_entry_count'),
    platformBoundEntryCount: numberValue(source.platform_bound_entry_count, 'split tunnel plan.platform_bound_entry_count'),
    manifestSHA256: stringValue(source.manifest_sha256, 'split tunnel plan.manifest_sha256'),
    runtimeSupported: booleanValue(source.runtime_supported, 'split tunnel plan.runtime_supported'),
    runtimeEnforced: booleanValue(source.runtime_enforced, 'split tunnel plan.runtime_enforced'),
    requiresRuntimeOwner: booleanValue(source.requires_runtime_owner, 'split tunnel plan.requires_runtime_owner'),
    warnings: stringArray(source.warnings, 'split tunnel plan.warnings'),
    invariants: stringArray(source.invariants, 'split tunnel plan.invariants'),
    readOnly: booleanValue(source.read_only, 'split tunnel plan.read_only'),
  };
}

export interface RelayRejectionPlan {
  id: string;
  reasons: string[];
}

export interface RelayConstraintPlan {
  mode: string;
  eligibleSinglehop: string[];
  eligibleEntry: string[];
  eligibleExit: string[];
  rejectedEntry: RelayRejectionPlan[];
  rejectedExit: RelayRejectionPlan[];
  suggestedEntry?: string;
  suggestedExit?: string;
  autohopUsesMultihop: boolean;
  requiresEndpointScoring: boolean;
  performsNetworkIO: boolean;
  installsTunnel: boolean;
  invariants: string[];
  readOnly: boolean;
}

export function parseRelayConstraintPlan(value: unknown): RelayConstraintPlan {
  const source = record(value, 'relay constraint plan');
  const parseRejections = (raw: unknown, label: string): RelayRejectionPlan[] => {
    if (!Array.isArray(raw)) throw new Error(`${label} must be an array`);
    return raw.map((item, index) => {
      const rejection = record(item, `${label}[${index}]`);
      return {
        id: stringValue(rejection.id, `${label}[${index}].id`),
        reasons: stringArray(rejection.reasons, `${label}[${index}].reasons`),
      };
    });
  };
  const suggestedEntry = optionalString(source.suggested_entry, 'relay constraint plan.suggested_entry');
  const suggestedExit = optionalString(source.suggested_exit, 'relay constraint plan.suggested_exit');
  return {
    mode: stringValue(source.mode, 'relay constraint plan.mode'),
    eligibleSinglehop: stringArray(source.eligible_singlehop, 'relay constraint plan.eligible_singlehop'),
    eligibleEntry: stringArray(source.eligible_entry, 'relay constraint plan.eligible_entry'),
    eligibleExit: stringArray(source.eligible_exit, 'relay constraint plan.eligible_exit'),
    rejectedEntry: parseRejections(source.rejected_entry, 'relay constraint plan.rejected_entry'),
    rejectedExit: parseRejections(source.rejected_exit, 'relay constraint plan.rejected_exit'),
    ...(suggestedEntry !== undefined ? { suggestedEntry } : {}),
    ...(suggestedExit !== undefined ? { suggestedExit } : {}),
    autohopUsesMultihop: booleanValue(source.autohop_uses_multihop, 'relay constraint plan.autohop_uses_multihop'),
    requiresEndpointScoring: booleanValue(source.requires_endpoint_scoring, 'relay constraint plan.requires_endpoint_scoring'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'relay constraint plan.performs_network_io'),
    installsTunnel: booleanValue(source.installs_tunnel, 'relay constraint plan.installs_tunnel'),
    invariants: stringArray(source.invariants, 'relay constraint plan.invariants'),
    readOnly: booleanValue(source.read_only, 'relay constraint plan.read_only'),
  };
}

export interface UpdateRolloutPlan {
  version: string;
  rollout: number;
  cohortThreshold: number;
  eligible: boolean;
  withdrawn: boolean;
  sequenceFresh: boolean;
  metadataReplayRejected: boolean;
  requiresPersistedHighWaterMark: boolean;
  persistsHighWaterMark: boolean;
  downloadsArtifact: boolean;
  installsUpdate: boolean;
  reasons: string[];
  invariants: string[];
  readOnly: boolean;
}

export function parseUpdateRolloutPlan(value: unknown): UpdateRolloutPlan {
  const source = record(value, 'update rollout plan');
  return {
    version: stringValue(source.version, 'update rollout plan.version'),
    rollout: numberValue(source.rollout, 'update rollout plan.rollout'),
    cohortThreshold: numberValue(source.cohort_threshold, 'update rollout plan.cohort_threshold'),
    eligible: booleanValue(source.eligible, 'update rollout plan.eligible'),
    withdrawn: booleanValue(source.withdrawn, 'update rollout plan.withdrawn'),
    sequenceFresh: booleanValue(source.sequence_fresh, 'update rollout plan.sequence_fresh'),
    metadataReplayRejected: booleanValue(source.metadata_replay_rejected, 'update rollout plan.metadata_replay_rejected'),
    requiresPersistedHighWaterMark: booleanValue(source.requires_persisted_high_water_mark, 'update rollout plan.requires_persisted_high_water_mark'),
    persistsHighWaterMark: booleanValue(source.persists_high_water_mark, 'update rollout plan.persists_high_water_mark'),
    downloadsArtifact: booleanValue(source.downloads_artifact, 'update rollout plan.downloads_artifact'),
    installsUpdate: booleanValue(source.installs_update, 'update rollout plan.installs_update'),
    reasons: stringArray(source.reasons, 'update rollout plan.reasons'),
    invariants: stringArray(source.invariants, 'update rollout plan.invariants'),
    readOnly: booleanValue(source.read_only, 'update rollout plan.read_only'),
  };
}

// Post-refactor-230 read-only convergence planners.
export interface TorBridgeSelectionDecision { id: string; address: string; transport: string; rankHash: string }
export interface TorBridgeSelectionPlan { selected: TorBridgeSelectionDecision[]; eligible: number; rejected: Record<string,string>; requestedCount: number; adaptiveCount: boolean; fetchesBridges: boolean; persistsClientKey: boolean; performsNetworkIO: boolean; readOnly: boolean; invariants: string[] }
export interface TorBootstrapEvidencePlan { state: string; ready: boolean; bootstrapProgress: number; authenticationMethod: string; warnings: string[]; controlsTor: boolean; readsCookieBytes: boolean; performsNetworkIO: boolean; readOnly: boolean; invariants: string[] }
export interface CensorshipAnomaly { id: string; kind: string; strength: string; reason: string }
export interface CensorshipMeasurementPlan { conclusion: string; confidence: string; anomalies: CensorshipAnomaly[]; missingControls: string[]; comparablePairs: number; performsProbes: boolean; appliesEvasion: boolean; readOnly: boolean; invariants: string[] }
export interface DTLSSessionPolicyPlan { role: string; identityMode: string; mtu: number; replayProtectionWindow: number; flightIntervalMillis: number; retransmitBackoff: boolean; extendedMasterSecret: string; supportedProtocols: string[]; connectionIDLength: number; maxPaddingBytes: number; sessionResumption: boolean; warnings: string[]; performsHandshake: boolean; writesKeyLog: boolean; readOnly: boolean; invariants: string[] }
export interface PhantomPoolDecision { id: string; address: string; transport: string; rankHash: string }
export interface PhantomPoolPlan { selected: PhantomPoolDecision[]; rejected: Record<string,string>; performsLivenessProbe: boolean; registersPhantom: boolean; performsNetworkIO: boolean; readOnly: boolean; invariants: string[] }
export interface FlowFilterClausePlan { field: string; operator: string; value: string }
export interface FlowFilterPlan { match: string; canonical: string; clauses: FlowFilterClausePlan[]; readsFlowBodies: boolean; modifiesFlows: boolean; replaysFlows: boolean; readOnly: boolean; invariants: string[] }

function stringMap(value: unknown, label: string): Record<string,string> {
  const source = record(value, label);
  const out: Record<string,string> = {};
  for (const [key, item] of Object.entries(source)) out[key] = stringValue(item, `${label}.${key}`);
  return out;
}

export function parseTorBridgeSelectionPlan(value: unknown): TorBridgeSelectionPlan {
  const source = record(value, 'Tor bridge selection plan');
  if (!Array.isArray(source.selected)) throw new Error('Tor bridge selection plan.selected must be an array');
  return {
    selected: source.selected.map((item,index) => { const r=record(item,`Tor bridge selection[${index}]`); return { id:stringValue(r.id,`Tor bridge selection[${index}].id`), address:stringValue(r.address,`Tor bridge selection[${index}].address`), transport:stringValue(r.transport,`Tor bridge selection[${index}].transport`), rankHash:stringValue(r.rank_hash,`Tor bridge selection[${index}].rank_hash`) }; }),
    eligible:numberValue(source.eligible,'Tor bridge selection plan.eligible'),
    rejected:stringMap(source.rejected,'Tor bridge selection plan.rejected'),
    requestedCount:numberValue(source.requested_count,'Tor bridge selection plan.requested_count'),
    adaptiveCount:booleanValue(source.adaptive_count,'Tor bridge selection plan.adaptive_count'),
    fetchesBridges:booleanValue(source.fetches_bridges,'Tor bridge selection plan.fetches_bridges'),
    persistsClientKey:booleanValue(source.persists_client_key,'Tor bridge selection plan.persists_client_key'),
    performsNetworkIO:booleanValue(source.performs_network_io,'Tor bridge selection plan.performs_network_io'),
    readOnly:booleanValue(source.read_only,'Tor bridge selection plan.read_only'),
    invariants:stringArray(source.invariants,'Tor bridge selection plan.invariants'),
  };
}

export function parseTorBootstrapEvidencePlan(value: unknown): TorBootstrapEvidencePlan {
  const source=record(value,'Tor bootstrap evidence plan');
  return { state:stringValue(source.state,'Tor bootstrap evidence plan.state'), ready:booleanValue(source.ready,'Tor bootstrap evidence plan.ready'), bootstrapProgress:numberValue(source.bootstrap_progress,'Tor bootstrap evidence plan.bootstrap_progress'), authenticationMethod:stringValue(source.authentication_method,'Tor bootstrap evidence plan.authentication_method'), warnings:stringArray(source.warnings,'Tor bootstrap evidence plan.warnings'), controlsTor:booleanValue(source.controls_tor,'Tor bootstrap evidence plan.controls_tor'), readsCookieBytes:booleanValue(source.reads_cookie_bytes,'Tor bootstrap evidence plan.reads_cookie_bytes'), performsNetworkIO:booleanValue(source.performs_network_io,'Tor bootstrap evidence plan.performs_network_io'), readOnly:booleanValue(source.read_only,'Tor bootstrap evidence plan.read_only'), invariants:stringArray(source.invariants,'Tor bootstrap evidence plan.invariants') };
}

export function parseCensorshipMeasurementPlan(value: unknown): CensorshipMeasurementPlan {
  const source=record(value,'censorship measurement plan');
  if (!Array.isArray(source.anomalies)) throw new Error('censorship measurement plan.anomalies must be an array');
  return { conclusion:stringValue(source.conclusion,'censorship measurement plan.conclusion'), confidence:stringValue(source.confidence,'censorship measurement plan.confidence'), anomalies:source.anomalies.map((item,index)=>{const r=record(item,`censorship anomaly[${index}]`);return{id:stringValue(r.id,`censorship anomaly[${index}].id`),kind:stringValue(r.kind,`censorship anomaly[${index}].kind`),strength:stringValue(r.strength,`censorship anomaly[${index}].strength`),reason:stringValue(r.reason,`censorship anomaly[${index}].reason`)}}), missingControls:stringArray(source.missing_controls,'censorship measurement plan.missing_controls'), comparablePairs:numberValue(source.comparable_pairs,'censorship measurement plan.comparable_pairs'), performsProbes:booleanValue(source.performs_probes,'censorship measurement plan.performs_probes'), appliesEvasion:booleanValue(source.applies_evasion,'censorship measurement plan.applies_evasion'), readOnly:booleanValue(source.read_only,'censorship measurement plan.read_only'), invariants:stringArray(source.invariants,'censorship measurement plan.invariants') };
}

export function parseDTLSSessionPolicyPlan(value: unknown): DTLSSessionPolicyPlan {
  const source=record(value,'DTLS session policy plan');
  return { role:stringValue(source.role,'DTLS session policy plan.role'), identityMode:stringValue(source.identity_mode,'DTLS session policy plan.identity_mode'), mtu:numberValue(source.mtu,'DTLS session policy plan.mtu'), replayProtectionWindow:numberValue(source.replay_protection_window,'DTLS session policy plan.replay_protection_window'), flightIntervalMillis:numberValue(source.flight_interval_ms,'DTLS session policy plan.flight_interval_ms'), retransmitBackoff:booleanValue(source.retransmit_backoff,'DTLS session policy plan.retransmit_backoff'), extendedMasterSecret:stringValue(source.extended_master_secret,'DTLS session policy plan.extended_master_secret'), supportedProtocols:stringArray(source.supported_protocols,'DTLS session policy plan.supported_protocols'), connectionIDLength:numberValue(source.connection_id_length,'DTLS session policy plan.connection_id_length'), maxPaddingBytes:numberValue(source.max_padding_bytes,'DTLS session policy plan.max_padding_bytes'), sessionResumption:booleanValue(source.session_resumption,'DTLS session policy plan.session_resumption'), warnings:stringArray(source.warnings,'DTLS session policy plan.warnings'), performsHandshake:booleanValue(source.performs_handshake,'DTLS session policy plan.performs_handshake'), writesKeyLog:booleanValue(source.writes_key_log,'DTLS session policy plan.writes_key_log'), readOnly:booleanValue(source.read_only,'DTLS session policy plan.read_only'), invariants:stringArray(source.invariants,'DTLS session policy plan.invariants') };
}

export function parsePhantomPoolPlan(value: unknown): PhantomPoolPlan {
  const source=record(value,'phantom pool plan');
  if (!Array.isArray(source.selected)) throw new Error('phantom pool plan.selected must be an array');
  return { selected:source.selected.map((item,index)=>{const r=record(item,`phantom selection[${index}]`);return{id:stringValue(r.id,`phantom selection[${index}].id`),address:stringValue(r.address,`phantom selection[${index}].address`),transport:stringValue(r.transport,`phantom selection[${index}].transport`),rankHash:stringValue(r.rank_hash,`phantom selection[${index}].rank_hash`)}}), rejected:stringMap(source.rejected,'phantom pool plan.rejected'), performsLivenessProbe:booleanValue(source.performs_liveness_probe,'phantom pool plan.performs_liveness_probe'), registersPhantom:booleanValue(source.registers_phantom,'phantom pool plan.registers_phantom'), performsNetworkIO:booleanValue(source.performs_network_io,'phantom pool plan.performs_network_io'), readOnly:booleanValue(source.read_only,'phantom pool plan.read_only'), invariants:stringArray(source.invariants,'phantom pool plan.invariants') };
}

export function parseFlowFilterPlan(value: unknown): FlowFilterPlan {
  const source=record(value,'flow filter plan');
  if (!Array.isArray(source.clauses)) throw new Error('flow filter plan.clauses must be an array');
  return { match:stringValue(source.match,'flow filter plan.match'), canonical:stringValue(source.canonical,'flow filter plan.canonical'), clauses:source.clauses.map((item,index)=>{const r=record(item,`flow filter clause[${index}]`);return{field:stringValue(r.field,`flow filter clause[${index}].field`),operator:stringValue(r.operator,`flow filter clause[${index}].operator`),value:stringValue(r.value,`flow filter clause[${index}].value`)}}), readsFlowBodies:booleanValue(source.reads_flow_bodies,'flow filter plan.reads_flow_bodies'), modifiesFlows:booleanValue(source.modifies_flows,'flow filter plan.modifies_flows'), replaysFlows:booleanValue(source.replays_flows,'flow filter plan.replays_flows'), readOnly:booleanValue(source.read_only,'flow filter plan.read_only'), invariants:stringArray(source.invariants,'flow filter plan.invariants') };
}

export interface PluggableTransportPlanView {
  transport: string; platform: string; observedState: string; ready: boolean; nextAction: string;
  localPort: number; proxySupported: boolean; normalizedMaxPeers: number; singletonRequired: boolean;
  stateDirRequired: boolean; safeLogging: boolean; startsTransport: boolean; performsNetworkIO: boolean;
  writesState: boolean; warnings: string[]; invariants: string[];
}

export function parsePluggableTransportPlan(value: unknown): PluggableTransportPlanView {
  const source = record(value, 'pluggable transport plan');
  return {
    transport: stringValue(source.transport, 'pluggable transport plan.transport'),
    platform: stringValue(source.platform, 'pluggable transport plan.platform'),
    observedState: stringValue(source.observed_state, 'pluggable transport plan.observed_state'),
    ready: booleanValue(source.ready, 'pluggable transport plan.ready'),
    nextAction: stringValue(source.next_action, 'pluggable transport plan.next_action'),
    localPort: numberValue(source.local_port, 'pluggable transport plan.local_port'),
    proxySupported: booleanValue(source.proxy_supported, 'pluggable transport plan.proxy_supported'),
    normalizedMaxPeers: numberValue(source.normalized_max_peers, 'pluggable transport plan.normalized_max_peers'),
    singletonRequired: booleanValue(source.singleton_required, 'pluggable transport plan.singleton_required'),
    stateDirRequired: booleanValue(source.state_dir_required, 'pluggable transport plan.state_dir_required'),
    safeLogging: booleanValue(source.safe_logging, 'pluggable transport plan.safe_logging'),
    startsTransport: booleanValue(source.starts_transport, 'pluggable transport plan.starts_transport'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'pluggable transport plan.performs_network_io'),
    writesState: booleanValue(source.writes_state, 'pluggable transport plan.writes_state'),
    warnings: stringArray(source.warnings, 'pluggable transport plan.warnings'),
    invariants: stringArray(source.invariants, 'pluggable transport plan.invariants'),
  };
}

export interface CircumventionFallbackPlanView {
  currentTransport: string; nextTransport?: string; action: string; terminal: boolean; resetDeadline: boolean;
  maximumTransitions: number; performsNetworkIO: boolean; startsTransport: boolean; mutatesPreferences: boolean;
  reasons: string[]; invariants: string[];
}

export function parseCircumventionFallbackPlan(value: unknown): CircumventionFallbackPlanView {
  const source = record(value, 'circumvention fallback plan');
  const nextTransport = optionalString(source.next_transport, 'circumvention fallback plan.next_transport');
  return {
    currentTransport: stringValue(source.current_transport, 'circumvention fallback plan.current_transport'),
    ...(nextTransport !== undefined ? { nextTransport } : {}),
    action: stringValue(source.action, 'circumvention fallback plan.action'),
    terminal: booleanValue(source.terminal, 'circumvention fallback plan.terminal'),
    resetDeadline: booleanValue(source.reset_deadline, 'circumvention fallback plan.reset_deadline'),
    maximumTransitions: numberValue(source.maximum_transitions, 'circumvention fallback plan.maximum_transitions'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'circumvention fallback plan.performs_network_io'),
    startsTransport: booleanValue(source.starts_transport, 'circumvention fallback plan.starts_transport'),
    mutatesPreferences: booleanValue(source.mutates_preferences, 'circumvention fallback plan.mutates_preferences'),
    reasons: stringArray(source.reasons, 'circumvention fallback plan.reasons'),
    invariants: stringArray(source.invariants, 'circumvention fallback plan.invariants'),
  };
}

export interface NaiveProxyPolicyPlanView {
  platform: string; padding: string; paddingNegotiatedByHeader: boolean; firstPaddedFrames: number;
  frameHeaderBytes: number; maxPaddingBytes: number; maxPayloadBytes: number; firstConnectFastOpenAllowed: boolean;
  naivePaddingEligible: boolean; performsNetworkIO: boolean; startsProxy: boolean; writesResolverRules: boolean;
  warnings: string[]; invariants: string[];
}

export function parseNaiveProxyPolicyPlan(value: unknown): NaiveProxyPolicyPlanView {
  const source = record(value, 'naive proxy policy plan');
  return {
    platform: stringValue(source.platform, 'naive proxy policy plan.platform'),
    padding: stringValue(source.padding, 'naive proxy policy plan.padding'),
    paddingNegotiatedByHeader: booleanValue(source.padding_negotiated_by_header, 'naive proxy policy plan.padding_negotiated_by_header'),
    firstPaddedFrames: numberValue(source.first_padded_frames, 'naive proxy policy plan.first_padded_frames'),
    frameHeaderBytes: numberValue(source.frame_header_bytes, 'naive proxy policy plan.frame_header_bytes'),
    maxPaddingBytes: numberValue(source.max_padding_bytes, 'naive proxy policy plan.max_padding_bytes'),
    maxPayloadBytes: numberValue(source.max_payload_bytes, 'naive proxy policy plan.max_payload_bytes'),
    firstConnectFastOpenAllowed: booleanValue(source.first_connect_fast_open_allowed, 'naive proxy policy plan.first_connect_fast_open_allowed'),
    naivePaddingEligible: booleanValue(source.naive_padding_eligible, 'naive proxy policy plan.naive_padding_eligible'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'naive proxy policy plan.performs_network_io'),
    startsProxy: booleanValue(source.starts_proxy, 'naive proxy policy plan.starts_proxy'),
    writesResolverRules: booleanValue(source.writes_resolver_rules, 'naive proxy policy plan.writes_resolver_rules'),
    warnings: stringArray(source.warnings, 'naive proxy policy plan.warnings'),
    invariants: stringArray(source.invariants, 'naive proxy policy plan.invariants'),
  };
}

export interface StegoSchemePlanView {
  direction: string; payloadBytes: number; selected?: Record<string, unknown>; fallbackOrder: Record<string, unknown>[];
  rejected: Record<string, unknown>; embedsPayload: boolean; loadsCoverAssets: boolean; performsNetworkIO: boolean;
  mutatesSchemeState: boolean; invariants: string[];
}

export function parseStegoSchemePlan(value: unknown): StegoSchemePlanView {
  const source = record(value, 'stego scheme plan');
  const order = source.fallback_order;
  if (!Array.isArray(order)) throw new Error('stego scheme plan.fallback_order must be an array');
  return {
    direction: stringValue(source.direction, 'stego scheme plan.direction'),
    payloadBytes: numberValue(source.payload_bytes, 'stego scheme plan.payload_bytes'),
    ...(source.selected !== undefined && source.selected !== null ? { selected: record(source.selected, 'stego scheme plan.selected') } : {}),
    fallbackOrder: order.map((item, index) => record(item, `stego scheme plan.fallback_order[${index}]`)),
    rejected: record(source.rejected, 'stego scheme plan.rejected'),
    embedsPayload: booleanValue(source.embeds_payload, 'stego scheme plan.embeds_payload'),
    loadsCoverAssets: booleanValue(source.loads_cover_assets, 'stego scheme plan.loads_cover_assets'),
    performsNetworkIO: booleanValue(source.performs_network_io, 'stego scheme plan.performs_network_io'),
    mutatesSchemeState: booleanValue(source.mutates_scheme_state, 'stego scheme plan.mutates_scheme_state'),
    invariants: stringArray(source.invariants, 'stego scheme plan.invariants'),
  };
}
