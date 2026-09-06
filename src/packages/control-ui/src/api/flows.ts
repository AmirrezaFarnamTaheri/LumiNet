export type FlowState = 'active' | 'closing';

export interface FlowProviderAttribution {
  providerID: string;
  displayName: string;
  prefix: string;
  confidence: string;
  corpusID: string;
  corpusStale: boolean;
}

export interface FlowSnapshot {
  id: string;
  owner: string;
  network: string;
  protocol: string;
  source: string;
  destination: string;
  host: string;
  process: string;
  processPath: string;
  rule: string;
  rulePayload: string;
  chain: string[];
  labels: Record<string, string>;
  startedAt: string;
  lastActivityAt: string;
  uploadBytes: number;
  downloadBytes: number;
  networkEpoch: number;
  state: FlowState;
  closeable: boolean;
  destinationProvider: FlowProviderAttribution | null;
}

export interface FlowCoverage {
  owner: string;
  visible: boolean;
  closeable: boolean;
  byteCounters: boolean;
  processAttribution: boolean;
  destinationMetadata: boolean;
  notes: string[];
}

export interface FlowStats {
  active: number;
  closing: number;
  capacity: number;
  uploadBytes: number;
  downloadBytes: number;
}

export interface FlowListResponse {
  flows: FlowSnapshot[];
  coverage: FlowCoverage[];
  stats: FlowStats;
  matched: number;
  returned: number;
  networkRevision: number;
  coverageComplete: boolean;
  coverageModel: string;
}

export interface NetworkInterfaceState {
  index: number;
  name: string;
  mtu: number;
  hardwareAddr: string;
  flags: string[];
  addresses: string[];
}

export interface NetworkSnapshot {
  revision: number;
  capturedAt: string;
  fingerprint: string;
  interfaces: NetworkInterfaceState[];
  defaultIPv4Interface: string;
  defaultIPv4LocalIP: string;
  defaultIPv6Interface: string;
  defaultIPv6LocalIP: string;
}

export interface NetworkChange {
  revision: number;
  observedAt: string;
  kinds: string[];
  previous: NetworkSnapshot;
  current: NetworkSnapshot;
}

export interface NetworkMonitorStatus {
  running: boolean;
  current: NetworkSnapshot;
  history: NetworkChange[];
  lastError: string;
}

export interface NetworkIntelligenceOwner {
  owner: string;
  visible: boolean;
  closeable: boolean;
  byteCounters: boolean;
  processAttribution: boolean;
  destinationMetadata: boolean;
  active: number;
  closing: number;
  preHandoff: number;
  unknownEpoch: number;
  uploadBytes: number;
  downloadBytes: number;
  notes: string[];
}

export interface NetworkIntelligenceProvider {
  providerID: string;
  displayName: string;
  flows: number;
  uploadBytes: number;
  downloadBytes: number;
}

export interface NetworkIntelligence {
  generatedAt: string;
  coverageComplete: boolean;
  coverageModel: string;
  networkRevision: number;
  networkCapturedAt: string;
  defaultIPv4Interface: string;
  defaultIPv4LocalIP: string;
  defaultIPv6Interface: string;
  defaultIPv6LocalIP: string;
  activeInterfaces: number;
  retainedHandoffs: number;
  latestHandoffKinds: string[];
  activeFlows: number;
  closingFlows: number;
  preHandoffFlows: number;
  unknownEpochFlows: number;
  unattributedFlows: number;
  uploadBytes: number;
  downloadBytes: number;
  distinctProtocols: number;
  distinctProviders: number;
  providerCorpusReady: boolean;
  providerCorpusID: string;
  providerCorpusStale: boolean;
  owners: NetworkIntelligenceOwner[];
  providers: NetworkIntelligenceProvider[];
}

type RecordValue = Record<string, unknown>;

function record(value: unknown, name: string): RecordValue {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`expected ${name} object`);
  }
  return value as RecordValue;
}

function stringValue(value: unknown, name: string, fallback = ''): string {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'string') throw new Error(`expected ${name} string`);
  return value;
}

function numberValue(value: unknown, name: string, fallback = 0): number {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`expected ${name} non-negative safe integer`);
  }
  return value;
}

function boolValue(value: unknown, name: string, fallback = false): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'boolean') throw new Error(`expected ${name} boolean`);
  return value;
}

function stringArray(value: unknown, name: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`expected ${name} string array`);
  }
  return value.slice();
}

function stringMap(value: unknown, name: string): Record<string, string> {
  if (value === undefined || value === null) return {};
  const source = record(value, name);
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(source)) {
    if (typeof item !== 'string') throw new Error(`expected ${name}.${key} string`);
    out[key] = item;
  }
  return out;
}

function parseFlow(value: unknown): FlowSnapshot {
  const r = record(value, 'flow');
  const state = stringValue(r.state, 'flow.state');
  if (state !== 'active' && state !== 'closing') throw new Error('invalid flow state');
  return {
    id: stringValue(r.id, 'flow.id'),
    owner: stringValue(r.owner, 'flow.owner'),
    network: stringValue(r.network, 'flow.network'),
    protocol: stringValue(r.protocol, 'flow.protocol'),
    source: stringValue(r.source, 'flow.source'),
    destination: stringValue(r.destination, 'flow.destination'),
    host: stringValue(r.host, 'flow.host'),
    process: stringValue(r.process, 'flow.process'),
    processPath: stringValue(r.process_path, 'flow.process_path'),
    rule: stringValue(r.rule, 'flow.rule'),
    rulePayload: stringValue(r.rule_payload, 'flow.rule_payload'),
    chain: stringArray(r.chain, 'flow.chain'),
    labels: stringMap(r.labels, 'flow.labels'),
    startedAt: stringValue(r.started_at, 'flow.started_at'),
    lastActivityAt: stringValue(r.last_activity_at, 'flow.last_activity_at'),
    uploadBytes: numberValue(r.upload_bytes, 'flow.upload_bytes'),
    downloadBytes: numberValue(r.download_bytes, 'flow.download_bytes'),
    networkEpoch: numberValue(r.network_epoch, 'flow.network_epoch'),
    state,
    closeable: boolValue(r.closeable, 'flow.closeable'),
    destinationProvider: r.destination_provider === undefined || r.destination_provider === null
      ? null
      : (() => {
          const provider = record(r.destination_provider, 'flow.destination_provider');
          return {
            providerID: stringValue(provider.provider_id, 'flow.destination_provider.provider_id'),
            displayName: stringValue(provider.display_name, 'flow.destination_provider.display_name'),
            prefix: stringValue(provider.prefix, 'flow.destination_provider.prefix'),
            confidence: stringValue(provider.confidence, 'flow.destination_provider.confidence'),
            corpusID: stringValue(provider.corpus_id, 'flow.destination_provider.corpus_id'),
            corpusStale: boolValue(provider.corpus_stale, 'flow.destination_provider.corpus_stale'),
          };
        })(),
  };
}

function parseCoverage(value: unknown): FlowCoverage {
  const r = record(value, 'coverage');
  return {
    owner: stringValue(r.owner, 'coverage.owner'),
    visible: boolValue(r.visible, 'coverage.visible'),
    closeable: boolValue(r.closeable, 'coverage.closeable'),
    byteCounters: boolValue(r.byte_counters, 'coverage.byte_counters'),
    processAttribution: boolValue(r.process_attribution, 'coverage.process_attribution'),
    destinationMetadata: boolValue(r.destination_metadata, 'coverage.destination_metadata'),
    notes: stringArray(r.notes, 'coverage.notes'),
  };
}

export function parseFlowList(value: unknown): FlowListResponse {
  const r = record(value, 'flow list');
  if (!Array.isArray(r.flows) || !Array.isArray(r.coverage)) throw new Error('invalid flow list arrays');
  const stats = record(r.stats, 'flow stats');
  return {
    flows: r.flows.map(parseFlow),
    coverage: r.coverage.map(parseCoverage),
    stats: {
      active: numberValue(stats.active, 'stats.active'),
      closing: numberValue(stats.closing, 'stats.closing'),
      capacity: numberValue(stats.capacity, 'stats.capacity'),
      uploadBytes: numberValue(stats.upload_bytes, 'stats.upload_bytes'),
      downloadBytes: numberValue(stats.download_bytes, 'stats.download_bytes'),
    },
    matched: numberValue(r.matched, 'matched'),
    returned: numberValue(r.returned, 'returned'),
    networkRevision: numberValue(r.network_revision, 'network_revision'),
    coverageComplete: boolValue(r.coverage_complete, 'coverage_complete'),
    coverageModel: stringValue(r.coverage_model, 'coverage_model'),
  };
}

function parseInterface(value: unknown): NetworkInterfaceState {
  const r = record(value, 'interface');
  return {
    index: numberValue(r.index, 'interface.index'),
    name: stringValue(r.name, 'interface.name'),
    mtu: numberValue(r.mtu, 'interface.mtu'),
    hardwareAddr: stringValue(r.hardware_addr, 'interface.hardware_addr'),
    flags: stringArray(r.flags, 'interface.flags'),
    addresses: stringArray(r.addresses, 'interface.addresses'),
  };
}

function parseNetworkSnapshot(value: unknown): NetworkSnapshot {
  const r = record(value, 'network snapshot');
  if (!Array.isArray(r.interfaces)) throw new Error('invalid network interfaces');
  return {
    revision: numberValue(r.revision, 'network.revision'),
    capturedAt: stringValue(r.captured_at, 'network.captured_at'),
    fingerprint: stringValue(r.fingerprint, 'network.fingerprint'),
    interfaces: r.interfaces.map(parseInterface),
    defaultIPv4Interface: stringValue(r.default_ipv4_interface, 'network.default_ipv4_interface'),
    defaultIPv4LocalIP: stringValue(r.default_ipv4_local_ip, 'network.default_ipv4_local_ip'),
    defaultIPv6Interface: stringValue(r.default_ipv6_interface, 'network.default_ipv6_interface'),
    defaultIPv6LocalIP: stringValue(r.default_ipv6_local_ip, 'network.default_ipv6_local_ip'),
  };
}

export function parseNetworkStatus(value: unknown): NetworkMonitorStatus {
  const r = record(value, 'network status');
  if (!Array.isArray(r.history)) throw new Error('invalid network history');
  return {
    running: boolValue(r.running, 'network.running'),
    current: parseNetworkSnapshot(r.current),
    history: r.history.map((raw) => {
      const change = record(raw, 'network change');
      return {
        revision: numberValue(change.revision, 'change.revision'),
        observedAt: stringValue(change.observed_at, 'change.observed_at'),
        kinds: stringArray(change.kinds, 'change.kinds'),
        previous: parseNetworkSnapshot(change.previous),
        current: parseNetworkSnapshot(change.current),
      };
    }),
    lastError: stringValue(r.last_error, 'network.last_error'),
  };
}


export function parseNetworkIntelligence(value: unknown): NetworkIntelligence {
  const r = record(value, 'network intelligence');
  if (!Array.isArray(r.owners) || !Array.isArray(r.providers)) throw new Error('invalid network intelligence arrays');
  return {
    generatedAt: stringValue(r.generated_at, 'network intelligence.generated_at'),
    coverageComplete: boolValue(r.coverage_complete, 'network intelligence.coverage_complete'),
    coverageModel: stringValue(r.coverage_model, 'network intelligence.coverage_model'),
    networkRevision: numberValue(r.network_revision, 'network intelligence.network_revision'),
    networkCapturedAt: stringValue(r.network_captured_at, 'network intelligence.network_captured_at'),
    defaultIPv4Interface: stringValue(r.default_ipv4_interface, 'network intelligence.default_ipv4_interface'),
    defaultIPv4LocalIP: stringValue(r.default_ipv4_local_ip, 'network intelligence.default_ipv4_local_ip'),
    defaultIPv6Interface: stringValue(r.default_ipv6_interface, 'network intelligence.default_ipv6_interface'),
    defaultIPv6LocalIP: stringValue(r.default_ipv6_local_ip, 'network intelligence.default_ipv6_local_ip'),
    activeInterfaces: numberValue(r.active_interfaces, 'network intelligence.active_interfaces'),
    retainedHandoffs: numberValue(r.retained_handoffs, 'network intelligence.retained_handoffs'),
    latestHandoffKinds: stringArray(r.latest_handoff_kinds, 'network intelligence.latest_handoff_kinds'),
    activeFlows: numberValue(r.active_flows, 'network intelligence.active_flows'),
    closingFlows: numberValue(r.closing_flows, 'network intelligence.closing_flows'),
    preHandoffFlows: numberValue(r.pre_handoff_flows, 'network intelligence.pre_handoff_flows'),
    unknownEpochFlows: numberValue(r.unknown_epoch_flows, 'network intelligence.unknown_epoch_flows'),
    unattributedFlows: numberValue(r.unattributed_flows, 'network intelligence.unattributed_flows'),
    uploadBytes: numberValue(r.upload_bytes, 'network intelligence.upload_bytes'),
    downloadBytes: numberValue(r.download_bytes, 'network intelligence.download_bytes'),
    distinctProtocols: numberValue(r.distinct_protocols, 'network intelligence.distinct_protocols'),
    distinctProviders: numberValue(r.distinct_providers, 'network intelligence.distinct_providers'),
    providerCorpusReady: boolValue(r.provider_corpus_ready, 'network intelligence.provider_corpus_ready'),
    providerCorpusID: stringValue(r.provider_corpus_id, 'network intelligence.provider_corpus_id'),
    providerCorpusStale: boolValue(r.provider_corpus_stale, 'network intelligence.provider_corpus_stale'),
    owners: r.owners.map((raw, i) => {
      const owner = record(raw, `network intelligence owner ${i}`);
      return {
        owner: stringValue(owner.owner, `network intelligence owner ${i}.owner`),
        visible: boolValue(owner.visible, `network intelligence owner ${i}.visible`),
        closeable: boolValue(owner.closeable, `network intelligence owner ${i}.closeable`),
        byteCounters: boolValue(owner.byte_counters, `network intelligence owner ${i}.byte_counters`),
        processAttribution: boolValue(owner.process_attribution, `network intelligence owner ${i}.process_attribution`),
        destinationMetadata: boolValue(owner.destination_metadata, `network intelligence owner ${i}.destination_metadata`),
        active: numberValue(owner.active, `network intelligence owner ${i}.active`),
        closing: numberValue(owner.closing, `network intelligence owner ${i}.closing`),
        preHandoff: numberValue(owner.pre_handoff, `network intelligence owner ${i}.pre_handoff`),
        unknownEpoch: numberValue(owner.unknown_epoch, `network intelligence owner ${i}.unknown_epoch`),
        uploadBytes: numberValue(owner.upload_bytes, `network intelligence owner ${i}.upload_bytes`),
        downloadBytes: numberValue(owner.download_bytes, `network intelligence owner ${i}.download_bytes`),
        notes: stringArray(owner.notes, `network intelligence owner ${i}.notes`),
      };
    }),
    providers: r.providers.map((raw, i) => {
      const provider = record(raw, `network intelligence provider ${i}`);
      return {
        providerID: stringValue(provider.provider_id, `network intelligence provider ${i}.provider_id`),
        displayName: stringValue(provider.display_name, `network intelligence provider ${i}.display_name`),
        flows: numberValue(provider.flows, `network intelligence provider ${i}.flows`),
        uploadBytes: numberValue(provider.upload_bytes, `network intelligence provider ${i}.upload_bytes`),
        downloadBytes: numberValue(provider.download_bytes, `network intelligence provider ${i}.download_bytes`),
      };
    }),
  };
}
