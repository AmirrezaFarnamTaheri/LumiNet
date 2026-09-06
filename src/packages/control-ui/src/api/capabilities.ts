export type CapabilityStatus = 'available' | 'unavailable';

export interface CapabilityAvailability {
  id: string;
  name: string;
  description: string;
  maturity: string;
  platforms: string[];
  workflow: string;
  status: CapabilityStatus;
  reason: string;
}

export interface NativeCoreAvailability {
  status: CapabilityStatus;
  version: string;
  reason: string;
}

export interface CapabilityRuntime {
  os: string;
  arch: string;
  nativeCore: NativeCoreAvailability;
}

export interface CapabilityFlowOwnerCoverage {
  owner: string;
  visible: boolean;
  closeable: boolean;
  byteCounters: boolean;
  processAttribution: boolean;
  destinationMetadata: boolean;
  notes: string[];
}

export interface CapabilityFlowStats {
  active: number;
  closing: number;
  capacity: number;
  uploadBytes: number;
  downloadBytes: number;
}

export interface CapabilityCoverage {
  flowRegistry: {
    coverageComplete: boolean;
    coverageModel: string;
    owners: CapabilityFlowOwnerCoverage[];
    stats: CapabilityFlowStats;
  };
  networkState: {
    running: boolean;
    revision: number;
    capturedAt: string;
    lastError: string;
  };
  providerCorpus: {
    ready: boolean;
    corpusID: string;
    generatorVersion: string;
    generatedAt: string;
    fetchedAt: string;
    staleAfter: string;
    checksum: string;
    stale: boolean;
  };
}

export interface CapabilityReport {
  schemaVersion: number;
  runtime: CapabilityRuntime;
  capabilities: CapabilityAvailability[];
  coverage: CapabilityCoverage;
  safetyBoundary: string;
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`expected ${label} object`);
  return value as JsonRecord;
}
function text(value: unknown, label: string, fallback = ''): string {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'string') throw new Error(`expected ${label} string`);
  return value;
}
function bool(value: unknown, label: string, fallback = false): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'boolean') throw new Error(`expected ${label} boolean`);
  return value;
}
function integer(value: unknown, label: string, fallback = 0): number {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error(`expected ${label} non-negative safe integer`);
  return value;
}
function stringArray(value: unknown, label: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) throw new Error(`expected ${label} string array`);
  return value.slice();
}

function parseFlowOwner(value: unknown, index: number): CapabilityFlowOwnerCoverage {
  const r = record(value, `flow owner ${index}`);
  return {
    owner: text(r.owner, `flow owner ${index}.owner`),
    visible: bool(r.visible, `flow owner ${index}.visible`),
    closeable: bool(r.closeable, `flow owner ${index}.closeable`),
    byteCounters: bool(r.byte_counters, `flow owner ${index}.byte_counters`),
    processAttribution: bool(r.process_attribution, `flow owner ${index}.process_attribution`),
    destinationMetadata: bool(r.destination_metadata, `flow owner ${index}.destination_metadata`),
    notes: stringArray(r.notes, `flow owner ${index}.notes`),
  };
}

export function parseCapabilityReport(value: unknown): CapabilityReport {
  const root = record(value, 'capability report');
  const runtime = record(root.runtime, 'runtime');
  const native = record(runtime.native_core, 'native core');
  const coverage = record(root.coverage, 'coverage');
  const flow = record(coverage.flow_registry, 'flow registry coverage');
  const stats = record(flow.stats, 'flow stats');
  const network = record(coverage.network_state, 'network state coverage');
  const provider = record(coverage.provider_corpus, 'provider corpus coverage');
  const providerStatus = provider.status === undefined || provider.status === null ? {} : record(provider.status, 'provider corpus status');
  if (!Array.isArray(root.capabilities) || !Array.isArray(flow.owners)) throw new Error('invalid capability report arrays');

  const nativeStatus = text(native.status, 'native core status') as CapabilityStatus;
  if (nativeStatus !== 'available' && nativeStatus !== 'unavailable') throw new Error('invalid native core status');

  return {
    schemaVersion: integer(root.schema_version, 'schema_version'),
    runtime: {
      os: text(runtime.os, 'runtime.os'),
      arch: text(runtime.arch, 'runtime.arch'),
      nativeCore: {
        status: nativeStatus,
        version: text(native.version, 'native core version'),
        reason: text(native.reason, 'native core reason'),
      },
    },
    capabilities: root.capabilities.map((raw, index): CapabilityAvailability => {
      const cap = record(raw, `capability ${index}`);
      const status = text(cap.status, `capability ${index}.status`) as CapabilityStatus;
      if (status !== 'available' && status !== 'unavailable') throw new Error(`invalid capability ${index} status`);
      return {
        id: text(cap.id, `capability ${index}.id`),
        name: text(cap.name, `capability ${index}.name`),
        description: text(cap.description, `capability ${index}.description`),
        maturity: text(cap.maturity, `capability ${index}.maturity`),
        platforms: stringArray(cap.platforms, `capability ${index}.platforms`),
        workflow: text(cap.workflow, `capability ${index}.workflow`),
        status,
        reason: text(cap.reason, `capability ${index}.reason`),
      };
    }),
    coverage: {
      flowRegistry: {
        coverageComplete: bool(flow.coverage_complete, 'flow coverage_complete'),
        coverageModel: text(flow.coverage_model, 'flow coverage_model'),
        owners: flow.owners.map(parseFlowOwner),
        stats: {
          active: integer(stats.active, 'flow stats.active'),
          closing: integer(stats.closing, 'flow stats.closing'),
          capacity: integer(stats.capacity, 'flow stats.capacity'),
          uploadBytes: integer(stats.upload_bytes, 'flow stats.upload_bytes'),
          downloadBytes: integer(stats.download_bytes, 'flow stats.download_bytes'),
        },
      },
      networkState: {
        running: bool(network.running, 'network running'),
        revision: integer(network.revision, 'network revision'),
        capturedAt: text(network.captured_at, 'network captured_at'),
        lastError: text(network.last_error, 'network last_error'),
      },
      providerCorpus: {
        ready: bool(provider.ready, 'provider corpus ready'),
        corpusID: text(providerStatus.corpus_id, 'provider corpus id'),
        generatorVersion: text(providerStatus.generator_version, 'provider generator version'),
        generatedAt: text(providerStatus.generated_at, 'provider generated_at'),
        fetchedAt: text(providerStatus.fetched_at, 'provider fetched_at'),
        staleAfter: text(providerStatus.stale_after, 'provider stale_after'),
        checksum: text(providerStatus.checksum, 'provider checksum'),
        stale: bool(providerStatus.stale, 'provider stale'),
      },
    },
    safetyBoundary: text(root.safety_boundary, 'safety_boundary'),
  };
}
