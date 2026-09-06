/**
 * Autonomous Hardware & Network Advisor for DNS Tunnel Configuration
 * 
 * Provides deterministic recommendation algorithms for client and server tuning
 * based on hardware capacity, link quality, and workload profiles.
 */

export type NetworkConnection = '4g' | 'wifi' | 'dsl' | 'fiber';
export type NetworkQuality = 'excellent' | 'good' | 'medium' | 'poor';
export type ResolverCensus = 'few' | 'medium' | 'many';
export type MtuPreference = 'stable' | 'balanced' | 'speed';
export type UseCase = 'browse' | 'chat' | 'stream' | 'download' | 'mixed';
export type EncryptionPreference = 'light' | 'balanced' | 'strong';

export interface ClientHardwareProfile {
  connection: NetworkConnection;
  quality: NetworkQuality;
  cpuCores: number;
  ramMB: number;
  resolverCensus: ResolverCensus;
  mtuPreference: MtuPreference;
  useCase: UseCase;
  encryptionPreference: EncryptionPreference;
}

export interface ClientRecommendation {
  dataEncryptionMethod: number; // 1: XOR, 2: ChaCha20, 5: AES-256-GCM
  packetDuplicationCount: number;
  setupPacketDuplicationCount: number;
  resolverBalancingStrategy: number; // 0: RR, 1: Random, 3: LowestLoss, 4: LowestLatency
  streamResolverFailoverThreshold: number;
  streamResolverFailoverCooldownSec: number;
  minUploadMtu: number;
  minDownloadMtu: number;
  maxUploadMtu: number;
  maxDownloadMtu: number;
  mtuTestParallelism: number;
  mtuTestRetries: number;
  mtuTestTimeoutSec: number;
  tunnelReaderWorkers: number;
  tunnelWriterWorkers: number;
  tunnelProcessWorkers: number;
  txChannelSize: number;
  rxChannelSize: number;
  resolverUdpConnectionPoolSize: number;
  uploadCompressionType: number; // 0: None, 1: ZSTD, 2: LZ4
  downloadCompressionType: number;
  arqWindowSize: number;
  arqDataNackMaxGap: number;
  arqMaxDataRetries: number;
  arqMaxRtoSec: number;
  pingAggressiveIntervalSec: number;
  pingLazyIntervalSec: number;
  pingCooldownIntervalSec: number;
  dispatcherIdlePollIntervalSec: number;
}

export type ServerTraffic = 'light' | 'moderate' | 'heavy';
export type ServerDnsUpstream = 'cf' | 'google' | 'both';

export interface ServerHardwareProfile {
  cpuCores: number;
  ramMB: number;
  networkMbps: number;
  concurrentUsers: number;
  traffic: ServerTraffic;
  encryptionPreference: EncryptionPreference;
  upstreamDns: ServerDnsUpstream;
  lossyClients: boolean;
}

export interface ServerRecommendation {
  dataEncryptionMethod: number;
  dnsUpstreamServers: string[];
  udpReaders: number;
  dnsRequestWorkers: number;
  deferredSessionWorkers: number;
  maxConcurrentRequests: number;
  deferredSessionQueueLimit: number;
  socketBufferSizeBytes: number;
  sessionTimeoutSeconds: number;
  dnsCacheMaxRecords: number;
  packetBlockControlDuplication: number;
  maxPacketsPerBatch: number;
  arqWindowSize: number;
  arqDataNackMaxGap: number;
  arqMaxDataRetries: number;
  socksConnectTimeoutSeconds: number;
  socks5FragmentStoreCapacity: number;
  dnsFragmentStoreCapacity: number;
  sessionCleanupIntervalSeconds: number;
  closedSessionRetentionSeconds: number;
}

export interface ConfigDiffItem {
  category: string;
  key: string;
  value: string | number | boolean | string[];
  description: string;
}

const QUALITY_MAP: Record<NetworkQuality, number> = {
  excellent: 1.0,
  good: 0.8,
  medium: 0.5,
  poor: 0.3,
};

const CENSUS_PARALLELISM: Record<ResolverCensus, number> = {
  many: 64,
  medium: 32,
  few: 16,
};

const CENSUS_WORKER_LIMIT: Record<ResolverCensus, number> = {
  many: 4,
  medium: 3,
  few: 2,
};

const CENSUS_UDP_POOL_SIZE: Record<ResolverCensus, number> = {
  many: 64,
  medium: 128,
  few: 256,
};

function computeCapacityFactor(value: number, highThreshold: number, midThreshold: number): number {
  if (value >= highThreshold) return 4;
  if (value >= midThreshold) return 2;
  return 1;
}


export function adviseClient(profile: ClientHardwareProfile): {
  recommendation: ClientRecommendation;
  changes: ConfigDiffItem[];
} {
  const q = QUALITY_MAP[profile.quality] ?? 0.5;
  const isLossy = q <= 0.5;
  const isMobile = profile.connection === '4g';
  const isStream = profile.useCase === 'stream';
  const isDownload = profile.useCase === 'download';
  const isMixed = profile.useCase === 'mixed';
  const isChat = profile.useCase === 'chat';

  const changes: ConfigDiffItem[] = [];

  // 1. Encryption
  const encMap: Record<EncryptionPreference, number> = { light: 1, balanced: 2, strong: 5 };
  const dataEncryptionMethod = encMap[profile.encryptionPreference] ?? 1;
  changes.push({
    category: '🔐',
    key: 'DATA_ENCRYPTION_METHOD',
    value: dataEncryptionMethod,
    description: `Encryption: ${profile.encryptionPreference}`,
  });

  // 2. Packet duplication
  let dup = 1;
  if (isLossy) dup = 4;
  else if (q <= 0.8) dup = 2;
  if (isMobile) dup = Math.max(dup, 3);
  const setupDup = Math.min(dup + 1, 8);
  changes.push({
    category: '📡',
    key: 'PACKET_DUPLICATION_COUNT',
    value: dup,
    description: `Duplication: ${dup}× (Setup: ${setupDup}×)`,
  });

  // 3. Resolver strategy
  let strat = 0;
  if (isLossy) strat = 3;
  else if (profile.resolverCensus === 'many') strat = 4;
  else if (profile.resolverCensus === 'medium') strat = 3;
  const stratNames: Record<number, string> = {
    0: 'Round Robin',
    1: 'Random',
    3: 'Lowest Loss',
    4: 'Lowest Latency',
  };
  changes.push({
    category: '⚡',
    key: 'RESOLVER_BALANCING_STRATEGY',
    value: strat,
    description: `Resolver Strategy: ${stratNames[strat] ?? strat}`,
  });

  // 4. Failover
  const failoverThreshold = isLossy ? 2 : 3;
  const failoverCooldown = isLossy ? 4 : 8;

  // 5. MTU
  const mtuProfiles: Record<MtuPreference, { minUp: number; minDn: number; maxUp: number; maxDn: number }> = {
    stable: { minUp: 25, minDn: 50, maxUp: 60, maxDn: 200 },
    balanced: { minUp: 40, minDn: 100, maxUp: 150, maxDn: 500 },
    speed: { minUp: 60, minDn: 120, maxUp: 220, maxDn: 700 },
  };
  const mtu = mtuProfiles[profile.mtuPreference] ?? mtuProfiles.balanced;

  // 6. MTU test parallelism
  let para = CENSUS_PARALLELISM[profile.resolverCensus] ?? 16;
  if (profile.cpuCores <= 2) para = Math.min(para, 16);
  if (profile.cpuCores <= 1) para = Math.min(para, 8);
  const mtuRetries = isLossy ? 3 : 2;
  const mtuTimeout = isLossy ? 3 : 2;

  // 7. Workers
  const maxWorkers = Math.max(1, profile.cpuCores - 1);
  const workerLimit = CENSUS_WORKER_LIMIT[profile.resolverCensus] ?? 2;
  let rw = Math.max(2, Math.min(maxWorkers, workerLimit));
  if (isStream || isDownload) rw = Math.min(Math.max(rw, 3), maxWorkers + 1);
  const procWorkers = Math.max(2, rw - 1);

  // 8. Buffers and Channels
  let txSz = 8192;
  let rxSz = 12288;
  if (profile.ramMB <= 512) {
    txSz = 4096;
    rxSz = 4096;
  } else if (profile.ramMB <= 2048) {
    txSz = 8192;
    rxSz = 8192;
  }
  if ((isStream || isDownload || isMixed) && profile.ramMB >= 2048) {
    txSz = 16384;
    rxSz = 16384;
  }
  if (isChat && profile.ramMB <= 2048) {
    txSz = 4096;
    rxSz = 4096;
  }

  // 9. UDP Pool
  let poolSz = CENSUS_UDP_POOL_SIZE[profile.resolverCensus] ?? 256;
  if (profile.ramMB <= 512) poolSz = Math.min(poolSz, 32);
  else if (profile.ramMB <= 2048) poolSz = Math.min(poolSz, 64);

  // 10. Compression
  let upComp = 0;
  let dnComp = 0;
  if (isStream || isDownload || isMixed) {
    upComp = 2;
    dnComp = 2;
  } else if (isLossy || isMobile) {
    upComp = 1;
    dnComp = 1;
  }

  // 11. ARQ
  let arqWin = 600;
  let arqGap = 32;
  let arqRetries = 1000;
  let arqRto = 3.0;
  if (isLossy) {
    arqWin = 1000;
    arqGap = 64;
    arqRetries = 1500;
    arqRto = 6.0;
  } else if (isStream || isDownload) {
    arqWin = 800;
    arqGap = 48;
    arqRetries = 1200;
    arqRto = 4.0;
  }

  // 12. Ping
  let pingAggr = 0.25;
  let pingLazy = 0.80;
  let pingCool = 2.0;
  if (isStream) {
    pingAggr = 0.15;
    pingLazy = 0.50;
    pingCool = 1.5;
  } else if (isChat) {
    pingAggr = 0.30;
    pingLazy = 1.0;
    pingCool = 3.0;
  } else if (isLossy) {
    pingAggr = 0.20;
    pingLazy = 0.75;
    pingCool = 2.0;
  }

  // 13. Dispatcher Idle Poll
  let dispInterval = 0.020;
  if (profile.cpuCores <= 1) dispInterval = 0.050;
  else if (profile.cpuCores <= 2) dispInterval = 0.030;
  else if (isStream || isDownload) dispInterval = 0.010;

  const recommendation: ClientRecommendation = {
    dataEncryptionMethod,
    packetDuplicationCount: dup,
    setupPacketDuplicationCount: setupDup,
    resolverBalancingStrategy: strat,
    streamResolverFailoverThreshold: failoverThreshold,
    streamResolverFailoverCooldownSec: failoverCooldown,
    minUploadMtu: mtu.minUp,
    minDownloadMtu: mtu.minDn,
    maxUploadMtu: mtu.maxUp,
    maxDownloadMtu: mtu.maxDn,
    mtuTestParallelism: para,
    mtuTestRetries: mtuRetries,
    mtuTestTimeoutSec: mtuTimeout,
    tunnelReaderWorkers: rw,
    tunnelWriterWorkers: rw,
    tunnelProcessWorkers: procWorkers,
    txChannelSize: txSz,
    rxChannelSize: rxSz,
    resolverUdpConnectionPoolSize: poolSz,
    uploadCompressionType: upComp,
    downloadCompressionType: dnComp,
    arqWindowSize: arqWin,
    arqDataNackMaxGap: arqGap,
    arqMaxDataRetries: arqRetries,
    arqMaxRtoSec: arqRto,
    pingAggressiveIntervalSec: pingAggr,
    pingLazyIntervalSec: pingLazy,
    pingCooldownIntervalSec: pingCool,
    dispatcherIdlePollIntervalSec: dispInterval,
  };

  return { recommendation, changes };
}

export function adviseServer(profile: ServerHardwareProfile): {
  recommendation: ServerRecommendation;
  changes: ConfigDiffItem[];
} {
  const cpuFactor = computeCapacityFactor(profile.cpuCores, 8, 4);
  const ramFactor = computeCapacityFactor(profile.ramMB, 4096, 2048);
  const isHeavy = profile.traffic === 'heavy';
  const isMultiUser = profile.concurrentUsers >= 5;
  const isLossy = profile.lossyClients;

  const changes: ConfigDiffItem[] = [];

  // 1. Encryption
  const encMap: Record<EncryptionPreference, number> = { light: 1, balanced: 2, strong: 5 };
  const dataEncryptionMethod = encMap[profile.encryptionPreference] ?? 1;

  // 2. Upstream DNS
  const dnsMap: Record<ServerDnsUpstream, string[]> = {
    cf: ['1.1.1.1:53', '1.0.0.1:53'],
    google: ['8.8.8.8:53', '8.8.4.4:53'],
    both: ['1.1.1.1:53', '1.0.0.1:53', '8.8.8.8:53', '8.8.4.4:53'],
  };
  const dnsUpstreamServers = dnsMap[profile.upstreamDns] ?? dnsMap.cf;

  // 3. Readers and workers
  let udpReaders = Math.max(2, cpuFactor);
  let dnsRequestWorkers = Math.max(4, cpuFactor * 2);
  if (isMultiUser) {
    udpReaders = Math.max(udpReaders, 3);
    dnsRequestWorkers = Math.max(dnsRequestWorkers, 6);
  }
  if (isHeavy) {
    udpReaders = Math.max(udpReaders, 4);
    dnsRequestWorkers = Math.max(dnsRequestWorkers, 8);
  }

  // 4. Deferred workers
  let deferredSessionWorkers = Math.max(2, cpuFactor);
  if (isMultiUser) deferredSessionWorkers = Math.max(deferredSessionWorkers, 3);

  // 5. Max concurrent requests
  let maxConcurrentRequests = 4096;
  if (ramFactor >= 2) maxConcurrentRequests = 8192;
  if (ramFactor >= 4) maxConcurrentRequests = 16384;
  if (isMultiUser && isHeavy) maxConcurrentRequests = Math.min(maxConcurrentRequests * 2, 32768);

  // 6. Deferred queue limit
  let deferredSessionQueueLimit = 2048;
  if (ramFactor >= 2) deferredSessionQueueLimit = 4096;
  if (isMultiUser) deferredSessionQueueLimit = Math.min(deferredSessionQueueLimit * 2, 14336);

  // 7. Socket buffer
  let socketBufferSizeBytes = 4 * 1024 * 1024;
  if (profile.ramMB >= 2048) socketBufferSizeBytes = 8 * 1024 * 1024;
  if (profile.ramMB >= 4096 && isHeavy) socketBufferSizeBytes = 16 * 1024 * 1024;

  // 8. Session timeout
  const sessionTimeoutSeconds = profile.concurrentUsers >= 15 ? 180 : 300;

  // 9. DNS cache
  let dnsCacheMaxRecords = 10000;
  if (ramFactor >= 4) dnsCacheMaxRecords = 100000;
  else if (ramFactor >= 2) dnsCacheMaxRecords = 50000;

  // 10. Control duplication for lossy clients
  const packetBlockControlDuplication = isLossy ? 3 : 1;
  const maxPacketsPerBatch = isLossy ? 12 : 10;

  // 11. ARQ
  let arqWindowSize = 600;
  let arqDataNackMaxGap = 32;
  let arqMaxDataRetries = 1000;
  if (isLossy || isHeavy) {
    arqWindowSize = 1000;
    arqDataNackMaxGap = 64;
    arqMaxDataRetries = 1500;
  }

  // 12. SOCKS connect timeout
  const socksConnectTimeoutSeconds = profile.concurrentUsers >= 15 ? 60 : 120;

  // 13. Fragment store capacity
  const socks5FragmentStoreCapacity = isMultiUser ? 2048 : 1024;
  const dnsFragmentStoreCapacity = isMultiUser ? 1024 : 512;

  // 14. Session cleanup and retention
  const sessionCleanupIntervalSeconds = profile.concurrentUsers >= 15 ? 15 : 30;
  const closedSessionRetentionSeconds = profile.concurrentUsers >= 15 ? 300 : 600;

  const recommendation: ServerRecommendation = {
    dataEncryptionMethod,
    dnsUpstreamServers,
    udpReaders,
    dnsRequestWorkers,
    deferredSessionWorkers,
    maxConcurrentRequests,
    deferredSessionQueueLimit,
    socketBufferSizeBytes,
    sessionTimeoutSeconds,
    dnsCacheMaxRecords,
    packetBlockControlDuplication,
    maxPacketsPerBatch,
    arqWindowSize,
    arqDataNackMaxGap,
    arqMaxDataRetries,
    socksConnectTimeoutSeconds,
    socks5FragmentStoreCapacity,
    dnsFragmentStoreCapacity,
    sessionCleanupIntervalSeconds,
    closedSessionRetentionSeconds,
  };

  return { recommendation, changes };
}
