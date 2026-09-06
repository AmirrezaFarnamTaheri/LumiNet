import { useEffect, useState, type ReactNode } from 'react';
import {
  ArrowDown,
  ArrowUp,
  BarChart2,
  Cpu,
  Globe,
  HardDrive,
  Play,
  RefreshCw,
  ShieldAlert,
  Wifi,
} from 'lucide-react';
import { controlTransport } from '../api/ControlTransport';
import {
  errorMessage,
  parseDiagnosticStatus,
  parseGeoIPData,
  parseMatrixResults,
  parsePingResult,
  parseSystemStatus,
  type GeoIPData,
  type MatrixResult,
  type SystemStatus,
} from '../api/contracts';
import { useSystemStore } from '../store/systemStore';

const HISTORY_POINTS = 15;
const DIAGNOSTIC_POLL_INTERVAL_MS = 1000;
const DIAGNOSTIC_MAX_POLLS = 120;

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function Dashboard() {
  const latency = useSystemStore((state) => state.latency);
  const throughput = useSystemStore((state) => state.throughput);

  const [pingTarget, setPingTarget] = useState('1.1.1.1');
  const [pingLatency, setPingLatency] = useState<number | null>(null);
  const [pingError, setPingError] = useState<string | null>(null);
  const [pinging, setPinging] = useState(false);

  const [geoData, setGeoData] = useState<GeoIPData | null>(null);
  const [geoError, setGeoError] = useState<string | null>(null);
  const [loadingGeo, setLoadingGeo] = useState(false);

  const [sysStats, setSysStats] = useState<SystemStatus | null>(null);
  const [systemError, setSystemError] = useState<string | null>(null);

  const [runningMatrix, setRunningMatrix] = useState(false);
  const [matrixProgress, setMatrixProgress] = useState(0);
  const [matrixError, setMatrixError] = useState<string | null>(null);
  const [matrixResults, setMatrixResults] = useState<MatrixResult[]>([]);
  const [matrixTarget, setMatrixTarget] = useState('104.16.124.96');
  const [matrixFakeSNI, setMatrixFakeSNI] = useState('challenges.cloudflare.com');

  const [rxHistory, setRxHistory] = useState<number[]>(new Array(HISTORY_POINTS).fill(0));

  async function fetchSystemStatus() {
    setSystemError(null);
    try {
      const status = await controlTransport.json('/api/system/status', parseSystemStatus);
      setSysStats(status);
    } catch (error) {
      setSystemError(errorMessage(error, 'System telemetry is unavailable.'));
    }
  }

  async function fetchGeoLocation() {
    setLoadingGeo(true);
    setGeoError(null);
    try {
      const geo = await controlTransport.json(
        '/api/diagnostics/geoip?target=cloudflare.com',
        parseGeoIPData,
      );
      setGeoData(geo);
    } catch (error) {
      setGeoError(errorMessage(error, 'GeoIP probe failed.'));
    } finally {
      setLoadingGeo(false);
    }
  }

  useEffect(() => {
    void fetchSystemStatus();
    void fetchGeoLocation();
  }, []);

  useEffect(() => {
    setRxHistory((previous) => [...previous.slice(1), Math.max(0, throughput.rx)]);
  }, [throughput.rx]);

  async function refreshDashboard() {
    await Promise.all([fetchSystemStatus(), fetchGeoLocation()]);
  }

  async function runPingTest() {
    const target = pingTarget.trim();
    if (!target) return;

    setPinging(true);
    setPingLatency(null);
    setPingError(null);
    try {
      const result = await controlTransport.json(
        `/api/system/ping?host=${encodeURIComponent(target)}&use_cache=false`,
        parsePingResult,
      );
      if (!result.success) {
        throw new Error(result.error || 'The TCP probe did not connect.');
      }
      setPingLatency(result.latencyMs);
    } catch (error) {
      setPingError(errorMessage(error, 'The TCP probe failed.'));
    } finally {
      setPinging(false);
    }
  }

  async function runMatrixTest() {
    const target = matrixTarget.trim();
    const fakeSNI = matrixFakeSNI.trim();
    if (!target || !fakeSNI) {
      setMatrixError('Target IP and fake SNI are required.');
      return;
    }

    setRunningMatrix(true);
    setMatrixProgress(0);
    setMatrixError(null);
    setMatrixResults([]);

    try {
      const jobID = await controlTransport.executeDiagnosticRun(
        'sni_matrix',
        target,
        { fake_sni: fakeSNI },
      );

      for (let poll = 0; poll < DIAGNOSTIC_MAX_POLLS; poll += 1) {
        const status = await controlTransport.json(
          `/api/diagnostics/${encodeURIComponent(jobID)}`,
          parseDiagnosticStatus,
        );
        setMatrixProgress(status.progress);

        if (status.status === 'completed') {
          setMatrixResults(parseMatrixResults(status.results));
          setMatrixProgress(100);
          return;
        }
        if (status.status === 'failed') {
          throw new Error(status.error || 'The SNI matrix diagnostic failed.');
        }
        await delay(DIAGNOSTIC_POLL_INTERVAL_MS);
      }
      throw new Error('The SNI matrix diagnostic exceeded the two-minute polling window.');
    } catch (error) {
      setMatrixError(errorMessage(error, 'The SNI matrix diagnostic failed.'));
    } finally {
      setRunningMatrix(false);
    }
  }

  const maxRx = Math.max(...rxHistory, 1);
  const svgPath = rxHistory
    .map((value, index) => {
      const x = (index / (HISTORY_POINTS - 1)) * 260 + 10;
      const y = 50 - (value / maxRx) * 40;
      return `${index === 0 ? 'M' : 'L'} ${x} ${y}`;
    })
    .join(' ');

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="m-0 text-2xl font-display text-text-primary">System Cockpit</h2>
          <p className="mt-1 text-text-secondary">Verified system status, tunnel telemetry, and network diagnostics.</p>
        </div>
        <button
          type="button"
          onClick={() => void refreshDashboard()}
          className="btn btn-secondary"
        >
          <RefreshCw size={16} aria-hidden="true" /> Refresh
        </button>
      </header>

      {(systemError || geoError) && (
        <div role="status" className="rounded-md border border-warning/40 bg-warning/10 p-3 text-sm text-warning">
          {[systemError, geoError].filter(Boolean).join(' ')}
        </div>
      )}

      <section aria-label="Live network metrics" className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={<Wifi size={24} />} label="Tunnel latency" value={latency !== null ? `${latency.toFixed(0)} ms` : '—'} tone="cyan" />
        <MetricCard icon={<ArrowDown size={24} />} label="RX rate" value={`${(throughput.rx / 1024 / 1024).toFixed(2)} MB/s`} tone="success" />
        <MetricCard icon={<ArrowUp size={24} />} label="TX rate" value={`${(throughput.tx / 1024 / 1024).toFixed(2)} MB/s`} tone="accent" />
        <MetricCard
          icon={<Globe size={24} />}
          label="Observed gateway"
          value={loadingGeo ? 'Probing…' : geoData ? `${geoData.city}, ${geoData.country}` : 'Unavailable'}
          tone="purple"
          compact
        />
      </section>

      {sysStats && (
        <section className="card space-y-4" aria-labelledby="reliability-title">
          <h3 id="reliability-title" className="m-0 border-b border-border-color pb-3 text-lg text-text-primary">Reliability telemetry</h3>
          <p className="m-0 text-sm text-text-secondary">Local optimistic-concurrency reconciliation and transient WebSocket fan-out pressure are separate from remote provider mutation retries.</p>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <DataPoint label="Config auto retries" value={String(sysStats.configMutationRetry.automaticRetries)} />
            <DataPoint label="Config retry exhaustion" value={String(sysStats.configMutationRetry.exhaustedRetries)} />
            <DataPoint label="WebSocket broadcast drops" value={String(sysStats.websocketBackpressure.broadcastDrops)} />
            <DataPoint label="Slow-client disconnects" value={String(sysStats.websocketBackpressure.slowClientDisconnects)} />
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
            <DataPoint label="Remote retry sleeps" value={String(sysStats.remoteMutationRetry.retrySleeps)} />
            <DataPoint label="Remote reconciliations" value={String(sysStats.remoteMutationRetry.reconciled)} />
            <DataPoint label="Remote rate limits" value={String(sysStats.remoteMutationRetry.rateLimits)} />
          </div>
        </section>
      )}

      <section className="card space-y-4" aria-labelledby="bandwidth-title">
        <h3 id="bandwidth-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg text-text-primary">
          <BarChart2 size={18} className="text-success" aria-hidden="true" /> RX throughput history
        </h3>
        <div className="flex h-40 w-full flex-col justify-between rounded-md border border-border-color bg-bg-secondary/40 p-4">
          <svg className="h-full w-full fill-none stroke-success" viewBox="0 0 280 60" role="img" aria-label="Recent receive throughput sparkline">
            <title>Recent receive throughput</title>
            <path d={svgPath} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div className="mt-2 flex justify-between border-t border-border-color/30 pt-1 text-[10px] text-text-muted">
            <span>15 s ago</span>
            <span>10 s ago</span>
            <span>5 s ago</span>
            <span className="font-semibold text-success">Peak {(maxRx / 1024 / 1024).toFixed(2)} MB/s</span>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <section className="card space-y-6" aria-labelledby="hardware-title">
          <h3 id="hardware-title" className="m-0 border-b border-border-color pb-3 text-lg text-text-primary">Hardware telemetry</h3>
          {sysStats ? (
            <div className="space-y-4">
              <UsageBar icon={<Cpu size={16} />} label="CPU usage" percent={sysStats.cpuUsage} detail={`${sysStats.cpuUsage}%`} tone="cyan" />
              <UsageBar icon={<Cpu size={16} />} label="RAM memory" percent={sysStats.ramUsage} detail={`${sysStats.usedRamGb.toFixed(1)} / ${sysStats.totalRamGb.toFixed(1)} GB`} tone="purple" />
              <div className="flex items-center justify-between pt-2 text-sm">
                <span className="flex items-center gap-2 text-text-secondary"><HardDrive size={16} aria-hidden="true" /> Free disk space</span>
                <span className="mono font-semibold text-text-primary">{sysStats.diskFreeGb} GB</span>
              </div>
            </div>
          ) : (
            <p className="m-0 text-sm text-text-muted">No verified hardware sample is available.</p>
          )}
        </section>

        <section className="card space-y-4 xl:col-span-2" aria-labelledby="probe-title">
          <h3 id="probe-title" className="m-0 border-b border-border-color pb-3 text-lg text-text-primary">Deduplicated TCP connect probe</h3>
          <p className="text-sm text-text-secondary">Measure outbound TCP connection delay without inventing a fallback value when the probe fails.</p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <label htmlFor="ping-target" className="sr-only">Probe target</label>
            <input
              id="ping-target"
              type="text"
              placeholder="google.com or 1.1.1.1"
              value={pingTarget}
              onChange={(event) => setPingTarget(event.target.value)}
              className="min-h-11 flex-1 rounded-md border border-border-color bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent"
            />
            <button type="button" onClick={() => void runPingTest()} disabled={pinging} className="btn btn-primary">
              {pinging ? <RefreshCw size={16} className="animate-spin" aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}
              Test probe
            </button>
          </div>
          {(pingLatency !== null || pingError) && (
            <div role="status" className={`flex items-center gap-2 rounded-md border p-4 text-sm font-semibold ${pingError ? 'border-error/30 bg-error/15 text-error' : 'border-success/30 bg-success/15 text-success'}`}>
              <ShieldAlert size={18} aria-hidden="true" />
              {pingError || `Connected in ${pingLatency} ms.`}
            </div>
          )}

          <div className="space-y-3 rounded-md border border-border-color bg-bg-secondary/50 p-4">
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm font-semibold text-text-primary">Observed exit location</span>
              <button type="button" onClick={() => void fetchGeoLocation()} disabled={loadingGeo} className="min-h-11 border-0 bg-transparent px-2 text-xs text-accent hover:underline">
                {loadingGeo ? 'Probing…' : 'Probe exit IP'}
              </button>
            </div>
            {geoData ? (
              <dl className="grid grid-cols-1 gap-4 text-xs sm:grid-cols-2">
                <DataPoint label="Exit IP" value={geoData.ip} />
                <DataPoint label="Country" value={`${geoData.country} (${geoData.countryCode})`} />
                <DataPoint label="Region / city" value={`${geoData.region}, ${geoData.city}`} />
                {geoData.asn && <DataPoint label="Provider / ASN" value={geoData.asn} />}
              </dl>
            ) : (
              <p className="m-0 text-xs text-text-muted">No successful GeoIP probe is available.</p>
            )}
          </div>
        </section>
      </div>

      <section className="card space-y-4" aria-labelledby="matrix-title">
        <h3 id="matrix-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg text-text-primary">
          <ShieldAlert size={18} className="text-accent" aria-hidden="true" /> SNI bypass matrix
        </h3>
        <p className="text-sm text-text-secondary">Run the server-side TLS fingerprint and ClientHello-fragmentation combinations as an asynchronous diagnostic job. Raw fake-packet repetition is not implemented and is not represented as a matrix dimension.</p>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <label className="text-xs text-text-muted">
            Target IP address
            <input
              type="text"
              value={matrixTarget}
              onChange={(event) => setMatrixTarget(event.target.value)}
              className="mt-1 min-h-11 w-full rounded-md border border-border-color bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent"
            />
          </label>
          <label className="text-xs text-text-muted">
            Fake SNI hostname
            <input
              type="text"
              value={matrixFakeSNI}
              onChange={(event) => setMatrixFakeSNI(event.target.value)}
              className="mt-1 min-h-11 w-full rounded-md border border-border-color bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent"
            />
          </label>
          <div className="flex items-end">
            <button type="button" onClick={() => void runMatrixTest()} disabled={runningMatrix} className="btn btn-primary w-full">
              {runningMatrix ? <RefreshCw size={16} className="animate-spin" aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}
              {runningMatrix ? `Running ${matrixProgress}%` : 'Run matrix scan'}
            </button>
          </div>
        </div>

        {matrixError && <div role="alert" className="rounded-md border border-error/30 bg-error/15 p-3 text-sm text-error">{matrixError}</div>}

        {matrixResults.length > 0 && (
          <div className="overflow-x-auto rounded-md border border-border-color">
            <table className="w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-border-color bg-bg-secondary text-text-muted">
                  <th className="p-3">Fingerprint</th>
                  <th className="p-3">Fragment</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Delay</th>
                </tr>
              </thead>
              <tbody>
                {matrixResults.map((row) => (
                  <tr key={`${row.utls}-${row.enableFragment}`} className="border-b border-border-color/40">
                    <td className="mono p-3 font-semibold text-text-primary">{row.utls}</td>
                    <td className="mono p-3 text-text-secondary">{row.enableFragment ? 'on' : 'off'}</td>
                    <td className="p-3">
                      <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${row.pass ? 'border-success/30 bg-success/15 text-success' : 'border-error/30 bg-error/15 text-error'}`} title={row.error}>
                        {row.pass ? 'Passed' : 'Failed'}
                      </span>
                    </td>
                    <td className="mono p-3 text-text-primary">{row.latencyMs.toFixed(1)} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function MetricCard({
  icon,
  label,
  value,
  tone,
  compact = false,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  tone: 'cyan' | 'success' | 'accent' | 'purple';
  compact?: boolean;
}) {
  const tones = {
    cyan: 'bg-cyan/15 text-cyan',
    success: 'bg-success/15 text-success',
    accent: 'bg-accent/15 text-accent',
    purple: 'bg-purple/15 text-purple',
  } as const;
  return (
    <div className="card flex items-start gap-4">
      <div className={`rounded-lg p-3 ${tones[tone]}`} aria-hidden="true">{icon}</div>
      <div className="min-w-0">
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-text-muted">{label}</h3>
        <p className={`mono m-0 truncate font-bold text-text-primary ${compact ? 'text-sm' : 'text-2xl'}`}>{value}</p>
      </div>
    </div>
  );
}

function UsageBar({
  icon,
  label,
  percent,
  detail,
  tone,
}: {
  icon: ReactNode;
  label: string;
  percent: number;
  detail: string;
  tone: 'cyan' | 'purple';
}) {
  const fill = tone === 'cyan' ? 'bg-cyan' : 'bg-purple';
  const text = tone === 'cyan' ? 'text-cyan' : 'text-purple';
  return (
    <div>
      <div className="mb-1 flex justify-between gap-3 text-sm">
        <span className="flex items-center gap-2 text-text-secondary">{icon}{label}</span>
        <span className={`mono font-semibold ${text}`}>{detail}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-bg-primary" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
        <div className={`h-full ${fill}`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

function DataPoint({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-text-muted">{label}</dt>
      <dd className="mono m-0 mt-0.5 break-words font-semibold text-text-primary">{value}</dd>
    </div>
  );
}
