import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  Activity,
  CheckCircle2,
  Download,
  HeartPulse,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react';
import { controlTransport } from '../api/ControlTransport';
import { parseCapabilityReport, type CapabilityReport } from '../api/capabilities';
import { errorMessage, parseDoctorReport, type DoctorReport } from '../api/contracts';
import { parseServiceIncidentPolicyPlan, parseTLSInterceptionEvidencePlan, parseTunnelSafetyPlan, parseWorkerAffinityPlan, type ServiceIncidentPolicyPlan, type TLSInterceptionEvidencePlan, type TunnelSafetyPlan, type WorkerAffinityPlan } from '../api/planners';
import { parseNetworkStatus, type NetworkMonitorStatus } from '../api/flows';
import { useSystemStore } from '../store/systemStore';

type HealthVerdict = 'healthy' | 'degraded' | 'unavailable';

interface HealthTimelineEntry {
  at: string;
  severity: 'success' | 'warning' | 'info';
  title: string;
  detail: string;
}

interface HealthSnapshot {
  doctor: DoctorReport | null;
  capabilities: CapabilityReport | null;
  network: NetworkMonitorStatus | null;
  sourceErrors: string[];
  capturedAt: string;
}

const EMPTY_SNAPSHOT: HealthSnapshot = {
  doctor: null,
  capabilities: null,
  network: null,
  sourceErrors: [],
  capturedAt: '',
};

async function loadDoctor(): Promise<DoctorReport> {
  const response = await controlTransport.request('/api/doctor');
  if (response.status !== 200 && response.status !== 503) {
    throw new Error(`readiness doctor returned status ${response.status}`);
  }
  return parseDoctorReport(await response.json());
}

function deriveVerdict(snapshot: HealthSnapshot): HealthVerdict {
  if (!snapshot.doctor && !snapshot.capabilities && !snapshot.network) return 'unavailable';
  if (snapshot.sourceErrors.length > 0) return 'degraded';
  if (snapshot.doctor && !snapshot.doctor.healthy) return 'degraded';
  if (snapshot.network?.lastError) return 'degraded';
  return 'healthy';
}

function verdictCopy(verdict: HealthVerdict): { title: string; detail: string; tone: string } {
  if (verdict === 'healthy') {
    return {
      title: 'Core health signals are coherent',
      detail: 'Readiness checks and passive network observation report no current degradation.',
      tone: 'border-success/35 bg-success/10 text-success',
    };
  }
  if (verdict === 'degraded') {
    return {
      title: 'One or more health signals need attention',
      detail: 'The page keeps healthy evidence and failures separate so a partial outage does not erase the last useful state.',
      tone: 'border-warning/35 bg-warning/10 text-warning',
    };
  }
  return {
    title: 'Health evidence is unavailable',
    detail: 'No readiness, capability, or network-state source could be read. This is not reported as healthy.',
    tone: 'border-error/35 bg-error/10 text-error',
  };
}

function buildTimeline(snapshot: HealthSnapshot): HealthTimelineEntry[] {
  const entries: HealthTimelineEntry[] = [];
  if (snapshot.doctor) {
    for (const check of snapshot.doctor.checks) {
      entries.push({
        at: snapshot.doctor.timestamp,
        severity: check.ok ? 'success' : 'warning',
        title: check.ok ? `${check.name} passed` : `${check.name} degraded`,
        detail: check.message || `${Math.round(check.latencyNs / 1_000_000)} ms`,
      });
    }
  }
  if (snapshot.network) {
    for (const change of snapshot.network.history) {
      entries.push({
        at: change.observedAt,
        severity: 'info',
        title: `Network epoch ${change.revision}`,
        detail: change.kinds.length > 0 ? change.kinds.join(', ') : 'passive network state changed',
      });
    }
    if (snapshot.network.lastError) {
      entries.push({
        at: snapshot.network.current.capturedAt || snapshot.capturedAt,
        severity: 'warning',
        title: 'Network monitor retained last-known-good state',
        detail: snapshot.network.lastError,
      });
    }
  }
  for (const sourceError of snapshot.sourceErrors) {
    entries.push({
      at: snapshot.capturedAt,
      severity: 'warning',
      title: 'Health source unavailable',
      detail: sourceError,
    });
  }
  return entries
    .sort((left, right) => Date.parse(right.at) - Date.parse(left.at))
    .slice(0, 32);
}

function buildDiagnosticBundle(snapshot: HealthSnapshot, connectionState: string, throughput: { rx: number; tx: number }) {
  const capability = snapshot.capabilities;
  const network = snapshot.network;
  return {
    schema: 'luminet.redacted-diagnostics.v1',
    generated_at: new Date().toISOString(),
    verdict: deriveVerdict(snapshot),
    telemetry: {
      websocket_state: connectionState,
      rx_bytes_per_second: Math.max(0, throughput.rx),
      tx_bytes_per_second: Math.max(0, throughput.tx),
    },
    readiness: snapshot.doctor ? {
      captured_at: snapshot.doctor.timestamp,
      healthy: snapshot.doctor.healthy,
      runtime: `${snapshot.doctor.goVersion} ${snapshot.doctor.goos}/${snapshot.doctor.goarch}`,
      checks: snapshot.doctor.checks.map((check) => ({
        name: check.name,
        ok: check.ok,
        latency_ns: check.latencyNs,
      })),
    } : null,
    capability_truth: capability ? {
      schema_version: capability.schemaVersion,
      runtime: capability.runtime,
      available: capability.capabilities.filter((item) => item.status === 'available').map((item) => item.id),
      unavailable: capability.capabilities.filter((item) => item.status !== 'available').map((item) => item.id),
      flow_registry: {
        coverage_complete: capability.coverage.flowRegistry.coverageComplete,
        coverage_model: capability.coverage.flowRegistry.coverageModel,
        active: capability.coverage.flowRegistry.stats.active,
        closing: capability.coverage.flowRegistry.stats.closing,
        participating_owners: capability.coverage.flowRegistry.owners.map((owner) => owner.owner),
      },
      provider_corpus: capability.coverage.providerCorpus,
      safety_boundary: capability.safetyBoundary,
    } : null,
    passive_network: network ? {
      running: network.running,
      revision: network.current.revision,
      captured_at: network.current.capturedAt,
      interface_count: network.current.interfaces.length,
      interfaces: network.current.interfaces.map((item) => ({ name: item.name, mtu: item.mtu, flags: item.flags })),
      retained_handoffs: network.history.map((entry) => ({ revision: entry.revision, observed_at: entry.observedAt, kinds: entry.kinds })),
      last_error_present: Boolean(network.lastError),
    } : null,
    source_errors: snapshot.sourceErrors.map((item) => item.split(':', 1)[0]),
    redaction: 'Diagnostic free-form error and check text is excluded. No configuration, API keys, URLs with credentials, raw logs, hardware addresses, or interface IP addresses are included by this exporter.',
  };
}

export function Health() {
  const connectionState = useSystemStore((state) => state.connectionState);
  const throughput = useSystemStore((state) => state.throughput);
  const [snapshot, setSnapshot] = useState<HealthSnapshot>(EMPTY_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [incidentPrevious, setIncidentPrevious] = useState<'up' | 'down' | 'unknown'>('up');
  const [incidentCurrent, setIncidentCurrent] = useState<'up' | 'down' | 'unknown'>('down');
  const [incidentReason, setIncidentReason] = useState('timeout');
  const [incidentFailureAge, setIncidentFailureAge] = useState(120);
  const [incidentGrace, setIncidentGrace] = useState(60);
  const [incidentMaintenance, setIncidentMaintenance] = useState(false);
  const [incidentPlan, setIncidentPlan] = useState<ServiceIncidentPolicyPlan | null>(null);
  const [incidentBusy, setIncidentBusy] = useState(false);
  const [incidentError, setIncidentError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    const capturedAt = new Date().toISOString();
    const [doctorResult, capabilityResult, networkResult] = await Promise.allSettled([
      loadDoctor(),
      controlTransport.json('/api/capabilities', parseCapabilityReport),
      controlTransport.json('/api/system/network-state?history=16', parseNetworkStatus),
    ]);
    const sourceErrors: string[] = [];
    if (doctorResult.status === 'rejected') sourceErrors.push(`doctor: ${errorMessage(doctorResult.reason, 'unavailable')}`);
    if (capabilityResult.status === 'rejected') sourceErrors.push(`capabilities: ${errorMessage(capabilityResult.reason, 'unavailable')}`);
    if (networkResult.status === 'rejected') sourceErrors.push(`network state: ${errorMessage(networkResult.reason, 'unavailable')}`);
    setSnapshot({
      doctor: doctorResult.status === 'fulfilled' ? doctorResult.value : null,
      capabilities: capabilityResult.status === 'fulfilled' ? capabilityResult.value : null,
      network: networkResult.status === 'fulfilled' ? networkResult.value : null,
      sourceErrors,
      capturedAt,
    });
    setLoading(false);
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const verdict = deriveVerdict(snapshot);
  const presentation = verdictCopy(verdict);
  const timeline = useMemo(() => buildTimeline(snapshot), [snapshot]);
  const capabilityCounts = useMemo(() => {
    const items = snapshot.capabilities?.capabilities ?? [];
    return {
      available: items.filter((item) => item.status === 'available').length,
      unavailable: items.filter((item) => item.status !== 'available').length,
    };
  }, [snapshot.capabilities]);

  async function analyzeIncidentPolicy() {
    setIncidentBusy(true);
    setIncidentError(null);
    try {
      const asOf = new Date();
      const failureStartedAt = new Date(asOf.getTime() - Math.max(0, incidentFailureAge) * 1000);
      const plan = await controlTransport.json(
        '/api/system/service-incident-policy-plan',
        parseServiceIncidentPolicyPlan,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            previous_status: incidentPrevious,
            current_status: incidentCurrent,
            previous_reason: incidentPrevious === 'down' ? incidentReason : '',
            current_reason: incidentCurrent === 'down' ? incidentReason : '',
            incident_open: incidentPrevious === 'down',
            failure_started_at: incidentCurrent === 'down' || incidentPrevious === 'down' ? failureStartedAt.toISOString() : undefined,
            as_of: asOf.toISOString(),
            maintenance: incidentMaintenance,
            notification_grace_seconds: Math.max(0, incidentGrace),
            incident_callback_every_seconds: 60,
            write_cooldown_seconds: 180,
            incident_retention_days: 90,
            latency_retention_hours: 12,
          }),
        },
      );
      setIncidentPlan(plan);
    } catch (caught) {
      setIncidentPlan(null);
      setIncidentError(errorMessage(caught, 'Incident policy analysis failed.'));
    } finally {
      setIncidentBusy(false);
    }
  }

  function downloadDiagnostics() {
    const bundle = buildDiagnosticBundle(snapshot, connectionState, throughput);
    const blob = new Blob([`${JSON.stringify(bundle, null, 2)}\n`], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `luminet-diagnostics-${new Date().toISOString().replaceAll(':', '-')}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="m-0 flex items-center gap-2 text-2xl font-display text-text-primary">
            <HeartPulse size={22} className="text-cyan" aria-hidden="true" /> Health & diagnostics
          </h2>
          <p className="mt-1 max-w-3xl text-text-secondary">
            One read-only health workspace across readiness, capability truth, passive network epochs, and telemetry. It does not create a second runtime owner.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void refresh()} disabled={loading} className="btn btn-secondary px-3 py-1.5">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} aria-hidden="true" /> Refresh
          </button>
          <button type="button" onClick={downloadDiagnostics} disabled={loading || verdict === 'unavailable'} className="btn btn-primary px-3 py-1.5">
            <Download size={14} aria-hidden="true" /> Export redacted diagnostics
          </button>
        </div>
      </header>

      <section className={`rounded-lg border p-4 ${presentation.tone}`} aria-live="polite">
        <div className="flex items-start gap-3">
          {verdict === 'healthy' ? <ShieldCheck size={22} aria-hidden="true" /> : <ShieldAlert size={22} aria-hidden="true" />}
          <div>
            <h3 className="m-0 text-base font-semibold">{loading ? 'Refreshing health evidence…' : presentation.title}</h3>
            <p className="mb-0 mt-1 text-sm opacity-90">{presentation.detail}</p>
          </div>
        </div>
      </section>


      <WorkerAffinityPlanner />
      <TunnelSafetyPlanner />
      <TLSInterceptionEvidencePlanner />

      <section className="card space-y-4" aria-labelledby="incident-policy-title">
        <div className="flex flex-col gap-3 border-b border-border-color pb-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h3 id="incident-policy-title" className="m-0 text-lg text-text-primary">Incident & maintenance policy</h3>
            <p className="mb-0 mt-1 max-w-3xl text-xs text-text-muted">Preview the incident lifecycle separately from endpoint health: first failure, grace, sustained incident callback, reason change, maintenance suppression, recovery, retention, and bounded persistence. This planner does not send notifications or write monitor state.</p>
          </div>
          <button type="button" onClick={() => void analyzeIncidentPolicy()} disabled={incidentBusy} className="btn btn-secondary px-3 py-1.5">
            {incidentBusy ? <RefreshCw size={14} className="animate-spin" aria-hidden="true" /> : <Activity size={14} aria-hidden="true" />} Analyze lifecycle
          </button>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-6">
          <label className="text-xs text-text-muted">Previous status
            <select className="field-input mt-1" value={incidentPrevious} onChange={(event) => setIncidentPrevious(event.target.value as 'up' | 'down' | 'unknown')}>
              <option value="up">up</option><option value="down">down</option><option value="unknown">unknown</option>
            </select>
          </label>
          <label className="text-xs text-text-muted">Current status
            <select className="field-input mt-1" value={incidentCurrent} onChange={(event) => setIncidentCurrent(event.target.value as 'up' | 'down' | 'unknown')}>
              <option value="up">up</option><option value="down">down</option><option value="unknown">unknown</option>
            </select>
          </label>
          <label className="text-xs text-text-muted">Failure reason
            <input className="field-input mt-1" value={incidentReason} onChange={(event) => setIncidentReason(event.target.value.slice(0, 256))} placeholder="timeout" />
          </label>
          <label className="text-xs text-text-muted">Failure age (s)
            <input type="number" min={0} max={86400} className="field-input mt-1" value={incidentFailureAge} onChange={(event) => setIncidentFailureAge(Math.max(0, Math.min(86400, Number(event.target.value) || 0)))} />
          </label>
          <label className="text-xs text-text-muted">Notify grace (s)
            <input type="number" min={0} max={86400} className="field-input mt-1" value={incidentGrace} onChange={(event) => setIncidentGrace(Math.max(0, Math.min(86400, Number(event.target.value) || 0)))} />
          </label>
          <label className="flex min-h-11 items-center gap-2 self-end rounded-md border border-border-color px-3 text-xs text-text-secondary">
            <input type="checkbox" checked={incidentMaintenance} onChange={(event) => setIncidentMaintenance(event.target.checked)} /> Maintenance window
          </label>
        </div>
        {incidentError && <div role="alert" className="rounded-md border border-error/30 bg-error/10 p-3 text-xs text-error">{incidentError}</div>}
        {incidentPlan && (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,0.7fr)_minmax(0,1.3fr)]">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-2">
              <HealthCard icon={<Activity size={16} aria-hidden="true" />} label="Transition" value={incidentPlan.transition} detail={`${incidentPlan.failureAgeSeconds}s failure age`} />
              <HealthCard icon={<ShieldAlert size={16} aria-hidden="true" />} label="Notification" value={incidentPlan.notify ? 'due' : 'suppressed'} detail={incidentPlan.suppressionReasons.join(' · ') || 'No suppression'} />
              <HealthCard icon={<CheckCircle2 size={16} aria-hidden="true" />} label="Incident callback" value={incidentPlan.incidentCallbackDue ? 'due' : 'not due'} detail="Sustained-incident callback cadence" />
              <HealthCard icon={<Download size={16} aria-hidden="true" />} label="Persistence" value={incidentPlan.persist ? 'write due' : 'cooldown'} detail={`${incidentPlan.latencyRetentionHours}h latency · ${incidentPlan.incidentRetentionDays}d incidents`} />
            </div>
            <div className="rounded-md border border-border-color bg-bg-primary/50 p-4">
              <div className="text-xs font-semibold uppercase tracking-wide text-text-muted">Lifecycle invariants</div>
              <ul className="mb-0 mt-2 space-y-1 pl-5 text-xs text-text-secondary">
                {incidentPlan.invariants.map((invariant) => <li key={invariant}>{invariant}</li>)}
              </ul>
            </div>
          </div>
        )}
      </section>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <HealthCard
          icon={<Activity size={18} aria-hidden="true" />}
          label="Readiness doctor"
          value={snapshot.doctor ? (snapshot.doctor.healthy ? 'Healthy' : 'Degraded') : 'Unavailable'}
          detail={snapshot.doctor ? `${snapshot.doctor.checks.filter((check) => check.ok).length}/${snapshot.doctor.checks.length} checks passing` : 'No report'}
        />
        <HealthCard
          icon={<Network size={18} aria-hidden="true" />}
          label="Passive network"
          value={snapshot.network ? `Epoch ${snapshot.network.current.revision}` : 'Unavailable'}
          detail={snapshot.network?.lastError || (snapshot.network ? `${snapshot.network.current.interfaces.length} interfaces observed` : 'No snapshot')}
        />
        <HealthCard
          icon={<ShieldCheck size={18} aria-hidden="true" />}
          label="Native core"
          value={snapshot.capabilities?.runtime.nativeCore.status ?? 'unavailable'}
          detail={snapshot.capabilities?.runtime.nativeCore.version || snapshot.capabilities?.runtime.nativeCore.reason || 'No capability report'}
        />
        <HealthCard
          icon={<CheckCircle2 size={18} aria-hidden="true" />}
          label="Capabilities"
          value={`${capabilityCounts.available} available`}
          detail={`${capabilityCounts.unavailable} explicitly unavailable · missing evidence never counts as ready`}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.25fr)_minmax(20rem,0.75fr)]">
        <section className="card space-y-4" aria-labelledby="health-timeline-title">
          <div className="flex items-center justify-between gap-3 border-b border-border-color pb-3">
            <div>
              <h3 id="health-timeline-title" className="m-0 text-lg text-text-primary">Evidence timeline</h3>
              <p className="mb-0 mt-1 text-xs text-text-muted">Readiness checks and retained network handoffs, newest first.</p>
            </div>
            <span className="mono text-xs text-text-muted">{timeline.length}/32</span>
          </div>
          {timeline.length === 0 ? (
            <div className="py-8 text-center text-sm text-text-muted">No timeline evidence is available.</div>
          ) : (
            <ol className="m-0 list-none space-y-3 p-0">
              {timeline.map((entry, index) => (
                <li key={`${entry.at}-${entry.title}-${index}`} className="grid grid-cols-[auto_1fr] gap-3 rounded-md border border-border-color bg-bg-primary/50 p-3">
                  <span className={`mt-1 h-2.5 w-2.5 rounded-full ${entry.severity === 'success' ? 'bg-success' : entry.severity === 'warning' ? 'bg-warning' : 'bg-cyan'}`} aria-hidden="true" />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-baseline justify-between gap-2">
                      <strong className="text-sm text-text-primary">{entry.title}</strong>
                      <time className="mono text-[10px] text-text-muted">{formatTime(entry.at)}</time>
                    </div>
                    <p className="mb-0 mt-1 break-words text-xs text-text-secondary">{entry.detail}</p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="card space-y-4" aria-labelledby="diagnostic-boundary-title">
          <h3 id="diagnostic-boundary-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg text-text-primary">
            <TriangleAlert size={18} className="text-warning" aria-hidden="true" /> Diagnostic boundary
          </h3>
          <p className="text-sm text-text-secondary">
            The exporter intentionally excludes configuration bodies, API keys, raw logs, hardware addresses, interface IPs, credential-bearing URLs, and mutation controls.
          </p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
            <dt className="text-text-muted">WebSocket</dt><dd className="m-0 text-right text-text-primary">{connectionState}</dd>
            <dt className="text-text-muted">Receive rate</dt><dd className="m-0 text-right text-text-primary">{formatBytes(throughput.rx)}/s</dd>
            <dt className="text-text-muted">Transmit rate</dt><dd className="m-0 text-right text-text-primary">{formatBytes(throughput.tx)}/s</dd>
            <dt className="text-text-muted">Flow coverage</dt><dd className="m-0 text-right text-text-primary">{snapshot.capabilities?.coverage.flowRegistry.coverageModel || 'unavailable'}</dd>
            <dt className="text-text-muted">Provider corpus</dt><dd className="m-0 text-right text-text-primary">{snapshot.capabilities?.coverage.providerCorpus.ready ? 'ready' : 'not ready'}</dd>
          </dl>
          {snapshot.sourceErrors.length > 0 && (
            <div role="alert" className="rounded-md border border-warning/30 bg-warning/10 p-3 text-xs text-warning">
              {snapshot.sourceErrors.map((item) => <div key={item}>{item}</div>)}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function HealthCard({ icon, label, value, detail }: { icon: ReactNode; label: string; value: string; detail: string }) {
  return (
    <article className="card min-w-0">
      <div className="flex items-center gap-2 text-text-muted">{icon}<span className="text-xs font-semibold uppercase tracking-wide">{label}</span></div>
      <strong className="mt-3 block truncate text-lg text-text-primary" title={value}>{value}</strong>
      <p className="mb-0 mt-1 line-clamp-2 text-xs text-text-secondary" title={detail}>{detail}</p>
    </article>
  );
}

function formatTime(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return value || 'unknown';
  return new Date(timestamp).toLocaleString();
}

function formatBytes(value: number): string {
  const safe = Math.max(0, Number.isFinite(value) ? value : 0);
  if (safe < 1024) return `${Math.round(safe)} B`;
  if (safe < 1024 * 1024) return `${(safe / 1024).toFixed(1)} KiB`;
  return `${(safe / (1024 * 1024)).toFixed(1)} MiB`;
}


function WorkerAffinityPlanner() {
  const [plan, setPlan] = useState<WorkerAffinityPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    try { setPlan(await controlTransport.json('/api/system/worker-affinity-plan', parseWorkerAffinityPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ pool_size:3, affinity_key:'health-preview', hard_deadline_ms:5000, max_restarts:4, workers:[{id:'worker-a',healthy:true,inflight:1,capacity:2},{id:'worker-b',healthy:true,inflight:0,capacity:2},{id:'worker-c',healthy:false,inflight:0,capacity:2}] }) })); }
    catch (caught) { setError(errorMessage(caught, 'Worker affinity planning failed.')); }
  }

  return (
    <section className="card space-y-3" aria-labelledby="worker-affinity-title">
      <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
        <div>
          <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Read-only · bounded recovery</p>
          <h3 id="worker-affinity-title" className="m-0 mt-1 text-lg text-text-primary">
            Worker affinity & recovery evidence
          </h3>
          <p className="m-0 mt-1 text-xs text-text-muted">
            Preview deterministic affinity, depth-one warm-slot buffering, unbuffered spillover, correlated NDJSON worker framing, hard deadlines, fail-open warming, and capped restart recovery. The planner starts or restarts no process.
          </p>
        </div>
        <button type="button" onClick={() => void analyze()} className="btn btn-secondary">
          Analyze workers
        </button>
      </div>
      {error && (
        <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">
          {error}
        </div>
      )}
      {plan && (
        <>
          <div className="grid gap-2 text-xs sm:grid-cols-4">
            <HealthCard icon={<Activity size={16} />} label="Preferred" value={plan.preferredWorker || 'none'} detail="Deterministic affinity" />
            <HealthCard icon={<CheckCircle2 size={16} />} label="Selected" value={plan.selectedWorker || 'fail-open'} detail={plan.spillover ? 'Spillover selected' : plan.failOpen ? 'No eligible worker' : 'Preferred eligible'} />
            <HealthCard icon={<ShieldCheck size={16} />} label="Deadline" value={`${plan.hardDeadlineMS} ms`} detail={`restart ${plan.restartBackoffMS.join(' / ')} ms`} />
            <HealthCard icon={<TriangleAlert size={16} />} label="Process authority" value={plan.startsProcess ? 'present' : 'none'} detail="Planning evidence only" />
          </div>
          <p className="mono m-0 text-[10px] text-text-muted">
            {plan.protocolFraming} · ready {plan.readyHandshake} · IDs {plan.correlatesRequestIDs ? 'correlated' : 'uncorrelated'} · affinity queue {plan.affinityQueueDepth} · shared queue {plan.sharedQueueDepth} · frame ≤ {plan.maxProtocolFrameBytes} B · ready ≤ {plan.readyTimeoutMS} ms · recycle on protocol error {plan.recycleOnProtocolError ? 'yes' : 'no'}
          </p>
        </>
      )}
    </section>
  );
}

function TunnelSafetyPlanner() {
  const [state, setState] = useState('error');
  const [firewallApplied, setFirewallApplied] = useState(false);
  const [quicGuard, setQuicGuard] = useState(true);
  const [stunGuard, setStunGuard] = useState(true);
  const [dohGuard, setDoHGuard] = useState(true);
  const [ipv6Guard, setIPv6Guard] = useState(true);
  const [plan, setPlan] = useState<TunnelSafetyPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    try { setPlan(await controlTransport.json('/api/system/tunnel-safety-plan', parseTunnelSafetyPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ desired_state:'secured', observed_state:state, persisted_target_state:'valid-secured', lockdown_mode:'auto', firewall_block_applied:firewallApplied, dns_guard_applied:true, quic_guard_applied:quicGuard, stun_guard_applied:stunGuard, doh_guard_applied:dohGuard, ipv6_guard_applied:ipv6Guard, required_guards:['dns','quic','stun','doh','ipv6'], action_after_disconnect:'reconnect', reconnect_attempt:1, max_reconnect_attempts:4 }) })); }
    catch (caught) { setError(errorMessage(caught, 'Tunnel safety planning failed.')); }
  }

  return (
    <section className="card space-y-3" aria-labelledby="tunnel-safety-title">
      <div>
        <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">
          Read-only · fail-closed state truth
        </p>
        <h3 id="tunnel-safety-title" className="m-0 mt-1 text-lg text-text-primary">
          Tunnel safety lifecycle
        </h3>
        <p className="m-0 mt-1 text-xs text-text-muted">
          Separate desired secure state from observed tunnel state, lockdown evidence, and explicit DNS/QUIC/STUN/DoH/IPv6 leak guards. Missing required guard evidence degrades a connected tunnel instead of silently calling it secure. Corrupt persisted secure intent fails closed; an error is never called secure when blocking failed. This planner mutates no host networking.
        </p>
      </div>
      <div className="flex flex-wrap gap-3">
        <label className="text-xs text-text-muted">
          Observed state
          <select className="field-input mt-1" value={state} onChange={(e) => setState(e.target.value)}>
            {['disconnected', 'connecting', 'connected', 'disconnecting', 'error', 'offline'].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="mt-5 flex items-center gap-2 text-xs text-text-muted">
          <input type="checkbox" checked={firewallApplied} onChange={(e) => setFirewallApplied(e.target.checked)} />
          Firewall
        </label>
        {[
          ['QUIC', quicGuard, setQuicGuard],
          ['STUN', stunGuard, setStunGuard],
          ['DoH', dohGuard, setDoHGuard],
          ['IPv6', ipv6Guard, setIPv6Guard],
        ].map(([label, value, setter]) => (
          <label key={String(label)} className="mt-5 flex items-center gap-2 text-xs text-text-muted">
            <input
              type="checkbox"
              checked={Boolean(value)}
              onChange={(e) => (setter as (value: boolean) => void)(e.target.checked)}
            />{' '}
            {String(label)} guard
          </label>
        ))}
      </div>
      <button type="button" className="btn btn-secondary" onClick={() => void analyze()}>
        Evaluate protection
      </button>
      {error && (
        <p role="alert" className="m-0 text-xs text-error">
          {error}
        </p>
      )}
      {plan && (
        <div className="space-y-1 rounded border border-border-color bg-bg-secondary/40 p-3 text-xs text-text-muted">
          <p className="m-0">
            <strong className="text-text-primary">{plan.effectiveProtectionState}</strong> · next {plan.nextAction} · lockdown {plan.lockdownRequired ? 'required' : 'not required'} · reconnect {plan.reconnectAllowed ? 'eligible' : 'no'}
          </p>
          <p className="m-0">
            firewall {plan.firewallBlockConfirmed ? 'confirmed' : 'not confirmed'} · DNS {plan.dnsGuardConfirmed ? 'confirmed' : 'not confirmed'} · host mutation {plan.mutatesHostNetwork ? 'yes' : 'no'}
          </p>
          <p className="m-0">
            required guards {plan.requiredGuards.join(', ') || 'none'} · missing/failed {plan.missingOrFailedGuards.join(', ') || 'none'}
          </p>
          {plan.reasons.map((reason) => (
            <p key={reason} className="m-0 text-warning">
              {reason}
            </p>
          ))}
        </div>
      )}
    </section>
  );
}

function TLSInterceptionEvidencePlanner() {
  const [componentMatch, setComponentMatch] = useState('possible');
  const [expectedGrade, setExpectedGrade] = useState('A');
  const [observedGrade, setObservedGrade] = useState('A');
  const [observedPFS, setObservedPFS] = useState(true);
  const [weakCiphers, setWeakCiphers] = useState(false);
  const [plan, setPlan] = useState<TLSInterceptionEvidencePlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    try { setPlan(await controlTransport.json('/api/system/tls-interception-evidence-plan', parseTLSInterceptionEvidencePlan, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({components:[{component:'extensions',match:componentMatch}],expected_grade:expectedGrade,observed_grade:observedGrade,expected_pfs:true,observed_pfs:observedPFS,weak_ciphers_detected:weakCiphers})})); }
    catch (caught) { setError(errorMessage(caught, 'TLS interception evidence planning failed.')); }
  }

  return (
    <section className="card space-y-3" aria-labelledby="tls-interception-title">
      <div>
        <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">
          Read-only · no fingerprint database
        </p>
        <h3 id="tls-interception-title" className="m-0 mt-1 text-lg text-text-primary">
          TLS interception evidence
        </h3>
        <p className="m-0 mt-1 text-xs text-text-muted">
          Evaluate caller-supplied TLS component compatibility, security-grade regression, PFS loss, and weak-cipher evidence. This does not capture traffic, install a CA, query a fingerprint database, or identify a specific interception product.
        </p>
      </div>
      <div className="flex flex-wrap gap-3">
        <label className="text-xs text-text-muted">
          Component match
          <select className="field-input mt-1" value={componentMatch} onChange={(e) => setComponentMatch(e.target.value)}>
            {['possible', 'unlikely', 'impossible', 'empty'].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-text-muted">
          Expected grade
          <select className="field-input mt-1" value={expectedGrade} onChange={(e) => setExpectedGrade(e.target.value)}>
            {['A', 'B', 'C', 'F'].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-text-muted">
          Observed grade
          <select className="field-input mt-1" value={observedGrade} onChange={(e) => setObservedGrade(e.target.value)}>
            {['A', 'B', 'C', 'F'].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label className="mt-5 flex items-center gap-2 text-xs text-text-muted">
          <input type="checkbox" checked={observedPFS} onChange={(e) => setObservedPFS(e.target.checked)} />
          PFS observed
        </label>
        <label className="mt-5 flex items-center gap-2 text-xs text-text-muted">
          <input type="checkbox" checked={weakCiphers} onChange={(e) => setWeakCiphers(e.target.checked)} />
          Weak ciphers observed
        </label>
      </div>
      <button type="button" className="btn btn-secondary" onClick={() => void analyze()}>
        Evaluate TLS evidence
      </button>
      {error && (
        <p role="alert" className="m-0 text-xs text-error">
          {error}
        </p>
      )}
      {plan && (
        <div className="space-y-1 rounded border border-border-color bg-bg-secondary/40 p-3 text-xs text-text-muted">
          <p className="m-0">
            <strong className={plan.suspicious ? 'text-warning' : 'text-success'}>
              {plan.suspicious ? 'anomaly evidence' : 'no modeled anomaly'}
            </strong>{' '}
            · worst match {plan.worstMatch} · grade {plan.expectedGrade || 'n/a'}→{plan.observedGrade || 'n/a'} · PFS loss {plan.pfsLost ? 'yes' : 'no'}
          </p>
          <p className="m-0">
            database {plan.usesFingerprintDatabase ? 'used' : 'not used'} · product identification {plan.identifiesInterceptionProduct ? 'claimed' : 'not claimed'} · network I/O {plan.performsNetworkIO ? 'yes' : 'no'}
          </p>
          {plan.reasons.map((reason) => (
            <p key={reason} className="m-0 text-warning">
              {reason}
            </p>
          ))}
        </div>
      )}
    </section>
  );
}
