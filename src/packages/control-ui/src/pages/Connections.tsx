import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, ArrowDownToLine, ArrowUpFromLine, Cable, CircleAlert, CircleCheck,
  Clock3, Network, RefreshCw, Search, ShieldCheck, Unplug, X,
} from 'lucide-react';
import { controlTransport } from '../api/ControlTransport';
import {
  parseFlowList,
  parseNetworkStatus,
  parseNetworkIntelligence,
  type FlowCoverage,
  type FlowListResponse,
  type FlowSnapshot,
  type NetworkMonitorStatus,
  type NetworkIntelligence,
} from '../api/flows';
import { parseEndpointDispatchPlan, parseMultiplexPolicyPlan, parseWebSocketReadinessPlan, type EndpointDispatchPlan, type MultiplexPolicyPlan, type WebSocketReadinessPlan } from '../api/planners';

const POLL_MS = 1500;
const FLOW_FETCH_LIMIT = 512;
const INITIAL_VISIBLE_FLOWS = 100;
const VISIBLE_FLOW_STEP = 100;

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function formatAge(iso: string): string {
  const started = Date.parse(iso);
  if (!Number.isFinite(started)) return 'unknown';
  const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function errorText(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function capabilityBadge(enabled: boolean, label: string) {
  return (
    <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${enabled ? 'border-success/25 bg-success/10 text-success' : 'border-border-color bg-bg-primary text-text-muted'}`}>
      {label}
    </span>
  );
}

function CoverageRow({ coverage }: { coverage: FlowCoverage }) {
  return (
    <div className="rounded-md border border-border-color bg-bg-primary/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="mono m-0 text-sm font-semibold text-text-primary">{coverage.owner}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">Runtime-owned publication contract</p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {capabilityBadge(coverage.visible, 'visible')}
          {capabilityBadge(coverage.closeable, 'close')}
          {capabilityBadge(coverage.byteCounters, 'bytes')}
          {capabilityBadge(coverage.processAttribution, 'process')}
          {capabilityBadge(coverage.destinationMetadata, 'destination')}
        </div>
      </div>
      {coverage.notes.length > 0 && (
        <ul className="mb-0 mt-3 space-y-1 pl-5 text-xs text-text-secondary">
          {coverage.notes.map((note) => <li key={note}>{note}</li>)}
        </ul>
      )}
    </div>
  );
}

function FlowEndpoint({ flow }: { flow: FlowSnapshot }) {
  const destination = flow.destination || flow.host || 'unknown destination';
  return (
    <div className="min-w-0">
      <p className="mono m-0 truncate text-xs font-semibold text-text-primary" title={destination}>{destination}</p>
      <p className="mono m-0 mt-1 truncate text-[11px] text-text-muted" title={flow.source || 'unknown source'}>
        {flow.source || 'source unavailable'}
      </p>
      {flow.destinationProvider && (
        <p className="m-0 mt-1 truncate text-[11px] text-purple" title={`${flow.destinationProvider.displayName} · ${flow.destinationProvider.prefix} · corpus ${flow.destinationProvider.corpusID}${flow.destinationProvider.corpusStale ? ' (stale)' : ''}`}>
          {flow.destinationProvider.displayName} · {flow.destinationProvider.prefix} · {flow.destinationProvider.confidence || 'unrated'}{flow.destinationProvider.corpusStale ? ' · stale corpus' : ''}
        </p>
      )}
      {flow.chain.length > 0 && <p className="m-0 mt-1 truncate text-[11px] text-accent">{flow.chain.join(' → ')}</p>}
    </div>
  );
}


function MetricCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
      <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">{label}</p>
      <p className="mono m-0 mt-1 text-lg font-semibold text-text-primary">{value}</p>
      <p className="m-0 mt-1 text-[10px] text-text-muted">{detail}</p>
    </div>
  );
}

export function Connections() {
  const [data, setData] = useState<FlowListResponse | null>(null);
  const [networkState, setNetworkState] = useState<NetworkMonitorStatus | null>(null);
  const [intelligence, setIntelligence] = useState<NetworkIntelligence | null>(null);
  const [query, setQuery] = useState('');
  const [owner, setOwner] = useState('');
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [busyIDs, setBusyIDs] = useState<Set<string>>(() => new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [muxProtocol, setMuxProtocol] = useState<'smux' | 'yamux' | 'h2mux'>('smux');
  const [muxConnections, setMuxConnections] = useState(2);
  const [muxStreams, setMuxStreams] = useState(32);
  const [muxPadding, setMuxPadding] = useState(false);
  const [muxPaddingBytes, setMuxPaddingBytes] = useState(256);
  const [muxPlan, setMuxPlan] = useState<MultiplexPolicyPlan | null>(null);
  const [muxBusy, setMuxBusy] = useState(false);
  const [muxError, setMuxError] = useState<string | null>(null);
  const [dispatchInput, setDispatchInput] = useState('');
  const [dispatchStrategy, setDispatchStrategy] = useState('quality-first');
  const [dispatchPlan, setDispatchPlan] = useState<EndpointDispatchPlan | null>(null);
  const [dispatchBusy, setDispatchBusy] = useState(false);
  const [dispatchError, setDispatchError] = useState<string | null>(null);
  const [visibleFlowLimit, setVisibleFlowLimit] = useState(INITIAL_VISIBLE_FLOWS);
  const requestSequence = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);

  const load = useCallback(async (foreground = false) => {
    const sequence = requestSequence.current + 1;
    requestSequence.current = sequence;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    if (foreground) setLoading(true);
    else setLoading(false);

    try {
      const params = new URLSearchParams({ limit: String(FLOW_FETCH_LIMIT) });
      if (owner) params.set('owner', owner);
      if (query.trim()) params.set('q', query.trim());
      const requestInit: RequestInit = { signal: controller.signal };
      const [flows, net, intel] = await Promise.all([
        controlTransport.json(`/api/system/flows?${params.toString()}`, parseFlowList, requestInit),
        controlTransport.json('/api/system/network-state?history=12', parseNetworkStatus, requestInit),
        controlTransport.json('/api/system/network-intelligence', parseNetworkIntelligence, requestInit),
      ]);
      if (controller.signal.aborted || sequence !== requestSequence.current) return;

      setData(flows);
      setNetworkState(net);
      setIntelligence(intel);
      setError(null);
      const live = new Set(flows.flows.map((flow) => flow.id));
      setSelected((previous) => new Set([...previous].filter((id) => live.has(id))));
    } catch (caught) {
      if (controller.signal.aborted || sequence !== requestSequence.current) return;
      setError(errorText(caught, 'Flow observability is unavailable.'));
    } finally {
      if (sequence === requestSequence.current) {
        if (activeRequest.current === controller) activeRequest.current = null;
        if (foreground) setLoading(false);
      }
    }
  }, [owner, query]);

  useEffect(() => {
    setVisibleFlowLimit(INITIAL_VISIBLE_FLOWS);
  }, [owner, query]);

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;

    const stopTimer = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = undefined;
    };
    const schedule = () => {
      stopTimer();
      if (stopped || document.hidden) return;
      timer = window.setTimeout(() => void poll(false), POLL_MS);
    };
    const poll = async (foreground: boolean) => {
      if (stopped || document.hidden) return;
      await load(foreground);
      schedule();
    };
    const visibility = () => {
      if (document.hidden) {
        stopTimer();
        activeRequest.current?.abort();
        return;
      }
      void poll(false);
    };

    void poll(true);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      stopped = true;
      stopTimer();
      requestSequence.current += 1;
      activeRequest.current?.abort();
      activeRequest.current = null;
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [load]);

  const owners = useMemo(() => {
    const values = new Set<string>();
    data?.coverage.forEach((item) => values.add(item.owner));
    data?.flows.forEach((flow) => values.add(flow.owner));
    return [...values].sort();
  }, [data]);

  const setBusy = (ids: string[], busy: boolean) => {
    setBusyIDs((previous) => {
      const next = new Set(previous);
      ids.forEach((id) => busy ? next.add(id) : next.delete(id));
      return next;
    });
  };

  const closeOne = async (flow: FlowSnapshot) => {
    if (!flow.closeable || busyIDs.has(flow.id)) return;
    if (!window.confirm(`Close ${flow.owner} flow ${flow.id}? The owning runtime will tear down the connection.`)) return;
    setBusy([flow.id], true);
    try {
      const response = await controlTransport.request(`/api/system/flows/${encodeURIComponent(flow.id)}`, { method: 'DELETE' });
      if (!response.ok) {
        const payload: unknown = await response.json().catch(() => null);
        const detail = typeof payload === 'object' && payload !== null && 'error' in payload ? String(payload.error) : `HTTP ${response.status}`;
        throw new Error(detail);
      }
      setSelected((previous) => {
        const next = new Set(previous);
        next.delete(flow.id);
        return next;
      });
      await load(false);
    } catch (caught) {
      setError(errorText(caught, 'Flow close failed.'));
    } finally {
      setBusy([flow.id], false);
    }
  };

  const closeSelected = async () => {
    const ids = [...selected];
    if (ids.length === 0) return;
    if (!window.confirm(`Close ${ids.length} explicitly selected flow${ids.length === 1 ? '' : 's'}? Each owning runtime will perform its own teardown.`)) return;
    setBusy(ids, true);
    try {
      const response = await controlTransport.request('/api/system/flows/close', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: true, ids }),
      });
      if (!response.ok) {
        const payload: unknown = await response.json().catch(() => null);
        const detail = typeof payload === 'object' && payload !== null && 'error' in payload ? String(payload.error) : `HTTP ${response.status}`;
        throw new Error(detail);
      }
      const payload: unknown = await response.json();
      if (typeof payload === 'object' && payload !== null && 'failed' in payload && Number(payload.failed) > 0) {
        setError(`${String(payload.failed)} selected flow close request(s) failed; successful owner teardowns were retained.`);
      } else {
        setError(null);
      }
      setSelected(new Set());
      await load(false);
    } catch (caught) {
      setError(errorText(caught, 'Bulk flow close failed.'));
    } finally {
      setBusy(ids, false);
    }
  };

  const analyzeEndpointDispatch = async () => {
    setDispatchBusy(true);
    setDispatchError(null);
    setDispatchPlan(null);
    try {
      const endpoints = dispatchInput.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
        const parts = line.split(',').map((part) => part.trim());
        if (parts.length < 3 || parts.length > 7) throw new Error(`Endpoint line ${index + 1} must use endpoint,successes,failures[,latency_ms,health,capacity,in_flight].`);
        const [endpoint, successesRaw, failuresRaw, latencyRaw = '0', health = 'unknown', capacityRaw = '0', inflightRaw = '0'] = parts;
        const successes = Number(successesRaw), failures = Number(failuresRaw), latency = Number(latencyRaw), capacity = Number(capacityRaw), inflight = Number(inflightRaw);
        if (![successes, failures, latency, capacity, inflight].every(Number.isFinite)) throw new Error(`Endpoint line ${index + 1} contains invalid numeric evidence.`);
        return { endpoint, successes, failures, latency_ms: latency, health_state: health, capacity, in_flight: inflight };
      });
      if (endpoints.length === 0) throw new Error('Enter at least one endpoint evidence row.');
      setDispatchPlan(await controlTransport.json('/api/system/endpoint-pool-plan', parseEndpointDispatchPlan, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ endpoints, strategy: dispatchStrategy, scope: 'connections-page' }),
      }));
    } catch (caught) {
      setDispatchError(errorText(caught, 'Endpoint dispatch analysis failed.'));
    } finally {
      setDispatchBusy(false);
    }
  };

  const analyzeMultiplexPolicy = async () => {
    setMuxBusy(true);
    setMuxError(null);
    try {
      const plan = await controlTransport.json(
        '/api/system/multiplex-policy-plan',
        parseMultiplexPolicyPlan,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            protocol: muxProtocol,
            version: 1,
            max_connections: muxConnections,
            max_streams_per_connection: muxStreams,
            session_selection: 'least-loaded',
            padding: muxPadding,
            max_padding_bytes: muxPadding ? muxPaddingBytes : 0,
          }),
        },
      );
      setMuxPlan(plan);
    } catch (caught) {
      setMuxError(errorText(caught, 'Multiplex policy analysis failed.'));
    } finally {
      setMuxBusy(false);
    }
  };

  const currentEpoch = networkState?.current.revision ?? data?.networkRevision ?? 0;
  const activeInterfaces = networkState?.current.interfaces ?? [];
  const visibleFlows = useMemo(() => data?.flows.slice(0, visibleFlowLimit) ?? [], [data, visibleFlowLimit]);
  const allVisibleSelected = visibleFlows.some((flow) => flow.closeable) && visibleFlows.filter((flow) => flow.closeable).every((flow) => selected.has(flow.id));

  return (
    <div className="space-y-6">
      <header className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <p className="mono m-0 text-xs uppercase tracking-[0.16em] text-accent">Cross-runtime observability</p>
          <h2 className="m-0 mt-1 text-2xl text-text-primary">Connections & network epochs</h2>
          <p className="m-0 mt-2 max-w-3xl text-sm text-text-secondary">
            Runtime owners publish only what they can prove. Missing coverage is shown explicitly; it is never interpreted as proof that the host has no other connections.
          </p>
        </div>
        <button type="button" className="btn btn-secondary" disabled={loading} onClick={() => void load(true)}>
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} aria-hidden="true" /> Refresh
        </button>
      </header>

      {error && (
        <div role="alert" className="flex items-start gap-3 rounded-md border border-error/30 bg-error/10 p-4 text-sm text-error">
          <CircleAlert size={18} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span className="flex-1">{error}</span>
          <button type="button" className="border-0 bg-transparent p-1 text-error" aria-label="Dismiss error" onClick={() => setError(null)}><X size={15} /></button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><Activity size={14} /> Registered flows</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-text-primary">{data?.stats.active ?? 0}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">{data?.stats.closing ?? 0} closing · capacity {data?.stats.capacity ?? 0}</p>
        </div>
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><ArrowUpFromLine size={14} /> Confirmed upload</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-cyan">{formatBytes(data?.stats.uploadBytes ?? 0)}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">Participating owners only</p>
        </div>
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><ArrowDownToLine size={14} /> Confirmed download</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-success">{formatBytes(data?.stats.downloadBytes ?? 0)}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">Monotonic per-flow counters</p>
        </div>
        <div className="card">
          <p className="m-0 flex items-center gap-2 text-xs text-text-muted"><Network size={14} /> Network epoch</p>
          <p className="mono m-0 mt-3 text-2xl font-semibold text-purple">#{currentEpoch}</p>
          <p className="m-0 mt-1 text-xs text-text-muted">{networkState?.running ? 'passive monitor live' : 'snapshot only'}</p>
        </div>
      </div>

      <section className="card space-y-4" aria-labelledby="path-intelligence-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Derived · passive · local-only</p>
            <h3 id="path-intelligence-title" className="m-0 mt-1 text-lg text-text-primary">Path intelligence</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Synthesized from owner-published flows, network epochs, and the active provider prefix corpus. No DNS, GeoIP fetch, scan, route mutation, or runtime mutation occurs here.</p>
          </div>
          <div className={`rounded border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${intelligence?.providerCorpusStale ? 'border-warning/30 bg-warning/10 text-warning' : intelligence?.providerCorpusReady ? 'border-success/25 bg-success/10 text-success' : 'border-border-color bg-bg-primary text-text-muted'}`}>
            {intelligence?.providerCorpusReady ? `provider corpus ${intelligence.providerCorpusStale ? 'stale' : 'ready'}` : 'provider corpus unavailable'}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
          <MetricCard label="Pre-handoff" value={String(intelligence?.preHandoffFlows ?? 0)} detail="flows from older network epochs" />
          <MetricCard label="Unknown epoch" value={String(intelligence?.unknownEpochFlows ?? 0)} detail="owner did not publish epoch" />
          <MetricCard label="Providers" value={String(intelligence?.distinctProviders ?? 0)} detail={`${intelligence?.unattributedFlows ?? 0} unattributed`} />
          <MetricCard label="Protocols" value={String(intelligence?.distinctProtocols ?? 0)} detail="participating flows only" />
          <MetricCard label="Interfaces" value={String(intelligence?.activeInterfaces ?? 0)} detail={`${intelligence?.retainedHandoffs ?? 0} retained handoffs`} />
          <MetricCard label="Coverage" value={intelligence?.coverageComplete ? 'complete' : 'partial'} detail={intelligence?.coverageModel || 'unavailable'} />
        </div>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
            <p className="m-0 text-xs font-semibold uppercase tracking-wide text-text-muted">Provider distribution</p>
            <div className="mt-2 space-y-2">
              {(intelligence?.providers ?? []).slice(0, 8).map((provider) => (
                <div key={`${provider.providerID}-${provider.displayName}`} className="flex items-center justify-between gap-4 text-xs">
                  <span className="truncate text-text-primary" title={provider.displayName || provider.providerID}>{provider.displayName || provider.providerID || 'unnamed provider'}</span>
                  <span className="mono shrink-0 text-text-muted">{provider.flows} flow{provider.flows === 1 ? '' : 's'} · ↑{formatBytes(provider.uploadBytes)} ↓{formatBytes(provider.downloadBytes)}</span>
                </div>
              ))}
              {(intelligence?.providers.length ?? 0) === 0 && <p className="m-0 text-xs text-text-muted">No currently registered numeric destination matches the active local provider corpus.</p>}
            </div>
          </div>
          <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
            <p className="m-0 text-xs font-semibold uppercase tracking-wide text-text-muted">Owner path state</p>
            <div className="mt-2 space-y-2">
              {(intelligence?.owners ?? []).map((entry) => (
                <div key={entry.owner} className="flex items-center justify-between gap-4 text-xs">
                  <span className="mono truncate text-text-primary">{entry.owner}</span>
                  <span className="mono shrink-0 text-text-muted">{entry.active} active · {entry.preHandoff} old epoch · {entry.unknownEpoch} unknown</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>


      <WebSocketReadinessPlanner />

      <section className="card space-y-4" aria-labelledby="endpoint-dispatch-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Read-only · health-aware dispatch</p>
            <h3 id="endpoint-dispatch-title" className="m-0 mt-1 text-lg text-text-primary">Endpoint dispatch evidence</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Rank caller-supplied success, latency, health and capacity evidence. Unhealthy, circuit-open, disabled or full endpoints remain ineligible; load/sticky strategies may only reorder near-equivalent quality candidates.</p>
          </div>
          <button type="button" className="btn btn-secondary" disabled={dispatchBusy} onClick={() => void analyzeEndpointDispatch()}>{dispatchBusy ? 'Analyzing…' : 'Analyze dispatch'}</button>
        </div>
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_14rem]">
          <label className="text-xs text-text-muted">One endpoint per line: <span className="mono">endpoint,successes,failures[,latency_ms,health,capacity,in_flight]</span>
            <textarea value={dispatchInput} onChange={(event) => setDispatchInput(event.target.value)} rows={4} placeholder={'relay-a.example:443,20,1,110,healthy,100,12\nrelay-b.example:443,18,2,90,degraded,100,5'} className="mono mt-1 w-full rounded border border-border-color bg-bg-primary px-3 py-2 text-xs text-text-primary" />
          </label>
          <label className="text-xs text-text-muted">Strategy
            <select value={dispatchStrategy} onChange={(event) => setDispatchStrategy(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary"><option value="quality-first">quality first</option><option value="least-loaded">least loaded</option><option value="weighted-quality">weighted quality</option><option value="sticky">sticky</option></select>
            <span className="mt-2 block text-[11px] text-text-muted">Secondary strategy never promotes a materially worse endpoint outside the bounded quality band.</span>
          </label>
        </div>
        {dispatchError && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{dispatchError}</div>}
        {dispatchPlan && <div className="space-y-3"><div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">{dispatchPlan.ranked.slice(0, 9).map((rank) => <div key={rank.endpoint} className="rounded border border-border-color bg-bg-primary/60 p-3 text-xs"><div className="flex justify-between gap-2"><strong className="mono truncate text-text-primary">{rank.endpoint}</strong><span className={rank.eligible ? 'text-success' : 'text-warning'}>{rank.eligible ? rank.quality : 'ineligible'}</span></div><div className="mt-1 text-text-muted">score {rank.score.toFixed(1)} · {rank.healthState}{rank.loadPct !== undefined ? ` · load ${rank.loadPct.toFixed(0)}%` : ''}{rank.circuitOpen ? ' · circuit open' : ''}</div></div>)}</div><p className="m-0 text-xs text-text-muted">Dispatch: <span className="mono text-text-primary">{dispatchPlan.dispatchOrder.join(' → ') || 'none'}</span> · warm pool {dispatchPlan.warmPool} · basis {dispatchPlan.selectionBasis.join(', ') || 'quality evidence'}</p></div>}
      </section>

      <section className="card space-y-4" aria-labelledby="mux-policy-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Read-only · session admission</p>
            <h3 id="mux-policy-title" className="m-0 mt-1 text-lg text-text-primary">Multiplex capacity policy</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">
              Evaluate stream/session limits before changing runtime configuration. LumiNet keeps one live SMUX owner; yamux and h2mux remain comparison-only unless a runtime explicitly reports support.
            </p>
          </div>
          <button type="button" className="btn btn-secondary" disabled={muxBusy} onClick={() => void analyzeMultiplexPolicy()}>
            {muxBusy ? <RefreshCw size={14} className="animate-spin" /> : <ShieldCheck size={14} />} Analyze admission
          </button>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
          <label className="text-xs text-text-muted">Protocol
            <select value={muxProtocol} onChange={(event) => setMuxProtocol(event.target.value as 'smux' | 'yamux' | 'h2mux')} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary">
              <option value="smux">SMUX</option><option value="yamux">Yamux</option><option value="h2mux">H2Mux</option>
            </select>
          </label>
          <label className="text-xs text-text-muted">Connections
            <input type="number" min={1} max={32} value={muxConnections} onChange={(event) => setMuxConnections(Math.max(1, Number(event.target.value) || 1))} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary" />
          </label>
          <label className="text-xs text-text-muted">Streams / connection
            <input type="number" min={1} max={4096} value={muxStreams} onChange={(event) => setMuxStreams(Math.max(1, Number(event.target.value) || 1))} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary" />
          </label>
          <label className="text-xs text-text-muted">Max padding bytes
            <input type="number" min={0} max={4096} disabled={!muxPadding} value={muxPaddingBytes} onChange={(event) => setMuxPaddingBytes(Math.max(0, Number(event.target.value) || 0))} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary disabled:opacity-50" />
          </label>
          <label className="flex min-h-11 items-center gap-2 self-end rounded border border-border-color bg-bg-primary px-3 py-2 text-xs text-text-secondary">
            <input type="checkbox" checked={muxPadding} onChange={(event) => setMuxPadding(event.target.checked)} /> Bounded padding
          </label>
        </div>

        {muxError && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{muxError}</div>}
        {muxPlan && (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <div className="rounded border border-border-color bg-bg-primary/60 p-3">
              <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">Runtime truth</p>
              <p className={`m-0 mt-1 text-sm font-semibold ${muxPlan.runtimeSupported ? 'text-success' : 'text-warning'}`}>{muxPlan.protocol} · {muxPlan.runtimeSupported ? 'supported' : 'planning only'}</p>
              <p className="m-0 mt-1 text-xs text-text-muted">{muxPlan.sessionSelection} selection · v{muxPlan.version}</p>
            </div>
            <div className="rounded border border-border-color bg-bg-primary/60 p-3">
              <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">Bounded capacity</p>
              <p className="mono m-0 mt-1 text-lg text-text-primary">{muxPlan.estimatedMaxConcurrentStreams} streams</p>
              <p className="m-0 mt-1 text-xs text-text-muted">{muxPlan.maxConnections} × {muxPlan.maxStreamsPerConnection}</p>
            </div>
            <div className="rounded border border-border-color bg-bg-primary/60 p-3">
              <p className="m-0 text-[10px] uppercase tracking-wide text-text-muted">Framing guards</p>
              <p className="m-0 mt-1 text-sm text-text-primary">padding {muxPlan.padding ? `≤ ${muxPlan.maxPaddingBytes ?? 0} B` : 'disabled'}</p>
              <p className="m-0 mt-1 text-xs text-text-muted">First Write counts application bytes; peer padding is bounded before skip/allocation.</p>
            </div>
          </div>
        )}
        {muxPlan && (muxPlan.warnings.length > 0 || muxPlan.invariants.length > 0) && (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ul className="m-0 space-y-1 pl-5 text-xs text-warning">{muxPlan.warnings.map((item) => <li key={item}>{item}</li>)}</ul>
            <ul className="m-0 space-y-1 pl-5 text-xs text-text-secondary">{muxPlan.invariants.map((item) => <li key={item}>{item}</li>)}</ul>
          </div>
        )}
      </section>

      <section className="card space-y-4" aria-labelledby="flow-table-title">
        <div className="flex flex-col justify-between gap-3 xl:flex-row xl:items-end">
          <div>
            <h3 id="flow-table-title" className="m-0 text-lg text-text-primary">Live owner-published flows</h3>
            <p className="m-0 mt-1 text-xs text-text-muted">{data?.matched ?? 0} matched · {data?.returned ?? 0} returned</p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="relative min-w-64 text-xs text-text-muted">
              <span className="sr-only">Search connections</span>
              <Search size={15} className="pointer-events-none absolute left-3 top-3.5 text-text-muted" aria-hidden="true" />
              <input className="field-input pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search host, process, source, rule…" />
            </label>
            <label className="text-xs text-text-muted">
              <span className="sr-only">Runtime owner filter</span>
              <select className="field-input min-w-48" value={owner} onChange={(event) => setOwner(event.target.value)}>
                <option value="">All declared owners</option>
                {owners.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border-color bg-bg-primary/60 px-3 py-2">
          <label className="flex min-h-11 cursor-pointer items-center gap-2 text-xs text-text-secondary">
            <input
              type="checkbox"
              checked={allVisibleSelected}
              onChange={(event) => {
                if (!data) return;
                setSelected(event.target.checked ? new Set(visibleFlows.filter((flow) => flow.closeable).map((flow) => flow.id)) : new Set());
              }}
            />
            Select closeable visible flows
          </label>
          <button type="button" className="btn btn-secondary" disabled={selected.size === 0} onClick={() => void closeSelected()}>
            <Unplug size={15} aria-hidden="true" /> Close selected ({selected.size})
          </button>
        </div>

        <div className="overflow-x-auto rounded-md border border-border-color">
          <table className="w-full min-w-[1040px] border-collapse text-left text-xs">
            <thead className="bg-bg-primary text-text-muted">
              <tr>
                <th className="w-10 px-3 py-3"><span className="sr-only">Select</span></th>
                <th className="px-3 py-3 font-medium">Runtime / protocol</th>
                <th className="px-3 py-3 font-medium">Endpoint</th>
                <th className="px-3 py-3 font-medium">Process / rule</th>
                <th className="px-3 py-3 font-medium">Transfer</th>
                <th className="px-3 py-3 font-medium">Age / epoch</th>
                <th className="px-3 py-3 text-right font-medium">Owner action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-color">
              {visibleFlows.map((flow) => {
                const busy = busyIDs.has(flow.id);
                const staleEpoch = currentEpoch > 0 && flow.networkEpoch > 0 && flow.networkEpoch < currentEpoch;
                return (
                  <tr key={flow.id} className="bg-bg-secondary/40 align-top hover:bg-bg-tertiary/60">
                    <td className="px-3 py-3">
                      <input
                        type="checkbox"
                        aria-label={`Select ${flow.id}`}
                        disabled={!flow.closeable || busy}
                        checked={selected.has(flow.id)}
                        onChange={(event) => setSelected((previous) => {
                          const next = new Set(previous);
                          if (event.target.checked) next.add(flow.id); else next.delete(flow.id);
                          return next;
                        })}
                      />
                    </td>
                    <td className="px-3 py-3">
                      <p className="mono m-0 font-semibold text-text-primary">{flow.owner}</p>
                      <p className="mono m-0 mt-1 text-[11px] text-accent">{flow.protocol || flow.network || 'unspecified'}</p>
                      <p className="mono m-0 mt-1 text-[10px] text-text-muted">{flow.id}</p>
                    </td>
                    <td className="max-w-80 px-3 py-3"><FlowEndpoint flow={flow} /></td>
                    <td className="max-w-72 px-3 py-3">
                      <p className="m-0 truncate text-text-primary" title={flow.processPath}>{flow.process || 'process attribution unavailable'}</p>
                      <p className="m-0 mt-1 truncate text-[11px] text-text-muted" title={flow.rulePayload}>{flow.rule ? `${flow.rule}${flow.rulePayload ? ` · ${flow.rulePayload}` : ''}` : 'no routing rule metadata'}</p>
                    </td>
                    <td className="px-3 py-3">
                      <p className="mono m-0 text-cyan">↑ {formatBytes(flow.uploadBytes)}</p>
                      <p className="mono m-0 mt-1 text-success">↓ {formatBytes(flow.downloadBytes)}</p>
                    </td>
                    <td className="px-3 py-3">
                      <p className="m-0 flex items-center gap-1 text-text-primary"><Clock3 size={12} /> {formatAge(flow.startedAt)}</p>
                      <p className={`mono m-0 mt-1 text-[11px] ${staleEpoch ? 'text-warning' : 'text-text-muted'}`}>epoch #{flow.networkEpoch || 0}{staleEpoch ? ' · pre-handoff' : ''}</p>
                    </td>
                    <td className="px-3 py-3 text-right">
                      <button type="button" className="btn btn-secondary min-h-9 px-3 py-1.5 text-xs" disabled={!flow.closeable || busy || flow.state === 'closing'} onClick={() => void closeOne(flow)}>
                        {busy || flow.state === 'closing' ? <RefreshCw size={13} className="animate-spin" /> : <Unplug size={13} />}
                        {flow.closeable ? (flow.state === 'closing' ? 'Closing' : 'Close') : 'Observe only'}
                      </button>
                    </td>
                  </tr>
                );
              })}
              {(!data || data.flows.length === 0) && (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-sm text-text-muted">No participating runtime owner currently publishes a matching flow.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {data && data.flows.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-text-muted">
            <span>
              Rendering {Math.min(visibleFlows.length, data.flows.length)} of {data.returned} fetched flows
              {data.matched > data.returned ? ` · ${data.matched} match the current filters; refine filters to inspect beyond the ${FLOW_FETCH_LIMIT}-flow fetch cap.` : '.'}
            </span>
            {visibleFlows.length < data.flows.length && (
              <button
                type="button"
                className="btn btn-secondary min-h-9 px-3 py-1.5 text-xs"
                onClick={() => setVisibleFlowLimit((current) => Math.min(current + VISIBLE_FLOW_STEP, data.flows.length))}
              >
                Show {Math.min(VISIBLE_FLOW_STEP, data.flows.length - visibleFlows.length)} more
              </button>
            )}
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="card space-y-4" aria-labelledby="coverage-title">
          <div className="flex items-start gap-3">
            <ShieldCheck size={20} className="mt-0.5 shrink-0 text-accent" aria-hidden="true" />
            <div>
              <h3 id="coverage-title" className="m-0 text-lg text-text-primary">Runtime coverage truth</h3>
              <p className="m-0 mt-1 text-xs text-text-muted">Model: {data?.coverageModel || 'unavailable'} · complete: {data?.coverageComplete ? 'yes' : 'no'}</p>
            </div>
          </div>
          <div className="space-y-3">
            {data?.coverage.map((coverage) => <CoverageRow key={coverage.owner} coverage={coverage} />)}
            {(!data || data.coverage.length === 0) && <p className="m-0 text-sm text-text-muted">No runtime owners have declared flow publication capability yet.</p>}
          </div>
        </section>

        <section className="card space-y-4" aria-labelledby="network-title">
          <div className="flex items-start gap-3">
            <Cable size={20} className="mt-0.5 shrink-0 text-purple" aria-hidden="true" />
            <div>
              <h3 id="network-title" className="m-0 text-lg text-text-primary">Passive network state</h3>
              <p className="m-0 mt-1 text-xs text-text-muted">Epoch changes only when interface/default-egress truth changes.</p>
            </div>
          </div>

          {networkState?.lastError && (
            <div className="rounded-md border border-warning/30 bg-warning/10 p-3 text-xs text-warning">Latest capture error: {networkState.lastError}. Last known-good state is retained.</div>
          )}

          <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
              <dt className="text-[10px] uppercase tracking-wide text-text-muted">IPv4 egress</dt>
              <dd className="mono m-0 mt-1 text-xs text-text-primary">{networkState?.current.defaultIPv4Interface || 'unknown'}</dd>
              <dd className="mono m-0 mt-1 text-[11px] text-text-muted">{networkState?.current.defaultIPv4LocalIP || 'no observed local IP'}</dd>
            </div>
            <div className="rounded-md border border-border-color bg-bg-primary/60 p-3">
              <dt className="text-[10px] uppercase tracking-wide text-text-muted">IPv6 egress</dt>
              <dd className="mono m-0 mt-1 text-xs text-text-primary">{networkState?.current.defaultIPv6Interface || 'unknown'}</dd>
              <dd className="mono m-0 mt-1 text-[11px] text-text-muted">{networkState?.current.defaultIPv6LocalIP || 'no observed local IP'}</dd>
            </div>
          </dl>

          <div>
            <p className="m-0 mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Active interfaces</p>
            <div className="space-y-2">
              {activeInterfaces.map((iface) => (
                <div key={`${iface.index}-${iface.name}`} className="rounded-md border border-border-color bg-bg-primary/60 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="mono text-xs font-semibold text-text-primary">{iface.name}</span>
                    <span className="mono text-[10px] text-text-muted">MTU {iface.mtu}</span>
                  </div>
                  <p className="mono m-0 mt-1 break-all text-[10px] text-text-muted">{iface.addresses.join(' · ') || 'no addresses'}</p>
                </div>
              ))}
              {activeInterfaces.length === 0 && <p className="m-0 text-xs text-text-muted">No non-loopback active interface is currently observed.</p>}
            </div>
          </div>

          <div>
            <p className="m-0 mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Recent handoffs</p>
            <div className="space-y-2">
              {[...(networkState?.history ?? [])].reverse().map((change) => (
                <div key={change.revision} className="flex items-start justify-between gap-4 rounded-md border border-border-color bg-bg-primary/60 p-3">
                  <div>
                    <p className="mono m-0 text-xs font-semibold text-text-primary">epoch #{change.revision}</p>
                    <p className="m-0 mt-1 text-[11px] text-text-muted">{change.kinds.join(', ')}</p>
                  </div>
                  <span className="mono shrink-0 text-[10px] text-text-muted">{new Date(change.observedAt).toLocaleTimeString()}</span>
                </div>
              ))}
              {(networkState?.history.length ?? 0) === 0 && (
                <div className="flex items-center gap-2 rounded-md border border-border-color bg-bg-primary/60 p-3 text-xs text-text-muted">
                  <CircleCheck size={14} className="text-success" /> No observed network handoff in retained history.
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}


function WebSocketReadinessPlanner() {
  const [status, setStatus] = useState(101);
  const [tlsVerified, setTLSVerified] = useState(true);
  const [plan, setPlan] = useState<WebSocketReadinessPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const key = 'MDEyMzQ1Njc4OWFiY2RlZg==';
  const accept = 'BACScCJPNqyz+UBoqMH89VmURoA=';
  async function analyze() {
    setError(null);
    setPlan(null);
    try {
      setPlan(
        await controlTransport.json('/api/system/websocket-readiness-plan', parseWebSocketReadinessPlan, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tcp_reachable: true,
            status_code: status,
            headers: {
              Upgrade: 'websocket',
              Connection: 'keep-alive, Upgrade',
              'Sec-WebSocket-Accept': accept,
            },
            sec_websocket_key: key,
            tls_expected: true,
            tls_verified: tlsVerified,
          }),
        }),
      );
    } catch (caught) {
      setError(errorText(caught, 'WebSocket readiness planning failed.'));
    }
  }

  return (
    <section className="card space-y-4" aria-labelledby="websocket-readiness-title">
      <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
        <div>
          <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">
            Protocol evidence · no probe performed
          </p>
          <h3 id="websocket-readiness-title" className="m-0 mt-1 text-lg text-text-primary">
            WebSocket backend readiness
          </h3>
          <p className="m-0 mt-1 text-xs text-text-muted">
            An open TCP port is not enough. Readiness requires an HTTP 101 upgrade, Upgrade/Connection evidence, the correct Sec-WebSocket-Accept, and verified TLS when expected.
          </p>
        </div>
        <button type="button" onClick={() => void analyze()} className="btn btn-secondary">
          Classify handshake
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-xs text-text-muted">
          Observed HTTP status
          <input
            type="number"
            min={100}
            max={599}
            value={status}
            onChange={(e) => setStatus(Number(e.target.value) || 0)}
            className="field-input mt-1"
          />
        </label>
        <label className="flex items-center gap-2 self-end pb-2 text-xs text-text-muted">
          <input
            type="checkbox"
            checked={tlsVerified}
            onChange={(e) => setTLSVerified(e.target.checked)}
          />
          Strict TLS verification observed
        </label>
      </div>

      {error && (
        <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">
          {error}
        </div>
      )}

      {plan && (
        <div
          className={`rounded border p-3 text-xs ${
            plan.ready ? 'border-success/30 bg-success/10' : 'border-warning/30 bg-warning/10'
          }`}
        >
          <strong>{plan.ready ? 'WebSocket ready' : 'Not WebSocket ready'}</strong>
          <p className="mb-0 mt-1 text-text-muted">
            101/Upgrade {plan.upgradeValid ? 'ok' : 'missing'} · Connection{' '}
            {plan.connectionValid ? 'ok' : 'missing'} · Accept {plan.acceptValid ? 'ok' : 'invalid'} · TLS{' '}
            {plan.tlsValid ? 'ok' : 'unverified'} · network I/O {plan.performsNetworkIO ? 'yes' : 'no'}
          </p>
          {plan.reasons.length > 0 && (
            <p className="mb-0 mt-2 text-warning">{plan.reasons.join(' · ')}</p>
          )}
        </div>
      )}
    </section>
  );
}
