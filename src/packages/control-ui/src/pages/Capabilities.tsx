import { Boxes, Cpu, Database, Network, RefreshCw, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { parseCapabilityReport, type CapabilityReport } from '../api/capabilities';
import { controlTransport } from '../api/ControlTransport';

function errorText(value: unknown, fallback: string): string {
  return value instanceof Error && value.message ? value.message : fallback;
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let amount = value;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

function statusClass(ok: boolean): string {
  return ok
    ? 'border-success/30 bg-success/10 text-success'
    : 'border-warning/30 bg-warning/10 text-warning';
}

function StatCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-md border border-border-color bg-bg-secondary/45 p-4">
      <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-text-muted">{label}</p>
      <p className="mono m-0 mt-2 text-xl font-semibold text-text-primary">{value}</p>
      <p className="m-0 mt-1 text-xs text-text-muted">{detail}</p>
    </div>
  );
}

export function Capabilities() {
  const [report, setReport] = useState<CapabilityReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const next = await controlTransport.json('/api/capabilities', parseCapabilityReport);
      setReport(next);
      setError(null);
    } catch (caught) {
      setError(errorText(caught, 'Capability coverage is unavailable.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const counts = useMemo(() => {
    const capabilities = report?.capabilities ?? [];
    return {
      available: capabilities.filter((item) => item.status === 'available').length,
      unavailable: capabilities.filter((item) => item.status === 'unavailable').length,
    };
  }, [report]);

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
        <div>
          <p className="mono m-0 text-[10px] uppercase tracking-[0.16em] text-accent">Capability truth plane</p>
          <h2 className="m-0 mt-1 flex items-center gap-2 text-2xl font-display text-text-primary"><Boxes size={24} className="text-accent" /> Capability & coverage center</h2>
          <p className="m-0 mt-2 max-w-4xl text-sm text-text-muted">One read-only view of registry availability, native-core linkage, runtime flow participation, passive network observation, and provider-corpus freshness. Missing coverage stays visible instead of being inferred as success.</p>
        </div>
        <button type="button" className="btn btn-secondary" disabled={loading} onClick={() => void load()}><RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Refresh truth</button>
      </header>

      {error && <div role="alert" className="rounded-md border border-error/30 bg-error/10 p-3 text-sm text-error">{error}</div>}

      {report && (
        <>
          <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Capability summary">
            <StatCard label="Available" value={String(counts.available)} detail={`${counts.unavailable} registry capabilities unavailable`} />
            <StatCard label="Runtime" value={`${report.runtime.os}/${report.runtime.arch}`} detail={`native core ${report.runtime.nativeCore.status}${report.runtime.nativeCore.version ? ` · ${report.runtime.nativeCore.version}` : ''}`} />
            <StatCard label="Flow registry" value={`${report.coverage.flowRegistry.stats.active} active`} detail={`${report.coverage.flowRegistry.owners.length} owners · ${formatBytes(report.coverage.flowRegistry.stats.uploadBytes + report.coverage.flowRegistry.stats.downloadBytes)} observed`} />
            <StatCard label="Network epoch" value={String(report.coverage.networkState.revision)} detail={report.coverage.networkState.running ? 'passive monitor running' : 'passive monitor not running'} />
          </section>

          <section className="card space-y-4" aria-labelledby="capability-registry-title">
            <div className="flex items-start gap-3">
              <ShieldCheck size={20} className="mt-0.5 text-cyan" />
              <div>
                <h3 id="capability-registry-title" className="m-0 text-lg text-text-primary">Registered product capabilities</h3>
                <p className="m-0 mt-1 text-xs text-text-muted">Availability is computed from the live capability registry and host platform. Source presence or historical porting evidence does not make a capability available.</p>
              </div>
            </div>
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              {report.capabilities.map((item) => (
                <article key={item.id} className="rounded-md border border-border-color bg-bg-secondary/40 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="m-0 text-sm font-semibold text-text-primary">{item.name}</p>
                      <p className="mono m-0 mt-1 text-[10px] text-text-muted">{item.id} · {item.workflow}</p>
                    </div>
                    <span className={`rounded border px-2 py-1 text-[10px] uppercase ${statusClass(item.status === 'available')}`}>{item.status}</span>
                  </div>
                  <p className="m-0 mt-3 text-xs text-text-secondary">{item.description}</p>
                  <div className="mt-3 flex flex-wrap gap-2 text-[10px] text-text-muted">
                    <span className="rounded border border-border-color px-2 py-1">{item.maturity}</span>
                    {item.platforms.map((platform) => <span key={platform} className="rounded border border-border-color px-2 py-1">{platform}</span>)}
                  </div>
                  {item.reason && <p className="m-0 mt-3 text-xs text-warning">{item.reason}</p>}
                </article>
              ))}
            </div>
          </section>

          <section className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <div className="card space-y-3">
              <div className="flex items-center gap-2"><Network size={18} className="text-accent" /><h3 className="m-0 text-base text-text-primary">Runtime flow coverage</h3></div>
              <p className="m-0 text-xs text-text-muted">Model: {report.coverage.flowRegistry.coverageModel}. Completeness is deliberately {report.coverage.flowRegistry.coverageComplete ? 'declared complete' : 'partial'}.</p>
              <div className="space-y-2">
                {report.coverage.flowRegistry.owners.map((owner) => (
                  <div key={owner.owner} className="rounded border border-border-color bg-bg-primary/40 p-3">
                    <div className="flex items-center justify-between gap-2"><span className="mono text-xs text-text-primary">{owner.owner}</span><span className={`rounded border px-2 py-0.5 text-[9px] uppercase ${statusClass(owner.visible)}`}>{owner.visible ? 'visible' : 'not visible'}</span></div>
                    <p className="m-0 mt-2 text-[10px] text-text-muted">close {owner.closeable ? 'yes' : 'no'} · bytes {owner.byteCounters ? 'yes' : 'no'} · process {owner.processAttribution ? 'yes' : 'no'} · destination {owner.destinationMetadata ? 'yes' : 'no'}</p>
                    {owner.notes.length > 0 && <p className="m-0 mt-2 text-[10px] text-text-secondary">{owner.notes.join(' · ')}</p>}
                  </div>
                ))}
                {report.coverage.flowRegistry.owners.length === 0 && <p className="m-0 text-xs text-text-muted">No runtime owner has declared flow participation.</p>}
              </div>
            </div>

            <div className="card space-y-3">
              <div className="flex items-center gap-2"><Cpu size={18} className="text-cyan" /><h3 className="m-0 text-base text-text-primary">Passive network observation</h3></div>
              <p className="m-0 text-sm text-text-primary">Revision <span className="mono">{report.coverage.networkState.revision}</span></p>
              <span className={`inline-flex rounded border px-2 py-1 text-[10px] uppercase ${statusClass(report.coverage.networkState.running)}`}>{report.coverage.networkState.running ? 'monitor running' : 'monitor stopped'}</span>
              <p className="mono m-0 break-all text-[10px] text-text-muted">captured {report.coverage.networkState.capturedAt || 'not captured yet'}</p>
              {report.coverage.networkState.lastError && <p className="m-0 text-xs text-warning">{report.coverage.networkState.lastError}</p>}
            </div>

            <div className="card space-y-3">
              <div className="flex items-center gap-2"><Database size={18} className="text-purple" /><h3 className="m-0 text-base text-text-primary">Provider corpus</h3></div>
              <span className={`inline-flex rounded border px-2 py-1 text-[10px] uppercase ${statusClass(report.coverage.providerCorpus.ready && !report.coverage.providerCorpus.stale)}`}>{!report.coverage.providerCorpus.ready ? 'not activated' : report.coverage.providerCorpus.stale ? 'stale' : 'ready'}</span>
              <p className="mono m-0 break-all text-xs text-text-primary">{report.coverage.providerCorpus.corpusID || 'no active corpus'}</p>
              {report.coverage.providerCorpus.generatorVersion && <p className="m-0 text-[10px] text-text-muted">generator {report.coverage.providerCorpus.generatorVersion}</p>}
              {report.coverage.providerCorpus.staleAfter && <p className="m-0 text-[10px] text-text-muted">stale after {report.coverage.providerCorpus.staleAfter}</p>}
            </div>
          </section>

          <section className="rounded-md border border-accent/20 bg-accent/5 p-4 text-xs text-text-secondary">
            <strong className="text-text-primary">Safety boundary:</strong> {report.safetyBoundary}
          </section>
        </>
      )}
    </div>
  );
}
