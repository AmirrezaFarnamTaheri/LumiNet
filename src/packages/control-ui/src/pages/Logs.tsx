import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDownToLine, Download, List, RefreshCw, Search, Trash } from 'lucide-react';
import { TelemetryService } from '../api/TelemetryService';
import { controlTransport } from '../api/ControlTransport';
import { errorMessage, parseLogsResponse, parseSystemStatus, type SystemStatus } from '../api/contracts';

const MAX_LOG_LINES = 500;

export function Logs() {
  const [logs, setLogs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [followTail, setFollowTail] = useState(true);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<'all' | 'error' | 'warning' | 'info' | 'debug'>('all');
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const terminalRef = useRef<HTMLDivElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const shouldStickToBottom = useRef(true);

  async function fetchLogs() {
    setLoading(true);
    setError(null);
    try {
      const [response, status] = await Promise.all([
        controlTransport.json('/api/system/evasion-tunnel/logs', parseLogsResponse),
        controlTransport.json('/api/system/status', parseSystemStatus),
      ]);
      setLogs(response.logs);
      setSystemStatus(status);
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to load the log history.'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void fetchLogs();
    const unsubscribe = TelemetryService.subscribe((event) => {
      if (event.type === 'EVASION_LOG') {
        setLogs((previous) => [...previous, event.data].slice(-MAX_LOG_LINES));
      }
    });
    return unsubscribe;
  }, []);

  useEffect(() => {
    if (!shouldStickToBottom.current) return;
    terminalEndRef.current?.scrollIntoView({ behavior: 'auto' });
  }, [logs]);

  function handleTerminalScroll() {
    const terminal = terminalRef.current;
    if (!terminal) return;
    const atBottom = terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight <= 24;
    shouldStickToBottom.current = atBottom;
    setFollowTail(atBottom);
  }

  const visibleLogs = useMemo(() => {
    const search = query.trim().toLowerCase();
    return logs.filter((log) => {
      if (search && !log.toLowerCase().includes(search)) return false;
      if (severity === 'all') return true;
      return logSeverity(log) === severity;
    });
  }, [logs, query, severity]);

  function exportVisibleLogs() {
    if (visibleLogs.length === 0) return;
    const blob = new Blob([`${visibleLogs.join('\n')}\n`], { type: 'text/plain' });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = href;
    anchor.download = 'luminet-visible-logs.txt';
    anchor.click();
    URL.revokeObjectURL(href);
  }

  function resumeTail() {
    shouldStickToBottom.current = true;
    setFollowTail(true);
    terminalEndRef.current?.scrollIntoView({ behavior: 'auto' });
  }

  return (
    <div className="flex min-h-[calc(100vh-8rem)] flex-col gap-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="m-0 flex items-center gap-2 text-2xl font-display text-text-primary">
            <List size={22} className="text-cyan" aria-hidden="true" /> Operational console logs
          </h2>
          <p className="mt-1 text-text-secondary">Live desynchronization and tunnel events, capped at {MAX_LOG_LINES} lines.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {!followTail && (
            <button type="button" onClick={resumeTail} className="btn btn-secondary px-3 py-1.5" title="Resume following the newest log line">
              <ArrowDownToLine size={14} aria-hidden="true" /> Resume live tail
            </button>
          )}
          <button type="button" onClick={() => setLogs([])} className="btn btn-secondary px-3 py-1.5" title="Clear console view">
            <Trash size={14} aria-hidden="true" /> Clear
          </button>
          <button type="button" onClick={() => void fetchLogs()} className="btn btn-primary px-3 py-1.5" title="Reload recent logs">
            <RefreshCw size={14} aria-hidden="true" /> Refresh
          </button>
        </div>
      </header>

      {error && <div role="alert" className="rounded-md border border-error/40 bg-error/10 p-3 text-sm text-error">{error}</div>}

      <section className="grid grid-cols-1 gap-3 lg:grid-cols-4" aria-label="Log evidence controls">
        <label className="relative lg:col-span-2"><span className="sr-only">Search visible log lines</span><Search size={14} className="pointer-events-none absolute left-3 top-3 text-text-muted"/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search retained log lines…" className="w-full rounded border border-border-color bg-bg-primary py-2 pl-9 pr-3 text-sm text-text-primary" /></label>
        <label><span className="sr-only">Severity filter</span><select value={severity} onChange={(event) => setSeverity(event.target.value as typeof severity)} className="w-full rounded border border-border-color bg-bg-primary px-3 py-2 text-sm text-text-primary"><option value="all">All severities</option><option value="error">Errors</option><option value="warning">Warnings</option><option value="info">Info</option><option value="debug">Debug</option></select></label>
        <button type="button" className="btn btn-secondary" disabled={visibleLogs.length === 0} onClick={exportVisibleLogs}><Download size={14}/> Export visible</button>
      </section>

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="Log and backpressure summary">
        <div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Visible lines</p><p className="mono m-0 mt-1 text-lg text-text-primary">{visibleLogs.length} / {logs.length}</p></div>
        <div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Retention cap</p><p className="mono m-0 mt-1 text-lg text-text-primary">{MAX_LOG_LINES}</p></div>
        <div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Broadcast drops</p><p className="mono m-0 mt-1 text-lg text-warning">{systemStatus?.websocketBackpressure.broadcastDrops ?? 0}</p></div>
        <div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Slow-client disconnects</p><p className="mono m-0 mt-1 text-lg text-warning">{systemStatus?.websocketBackpressure.slowClientDisconnects ?? 0}</p></div>
      </section>

      {loading ? (
        <div className="card flex flex-1 items-center justify-center py-12 text-center text-text-muted">Loading log history…</div>
      ) : (
        <div
          ref={terminalRef}
          onScroll={handleTerminalScroll}
          role="log"
          aria-live="polite"
          aria-relevant="additions"
          className="flex-1 select-text space-y-1 overflow-y-auto rounded-lg border border-border-color bg-bg-secondary p-4 font-mono text-xs"
        >
          {visibleLogs.length === 0 ? (
            <div className="py-12 text-center text-text-muted">No retained log lines match the current filter.</div>
          ) : (
            visibleLogs.map((log, index) => (
              <div key={`${index}-${log}`} className={`whitespace-pre-wrap break-words leading-relaxed ${logTone(log)}`}>
                {log}
              </div>
            ))
          )}
          <div ref={terminalEndRef} />
        </div>
      )}
    </div>
  );
}

function logSeverity(log: string): 'error' | 'warning' | 'info' | 'debug' | 'other' {
  const normalized = log.toLowerCase();
  if (normalized.includes('[error]') || normalized.includes('failed')) return 'error';
  if (normalized.includes('[warn]') || normalized.includes('degraded')) return 'warning';
  if (normalized.includes('[debug]')) return 'debug';
  if (normalized.includes('[info]') || normalized.includes('success')) return 'info';
  return 'other';
}

function logTone(log: string): string {
  const normalized = log.toLowerCase();
  if (normalized.includes('[error]') || normalized.includes('failed')) return 'text-error';
  if (normalized.includes('[warn]') || normalized.includes('degraded')) return 'text-warning';
  if (normalized.includes('[debug]')) return 'text-text-muted';
  if (normalized.includes('[info]') || normalized.includes('success')) return 'text-success';
  return 'text-text-primary';
}
