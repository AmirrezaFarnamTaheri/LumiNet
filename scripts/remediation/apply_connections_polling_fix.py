#!/usr/bin/env python3
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "src/packages/control-ui/src/pages/Connections.tsx"
EXPECTED_BLOB = "07ac7404134c8be7207f3b4489b8aeae1f8209e3"

actual = subprocess.check_output(["git", "hash-object", str(PATH)], cwd=ROOT, text=True).strip()
if actual != EXPECTED_BLOB:
    raise SystemExit(f"Connections.tsx drifted: expected {EXPECTED_BLOB}, got {actual}")

source = PATH.read_text(encoding="utf-8")

def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    source = source.replace(old, new, 1)

replace_once(
    "import { useCallback, useEffect, useMemo, useState } from 'react';",
    "import { useCallback, useEffect, useMemo, useRef, useState } from 'react';",
    "React hook import",
)
replace_once(
    "const POLL_MS = 1500;",
    "const POLL_MS = 1500;\nconst FLOW_FETCH_LIMIT = 512;\nconst INITIAL_VISIBLE_FLOWS = 100;\nconst VISIBLE_FLOW_STEP = 100;",
    "poll constants",
)
replace_once(
    "  const [dispatchError, setDispatchError] = useState<string | null>(null);\n\n  const load",
    "  const [dispatchError, setDispatchError] = useState<string | null>(null);\n"
    "  const [visibleFlowLimit, setVisibleFlowLimit] = useState(INITIAL_VISIBLE_FLOWS);\n"
    "  const requestSequence = useRef(0);\n"
    "  const activeRequest = useRef<AbortController | null>(null);\n\n"
    "  const load",
    "poll state",
)

old_poll = '''  const load = useCallback(async (foreground = false) => {
    if (foreground) setLoading(true);
    try {
      const params = new URLSearchParams({ limit: '4096' });
      if (owner) params.set('owner', owner);
      if (query.trim()) params.set('q', query.trim());
      const [flows, net, intel] = await Promise.all([
        controlTransport.json(`/api/system/flows?${params.toString()}`, parseFlowList),
        controlTransport.json('/api/system/network-state?history=12', parseNetworkStatus),
        controlTransport.json('/api/system/network-intelligence', parseNetworkIntelligence),
      ]);
      setData(flows);
      setNetworkState(net);
      setIntelligence(intel);
      setError(null);
      const live = new Set(flows.flows.map((flow) => flow.id));
      setSelected((previous) => new Set([...previous].filter((id) => live.has(id))));
    } catch (caught) {
      setError(errorText(caught, 'Flow observability is unavailable.'));
    } finally {
      if (foreground) setLoading(false);
    }
  }, [owner, query]);

  useEffect(() => {
    void load(true);
    let timer: number | undefined;
    const start = () => {
      if (timer !== undefined || document.hidden) return;
      timer = window.setInterval(() => void load(false), POLL_MS);
    };
    const stop = () => {
      if (timer !== undefined) window.clearInterval(timer);
      timer = undefined;
    };
    const visibility = () => {
      if (document.hidden) stop();
      else {
        void load(false);
        start();
      }
    };
    start();
    document.addEventListener('visibilitychange', visibility);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [load]);
'''
new_poll = '''  const load = useCallback(async (foreground = false) => {
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
'''
replace_once(old_poll, new_poll, "poll implementation")
replace_once(
    "  const allVisibleSelected = Boolean(data?.flows.length) && data!.flows.filter((flow) => flow.closeable).every((flow) => selected.has(flow.id));",
    "  const visibleFlows = useMemo(() => data?.flows.slice(0, visibleFlowLimit) ?? [], [data, visibleFlowLimit]);\n"
    "  const allVisibleSelected = visibleFlows.some((flow) => flow.closeable) && visibleFlows.filter((flow) => flow.closeable).every((flow) => selected.has(flow.id));",
    "visible flow derivation",
)
replace_once(
    "setSelected(event.target.checked ? new Set(data.flows.filter((flow) => flow.closeable).map((flow) => flow.id)) : new Set());",
    "setSelected(event.target.checked ? new Set(visibleFlows.filter((flow) => flow.closeable).map((flow) => flow.id)) : new Set());",
    "visible selection",
)
replace_once("{data?.flows.map((flow) => {", "{visibleFlows.map((flow) => {", "windowed table")
replace_once(
    '''        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">''',
    '''        </div>
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

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">''',
    "windowing controls",
)

PATH.write_text(source, encoding="utf-8")
print("Connections stale-response sequencing and render window applied")
