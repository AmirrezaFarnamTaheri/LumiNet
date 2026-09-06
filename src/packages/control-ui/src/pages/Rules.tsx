import { useEffect, useState, type FormEvent } from 'react';
import { controlTransport } from '../api/ControlTransport';
import { errorMessage, parsePerAppProxyConfig } from '../api/contracts';
import { formatPresetLine, listRoutingPresets } from '../utils/routingPresets';
import { parseL7SignatureAdmissionPlan, parseLocalRuleSetPlan, parseRoutingArtifactPlan, parseRoutingPolicyGroupPlan, parseSplitTunnelPlan, type L7SignatureAdmissionPlan, type LocalRuleSetPlan, type RoutingArtifactPlan, type RoutingPolicyGroupPlan, type SplitTunnelPlan } from '../api/planners';

type ProxyMode = 'off' | 'include' | 'exclude';

interface PerAppProxyConfig {
  mode: ProxyMode;
  packages: string[];
  supported: boolean;
  enforced: boolean;
  reason?: string;
}

function normalizeConfig(value: ReturnType<typeof parsePerAppProxyConfig>): PerAppProxyConfig {
  if (value.mode !== 'off' && value.mode !== 'include' && value.mode !== 'exclude') {
    throw new Error(`Unsupported per-app proxy mode: ${value.mode}`);
  }
  return {
    mode: value.mode,
    packages: value.packages,
    supported: value.supported,
    enforced: value.enforced,
    ...(value.reason !== undefined ? { reason: value.reason } : {}),
  };
}

export function Rules() {
  const [config, setConfig] = useState<PerAppProxyConfig>({ mode: 'off', packages: [], supported: true, enforced: true });
  const [newPackage, setNewPackage] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [artifactURL, setArtifactURL] = useState('https://example.invalid/rules.srs');
  const [artifactFormat, setArtifactFormat] = useState('srs');
  const [artifactKind, setArtifactKind] = useState('domain');
  const [artifactBytes, setArtifactBytes] = useState(1024);
  const [artifactExpectedSHA, setArtifactExpectedSHA] = useState('');
  const [artifactActualSHA, setArtifactActualSHA] = useState('');
  const [artifactVersion, setArtifactVersion] = useState('manual-review');
  const [artifactPlan, setArtifactPlan] = useState<RoutingArtifactPlan | null>(null);
  const [artifactBusy, setArtifactBusy] = useState(false);
  const [artifactError, setArtifactError] = useState<string | null>(null);
  const [l7Input, setL7Input] = useState('');
  const [l7Plan, setL7Plan] = useState<L7SignatureAdmissionPlan | null>(null);
  const [l7Busy, setL7Busy] = useState(false);
  const [l7Error, setL7Error] = useState<string | null>(null);

  async function fetchConfig() {
    setLoading(true);
    setError(null);
    try {
      const value = await controlTransport.json('/api/system/per-app-proxy', parsePerAppProxyConfig);
      setConfig(normalizeConfig(value));
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to fetch per-app proxy configuration.'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void fetchConfig();
  }, []);

  async function updateMode(mode: ProxyMode) {
    setSaving(true);
    setError(null);
    try {
      const value = await controlTransport.json(
        '/api/system/per-app-proxy',
        parsePerAppProxyConfig,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...config, mode }),
        },
      );
      setConfig(normalizeConfig(value));
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to update the routing mode.'));
    } finally {
      setSaving(false);
    }
  }

  async function addPackage(event: FormEvent) {
    event.preventDefault();
    const packageName = newPackage.trim();
    if (!packageName || config.packages.includes(packageName)) {
      setNewPackage('');
      return;
    }

    setSaving(true);
    setError(null);
    try {
      const value = await controlTransport.json(
        '/api/system/per-app-proxy/packages',
        parsePerAppProxyConfig,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: packageName }),
        },
      );
      setConfig(normalizeConfig(value));
      setNewPackage('');
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to add the package.'));
    } finally {
      setSaving(false);
    }
  }

  async function removePackage(packageName: string) {
    setSaving(true);
    setError(null);
    try {
      const value = await controlTransport.json(
        `/api/system/per-app-proxy/packages/${encodeURIComponent(packageName)}`,
        parsePerAppProxyConfig,
        { method: 'DELETE' },
      );
      setConfig(normalizeConfig(value));
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to remove the package.'));
    } finally {
      setSaving(false);
    }
  }

  async function analyzeRoutingArtifact() {
    setArtifactBusy(true);
    setArtifactError(null);
    try {
      const value = await controlTransport.json(
        '/api/system/routing-artifact-plan',
        parseRoutingArtifactPlan,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ artifacts: [{
            id: 'candidate',
            source_url: artifactURL,
            expected_sha256: artifactExpectedSHA,
            actual_sha256: artifactActualSHA,
            format: artifactFormat,
            kind: artifactKind,
            size_bytes: artifactBytes,
            version: artifactVersion,
          }] }),
        },
      );
      setArtifactPlan(value);
    } catch (caught) {
      setArtifactError(errorMessage(caught, 'Routing artifact analysis failed.'));
    } finally {
      setArtifactBusy(false);
    }
  }

  async function analyzeL7Signatures() {
    setL7Busy(true);
    setL7Error(null);
    setL7Plan(null);
    try {
      const signatures = l7Input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
        const split = line.indexOf('::');
        if (split <= 0) throw new Error(`Signature line ${index + 1} must use name::RE2-expression.`);
        return { name: line.slice(0, split).trim(), expression: line.slice(split + 2) };
      });
      if (signatures.length === 0) throw new Error('Enter at least one signature as name::RE2-expression.');
      setL7Plan(await controlTransport.json('/api/system/l7-signature-plan', parseL7SignatureAdmissionPlan, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ signatures }),
      }));
    } catch (caught) {
      setL7Error(errorMessage(caught, 'L7 signature admission failed.'));
    } finally {
      setL7Busy(false);
    }
  }

  return (
    <div className="space-y-6">

      <details className="rounded-md border border-border-color bg-bg-secondary/35 p-3">
        <summary className="cursor-pointer text-sm font-medium">Routing presets ({listRoutingPresets().length})</summary>
        <div className="mt-2 space-y-1 text-xs text-text-muted">
          {listRoutingPresets().map((preset) => (
            <div key={preset.id}>
              <span className="font-medium text-text-primary">{preset.id}</span>
              {' — '}
              {formatPresetLine(preset)}
              {" "}({preset.defaultStrategy} default{preset.hasDnsConfig ? ', includes DNS config' : ''})
            </div>
          ))}
        </div>
      </details>
      <header>
        <h2 className="m-0 text-2xl text-text-primary">Rules & Routing</h2>
        <p className="mt-1 text-text-secondary">Manage traffic interception policies and per-app proxy lists.</p>
      </header>

      {error && <div role="alert" className="rounded-md border border-error/50 bg-error/20 p-4 text-sm text-text-primary">{error}</div>}

      <section className="card space-y-4" aria-labelledby="routing-artifact-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Read-only · provenance admission</p>
            <h3 id="routing-artifact-title" className="m-0 mt-1 text-lg text-text-primary">Routing artifact provenance</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Validate source, format, size and immutable digest evidence before a remote rules artifact could be considered. This planner never downloads or installs the artifact.</p>
          </div>
          <button type="button" className="btn btn-secondary" disabled={artifactBusy} onClick={() => void analyzeRoutingArtifact()}>
            {artifactBusy ? 'Analyzing…' : 'Analyze provenance'}
          </button>
        </div>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <label className="text-xs text-text-muted lg:col-span-2">HTTPS source URL
            <input value={artifactURL} onChange={(event) => setArtifactURL(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 font-mono text-xs text-text-primary" />
          </label>
          <label className="text-xs text-text-muted">Version / provenance label
            <input value={artifactVersion} onChange={(event) => setArtifactVersion(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary" />
          </label>
          <label className="text-xs text-text-muted">Format
            <select value={artifactFormat} onChange={(event) => setArtifactFormat(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary"><option value="srs">SRS</option><option value="json">JSON</option><option value="txt">Text</option><option value="dat">DAT</option></select>
          </label>
          <label className="text-xs text-text-muted">Kind
            <select value={artifactKind} onChange={(event) => setArtifactKind(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary"><option value="domain">Domain</option><option value="ip">IP/CIDR</option><option value="mixed">Mixed</option></select>
          </label>
          <label className="text-xs text-text-muted">Size bytes
            <input type="number" min={0} value={artifactBytes} onChange={(event) => setArtifactBytes(Math.max(0, Number(event.target.value) || 0))} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary" />
          </label>
          <label className="text-xs text-text-muted">Expected SHA-256
            <input value={artifactExpectedSHA} onChange={(event) => setArtifactExpectedSHA(event.target.value.trim())} placeholder="64 hex characters" className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 font-mono text-xs text-text-primary" />
          </label>
          <label className="text-xs text-text-muted">Observed SHA-256
            <input value={artifactActualSHA} onChange={(event) => setArtifactActualSHA(event.target.value.trim())} placeholder="64 hex characters" className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 font-mono text-xs text-text-primary" />
          </label>
        </div>
        {artifactError && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{artifactError}</div>}
        {artifactPlan && (
          <div className="space-y-2">
            {artifactPlan.artifacts.map((artifact) => (
              <div key={artifact.id} className="flex flex-col justify-between gap-2 rounded border border-border-color bg-bg-primary/60 p-3 sm:flex-row sm:items-center">
                <div><p className="m-0 text-sm font-semibold text-text-primary">{artifact.id}</p><p className="mono m-0 mt-1 break-all text-[10px] text-text-muted">{artifact.provenanceSHA256}</p></div>
                <span className={`rounded px-2 py-1 text-xs font-semibold ${artifact.admitted ? 'bg-success/10 text-success' : 'bg-error/10 text-error'}`}>{artifact.admitted ? 'admitted evidence' : artifact.reason || 'rejected'}</span>
              </div>
            ))}
            <p className="m-0 text-xs text-text-muted">read-only: {artifactPlan.readOnly ? 'yes' : 'no'} · fetches: {artifactPlan.fetches ? 'yes' : 'no'} · installs: {artifactPlan.installs ? 'yes' : 'no'}</p>
          </div>
        )}
      </section>


      <section className="card space-y-4" aria-labelledby="l7-admission-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Offline only · RE2 admission</p>
            <h3 id="l7-admission-title" className="m-0 mt-1 text-lg text-text-primary">L7 signature admission</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Validate bounded protocol-signature expressions before they enter classifier workflows. This surface hashes admitted expressions and never captures traffic or installs a classifier.</p>
          </div>
          <button type="button" className="btn btn-secondary" disabled={l7Busy} onClick={() => void analyzeL7Signatures()}>{l7Busy ? 'Analyzing…' : 'Validate signatures'}</button>
        </div>
        <label className="block text-xs text-text-muted">One signature per line: <span className="mono">name::RE2-expression</span>
          <textarea value={l7Input} onChange={(event) => setL7Input(event.target.value)} rows={5} placeholder={'tls-record::^\\x16\\x03\nhttp-request::^(GET|POST|HEAD) '} className="mono mt-1 w-full rounded border border-border-color bg-bg-primary px-3 py-2 text-xs text-text-primary" />
        </label>
        {l7Error && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{l7Error}</div>}
        {l7Plan && <div className="space-y-2">
          <p className="m-0 text-xs text-text-muted">{l7Plan.admitted} admitted · {l7Plan.rejected} rejected · offline only: {l7Plan.offlineOnly ? 'yes' : 'no'} · installs classifier: {l7Plan.installsClassifier ? 'yes' : 'no'}</p>
          {l7Plan.results.map((result) => <div key={`${result.name}-${result.expressionSHA256 || result.reason}`} className="flex flex-col gap-1 rounded border border-border-color bg-bg-primary/60 p-3 text-xs sm:flex-row sm:items-center sm:justify-between"><div><strong className="text-text-primary">{result.name || 'unnamed'}</strong>{result.expressionSHA256 && <div className="mono mt-1 break-all text-[10px] text-text-muted">{result.expressionSHA256}</div>}</div><span className={result.admitted ? 'text-success' : 'text-warning'}>{result.admitted ? 'admitted' : result.reason || 'rejected'}</span></div>)}
        </div>}
      </section>

      <LocalRuleSetPlanner />
      <RoutingPolicyGroupPlanner />
      <SplitTunnelPlanner />

      {loading ? (
        <div className="card py-12 text-center text-text-muted">Loading configuration…</div>
      ) : !config.supported || !config.enforced ? (
        <section className="card space-y-3" aria-labelledby="routing-unavailable-title">
          <h3 id="routing-unavailable-title" className="m-0 text-lg text-text-primary">Per-app routing unavailable</h3>
          <p className="m-0 text-sm text-text-secondary">
            {config.reason ?? 'The active runtime cannot enforce application or process routing rules.'}
          </p>
          <p className="m-0 text-sm text-text-muted">No inert routing configuration is stored while enforcement is unavailable.</p>
        </section>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <section className="card space-y-6" aria-labelledby="mode-title">
            <h3 id="mode-title" className="m-0 border-b border-border-color pb-3 text-lg text-text-primary">Mode selector</h3>
            <div className="space-y-3">
              <ModeOption mode="off" current={config.mode} disabled={saving} onChange={updateMode} title="Off" description="Route all device traffic through the tunnel." />
              <ModeOption mode="include" current={config.mode} disabled={saving} onChange={updateMode} title="Include mode" description="Proxy only the specified applications or processes." />
              <ModeOption mode="exclude" current={config.mode} disabled={saving} onChange={updateMode} title="Exclude mode" description="Proxy all traffic except the specified applications." />
            </div>
          </section>

          <section className="card space-y-4 lg:col-span-2" aria-labelledby="packages-title">
            <div className="flex items-center justify-between border-b border-border-color pb-3">
              <h3 id="packages-title" className="m-0 text-lg text-text-primary">Managed packages & processes</h3>
              <span className="rounded bg-accent/20 px-2 py-0.5 text-xs font-semibold uppercase tracking-wider text-accent">{config.packages.length} apps</span>
            </div>

            {config.mode === 'off' ? (
              <div className="rounded-md border border-dashed border-border-color bg-bg-secondary/40 py-16 text-center text-text-muted">Per-app routing is off. All traffic follows the tunnel policy.</div>
            ) : (
              <div className="space-y-4">
                <form onSubmit={(event) => void addPackage(event)} className="flex flex-col gap-2 sm:flex-row">
                  <label htmlFor="package-name" className="sr-only">Package or process name</label>
                  <input
                    id="package-name"
                    type="text"
                    placeholder="chrome.exe or com.android.chrome"
                    value={newPackage}
                    onChange={(event) => setNewPackage(event.target.value)}
                    className="min-h-11 flex-1 rounded-md border border-border-color bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent"
                  />
                  <button type="submit" disabled={saving} className="btn btn-primary px-4 py-2">Add</button>
                </form>

                {config.packages.length === 0 ? (
                  <div className="rounded-md bg-bg-secondary/20 py-12 text-center text-text-muted">No packages have been added.</div>
                ) : (
                  <div className="grid max-h-[300px] grid-cols-1 gap-2 overflow-y-auto pr-1 sm:grid-cols-2">
                    {config.packages.map((packageName) => (
                      <div key={packageName} className="flex items-center justify-between rounded border border-border-color bg-bg-secondary px-3 py-2 text-sm">
                        <span className="truncate font-mono text-text-primary">{packageName}</span>
                        <button
                          type="button"
                          onClick={() => void removePackage(packageName)}
                          disabled={saving}
                          className="min-h-11 min-w-11 cursor-pointer border-0 bg-transparent p-2 font-semibold text-text-muted transition-colors hover:text-error focus-visible:outline-2 focus-visible:outline-accent"
                          aria-label={`Remove ${packageName}`}
                        >
                          ×
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}


function LocalRuleSetPlanner() {
  const [format, setFormat] = useState('auto');
  const [content, setContent] = useState('||ads.example^\n@@||allowed.example^\nDOMAIN-KEYWORD,github,PROXY\nIP-CIDR,10.1.2.3/8,REJECT\nGEOIP,CN,DIRECT\nMATCH,PROXY');
  const [plan, setPlan] = useState<LocalRuleSetPlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function analyze() {
    setBusy(true); setError(null); setPlan(null);
    try {
      setPlan(await controlTransport.json('/api/system/local-ruleset-plan', parseLocalRuleSetPlan, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ format, content }),
      }));
    } catch (caught) { setError(errorMessage(caught, 'Local rule-set normalization failed.')); } finally { setBusy(false); }
  }

  return <section className="card space-y-4" aria-labelledby="local-ruleset-title">
    <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start"><div>
      <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Local only · deterministic normalization</p>
      <h3 id="local-ruleset-title" className="m-0 mt-1 text-lg text-text-primary">Local rule-set normalization</h3>
      <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Normalize AdGuard, hosts, Clash/Surge, or LumiNet rules into bounded local evidence, including domain keywords, source CIDRs, ports, process names, GEOIP symbols, local rule-set references, and final MATCH rules. No URL is fetched and no converted rule is installed or activated.</p>
    </div><button type="button" className="btn btn-secondary" disabled={busy || !content.trim()} onClick={() => void analyze()}>{busy ? 'Normalizing…' : 'Normalize locally'}</button></div>
    <div className="grid gap-3 lg:grid-cols-[180px_1fr]"><label className="text-xs text-text-muted">Format<select value={format} onChange={(event) => setFormat(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary"><option value="auto">auto</option><option value="adguard">AdGuard</option><option value="hosts">hosts</option><option value="clash">Clash</option><option value="surge">Surge</option><option value="luminet">LumiNet</option></select></label><label className="text-xs text-text-muted">Rule text<textarea value={content} onChange={(event) => setContent(event.target.value)} rows={6} className="mono mt-1 w-full rounded border border-border-color bg-bg-primary px-3 py-2 text-xs text-text-primary" /></label></div>
    {error && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{error}</div>}
    {plan && <div className="space-y-2"><p className="m-0 text-xs text-text-muted">{plan.rules.length} normalized · {plan.duplicateCount} duplicate · {plan.ignoredCount} ignored · fetches {plan.fetches ? 'yes' : 'no'} · installs {plan.installs ? 'yes' : 'no'}</p><div className="max-h-52 overflow-auto rounded border border-border-color">{plan.rules.map((rule) => <div key={`${rule.sourceLine}-${rule.action}-${rule.kind}-${rule.value}`} className="grid grid-cols-[70px_120px_1fr_auto] gap-2 border-b border-border-color/50 p-2 text-xs last:border-0"><span className={rule.action === 'block' ? 'text-warning' : rule.action === 'proxy' ? 'text-accent' : 'text-success'}>{rule.action}</span><span className="text-text-muted">{rule.kind}</span><span className="mono break-all text-text-primary">{rule.value}</span><span className="text-text-muted">{rule.options.join(' · ')}</span></div>)}</div></div>}
  </section>;
}

function RoutingPolicyGroupPlanner() {
  const [mode, setMode] = useState('latency-auto');
  const [scope, setScope] = useState('default-policy');
  const [selected, setSelected] = useState('edge-a');
  const [candidateText, setCandidateText] = useState('[{"name":"edge-a","healthy":true,"latency_ms":42,"weight":2},{"name":"edge-b","healthy":true,"latency_ms":58,"weight":1},{"name":"edge-c","healthy":false,"latency_ms":30,"weight":1}]');
  const [plan, setPlan] = useState<RoutingPolicyGroupPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function analyze() {
    setBusy(true); setError(null); setPlan(null);
    try {
      const candidates: unknown = JSON.parse(candidateText);
      setPlan(await controlTransport.json('/api/system/routing-policy-group-plan', parseRoutingPolicyGroupPlan, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode, candidates, selected: mode === 'manual-select' ? selected : undefined, scope }),
      }));
    } catch (caught) { setError(errorMessage(caught, 'Routing policy-group planning failed.')); } finally { setBusy(false); }
  }

  return <section className="card space-y-4" aria-labelledby="routing-policy-group-title">
    <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start"><div>
      <p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Policy groups · caller evidence only</p>
      <h3 id="routing-policy-group-title" className="m-0 mt-1 text-lg text-text-primary">Routing policy-group preview</h3>
      <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Preview manual selection, latency-based auto choice, ordered failover, or deterministic weighted balancing. Latency is supplied evidence only: LumiNet does not probe a donor URL or install a policy from this screen.</p>
    </div><button type="button" className="btn btn-secondary" disabled={busy || !candidateText.trim()} onClick={() => void analyze()}>{busy ? 'Planning…' : 'Plan group'}</button></div>
    <div className="grid gap-3 lg:grid-cols-3"><label className="text-xs text-text-muted">Mode<select value={mode} onChange={(event)=>setMode(event.target.value)} className="mt-1 w-full rounded border border-border-color bg-bg-primary px-2 py-2 text-text-primary"><option value="manual-select">manual select</option><option value="latency-auto">latency auto</option><option value="fallback">fallback</option><option value="load-balance">load balance</option></select></label><label className="text-xs text-text-muted">Scope<input value={scope} onChange={(event)=>setScope(event.target.value)} className="field-input mono mt-1" /></label><label className="text-xs text-text-muted">Manual selection<input value={selected} onChange={(event)=>setSelected(event.target.value)} disabled={mode !== 'manual-select'} className="field-input mono mt-1" /></label></div>
    <label className="block text-xs text-text-muted">Candidate evidence JSON<textarea value={candidateText} onChange={(event)=>setCandidateText(event.target.value)} rows={5} className="field-input mono mt-1 resize-y" /></label>
    {error && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{error}</div>}
    {plan && <div className="space-y-2 text-xs text-text-muted"><p className="m-0"><strong className="text-text-primary">{plan.mode}</strong> · preferred {plan.preferred || 'none'} · network I/O {plan.performsNetworkIO ? 'yes' : 'no'} · installs {plan.installsPolicy ? 'yes' : 'no'}</p><p className="m-0"><strong className="text-text-primary">dispatch</strong> {plan.dispatchOrder.join(' → ') || 'none'}{plan.skipped.length ? ` · skipped ${plan.skipped.join(', ')}` : ''}</p>{plan.shares.length > 0 && <p className="m-0 mono">{plan.shares.map((share)=>`${share.name} ${share.sharePct}%`).join(' · ')}</p>}</div>}
  </section>;
}

function ModeOption({
  mode,
  current,
  disabled,
  onChange,
  title,
  description,
}: {
  mode: ProxyMode;
  current: ProxyMode;
  disabled: boolean;
  onChange: (mode: ProxyMode) => Promise<void>;
  title: string;
  description: string;
}) {
  return (
    <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-3 transition-colors hover:bg-bg-secondary">
      <input
        type="radio"
        name="proxy_mode"
        value={mode}
        checked={current === mode}
        disabled={disabled}
        onChange={() => void onChange(mode)}
        className="mt-1 accent-accent"
      />
      <span>
        <span className="block font-semibold text-text-primary">{title}</span>
        <span className="mt-0.5 block text-xs text-text-secondary">{description}</span>
      </span>
    </label>
  );
}

function SplitTunnelPlanner() {
  const [platform, setPlatform] = useState('android');
  const [mode, setMode] = useState<'off' | 'include' | 'exclude'>('exclude');
  const [entries, setEntries] = useState('package:com.example.browser\nprocess:curl');
  const [plan, setPlan] = useState<SplitTunnelPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    try {
      const parsed = mode === 'off' ? [] : entries.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
        const index = line.indexOf(':');
        if (index < 1) throw new Error(`Entry must be kind:identifier: ${line}`);
        return { kind: line.slice(0, index), identifier: line.slice(index + 1) };
      });
      setPlan(await controlTransport.json('/api/system/split-tunnel-plan', parseSplitTunnelPlan, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ platform, mode, entries: parsed }) }));
    } catch (caught) { setError(errorMessage(caught, 'Split-tunnel planning failed.')); }
  }
  return <section className="card space-y-3" aria-labelledby="split-tunnel-plan-title">
    <div><p className="m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Planning/import only · no OS enforcement</p><h3 id="split-tunnel-plan-title" className="m-0 mt-1 text-lg text-text-primary">Split-tunnel admission & backup identity</h3><p className="m-0 mt-1 text-xs text-text-muted">Normalize include/exclude app, process, and path intent into a deterministic restore identity. The current LumiNet runtime still reports per-app enforcement unavailable; this preview installs no driver, BPF program, firewall rule, or route.</p></div>
    <div className="grid gap-2 md:grid-cols-2"><label className="text-xs text-text-muted">Platform<select className="field-input mt-1" value={platform} onChange={(e)=>setPlatform(e.target.value)}><option value="android">Android</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option></select></label><label className="text-xs text-text-muted">Mode<select className="field-input mt-1" value={mode} onChange={(e)=>setMode(e.target.value as typeof mode)}><option value="off">Off</option><option value="include">Include only</option><option value="exclude">Exclude</option></select></label></div>
    {mode !== 'off' && <label className="block text-xs text-text-muted">Entries · package/process/path<textarea className="field-input mono mt-1 resize-y" rows={4} value={entries} onChange={(e)=>setEntries(e.target.value)} /></label>}
    <button type="button" className="btn btn-secondary" onClick={()=>void analyze()}>Normalize intent</button>
    {error && <p role="alert" className="m-0 text-xs text-error">{error}</p>}
    {plan && <div className="space-y-1 rounded border border-border-color bg-bg-primary/60 p-3 text-xs text-text-muted"><p className="m-0"><strong className="text-text-primary">{plan.mode}</strong> · {plan.entries.length} normalized · duplicates {plan.duplicateCount} · enforced {plan.runtimeEnforced ? 'yes' : 'no'}</p><p className="mono m-0 break-all">manifest {plan.manifestSHA256}</p>{plan.warnings.map((warning)=><p key={warning} className="m-0 text-warning">{warning}</p>)}</div>}
  </section>;
}
