import { useEffect, useState, type FormEvent } from 'react';
import { FlaskConical, Plus, RotateCcw, Server, ShieldCheck, Trash, TriangleAlert } from 'lucide-react';
import { controlTransport } from '../api/ControlTransport';
import { errorMessage, parseDNSConfig } from '../api/contracts';
import { parseDNSResolutionPolicyPlan, parseDoHResolverPoolPlan, type DNSResolutionPolicyPlan, type DoHResolverPoolPlan } from '../api/planners';

interface DNSConfig {
  interface: string;
  servers: string[];
  source: string;
}

interface DNSPreset {
  id: string;
  name: string;
  primary: string;
  secondary: string;
  description: string;
}

function parseDNSPresets(value: unknown): DNSPreset[] {
  if (!Array.isArray(value)) throw new Error('DNS presets response must be an array.');
  return value.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error(`DNS preset ${index + 1} must be an object.`);
    const record = item as Record<string, unknown>;
    for (const key of ['id', 'name', 'primary', 'secondary', 'description'] as const) {
      if (typeof record[key] !== 'string') throw new Error(`DNS preset ${index + 1}.${key} must be a string.`);
    }
    if (!isIPAddress(record.primary as string) || !isIPAddress(record.secondary as string)) throw new Error(`DNS preset ${index + 1} contains an invalid resolver address.`);
    return { id: record.id as string, name: record.name as string, primary: record.primary as string, secondary: record.secondary as string, description: record.description as string };
  });
}

export function Dns() {
  const [dnsConfig, setDnsConfig] = useState<DNSConfig>({ interface: 'unknown', servers: [], source: 'unknown' });
  const [newServer, setNewServer] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [policyPrimaryKind, setPolicyPrimaryKind] = useState('https');
  const [policyFallbackKind, setPolicyFallbackKind] = useState('tls');
  const [policyStrategy, setPolicyStrategy] = useState('prefer-ipv4');
  const [policyCacheScope, setPolicyCacheScope] = useState('shared');
  const [policyRequireSecure, setPolicyRequireSecure] = useState(true);
  const [policyECS, setPolicyECS] = useState('');
  const [policyPlan, setPolicyPlan] = useState<DNSResolutionPolicyPlan | null>(null);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [dnsPresets, setDnsPresets] = useState<DNSPreset[]>([]);
  const [dnsPresetId, setDnsPresetId] = useState('');
  const [dnsPresetError, setDnsPresetError] = useState<string | null>(null);
  const [poolInput, setPoolInput] = useState('cloudflare,https://cloudflare-dns.com/dns-query,10,0,unknown\nquad9,https://dns.quad9.net/dns-query,20,0,unknown');
  const [poolPlan, setPoolPlan] = useState<DoHResolverPoolPlan | null>(null);
  const [poolBusy, setPoolBusy] = useState(false);
  const [poolError, setPoolError] = useState<string | null>(null);

  async function fetchDNSStatus() {
    setLoading(true);
    setError(null);
    try {
      setDnsConfig(await controlTransport.json('/api/system/dns', parseDNSConfig));
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to fetch DNS configuration.'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void fetchDNSStatus();
    void controlTransport.json('/api/presets/dns', parseDNSPresets).then((presets) => {
      setDnsPresets(presets);
      setDnsPresetId((current) => current || presets[0]?.id || '');
      setDnsPresetError(null);
    }).catch((caught) => setDnsPresetError(errorMessage(caught, 'Failed to load DNS presets.')));
  }, []);

  function loadDNSPreset() {
    const preset = dnsPresets.find((candidate) => candidate.id === dnsPresetId);
    if (!preset) return;
    setDnsConfig((current) => ({ ...current, servers: [preset.primary, preset.secondary] }));
    setMessage(`Loaded ${preset.name}. Review and Apply config to make it active.`);
    setError(null);
  }

  function handleAddServer(event: FormEvent) {
    event.preventDefault();
    const cleanIP = newServer.trim();
    if (!cleanIP) return;
    if (!isIPAddress(cleanIP)) {
      setError('Enter a valid IPv4 or IPv6 address.');
      return;
    }
    if (!dnsConfig.servers.includes(cleanIP)) {
      setDnsConfig((current) => ({ ...current, servers: [...current.servers, cleanIP] }));
    }
    setNewServer('');
    setError(null);
  }

  function handleRemoveServer(ip: string) {
    setDnsConfig((current) => ({ ...current, servers: current.servers.filter((server) => server !== ip) }));
  }

  async function saveDNSConfig() {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const response = await controlTransport.request('/api/system/dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: dnsConfig.interface, servers: dnsConfig.servers }),
      });
      if (!response.ok) {
        throw new Error(`DNS update failed with status ${response.status}`);
      }
      setMessage('DNS configuration applied.');
      await fetchDNSStatus();
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to save DNS configuration.'));
    } finally {
      setSaving(false);
    }
  }

  async function analyzeResolutionPolicy() {
    setPolicyBusy(true);
    setPolicyError(null);
    setPolicyPlan(null);
    try {
      const primary = {
        id: 'primary',
        kind: policyPrimaryKind,
        server: policyPrimaryKind === 'https' ? 'https://dns.quad9.net/dns-query' : undefined,
        fallback_to: 'fallback',
        truncation_fallback_to: policyPrimaryKind === 'udp' && policyFallbackKind === 'tcp' ? 'fallback' : undefined,
        edns_client_subnet: policyECS.trim() || undefined,
      };
      const fallback = {
        id: 'fallback',
        kind: policyFallbackKind,
        server: policyFallbackKind === 'https' ? 'https://dns.cloudflare.com/dns-query' : undefined,
      };
      const plan = await controlTransport.json('/api/system/dns-resolution-policy-plan', parseDNSResolutionPolicyPlan, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          transports: [primary, fallback],
          primary_transport: 'primary',
          strategy: policyStrategy,
          cache_scope: policyCacheScope,
          require_secure_transport: policyRequireSecure,
          response_rejection_cache: true,
        }),
      });
      setPolicyPlan(plan);
    } catch (caught) {
      setPolicyError(errorMessage(caught, 'DNS policy analysis failed.'));
    } finally {
      setPolicyBusy(false);
    }
  }

  async function resetToDHCP() {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const response = await controlTransport.request('/api/system/dns', { method: 'DELETE' });
      if (!response.ok) {
        throw new Error(`DNS reset failed with status ${response.status}`);
      }
      setMessage('DNS configuration reverted to the system default.');
      await fetchDNSStatus();
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to restore the system DNS configuration.'));
    } finally {
      setSaving(false);
    }
  }

  async function analyzeResolverPool() {
    setPoolBusy(true);
    setPoolError(null);
    setPoolPlan(null);
    try {
      const candidates = poolInput.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
        const parts = line.split(',').map((part) => part.trim());
        if (parts.length < 2 || parts.length > 5) throw new Error(`Resolver line ${index + 1} must use id,url[,priority,rtt_ms,canary].`);
        const priority = parts[2] ? Number(parts[2]) : 0;
        const rtt = parts[3] ? Number(parts[3]) : 0;
        if (!Number.isFinite(priority) || !Number.isFinite(rtt)) throw new Error(`Resolver line ${index + 1} has invalid numeric evidence.`);
        return { id: parts[0], url: parts[1], priority, rtt_ms: rtt, canary_status: parts[4] || 'unknown' };
      });
      if (candidates.length === 0) throw new Error('Enter at least one resolver candidate.');
      setPoolPlan(await controlTransport.json('/api/system/doh-resolver-pool-plan', parseDoHResolverPoolPlan, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ candidates, max_fallbacks: Math.min(8, candidates.length) }),
      }));
    } catch (caught) {
      setPoolError(errorMessage(caught, 'Resolver pool analysis failed.'));
    } finally {
      setPoolBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h2 className="m-0 text-2xl font-display text-text-primary">DNS & Security</h2>
        <p className="mt-1 text-text-secondary">Configure upstream DNS resolvers and return cleanly to DHCP.</p>
      </header>

      {error && <div role="alert" className="rounded-md border border-error/50 bg-error/20 p-4 text-sm text-text-primary">{error}</div>}
      {message && <div role="status" className="rounded-md border border-success/50 bg-success/20 p-4 text-sm text-text-primary">{message}</div>}


      <section className="card space-y-4" aria-labelledby="resolution-policy-title">
        <div className="flex flex-col gap-3 border-b border-border-color pb-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h3 id="resolution-policy-title" className="m-0 flex items-center gap-2 text-lg text-text-primary"><FlaskConical size={18} className="text-purple" aria-hidden="true" /> Resolution policy lab</h3>
            <p className="mb-0 mt-1 max-w-3xl text-xs text-text-muted">Model transport fallback, address-family strategy, cache scope, UDP truncation, secure-downgrade prevention, and EDNS client-subnet privacy before changing the live resolver. This planner never fetches DNS or installs a resolver.</p>
          </div>
          <button type="button" onClick={() => void analyzeResolutionPolicy()} disabled={policyBusy} className="btn btn-secondary px-3 py-1.5">{policyBusy ? 'Analyzing…' : 'Analyze policy'}</button>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
          <label className="text-xs text-text-muted">Primary transport
            <select className="field-input mt-1" value={policyPrimaryKind} onChange={(event) => setPolicyPrimaryKind(event.target.value)}>
              <option value="https">DoH / HTTPS</option><option value="tls">DoT / TLS</option><option value="quic">DoQ / QUIC</option><option value="http3">DoH3 / HTTP3</option><option value="udp">UDP</option><option value="tcp">TCP</option>
            </select>
          </label>
          <label className="text-xs text-text-muted">Fallback transport
            <select className="field-input mt-1" value={policyFallbackKind} onChange={(event) => setPolicyFallbackKind(event.target.value)}>
              <option value="tls">DoT / TLS</option><option value="https">DoH / HTTPS</option><option value="quic">DoQ / QUIC</option><option value="http3">DoH3 / HTTP3</option><option value="tcp">TCP</option><option value="udp">UDP</option>
            </select>
          </label>
          <label className="text-xs text-text-muted">Address strategy
            <select className="field-input mt-1" value={policyStrategy} onChange={(event) => setPolicyStrategy(event.target.value)}>
              <option value="as-is">as requested</option><option value="prefer-ipv4">prefer IPv4</option><option value="prefer-ipv6">prefer IPv6</option><option value="ipv4-only">IPv4 only</option><option value="ipv6-only">IPv6 only</option>
            </select>
          </label>
          <label className="text-xs text-text-muted">Cache scope
            <select className="field-input mt-1" value={policyCacheScope} onChange={(event) => setPolicyCacheScope(event.target.value)}>
              <option value="shared">shared</option><option value="per-transport">per transport</option><option value="disabled">disabled</option>
            </select>
          </label>
          <label className="text-xs text-text-muted">EDNS client subnet
            <input className="field-input mt-1 mono" value={policyECS} onChange={(event) => setPolicyECS(event.target.value)} placeholder="optional: 203.0.113.0/24" />
          </label>
          <label className="flex min-h-11 items-center gap-2 self-end rounded-md border border-border-color px-3 text-xs text-text-secondary"><input type="checkbox" checked={policyRequireSecure} onChange={(event) => setPolicyRequireSecure(event.target.checked)} /> Prevent secure → plaintext fallback</label>
        </div>
        {policyError && <div role="alert" className="rounded-md border border-error/30 bg-error/10 p-3 text-xs text-error"><TriangleAlert size={14} className="mr-2 inline" aria-hidden="true" />{policyError}</div>}
        {policyPlan && (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(20rem,0.8fr)]">
            <div className="overflow-hidden rounded-md border border-border-color">
              {policyPlan.transports.map((transport) => <div key={transport.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 border-b border-border-color/50 p-3 text-xs last:border-b-0"><div><div className="flex items-center gap-2"><strong className="text-text-primary">{transport.id}</strong><span className="mono text-text-muted">{transport.kind}</span>{transport.secure && <span className="inline-flex items-center gap-1 rounded bg-success/10 px-1.5 py-0.5 text-[10px] text-success"><ShieldCheck size={10} /> secure</span>}</div><div className="mt-1 text-text-muted">fallback {transport.fallbackTo || 'none'} · truncation {transport.truncationFallbackTo || 'none'}</div></div><span className={transport.ecsPrivacyImpact ? 'text-warning' : 'text-text-muted'}>{transport.ecsPrivacyImpact ? 'ECS leaks locality' : 'no ECS'}</span></div>)}
            </div>
            <div className="space-y-3 rounded-md border border-border-color bg-bg-primary/50 p-4 text-xs">
              <div><span className="text-text-muted">Primary</span><div className="mono mt-1 font-semibold text-text-primary">{policyPlan.primaryTransport}</div></div>
              <div><span className="text-text-muted">Lookup order</span><div className="mono mt-1 text-text-primary">{policyPlan.lookupFamilies.join(' → ')}</div></div>
              <div><span className="text-text-muted">Cache</span><div className="mono mt-1 text-text-primary">{policyPlan.cacheScope}</div></div>
              {policyPlan.warnings.length > 0 && <ul className="m-0 space-y-1 pl-5 text-warning">{policyPlan.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>}
            </div>
          </div>
        )}
      </section>


      <section className="card space-y-4" aria-labelledby="resolver-pool-title">
        <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-start">
          <div>
            <p className="mono m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Read-only · fallback evidence</p>
            <h3 id="resolver-pool-title" className="m-0 mt-1 text-lg text-text-primary">DoH resolver pool evidence</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Admit credential-free HTTPS resolver evidence, quarantine invalid endpoints, and derive a bounded fallback order from priority, canary and RTT. This planner performs no DNS request and installs no resolver.</p>
          </div>
          <button type="button" className="btn btn-secondary" disabled={poolBusy} onClick={() => void analyzeResolverPool()}>{poolBusy ? 'Analyzing…' : 'Analyze pool'}</button>
        </div>
        <label className="block text-xs text-text-muted">One candidate per line: <span className="mono">id,url[,priority,rtt_ms,canary]</span>
          <textarea value={poolInput} onChange={(event) => setPoolInput(event.target.value)} rows={4} className="mono mt-1 w-full rounded border border-border-color bg-bg-primary px-3 py-2 text-xs text-text-primary" />
        </label>
        {poolError && <div role="alert" className="rounded border border-error/30 bg-error/10 p-3 text-xs text-error">{poolError}</div>}
        {poolPlan && <div className="grid gap-3 lg:grid-cols-3">
          {([['active', poolPlan.active], ['reserve', poolPlan.reserve], ['invalid', poolPlan.invalid]] as const).map(([tier, items]) => <div key={tier} className="rounded border border-border-color bg-bg-primary/50 p-3"><p className="m-0 text-xs font-semibold uppercase tracking-wide text-text-muted">{tier} · {items.length}</p><div className="mt-2 space-y-2">{items.map((item) => <div key={item.id} className="text-xs"><div className="flex justify-between gap-3"><strong className="text-text-primary">{item.id}</strong><span className="mono text-text-muted">{item.rttMs ? `${item.rttMs} ms` : item.canaryStatus}</span></div><div className="mono mt-1 break-all text-[10px] text-text-muted">{item.url}</div>{item.reason && <div className="mt-1 text-warning">{item.reason}</div>}</div>)}</div></div>)}
          <div className="lg:col-span-3 rounded border border-border-color bg-bg-primary/50 p-3 text-xs text-text-muted">Fallback order: <span className="mono text-text-primary">{poolPlan.fallbackOrder.join(' → ') || 'none'}</span> · read-only: {poolPlan.readOnly ? 'yes' : 'no'}</div>
        </div>}
      </section>

      {loading ? (
        <div className="card py-12 text-center text-text-muted">Loading DNS status…</div>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <section className="card space-y-6" aria-labelledby="interface-title">
            <h3 id="interface-title" className="m-0 border-b border-border-color pb-3 text-lg text-text-primary">Active interface</h3>
            <dl className="space-y-4 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-text-secondary">Network adapter</dt>
                <dd className="mono m-0 break-all font-semibold text-text-primary">{dnsConfig.interface}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-text-secondary">Resolver mode</dt>
                <dd className={`m-0 rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wider ${dnsConfig.source === 'manual' ? 'bg-purple/20 text-purple' : 'bg-cyan/20 text-cyan'}`}>{dnsConfig.source}</dd>
              </div>
            </dl>
          </section>

          <section className="card space-y-4 lg:col-span-2" aria-labelledby="resolvers-title">
            <div className="flex flex-col gap-3 border-b border-border-color pb-3 sm:flex-row sm:items-center sm:justify-between">
              <h3 id="resolvers-title" className="m-0 text-lg text-text-primary">Upstream DNS resolvers</h3>
              <div className="flex flex-wrap gap-2">
                <button type="button" disabled={saving} onClick={() => void resetToDHCP()} className="btn btn-secondary px-3 py-1.5" title="Reset to DHCP">
                  <RotateCcw size={14} aria-hidden="true" /> Reset DHCP
                </button>
                <button type="button" disabled={saving} onClick={() => void saveDNSConfig()} className="btn btn-primary px-3 py-1.5">Apply config</button>
              </div>
            </div>

            <div className="grid gap-2 rounded-md border border-border-color bg-bg-primary/40 p-3 sm:grid-cols-[minmax(0,1fr)_auto]">
              <label className="text-xs text-text-muted">Resolver preset
                <select className="field-input mt-1" value={dnsPresetId} onChange={(event) => setDnsPresetId(event.target.value)} disabled={dnsPresets.length === 0}>
                  {dnsPresets.map((preset) => <option key={preset.id} value={preset.id}>{preset.name} · {preset.primary} / {preset.secondary}</option>)}
                </select>
                <span className="mt-1 block text-[11px] text-text-muted">Loads resolver addresses into the draft only. Nothing changes until you choose Apply config.</span>
              </label>
              <button type="button" className="btn btn-secondary self-end px-3 py-2" onClick={loadDNSPreset} disabled={!dnsPresetId}>Load preset</button>
              {dnsPresetError && <div role="alert" className="text-xs text-warning sm:col-span-2">{dnsPresetError}</div>}
            </div>

            <form onSubmit={handleAddServer} className="flex flex-col gap-2 sm:flex-row">
              <label htmlFor="dns-server" className="sr-only">DNS server address</label>
              <input
                id="dns-server"
                type="text"
                inputMode="text"
                placeholder="8.8.8.8 or 2606:4700:4700::1111"
                value={newServer}
                onChange={(event) => setNewServer(event.target.value)}
                className="min-h-11 flex-1 rounded-md border border-border-color bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent"
              />
              <button type="submit" className="btn btn-secondary px-3 py-2"><Plus size={16} aria-hidden="true" /> Add</button>
            </form>

            {dnsConfig.servers.length === 0 ? (
              <div className="rounded-md bg-bg-secondary/20 py-12 text-center text-text-muted">No manual resolvers. The operating system controls DNS.</div>
            ) : (
              <ul className="m-0 list-none space-y-2 p-0">
                {dnsConfig.servers.map((ip) => (
                  <li key={ip} className="flex min-h-11 items-center justify-between rounded border border-border-color bg-bg-secondary px-3 py-2 text-sm">
                    <span className="flex min-w-0 items-center gap-2"><Server size={14} className="shrink-0 text-text-muted" aria-hidden="true" /><span className="mono break-all text-text-primary">{ip}</span></span>
                    <button type="button" onClick={() => handleRemoveServer(ip)} className="min-h-11 min-w-11 border-0 bg-transparent p-2 text-text-muted hover:text-error" aria-label={`Remove DNS server ${ip}`}>
                      <Trash size={14} aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function isIPAddress(value: string): boolean {
  if (value.includes(':')) {
    return /^[0-9a-fA-F:]+$/.test(value) && (value.includes('::') || value.split(':').length === 8);
  }
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}
