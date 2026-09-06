import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { CircleCheck, CircleX, Copy, Download, FlaskConical, Plus, RefreshCw, RotateCw, Trash2, Upload } from 'lucide-react';
import { stampFeedHint } from '../utils/stampFeed';
import { v2raynImportHint } from '../utils/v2raynImport';
import { controlTransport } from '../api/ControlTransport';
import { parseRelayConstraintPlan, type RelayConstraintPlan } from '../api/planners';
import { parseConversionResult, type ConversionResult, type ConversionTarget } from '../api/conversion';
import {
  errorMessage,
  parseSubscriptionProfile,
  parseSubscriptionProfiles,
  parseSubscriptionNodes,
  parseSubscriptionRuntime,
  type SubscriptionNode,
  type SubscriptionProfile,
  type SubscriptionRuntimeStatus,
} from '../api/contracts';

export function Profiles() {
  const [profiles, setProfiles] = useState<SubscriptionProfile[]>([]);
  const [loading, setLoading] = useState(false);
  const [busyID, setBusyID] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [nodesByProfile, setNodesByProfile] = useState<Record<string, SubscriptionNode[]>>({});
  const [subscriptionRuntime, setSubscriptionRuntime] = useState<SubscriptionRuntimeStatus>({ active: false });
  const [profileQuery, setProfileQuery] = useState('');

  const [name, setName] = useState('');
  const [url, setURL] = useState('');
  const [mirrors, setMirrors] = useState('');
  const [interval, setIntervalHours] = useState(6);
  const [remoteFetch, setRemoteFetch] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [deepLink, setDeepLink] = useState('');
  const [deepLinkBusy, setDeepLinkBusy] = useState(false);
  const [conversionInput, setConversionInput] = useState('');
  const [conversionTarget, setConversionTarget] = useState<ConversionTarget>('sing-box');
  const [conversionStrict, setConversionStrict] = useState(true);
  const [conversionBusy, setConversionBusy] = useState(false);
  const [conversionResult, setConversionResult] = useState<ConversionResult | null>(null);
  const [conversionInclude, setConversionInclude] = useState('');
  const [conversionExclude, setConversionExclude] = useState('');
  const [conversionProtocols, setConversionProtocols] = useState('');

  const visibleProfiles = useMemo(() => {
    const query = profileQuery.trim().toLowerCase();
    if (!query) return profiles;
    return profiles.filter((profile) => {
      const profileEvidence = [
        profile.name,
        maskedSubscriptionSource(profile.url),
        ...profile.mirrors.map(maskedSubscriptionSource),
      ].join('\n').toLowerCase();
      if (profileEvidence.includes(query)) return true;
      return (nodesByProfile[profile.id] ?? []).some((node) => [
        node.name,
        node.address,
        node.protocol,
        node.transport,
        node.sni,
      ].filter(Boolean).join('\n').toLowerCase().includes(query));
    });
  }, [nodesByProfile, profileQuery, profiles]);
  const [conversionRenamePattern, setConversionRenamePattern] = useState('');
  const [conversionRenameReplacement, setConversionRenameReplacement] = useState('');
  const [conversionSortBy, setConversionSortBy] = useState<'original' | 'name' | 'protocol' | 'address'>('original');
  const [conversionDeduplicate, setConversionDeduplicate] = useState(false);
  const [conversionLimit, setConversionLimit] = useState(0);

  const loadProfiles = async () => {
    setLoading(true);
    setError(null);
    try {
      setProfiles(await controlTransport.json('/api/subscriptions/profiles', parseSubscriptionProfiles));
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to load subscription profiles.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadProfiles();
  }, []);

  const loadSubscriptionRuntime = async () => {
    try {
      setSubscriptionRuntime(await controlTransport.json('/api/subscriptions/runtime', parseSubscriptionRuntime));
    } catch {
      setSubscriptionRuntime({ active: false });
    }
  };

  useEffect(() => {
    void loadSubscriptionRuntime();
  }, []);

  const loadSubscriptionNodes = async (profileID: string) => {
    setBusyID(profileID); setError(null);
    try {
      const nodes = await controlTransport.json(`/api/subscriptions/profiles/${encodeURIComponent(profileID)}/nodes?include_hidden=true`, parseSubscriptionNodes);
      setNodesByProfile((current) => ({ ...current, [profileID]: nodes }));
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to load materialized subscription nodes.'));
    } finally { setBusyID(null); }
  };

  const setSubscriptionNodeHidden = async (profileID: string, node: SubscriptionNode, hidden: boolean) => {
    setBusyID(profileID); setError(null); setMessage(null);
    try {
      const nodes = await controlTransport.json(`/api/subscriptions/profiles/${encodeURIComponent(profileID)}/nodes/visibility`, parseSubscriptionNodes, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ node_ids: [node.id], hidden }),
      });
      setNodesByProfile((current) => ({ ...current, [profileID]: nodes }));
      setMessage(`${hidden ? 'Hidden' : 'Restored'} node “${node.name || node.address}” locally. The upstream subscription was not modified.`);
    } catch (caught) { setError(errorMessage(caught, 'Failed to change local node visibility.')); } finally { setBusyID(null); }
  };

  const activateSubscriptionNode = async (profileID: string, node: SubscriptionNode) => {
    setBusyID(profileID); setError(null); setMessage(null);
    try {
      const runtime = await controlTransport.json(`/api/subscriptions/profiles/${encodeURIComponent(profileID)}/nodes/${encodeURIComponent(node.id)}/activate`, parseSubscriptionRuntime, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ socks_port: 10808 }),
      });
      setSubscriptionRuntime(runtime);
      setMessage(`Activated “${node.name || node.address}” as a local SOCKS session. This does not change the system proxy.`);
    } catch (caught) { setError(errorMessage(caught, 'Failed to activate subscription node.')); } finally { setBusyID(null); }
  };

  const stopSubscriptionRuntime = async () => {
    const { profileId, nodeId } = subscriptionRuntime;
    if (!subscriptionRuntime.active || !profileId || !nodeId) return;
    setBusyID(profileId); setError(null); setMessage(null);
    try {
      const runtime = await controlTransport.json('/api/subscriptions/runtime/stop', parseSubscriptionRuntime, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ profile_id: profileId, node_id: nodeId }),
      });
      setSubscriptionRuntime(runtime);
      setMessage('Stopped the exact subscription-owned local SOCKS session.');
    } catch (caught) { setError(errorMessage(caught, 'Failed to stop subscription runtime.')); } finally { setBusyID(null); }
  };

  const runConversion = async () => {
    if (!conversionInput.trim() || conversionBusy) return;
    setConversionBusy(true); setError(null); setMessage(null); setConversionResult(null);
    try {
      const include = conversionInclude.split(/\r?\n/).filter((pattern) => pattern.trim().length > 0);
      const exclude = conversionExclude.split(/\r?\n/).filter((pattern) => pattern.trim().length > 0);
      const protocols = conversionProtocols.split(',').map((protocol) => protocol.trim()).filter(Boolean);
      const rename = conversionRenamePattern.trim().length > 0
        ? [{ pattern: conversionRenamePattern, replacement: conversionRenameReplacement }]
        : [];
      const response = await controlTransport.request('/api/subscriptions/convert', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: conversionInput, target: conversionTarget, strict: conversionStrict,
          transform: { include, exclude, protocols, rename, sort_by: conversionSortBy, deduplicate: conversionDeduplicate, limit: conversionLimit },
        }),
      });
      const payload: unknown = await response.json();
      if (response.ok) {
        const converted = parseConversionResult(payload);
        setConversionResult(converted);
        setMessage(`Converted ${converted.report.emittedNodes}/${converted.report.sourceNodes} node${converted.report.sourceNodes === 1 ? '' : 's'} to ${converted.target}.`);
        return;
      }
      if (typeof payload === 'object' && payload !== null && 'result' in payload) {
        const converted = parseConversionResult((payload as { result: unknown }).result);
        setConversionResult(converted);
        const detail = 'error' in payload ? String((payload as { error: unknown }).error) : `conversion rejected (${response.status})`;
        setError(detail);
        return;
      }
      const detail = typeof payload === 'object' && payload !== null && 'error' in payload ? String((payload as { error: unknown }).error) : `conversion failed (${response.status})`;
      throw new Error(detail);
    } catch (caught) {
      setError(errorMessage(caught, 'Profile conversion failed.'));
    } finally {
      setConversionBusy(false);
    }
  };

  const downloadConversion = () => {
    if (!conversionResult) return;
    const extensions: Record<ConversionTarget, string> = { 'uri-list': 'txt', base64: 'txt', 'luminet-json': 'json', 'clash-meta': 'yaml', 'sing-box': 'json' };
    const blob = new Blob([conversionResult.content], { type: conversionResult.mimeType || 'text/plain' });
    const href = URL.createObjectURL(blob); const anchor = document.createElement('a');
    anchor.href = href; anchor.download = `luminet-converted-${conversionResult.target}.${extensions[conversionResult.target]}`; anchor.click(); URL.revokeObjectURL(href);
  };

  const inspectDeepLink = async () => {
    if (!deepLink.trim() || deepLinkBusy) return;
    setDeepLinkBusy(true); setError(null); setMessage(null);
    try {
      const payload: unknown = await controlTransport.json('/api/subscriptions/deeplink/inspect', (value: unknown) => value, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deep_link: deepLink.trim() }),
      });
      if (typeof payload !== 'object' || payload === null || !('proposal' in payload)) throw new Error('Invalid deep-link inspection response.');
      const proposal = (payload as { proposal?: unknown }).proposal;
      if (typeof proposal !== 'object' || proposal === null) throw new Error('Invalid deep-link proposal.');
      const record = proposal as Record<string, unknown>;
      if (typeof record.url !== 'string' || typeof record.name !== 'string') throw new Error('Invalid deep-link proposal fields.');
      setURL(record.url); setName(record.name);
      setMessage('Deep link inspected. Review the proposed profile below, then create it explicitly. No subscription was fetched or activated.');
    } catch (caught) {
      setError(errorMessage(caught, 'Deep-link inspection failed.'));
    } finally { setDeepLinkBusy(false); }
  };

  const createProfile = async () => {
    setBusyID('create');
    setError(null);
    setMessage(null);
    try {
      const mirrorList = mirrors.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
      const created = await controlTransport.json('/api/subscriptions/profiles', parseSubscriptionProfile, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name, url, mirrors: mirrorList, update_interval_hours: interval,
          remote_fetch_enabled: remoteFetch, auto_refresh: autoRefresh,
        }),
      });
      setProfiles((current) => [...current, created].sort((a, b) => a.id.localeCompare(b.id)));
      setName('');
      setURL('');
      setMirrors('');
      setMessage(`Created profile “${created.name}”.`);
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to create profile.'));
    } finally {
      setBusyID(null);
    }
  };

  const patchProfile = async (profile: SubscriptionProfile, patch: Record<string, unknown>, label: string) => {
    setBusyID(profile.id);
    setError(null);
    setMessage(null);
    try {
      const updated = await controlTransport.json(`/api/subscriptions/profiles/${encodeURIComponent(profile.id)}`, parseSubscriptionProfile, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch),
      });
      setProfiles((current) => current.map((item) => item.id === profile.id ? updated : item));
      setMessage(`${label} for “${profile.name}”.`);
    } catch (caught) {
      setError(errorMessage(caught, `Failed to update “${profile.name}”.`));
    } finally {
      setBusyID(null);
    }
  };

  const refreshProfile = async (profile: SubscriptionProfile) => {
    setBusyID(profile.id);
    setError(null);
    setMessage(null);
    try {
      const response = await controlTransport.request(`/api/subscriptions/profiles/${encodeURIComponent(profile.id)}/refresh`, { method: 'POST' });
      if (!response.ok) throw new Error(`refresh failed (${response.status})`);
      setMessage(`Refresh queued for “${profile.name}”.`);
      window.setTimeout(() => void loadProfiles(), 650);
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to queue profile refresh.'));
    } finally {
      setBusyID(null);
    }
  };

  const exportProfiles = () => {
    const payload = profiles.map((profile) => ({
      name: profile.name, url: profile.url, mirrors: profile.mirrors,
      update_interval_hours: profile.updateIntervalHours, remote_fetch_enabled: profile.remoteFetchEnabled,
      auto_refresh: profile.autoRefresh, active: profile.active,
    }));
    const blob = new Blob([JSON.stringify({ schema: 'luminet.subscription-profiles.v1', profiles: payload }, null, 2)], { type: 'application/json' });
    const href = URL.createObjectURL(blob); const anchor = document.createElement('a');
    anchor.href = href; anchor.download = 'luminet-subscription-profiles.json'; anchor.click(); URL.revokeObjectURL(href);
  };

  const importProfiles = async (file: File | undefined) => {
    if (!file) return; setBusyID('import'); setError(null); setMessage(null);
    try {
      if (file.size > 512 * 1024) throw new Error('Profile backup exceeds 512 KiB.');
      const parsed: unknown = JSON.parse(await file.text());
      if (typeof parsed !== 'object' || parsed === null || !('profiles' in parsed) || !Array.isArray((parsed as { profiles?: unknown }).profiles)) throw new Error('Invalid profile backup.');
      const entries = (parsed as { profiles: unknown[] }).profiles; if (entries.length > 64) throw new Error('Profile backup contains more than 64 entries.');
      let imported = 0;
      for (const entry of entries) {
        if (typeof entry !== 'object' || entry === null) continue; const record = entry as Record<string, unknown>;
        if (typeof record.name !== 'string' || typeof record.url !== 'string') continue;
        const created = await controlTransport.json('/api/subscriptions/profiles', parseSubscriptionProfile, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: record.name, url: record.url, mirrors: Array.isArray(record.mirrors) ? record.mirrors.filter((value): value is string => typeof value === 'string').slice(0, 3) : [], update_interval_hours: typeof record.update_interval_hours === 'number' ? record.update_interval_hours : 6, remote_fetch_enabled: record.remote_fetch_enabled !== false, auto_refresh: record.auto_refresh !== false, active: record.active !== false }),
        });
        imported += 1; setProfiles((current) => [...current.filter((item) => item.id !== created.id), created].sort((a, b) => a.id.localeCompare(b.id)));
      }
      setMessage(`Imported ${imported} profile${imported === 1 ? '' : 's'}.`);
    } catch (caught) { setError(errorMessage(caught, 'Failed to import profiles.')); } finally { setBusyID(null); }
  };

  const deleteProfile = async (profile: SubscriptionProfile) => {
    setBusyID(profile.id);
    setError(null);
    setMessage(null);
    try {
      const response = await controlTransport.request(`/api/subscriptions/profiles/${encodeURIComponent(profile.id)}`, { method: 'DELETE' });
      if (!response.ok) throw new Error(`delete failed (${response.status})`);
      setProfiles((current) => current.filter((item) => item.id !== profile.id));
      setMessage(`Deleted profile “${profile.name}”.`);
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to delete profile.'));
    } finally {
      setBusyID(null);
    }
  };

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="mono mb-2 text-xs uppercase tracking-[0.2em] text-accent">Subscription catalog</p>
          <h2 className="mb-2 text-3xl text-text-primary">Profiles & source health</h2>
          <p className="m-0 max-w-3xl text-sm text-text-secondary">Manage primary subscription feeds, fallback mirrors, refresh cadence, and per-source health without editing configuration files.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={exportProfiles} disabled={profiles.length === 0} className="btn btn-secondary"><Download size={16} /> Export</button>
          <label className="btn btn-secondary cursor-pointer"><Upload size={16} /> Import<input type="file" accept="application/json,.json" className="sr-only" onChange={(e) => void importProfiles(e.target.files?.[0])} /></label>
          <button type="button" onClick={() => void loadProfiles()} disabled={loading} className="btn btn-secondary"><RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Refresh</button>
        </div>
      </header>

      {error && <div role="alert" className="rounded-md border border-error/30 bg-error/15 p-3 text-sm text-error">{error}</div>}
      {message && <div role="status" className="rounded-md border border-success/30 bg-success/10 p-3 text-sm text-success">{message}</div>}

      <section className="card space-y-4" aria-labelledby="deeplink-title">
        <h3 id="deeplink-title" className="m-0 border-b border-border-color pb-3 text-lg">One-tap import proposal</h3>
        <p className="m-0 text-sm text-text-secondary">Inspect a bounded <span className="mono">luminet://import</span> link. Inspection is read-only: it never fetches, saves, refreshes, or activates the subscription.</p>
        <div className="flex flex-col gap-2 lg:flex-row">
          <input className="field-input mono flex-1" value={deepLink} onChange={(event) => setDeepLink(event.target.value)} placeholder="luminet://import?url=https%3A%2F%2Fprovider.example%2Fsub&name=Provider" />
          <button type="button" className="btn btn-secondary" disabled={deepLinkBusy || !deepLink.trim()} onClick={() => void inspectDeepLink()}>{deepLinkBusy ? 'Inspecting…' : 'Inspect & prefill'}</button>
        </div>
      </section>

      <section className="card space-y-4" aria-labelledby="new-profile-title">
        <h3 id="new-profile-title" className="m-0 flex items-center gap-2 border-b border-border-color pb-3 text-lg"><Plus size={18} className="text-accent" /> Add managed profile</h3>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Field label="Profile name"><input className="field-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Primary provider" /></Field>
          <Field label="Primary HTTPS subscription URL"><input className="field-input mono" value={url} onChange={(e) => setURL(e.target.value)} placeholder="https://provider.example/subscription" /></Field>
          <Field label="Fallback mirrors (one per line, up to 3)"><textarea className="field-input mono resize-y" rows={4} value={mirrors} onChange={(e) => setMirrors(e.target.value)} placeholder={'https://mirror-a.example/sub\nhttps://mirror-b.example/sub'} /></Field>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="Refresh interval (hours)"><input type="number" min={1} max={720} className="field-input" value={interval} onChange={(e) => setIntervalHours(Number(e.target.value))} /></Field>
            <div className="space-y-2 pt-5">
              <label className="flex min-h-11 items-center gap-2 rounded-md border border-border-color px-3 text-sm text-text-secondary"><input type="checkbox" checked={remoteFetch} onChange={(e) => setRemoteFetch(e.target.checked)} /> Enable remote fetch</label>
              <label className="flex min-h-11 items-center gap-2 rounded-md border border-border-color px-3 text-sm text-text-secondary"><input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} /> Auto refresh</label>
            </div>
          </div>
        </div>
        <button type="button" onClick={() => void createProfile()} disabled={busyID !== null || !name.trim() || !url.trim()} className="btn btn-primary"><Plus size={16} /> Create profile</button>
      </section>

      <section className="card space-y-4" aria-labelledby="compatibility-lab-title">
        <div className="flex flex-col justify-between gap-3 border-b border-border-color pb-3 lg:flex-row lg:items-end">
          <div>
            <h3 id="compatibility-lab-title" className="m-0 flex items-center gap-2 text-lg"><FlaskConical size={18} className="text-purple" /> Compatibility lab</h3>
            <p className="m-0 mt-1 max-w-3xl text-xs text-text-muted">Convert locally supplied subscription/profile content through LumiNet’s canonical model. This action never fetches URLs and never mutates managed profiles. Strict mode refuses unsupported/lossy semantics and also re-ingests the generated output through LumiNet’s canonical parser; round-trip drift rejects the conversion instead of silently declaring compatibility.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <label className="text-xs text-text-muted">Target
              <select className="field-input mt-1 min-w-44" value={conversionTarget} onChange={(event) => setConversionTarget(event.target.value as ConversionTarget)}>
                <option value="sing-box">sing-box JSON</option>
                <option value="clash-meta">Clash Meta YAML</option>
                <option value="base64">Base64 subscription</option>
                <option value="uri-list">URI list</option>
                <option value="luminet-json">LumiNet canonical JSON</option>
              </select>
            </label>
            <label className="flex min-h-11 items-center gap-2 self-end rounded-md border border-border-color px-3 text-xs text-text-secondary">
              <input type="checkbox" checked={conversionStrict} onChange={(event) => setConversionStrict(event.target.checked)} /> Strict compatibility
            </label>
          </div>
        </div>

        <label className="block text-xs text-text-muted">Local subscription / profile content
          <textarea className="field-input mono mt-1 min-h-40 resize-y" value={conversionInput} onChange={(event) => setConversionInput(event.target.value)} placeholder="Paste URI list, Base64 subscription, Clash YAML, or sing-box JSON…" spellCheck={false} />
            {stampFeedHint(conversionInput) && (
            <span className="mt-1 block text-amber-500">
              {stampFeedHint(conversionInput)}
            </span>
          )}
          {v2raynImportHint(conversionInput) && (
            <span className="mt-1 block text-sky-500">
              {v2raynImportHint(conversionInput)}
            </span>
          )}
          </label>
        <details className="rounded-md border border-border-color bg-bg-secondary/35 p-3">
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-text-secondary">Local shaping pipeline</summary>
          <p className="mb-3 mt-2 text-xs text-text-muted">Bounded RE2-style regex filtering/rename, protocol allowlisting, semantic de-duplication, sorting, and limiting. Shaping is local-only; scripts, remote includes, and filesystem access are intentionally unavailable. Detour chains fail closed if a filter or limit would orphan a hop.</p>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <Field label="Include name regexes (one per line)"><textarea className="field-input mono resize-y" rows={3} value={conversionInclude} onChange={(event) => setConversionInclude(event.target.value)} placeholder={'^US \n^JP '} spellCheck={false} /></Field>
            <Field label="Exclude name regexes (one per line)"><textarea className="field-input mono resize-y" rows={3} value={conversionExclude} onChange={(event) => setConversionExclude(event.target.value)} placeholder={'expired\ntraffic'} spellCheck={false} /></Field>
            <Field label="Protocol allowlist (comma-separated)"><input className="field-input mono" value={conversionProtocols} onChange={(event) => setConversionProtocols(event.target.value)} placeholder="vless, vmess, hysteria2" /></Field>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2"><Field label="Rename regex"><input className="field-input mono" value={conversionRenamePattern} onChange={(event) => setConversionRenamePattern(event.target.value)} placeholder="^US " /></Field><Field label="Replacement"><input className="field-input mono" value={conversionRenameReplacement} onChange={(event) => setConversionRenameReplacement(event.target.value)} placeholder="US · " /></Field></div>
            <Field label="Sort"><select className="field-input" value={conversionSortBy} onChange={(event) => setConversionSortBy(event.target.value as typeof conversionSortBy)}><option value="original">Original order</option><option value="name">Name</option><option value="protocol">Protocol</option><option value="address">Address</option></select></Field>
            <Field label="Node limit (0 = no extra limit)"><input type="number" min={0} max={4096} className="field-input" value={conversionLimit} onChange={(event) => setConversionLimit(Math.max(0, Math.min(4096, Number(event.target.value) || 0)))} /></Field>
          </div>
          <label className="mt-3 flex min-h-11 items-center gap-2 rounded-md border border-border-color px-3 text-xs text-text-secondary"><input type="checkbox" checked={conversionDeduplicate} onChange={(event) => setConversionDeduplicate(event.target.checked)} /> Deduplicate standalone nodes by canonical semantics (detour-bearing nodes are never collapsed)</label>
        </details>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn btn-primary" disabled={conversionBusy || !conversionInput.trim()} onClick={() => void runConversion()}><FlaskConical size={15} className={conversionBusy ? 'animate-pulse' : ''} /> Analyze & convert</button>
          {conversionResult && <button type="button" className="btn btn-secondary" onClick={() => void navigator.clipboard.writeText(conversionResult.content)}><Copy size={15} /> Copy output</button>}
          {conversionResult && <button type="button" className="btn btn-secondary" onClick={downloadConversion}><Download size={15} /> Download output</button>}
        </div>

        {conversionResult && (
          <div className="space-y-4 rounded-md border border-border-color bg-bg-secondary/45 p-4">
            {conversionResult.transformation && <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
              <Metric label="Shaped in" value={String(conversionResult.transformation.inputNodes)} />
              <Metric label="Shaped out" value={String(conversionResult.transformation.outputNodes)} />
              <Metric label="Filtered" value={String(conversionResult.transformation.filtered)} />
              <Metric label="Renamed" value={String(conversionResult.transformation.renamed)} />
              <Metric label="Deduped" value={String(conversionResult.transformation.deduplicated)} />
              <Metric label="Truncated" value={String(conversionResult.transformation.truncated)} />
            </div>}
            <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
              <Metric label="Source" value={String(conversionResult.report.sourceNodes)} />
              <Metric label="Emitted" value={String(conversionResult.report.emittedNodes)} />
              <Metric label="Unsupported" value={String(conversionResult.report.unsupported)} />
              <Metric label="Lossy" value={String(conversionResult.report.lossy)} />
              <Metric label="Warnings" value={String(conversionResult.report.warnings)} />
            </div>
            {conversionResult.roundTrip && (
              <div className={`rounded-md border p-3 ${conversionResult.roundTrip.compatible ? 'border-success/30 bg-success/10' : 'border-error/30 bg-error/10'}`}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-semibold uppercase tracking-wide">Local re-ingest proof · {conversionResult.roundTrip.compatible ? 'compatible' : 'drift detected'}</div>
                  <div className="text-xs text-text-muted">No network fetch or runtime execution</div>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-6">
                  <Metric label="Reparsed" value={`${conversionResult.roundTrip.reparsedNodes}/${conversionResult.roundTrip.sourceNodes}`} />
                  <Metric label="Exact" value={String(conversionResult.roundTrip.exactNodes)} />
                  <Metric label="Changed" value={String(conversionResult.roundTrip.changedNodes)} />
                  <Metric label="Missing" value={String(conversionResult.roundTrip.missingNodes)} />
                  <Metric label="Extra" value={String(conversionResult.roundTrip.extraNodes)} />
                  <Metric label="Parser" value={conversionResult.roundTrip.parserError ? 'error' : 'ok'} />
                </div>
                {conversionResult.roundTrip.parserError && <div className="mono mt-3 rounded border border-error/30 bg-error/10 p-2 text-xs text-error">{conversionResult.roundTrip.parserError}</div>}
                {conversionResult.roundTrip.issues.length > 0 && <div className="mt-3 max-h-48 space-y-2 overflow-y-auto pr-1">
                  {conversionResult.roundTrip.issues.slice(0, 100).map((issue, index) => <div key={`${issue.index}-${issue.code}-${index}`} className="rounded border border-border-color p-2 text-xs text-text-secondary"><span className="mono font-semibold">#{issue.index} {issue.code}</span><div className="mt-1">{issue.message}</div></div>)}
                </div>}
              </div>
            )}
            {conversionResult.report.issues.length > 0 && (
              <div>
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Compatibility evidence · first {Math.min(100, conversionResult.report.issues.length)} of {conversionResult.report.issues.length}</div>
                <div className="max-h-64 space-y-2 overflow-y-auto pr-1">
                  {conversionResult.report.issues.slice(0, 100).map((issue, index) => (
                    <div key={`${issue.index}-${issue.code}-${index}`} className={`rounded border p-2 text-xs ${issue.severity === 'unsupported' ? 'border-error/25 bg-error/10 text-error' : issue.severity === 'lossy' ? 'border-warning/25 bg-warning/10 text-warning' : 'border-border-color text-text-secondary'}`}>
                      <span className="mono font-semibold">#{issue.index} {issue.protocol || 'unknown'} {issue.name ? `· ${issue.name}` : ''}</span>
                      <span className="mono ml-2 opacity-75">{issue.code}</span>
                      <div className="mt-1">{issue.message}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <label className="block text-xs text-text-muted">Generated {conversionResult.target} output
              <textarea className="field-input mono mt-1 min-h-56 resize-y" readOnly value={conversionResult.content} spellCheck={false} />
            </label>
          </div>
        )}
      </section>

      <RelayConstraintPlanner />

      <section className="space-y-4" aria-label="Managed subscription profiles">
        <div className="card flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <Field label="Search profiles or loaded nodes">
            <input
              className="field-input min-w-72"
              value={profileQuery}
              onChange={(event) => setProfileQuery(event.target.value)}
              placeholder="name, source host, mirror, node, protocol, SNI…"
              autoComplete="off"
            />
          </Field>
          <div className="text-xs text-text-muted">Showing {visibleProfiles.length} of {profiles.length} managed profiles · local filter only, no source fetch.</div>
        </div>
        {profiles.length === 0 && !loading ? <div className="card text-sm text-text-muted">No managed subscription profiles yet.</div> : null}
        {profiles.length > 0 && visibleProfiles.length === 0 ? <div className="card text-sm text-text-muted">No profiles or already-loaded nodes match this local search.</div> : null}
        {visibleProfiles.map((profile) => (
          <article key={profile.id} className="card space-y-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2"><h3 className="m-0 text-lg">{profile.name}</h3><StatusPill enabled={profile.active} on="active" off="inactive" /><StatusPill enabled={profile.remoteFetchEnabled} on="remote" off="local only" /><StatusPill enabled={profile.autoRefresh} on="auto refresh" off="manual refresh" /><EntitlementPill status={profile.entitlement.status} /></div>
                <div className="mono mt-2 break-all text-xs text-text-secondary">{maskedSubscriptionSource(profile.url)}</div>
              </div>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="btn btn-secondary" disabled={busyID !== null || !profile.remoteFetchEnabled} onClick={() => void refreshProfile(profile)}><RotateCw size={15} className={busyID === profile.id ? 'animate-spin' : ''} /> Refresh now</button>
                <button type="button" className="btn btn-secondary" disabled={busyID !== null} onClick={() => void patchProfile(profile, { auto_refresh: !profile.autoRefresh }, profile.autoRefresh ? 'Disabled auto refresh' : 'Enabled auto refresh')}>{profile.autoRefresh ? 'Manual refresh' : 'Auto refresh'}</button>
                <button type="button" className="btn btn-secondary" disabled={busyID !== null} onClick={() => void patchProfile(profile, { active: !profile.active }, profile.active ? 'Paused profile' : 'Activated profile')}>{profile.active ? 'Pause' : 'Activate'}</button>
                <button type="button" className="btn btn-secondary text-error" disabled={busyID !== null} onClick={() => void deleteProfile(profile)}><Trash2 size={15} /> Delete</button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Metric label="Nodes" value={String(profile.nodeCount)} />
              <Metric label="Interval" value={`${profile.updateIntervalHours} h`} />
              <Metric label="Failures" value={String(profile.sourceHealth.consecutiveFailures)} />
              <Metric label="Mirrors" value={String(profile.mirrors.length)} />
            </div>

            <div className="rounded-md border border-border-color bg-bg-secondary/35 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-text-muted">Materialized nodes</div>
                  <div className="mt-1 max-w-3xl text-xs text-text-secondary">Local visibility never edits the upstream subscription. Activation starts one explicit loopback SOCKS session and does not change the system proxy. Node credentials never cross this API.</div>
                </div>
                <button type="button" className="btn btn-secondary" disabled={busyID !== null || profile.nodeCount === 0} onClick={() => void loadSubscriptionNodes(profile.id)}>Manage nodes</button>
              </div>
              {subscriptionRuntime.active && subscriptionRuntime.profileId === profile.id && (
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded border border-success/30 bg-success/10 p-3 text-xs">
                  <span>Local SOCKS active · node <span className="mono">{subscriptionRuntime.nodeId}</span> · 127.0.0.1:{subscriptionRuntime.socksPort ?? 10808}</span>
                  <button type="button" className="btn btn-secondary" disabled={busyID !== null} onClick={() => void stopSubscriptionRuntime()}>Stop exact runtime</button>
                </div>
              )}
              {(nodesByProfile[profile.id] ?? []).length > 0 && (
                <div className="mt-3 max-h-80 space-y-2 overflow-y-auto pr-1">
                  {(nodesByProfile[profile.id] ?? []).map((node) => {
                    const isActive = subscriptionRuntime.active && subscriptionRuntime.profileId === profile.id && subscriptionRuntime.nodeId === node.id;
                    return <div key={node.id} className={`rounded border p-3 text-xs ${node.hidden ? 'border-border-color opacity-65' : isActive ? 'border-success/40 bg-success/5' : 'border-border-color'}`}>
                      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2"><span className="font-semibold text-text-primary">{node.name || node.address}</span><span className="mono text-[10px] uppercase text-text-muted">{node.protocol}</span>{node.hidden && <span className="text-[10px] uppercase text-warning">hidden locally</span>}{isActive && <span className="text-[10px] uppercase text-success">active</span>}{!node.runtimeActivatable && <span className="text-[10px] uppercase text-warning">planning/import only</span>}</div>
                          <div className="mono mt-1 truncate text-text-muted">{node.address}:{node.port}{node.transport ? ` · ${node.transport}` : ''}{node.tls ? ' · TLS' : ''}{node.sni ? ` · SNI ${node.sni}` : ''}</div>
                          {node.runtimeActivatable ? <div className="mt-1 text-[10px] text-text-muted">External-core candidates: {node.runtimeCores.join(', ') || 'none detected'}</div> : <div className="mt-1 max-w-2xl text-[10px] text-warning">{node.runtimeReason || 'No maintained external core can represent this node without semantic loss.'}</div>}
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <button type="button" className="btn btn-secondary" disabled={busyID !== null || isActive} onClick={() => void setSubscriptionNodeHidden(profile.id, node, !node.hidden)}>{node.hidden ? 'Restore' : 'Hide locally'}</button>
                          <button type="button" className="btn btn-primary" disabled={busyID !== null || node.hidden || subscriptionRuntime.active || !node.runtimeActivatable} onClick={() => void activateSubscriptionNode(profile.id, node)}>Activate SOCKS</button>
                        </div>
                      </div>
                    </div>;
                  })}
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div className="rounded-md border border-border-color bg-bg-secondary/45 p-4">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Source route</div>
                <div className="space-y-2 text-xs"><SourceLine label="Primary" url={profile.url} active={profile.lastSourceUrl === profile.url} health={profile.sourceHealthByUrl[profile.url]} />{profile.mirrors.map((mirror, index) => <SourceLine key={mirror} label={`Mirror ${index + 1}`} url={mirror} active={profile.lastSourceUrl === mirror} health={profile.sourceHealthByUrl[mirror]} />)}</div>
              </div>
              <div className="rounded-md border border-border-color bg-bg-secondary/45 p-4">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Health evidence</div>
                <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2"><Data label="Last attempt" value={profile.sourceHealth.lastAttemptAt ? new Date(profile.sourceHealth.lastAttemptAt).toLocaleString() : '—'} /><Data label="Last success" value={profile.sourceHealth.lastSuccessAt ? new Date(profile.sourceHealth.lastSuccessAt).toLocaleString() : '—'} /><Data label="Next eligible" value={profile.sourceHealth.nextEligibleAt ? new Date(profile.sourceHealth.nextEligibleAt).toLocaleString() : '—'} /><Data label="Last updated" value={profile.lastUpdated ? new Date(profile.lastUpdated).toLocaleString() : '—'} /></dl>
                {profile.sourceHealth.failureKind && <SourceFailureGuidance kind={profile.sourceHealth.failureKind} />}
                {profile.sourceHealth.lastError && <div className="mt-3 rounded border border-warning/30 bg-warning/10 p-2 text-xs text-warning">{profile.sourceHealth.lastError}</div>}
              </div>
            </div>

            <EntitlementSummary entitlement={profile.entitlement} />
            {profile.subscriptionInfo && <ProviderInfo info={profile.subscriptionInfo} />}
          </article>
        ))}
      </section>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="block text-xs text-text-muted"><span className="mb-1 block">{label}</span>{children}</label>; }
function Metric({ label, value }: { label: string; value: string }) { return <div className="rounded-md border border-border-color bg-bg-secondary/45 p-3"><div className="mono text-xl font-semibold text-text-primary">{value}</div><div className="text-[10px] uppercase tracking-wide text-text-muted">{label}</div></div>; }
function Data({ label, value }: { label: string; value: string }) { return <div><dt className="text-text-muted">{label}</dt><dd className="m-0 mt-1 text-text-primary">{value}</dd></div>; }
function StatusPill({ enabled, on, off }: { enabled: boolean; on: string; off: string }) { return <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-semibold uppercase ${enabled ? 'border-success/30 bg-success/10 text-success' : 'border-border-color text-text-muted'}`}>{enabled ? <CircleCheck size={11} /> : <CircleX size={11} />}{enabled ? on : off}</span>; }
function EntitlementPill({ status }: { status: SubscriptionProfile['entitlement']['status'] }) {
  const tone = status === 'expired' || status === 'exhausted'
    ? 'border-error/30 bg-error/10 text-error'
    : status === 'warning'
      ? 'border-warning/30 bg-warning/10 text-warning'
      : status === 'active'
        ? 'border-success/30 bg-success/10 text-success'
        : 'border-border-color text-text-muted';
  return <span className={`inline-flex items-center rounded-full border px-2 py-1 text-[10px] font-semibold uppercase ${tone}`}>entitlement {status}</span>;
}
function EntitlementSummary({ entitlement }: { entitlement: SubscriptionProfile['entitlement'] }) {
  const warningLabels: Record<string, string> = {
    quota_exhausted: 'Provider-reported quota is exhausted.',
    quota_low: 'Provider-reported quota is below 10%.',
    expired: 'Provider-reported subscription expiry has passed.',
    expires_soon: 'Provider-reported subscription expires within 72 hours.',
  };
  return <div className="rounded-md border border-border-color bg-bg-secondary/45 p-4">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <div>
        <div className="text-xs font-semibold uppercase tracking-wide text-text-muted">Entitlement evidence</div>
        <div className="mt-1 text-xs text-text-secondary">Advisory provider metadata only; it does not grant, revoke, or meter connectivity.</div>
      </div>
      <EntitlementPill status={entitlement.status} />
    </div>
    <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
      <Data label="Used" value={entitlement.quotaKnown ? formatBytes(entitlement.usedBytes) : 'Unknown'} />
      <Data label="Remaining" value={entitlement.quotaKnown ? formatBytes(entitlement.remainingBytes) : 'Unknown'} />
      <Data label="Usage" value={entitlement.quotaKnown ? `${entitlement.usagePercent.toFixed(1)}%` : 'Unknown'} />
      <Data label="Expiry" value={entitlement.expiryKnown ? formatRelativeSeconds(entitlement.secondsUntilExpiry, entitlement.status === 'expired' ? 'Expired' : 'Now') : 'Unknown'} />
    </dl>
    {entitlement.secondsUntilRefill !== undefined && entitlement.secondsUntilRefill > 0 && <div className="mt-3 text-xs text-text-secondary">Provider-reported refill in {formatRelativeSeconds(entitlement.secondsUntilRefill, 'Now')}.</div>}
    {entitlement.warnings.length > 0 && <ul className="m-0 mt-3 space-y-1 pl-5 text-xs text-warning">{entitlement.warnings.map((warning) => <li key={warning}>{warningLabels[warning] ?? warning.replaceAll('_', ' ')}</li>)}</ul>}
  </div>;
}
function SourceLine({ label, url, active, health }: { label: string; url: string; active: boolean; health: SubscriptionProfile['sourceHealth'] | undefined }) {
  return <div className={`rounded border p-2 ${active ? 'border-success/30 bg-success/10' : 'border-border-color'}`}>
    <div className="flex items-center justify-between gap-2"><span className="font-semibold text-text-primary">{label}</span><div className="flex items-center gap-2">{health && <span className={`text-[10px] uppercase ${health.consecutiveFailures > 0 ? 'text-warning' : 'text-text-muted'}`}>{health.consecutiveFailures} fail</span>}{active && <span className="text-[10px] uppercase text-success">last good</span>}</div></div>
    <div className="mono mt-1 break-all text-text-muted">{maskedSubscriptionSource(url)}</div>
    {health?.failureKind && <div className="mt-1 text-[10px] font-semibold text-warning">{sourceFailureLabel(health.failureKind)}</div>}
    {health?.lastError && <div className="mt-1 truncate text-[10px] text-warning" title={health.lastError}>{health.lastError}</div>}
  </div>;
}

function sourceFailureLabel(kind: NonNullable<SubscriptionProfile['sourceHealth']['failureKind']>) {
  switch (kind) {
    case 'certificate_verification': return 'Certificate verification failed';
    case 'path_interference_suspected': return 'TLS path interference suspected';
    case 'timeout': return 'Subscription endpoint timed out';
    case 'canceled': return 'Refresh canceled';
    case 'network_failure': return 'Network fetch failed';
  }
}

function SourceFailureGuidance({ kind }: { kind: NonNullable<SubscriptionProfile['sourceHealth']['failureKind']> }) {
  const detail = kind === 'certificate_verification'
    ? 'Check the provider hostname/certificate and local trust store. TLS certificate verification remains enforced.'
    : kind === 'path_interference_suspected'
      ? 'The HTTPS path may be intercepted or rewritten. Try a different network or tunnel path; TLS verification was not disabled.'
      : kind === 'timeout'
        ? 'The subscription endpoint did not answer within the bounded refresh window.'
        : kind === 'canceled'
          ? 'The refresh was canceled before a source result was accepted.'
          : 'The subscription source could not be reached. Check connectivity and retry when the source is eligible.';
  return <div className="mt-3 rounded border border-warning/30 bg-warning/10 p-2 text-xs text-warning"><div className="font-semibold">{sourceFailureLabel(kind)}</div><div className="mt-1 text-text-secondary">{detail}</div></div>;
}

function maskedSubscriptionSource(raw: string) {
  try {
    const parsed = new URL(raw);
    const port = parsed.port ? `:${parsed.port}` : '';
    return `${parsed.protocol}//${parsed.hostname}${port}/…`;
  } catch {
    return 'subscription source (masked)';
  }
}

function ProviderInfo({ info }: { info: NonNullable<SubscriptionProfile['subscriptionInfo']> }) {
  const used = Math.max(0, info.upload + info.download);
  const utilization = info.total > 0 ? Math.min(100, (used / info.total) * 100) : 0;
  return <div className="rounded-md border border-border-color bg-bg-secondary/45 p-4">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><div><div className="text-xs font-semibold uppercase tracking-wide text-text-muted">Provider metadata</div>{info.profileTitle && <div className="mt-1 text-sm font-semibold text-text-primary">{info.profileTitle}</div>}</div><div className="flex gap-2">{info.webPageUrl && <button type="button" className="btn btn-secondary" onClick={() => openProviderLink(info.webPageUrl!)}>Provider</button>}{info.supportUrl && <button type="button" className="btn btn-secondary" onClick={() => openProviderLink(info.supportUrl!)}>Support</button>}</div></div>
    {info.total > 0 && <div className="space-y-2"><div className="flex justify-between text-xs text-text-secondary"><span>{formatBytes(used)} used</span><span>{formatBytes(info.total)} total</span></div><div className="h-2 overflow-hidden rounded-full bg-bg-primary"><div className="h-full bg-accent" style={{ width: `${utilization.toFixed(2)}%` }} /></div></div>}
    <dl className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-3"><Data label="Upload" value={formatBytes(info.upload)} /><Data label="Download" value={formatBytes(info.download)} /><Data label="Expires" value={info.expire ? new Date(info.expire).toLocaleString() : '—'} /></dl>
    {info.announcement && <div className="mt-3 rounded border border-accent/20 bg-accent/5 p-3 text-xs text-text-secondary">{info.announcement}</div>}
  </div>;
}

function openProviderLink(raw: string) {
  try {
    const target = new URL(raw);
    if (!['http:', 'https:'].includes(target.protocol)) throw new Error('unsupported URL scheme');
    if (window.confirm(`Open external provider link?\n\n${target.toString()}`)) {
      window.open(target.toString(), '_blank', 'noopener,noreferrer');
    }
  } catch {
    window.alert('Provider link is not a valid HTTP(S) URL.');
  }
}

function formatRelativeSeconds(seconds: number | undefined, fallback: string) {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) return fallback;
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
  return `${amount >= 10 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
}

function RelayConstraintPlanner() {
  const [mode, setMode] = useState('autohop');
  const [plan, setPlan] = useState<RelayConstraintPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    try {
      setPlan(await controlTransport.json('/api/system/relay-constraint-plan', parseRelayConstraintPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ mode, entry:{ ownership:'owned', ip_version:'4', obfuscation:'quic' }, exit:{ country:'us', ip_version:'4' }, candidates:[{id:'se-entry',country:'se',city:'sto',provider:'provider-a',owned:true,active:true,ip_versions:['4','6'],ports:[443,51820],features:['daita'],obfuscation:['quic','udp2tcp']},{id:'us-exit',country:'us',city:'nyc',provider:'provider-b',owned:false,active:true,ip_versions:['4'],ports:[51820],features:[],obfuscation:[]},{id:'us-owned',country:'us',city:'nyc',provider:'provider-a',owned:true,active:true,ip_versions:['4'],ports:[443],features:[],obfuscation:['quic']}] }) }));
    } catch (caught) { setError(errorMessage(caught,'Relay constraint planning failed.')); }
  }
  return <section className="card space-y-3" aria-labelledby="relay-constraint-title"><div><p className="m-0 text-[10px] uppercase tracking-[0.14em] text-cyan">Eligibility only · endpoint scorer remains authoritative</p><h3 id="relay-constraint-title" className="m-0 mt-1 text-lg text-text-primary">Relay, multihop & obfuscation constraints</h3><p className="m-0 mt-1 text-xs text-text-muted">Filter caller-supplied relay metadata by location, provider, ownership, activity, IP family, port, feature, and obfuscation compatibility. Multihop never reuses the same relay identity; no latency probe or tunnel launch occurs here.</p></div><div className="flex flex-wrap items-end gap-3"><label className="text-xs text-text-muted">Path mode<select className="field-input mt-1" value={mode} onChange={(e)=>setMode(e.target.value)}><option value="singlehop">Singlehop</option><option value="multihop">Multihop</option><option value="autohop">Autohop</option></select></label><button type="button" className="btn btn-secondary" onClick={()=>void analyze()}>Filter sample relays</button></div>{error && <p role="alert" className="m-0 text-xs text-error">{error}</p>}{plan && <div className="space-y-1 rounded border border-border-color bg-bg-secondary/40 p-3 text-xs text-text-muted"><p className="m-0"><strong className="text-text-primary">{plan.mode}</strong> · entry {plan.suggestedEntry||'—'} · exit {plan.suggestedExit||'—'} · autohop multihop {plan.autohopUsesMultihop?'yes':'no'}</p><p className="m-0">eligible entry {plan.eligibleEntry.join(', ')||'none'} · eligible exit {plan.eligibleExit.join(', ')||'none'}</p><p className="m-0">endpoint scoring still required {plan.requiresEndpointScoring?'yes':'no'} · network I/O {plan.performsNetworkIO?'yes':'no'} · installs tunnel {plan.installsTunnel?'yes':'no'}</p></div>}</section>;
}
