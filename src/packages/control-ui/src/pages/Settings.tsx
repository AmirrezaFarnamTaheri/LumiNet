import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Play, RefreshCw, Key, ShieldAlert, Cloud, Monitor, Moon, Sun, Copy, Download } from 'lucide-react';
import { controlTransport } from '../api/ControlTransport';
import { useAppearance } from '../hooks/useAppearance';
import {
  errorMessage,
  parseEvasionSettings,
  parseWarpParams,
  parseWarpScanResults,
  type WarpParams,
  type WarpScanResult,
} from '../api/contracts';
import { parseBrowserProxyHandoffPlan, parseTailnetTransactionPlan, parseUpdateRolloutPlan, type BrowserProxyHandoffPlan, type TailnetTransactionPlan, type UpdateRolloutPlan } from '../api/planners';

const DEFAULT_WORKER_SCRIPT = `// Generic Cloudflare Worker upload template.
// This template is intentionally not presented as a VLESS implementation.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response("OK", { status: 200 });
    }
    return new Response("LumiNet custom Worker online", { status: 200 });
  }
};`;

export function Settings() {
  const [appearance, setAppearance] = useAppearance();
  // Evasion settings state
  const [evasionEnabled, setEvasionEnabled] = useState(false);
  const [splitBytes, setSplitBytes] = useState(2);
  const [delayMs, setDelayMs] = useState(10);
  const [mutateHost, setMutateHost] = useState(false);
  const [fakePacketInject, setFakePacketInject] = useState(false);
  const [wsUseUtls, setWsUseUtls] = useState(false);
  const [wsFingerprint, setWsFingerprint] = useState('firefox');
  const [savingEvasion, setSavingEvasion] = useState(false);

  // Cloudflare Workers deployer state
  const [cfEmail, setCfEmail] = useState('');
  const [cfToken, setCfToken] = useState('');
  const [cfAccountId, setCfAccountId] = useState('');
  const [cfWorkerName, setCfWorkerName] = useState('luminet-vless-node');
  const [cfScriptBody, setCfScriptBody] = useState(DEFAULT_WORKER_SCRIPT);
  const [deployingWorker, setDeployingWorker] = useState(false);

  // Warp register state
  const [warpParams, setWarpParams] = useState<WarpParams | null>(null);
  const [registeringWarp, setRegisteringWarp] = useState(false);
  const [warpPrivateKeyVisible, setWarpPrivateKeyVisible] = useState(false);

  // Warp scan state
  const [scanResults, setScanResults] = useState<WarpScanResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanCount, setScanCount] = useState(30);
  const bestWarpEndpoint = scanResults[0] ?? null;
  const warpMedianRTT = scanResults.length > 0 ? scanResults[Math.floor(scanResults.length / 2)]?.rttMilliseconds ?? 0 : 0;

  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchEvasionStatus();
  }, []);

  const fetchEvasionStatus = async () => {
    try {
      const data = await controlTransport.json('/api/system/evasion-tunnel', parseEvasionSettings);
      setEvasionEnabled(data.running);
      setSplitBytes(data.splitBytes);
      setDelayMs(data.delayMs);
      setMutateHost(data.mutateHost);
      setFakePacketInject(data.fakePacketInject);
      setWsUseUtls(data.wsUseUtls);
      setWsFingerprint(data.wsFingerprint || 'firefox');
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to load evasion settings.'));
    }
  };

  const applyEvasionSettings = async () => {
    setSavingEvasion(true);
    setError(null);
    setMessage(null);
    try {
      const res = await controlTransport.request('/api/system/evasion-tunnel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: evasionEnabled,
          split_bytes: splitBytes,
          delay_ms: delayMs,
          mutate_host: mutateHost,
          fake_packet_inject: fakePacketInject,
          ws_use_utls: wsUseUtls,
          ws_fingerprint: wsFingerprint,
        }),
      });
      if (res.ok) {
        setMessage('Evasion and uTLS parameters successfully updated.');
      } else {
        throw new Error('Failed to update evasion tunnel configuration');
      }
    } catch (caught) {
      setError(errorMessage(caught, 'Error saving evasion settings.'));
    } finally {
      setSavingEvasion(false);
    }
  };

  const deployWorkersScript = async () => {
    setDeployingWorker(true);
    setError(null);
    setMessage(null);
    try {
      const res = await controlTransport.request('/api/system/cloudflare-deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: cfEmail,
          token: cfToken,
          account_id: cfAccountId,
          name: cfWorkerName,
          script: cfScriptBody,
        }),
      });
      if (!res.ok) {
        throw new Error(`Cloudflare Worker deployment failed with status ${res.status}`);
      }
      setMessage('Cloudflare accepted the Worker script upload. This action does not verify VLESS or other runtime protocol behavior.');
    } catch (caught) {
      setError(errorMessage(caught, 'Error deploying Workers script.'));
    } finally {
      setDeployingWorker(false);
    }
  };

  const registerWarpAccount = async () => {
    setRegisteringWarp(true);
    setError(null);
    setMessage(null);
    try {
      const profile = await controlTransport.json(
        '/api/system/warp-register',
        parseWarpParams,
        { method: 'POST' },
      );
      setWarpPrivateKeyVisible(false);
      setWarpParams(profile);
      setMessage('Successfully registered a new Cloudflare WARP account profile.');
    } catch (caught) {
      setError(errorMessage(caught, 'Error occurred during registration.'));
    } finally {
      setRegisteringWarp(false);
    }
  };

  const runWarpIPScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const cleanResults = await controlTransport.json(
        '/api/system/warp-scan',
        parseWarpScanResults,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            count: scanCount,
            concurrency: 15,
            timeout_ms: 1000,
          }),
        },
      );
      setScanResults(cleanResults);
    } catch (caught) {
      setError(errorMessage(caught, 'Failed to scan WARP endpoints.'));
    } finally {
      setScanning(false);
    }
  };

  const copyBestWarpEndpoint = async () => {
    if (!bestWarpEndpoint) return;
    try {
      await navigator.clipboard.writeText(bestWarpEndpoint.endpoint);
      setMessage(`Copied best observed WARP endpoint: ${bestWarpEndpoint.endpoint}`);
    } catch (caught) {
      setError(errorMessage(caught, 'Could not copy the WARP endpoint.'));
    }
  };

  const exportWarpScanEvidence = () => {
    if (scanResults.length === 0) return;
    const payload = JSON.stringify({
      generated_at: new Date().toISOString(),
      authority: 'observed scan evidence only; does not modify active WARP configuration',
      results: scanResults.map((row, rank) => ({ rank: rank + 1, endpoint: row.endpoint, rtt_ms: Number(row.rttMilliseconds.toFixed(3)) })),
    }, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'luminet-warp-scan-evidence.json';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-2xl text-text-primary m-0 font-display">System Settings</h2>
        <p className="text-text-secondary mt-1">Configure evasion engines, Cloudflare Warp profiles, and scan parameters.</p>
      </header>

      {error && (
        <div role="alert" aria-live="assertive" className="p-4 bg-error/20 border border-error/50 text-text-primary rounded-md text-sm">
          {error}
        </div>
      )}

      {message && (
        <div role="status" aria-live="polite" className="p-4 bg-success/20 border border-success/50 text-text-primary rounded-md text-sm">
          {message}
        </div>
      )}

      <section className="card space-y-4" aria-labelledby="appearance-heading">
        <div className="border-b border-border-color pb-3">
          <h3 id="appearance-heading" className="m-0 flex items-center gap-2 text-lg text-text-primary">
            <Monitor size={18} className="text-accent" aria-hidden="true" /> Appearance
          </h3>
          <p className="mb-0 mt-1 text-xs text-text-secondary">
            A local-only display preference. System follows your operating-system theme; it never changes daemon configuration.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Appearance preference">
          {([
            ['system', 'System', <Monitor key="system-icon" size={16} aria-hidden="true" />],
            ['dark', 'Dark', <Moon key="dark-icon" size={16} aria-hidden="true" />],
            ['light', 'Light', <Sun key="light-icon" size={16} aria-hidden="true" />],
          ] as const).map(([value, label, icon]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={appearance === value}
              onClick={() => setAppearance(value)}
              className={`btn justify-start px-3 py-2 ${appearance === value ? 'border-accent bg-accent/10 text-accent' : 'btn-secondary'}`}
            >
              {icon}{label}
            </button>
          ))}
        </div>
      </section>

      <PostRefactor226SettingsPlanning />
      <UpdateRolloutPlanner />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Evasion Engine Settings */}
        <div className="card space-y-4">
          <div className="flex items-center justify-between border-b border-border-color pb-3">
            <h3 className="text-lg text-text-primary m-0 flex items-center gap-2">
              <SettingsIcon size={18} className="text-accent" /> DPI Evasion & uTLS Config
            </h3>
            <button
              disabled={savingEvasion}
              onClick={applyEvasionSettings}
              className="btn btn-primary px-3 py-1.5"
            >
              {savingEvasion ? 'Applying...' : 'Apply Config'}
            </button>
          </div>

          <div className="space-y-4 text-sm">
            <label className="flex items-center justify-between p-2 rounded-md hover:bg-bg-secondary cursor-pointer">
              <div>
                <div className="font-semibold text-text-primary">Enable Active Desync</div>
                <div className="text-xs text-text-secondary mt-0.5">Use active packet fragmentation & sequence spoofing.</div>
              </div>
              <input
                type="checkbox"
                checked={evasionEnabled}
                onChange={e => setEvasionEnabled(e.target.checked)}
                className="w-4 h-4 accent-accent"
              />
            </label>

            <label className="block">
              <span className="flex justify-between mb-1">
                <span className="text-text-secondary">ClientHello Split Offset</span>
                <span className="mono text-cyan">{splitBytes} bytes</span>
              </span>
              <input
                type="range"
                min="1"
                max="10"
                value={splitBytes}
                onChange={e => setSplitBytes(parseInt(e.target.value))}
                className="w-full accent-accent"
              />
            </label>

            <label className="block">
              <span className="flex justify-between mb-1">
                <span className="text-text-secondary">Inter-packet Desync Delay</span>
                <span className="mono text-cyan">{delayMs} ms</span>
              </span>
              <input
                type="range"
                min="0"
                max="100"
                value={delayMs}
                onChange={e => setDelayMs(parseInt(e.target.value))}
                className="w-full accent-accent"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded-md hover:bg-bg-secondary cursor-pointer">
              <div>
                <div className="font-semibold text-text-primary">Mangle HTTP Host Case</div>
                <div className="text-xs text-text-secondary mt-0.5">Randomize HTTP Host casing to disrupt parser matching.</div>
              </div>
              <input
                type="checkbox"
                checked={mutateHost}
                onChange={e => setMutateHost(e.target.checked)}
                className="w-4 h-4 accent-accent"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded-md hover:bg-bg-secondary cursor-pointer">
              <div>
                <div className="font-semibold text-text-primary">Inject Out-of-Window Decoys</div>
                <div className="text-xs text-text-secondary mt-0.5">Inject decoy packets with wrong checksums.</div>
              </div>
              <input
                type="checkbox"
                checked={fakePacketInject}
                onChange={e => setFakePacketInject(e.target.checked)}
                className="w-4 h-4 accent-accent"
              />
            </label>

            <div className="border-t border-border-color pt-3">
              <label className="flex items-center justify-between p-2 rounded-md hover:bg-bg-secondary cursor-pointer">
                <div>
                  <div className="font-semibold text-text-primary">Use uTLS ClientHello Spoofing</div>
                  <div className="text-xs text-text-secondary mt-0.5">Mimic specific browser signatures on connection TLS handshakes.</div>
                </div>
                <input
                  type="checkbox"
                  checked={wsUseUtls}
                  onChange={e => setWsUseUtls(e.target.checked)}
                  className="w-4 h-4 accent-accent"
                />
              </label>
            </div>

            {wsUseUtls && (
              <label className="block p-2 space-y-1">
                <span className="text-text-secondary">Browser Fingerprint Type</span>
                <select
                  value={wsFingerprint}
                  onChange={e => setWsFingerprint(e.target.value)}
                  className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
                >
                  <option value="chrome">Chrome 120 (Standard)</option>
                  <option value="firefox">Firefox 120 (Covert)</option>
                  <option value="safari">Safari 17</option>
                  <option value="edge">Edge 120</option>
                  <option value="randomized">Randomized Anti-Detect</option>
                </select>
              </label>
            )}
          </div>
        </div>

        {/* Cloudflare Warp Profile Manager */}
        <div className="card space-y-4">
          <div className="flex items-center justify-between border-b border-border-color pb-3">
            <h3 className="text-lg text-text-primary m-0 flex items-center gap-2">
              <Key size={18} className="text-purple" /> Cloudflare WARP Profile
            </h3>
            <button
              disabled={registeringWarp}
              onClick={registerWarpAccount}
              className="btn btn-secondary px-3 py-1.5 flex items-center gap-1.5"
            >
              {registeringWarp ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />} Register
            </button>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            Generate an on-the-fly WireGuard profile utilizing Cloudflare Client API endpoints. The registration returns WireGuard private key bindings and ClientID reserved bytes.
          </p>

          {warpParams ? (
            <div className="space-y-2 text-xs bg-bg-secondary/40 border border-border-color p-3 rounded-md">
              <div>
                <span className="text-text-muted">IPv4 Address</span>
                <p className="mono font-semibold text-text-primary m-0 mt-0.5">{warpParams.ipv4}</p>
              </div>
              <div>
                <span className="text-text-muted">IPv6 Address</span>
                <p className="mono font-semibold text-text-primary m-0 mt-0.5 truncate">{warpParams.ipv6}</p>
              </div>
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-text-muted">WireGuard Private Key</span>
                  <button
                    type="button"
                    onClick={() => setWarpPrivateKeyVisible(visible => !visible)}
                    className="text-accent hover:underline"
                  >
                    {warpPrivateKeyVisible ? 'Hide' : 'Reveal'}
                  </button>
                </div>
                <p className="mono font-semibold text-text-primary m-0 mt-0.5 truncate">
                  {warpPrivateKeyVisible ? warpParams.privateKey : '••••••••••••••••'}
                </p>
              </div>
              <div>
                <span className="text-text-muted">Reserved Traffic Bytes</span>
                <p className="mono font-semibold text-text-primary m-0 mt-0.5 truncate">
                  [{warpParams.reserved.join(', ')}]
                </p>
              </div>
            </div>
          ) : (
            <div className="text-center py-8 text-text-muted border border-dashed border-border-color rounded-md text-sm">
              No active Warp credentials generated. Click "Register" to generate.
            </div>
          )}
        </div>

        {/* Generic Worker upload. This surface makes no protocol-readiness claim. */}
        <div className="card space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-border-color pb-3">
            <h3 className="text-lg text-text-primary m-0 flex items-center gap-2">
              <Cloud size={18} className="text-yellow-500" aria-hidden="true" /> Custom Cloudflare Worker upload
            </h3>
            <button
              type="button"
              disabled={deployingWorker}
              onClick={deployWorkersScript}
              className="btn btn-primary px-3 py-1.5 flex items-center gap-1.5"
            >
              {deployingWorker ? <RefreshCw size={14} className="animate-spin" aria-hidden="true" /> : <Play size={14} aria-hidden="true" />} Upload Script
            </button>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            Upload the exact JavaScript shown below. Success means Cloudflare accepted the source; this action does not claim that VLESS, WebSocket, or any other protocol is operational.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <label className="space-y-1">
              <span className="text-text-secondary">Auth Email</span>
              <input
                type="email"
                value={cfEmail}
                onChange={e => setCfEmail(e.target.value)}
                placeholder="user@example.com"
                className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
              />
            </label>
            <label className="space-y-1">
              <span className="text-text-secondary">API Token</span>
              <input
                type="password"
                value={cfToken}
                onChange={e => setCfToken(e.target.value)}
                placeholder="Paste API token..."
                autoComplete="off"
                className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
              />
            </label>
            <label className="space-y-1">
              <span className="text-text-secondary">Account ID</span>
              <input
                type="text"
                value={cfAccountId}
                onChange={e => setCfAccountId(e.target.value)}
                placeholder="Paste Account ID..."
                className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
              />
            </label>
          </div>

          <div className="space-y-2 text-xs">
            <label className="flex justify-between items-center gap-3">
              <span className="text-text-secondary font-semibold">Worker script name</span>
              <input
                type="text"
                value={cfWorkerName}
                onChange={e => setCfWorkerName(e.target.value)}
                className="w-48 bg-bg-secondary text-text-primary border border-border-color rounded px-2 py-1 outline-none font-mono text-[10px]"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-text-secondary font-semibold">Worker JavaScript source</span>
              <textarea
                value={cfScriptBody}
                onChange={e => setCfScriptBody(e.target.value)}
                className="w-full h-40 bg-bg-secondary text-text-primary border border-border-color rounded p-2 font-mono text-[11px] outline-none"
              />
            </label>
          </div>
        </div>

        {/* Warp IP Scan and Speedtest */}
        <div className="card space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-border-color pb-3">
            <h3 className="text-lg text-text-primary m-0 flex items-center gap-2">
              <ShieldAlert size={18} className="text-cyan" /> Cloudflare Warp IP Scanner
            </h3>
            <div className="flex gap-2 items-center">
              <input
                type="number"
                value={scanCount}
                onChange={e => setScanCount(parseInt(e.target.value) || 30)}
                className="w-16 bg-bg-primary text-text-primary border border-border-color rounded px-2 py-1 text-xs text-center outline-none"
                title="Number of candidates"
              />
              <button
                disabled={scanning}
                onClick={runWarpIPScan}
                className="btn btn-primary px-3 py-1.5 flex items-center gap-1.5"
              >
                {scanning ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />} Scan Endpoints
              </button>
            </div>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            Performs concurrent UDP handshake probes over random endpoints selected from Cloudflare Warp subnets (162.159.192.x, 188.114.97.x, etc.) to discover clean endpoints.
          </p>

          {scanResults.length > 0 ? (
            <div className="space-y-3">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Best observed</p><p className="mono m-0 mt-1 text-xs text-success">{bestWarpEndpoint?.endpoint}</p><p className="m-0 mt-1 text-[10px] text-text-muted">{bestWarpEndpoint?.rttMilliseconds.toFixed(1)} ms</p></div>
                <div className="rounded border border-border-color bg-bg-primary/60 p-3"><p className="m-0 text-[10px] uppercase text-text-muted">Median RTT</p><p className="mono m-0 mt-1 text-lg text-text-primary">{warpMedianRTT.toFixed(1)} ms</p><p className="m-0 mt-1 text-[10px] text-text-muted">{scanResults.length} successful observations</p></div>
                <div className="flex items-center justify-end gap-2 rounded border border-border-color bg-bg-primary/60 p-3"><button type="button" className="btn btn-secondary px-3 py-1.5 text-xs" onClick={() => void copyBestWarpEndpoint()}><Copy size={13} /> Copy best</button><button type="button" className="btn btn-secondary px-3 py-1.5 text-xs" onClick={exportWarpScanEvidence}><Download size={13} /> Export evidence</button></div>
              </div>
              <div className="max-h-[250px] overflow-y-auto rounded border border-border-color">
                <table className="w-full border-collapse text-xs">
                  <thead className="sticky top-0 bg-bg-tertiary text-left text-text-muted"><tr><th className="px-3 py-2">Rank</th><th className="px-3 py-2">Endpoint</th><th className="px-3 py-2 text-right">RTT</th></tr></thead>
                  <tbody className="divide-y divide-border-color">{scanResults.map((r, index) => <tr key={r.endpoint} className="bg-bg-secondary/40"><td className="mono px-3 py-2 text-text-muted">#{index + 1}</td><td className="mono px-3 py-2 text-text-primary">{r.endpoint}</td><td className="mono px-3 py-2 text-right text-success">{r.rttMilliseconds.toFixed(1)} ms</td></tr>)}</tbody>
                </table>
              </div>
              <p className="m-0 text-[10px] text-text-muted">Ranking is observed scan evidence only. Copy/export does not activate, persist, or replace the runtime WARP endpoint.</p>
            </div>
          ) : (
            <div className="text-center py-12 text-text-muted bg-bg-secondary/20 rounded-md text-sm">
              {scanning ? 'Scanning Cloudflare subnets in parallel...' : 'No IP scan results available. Click "Scan Endpoints" to start.'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


function PostRefactor226SettingsPlanning() {
  const [tailnetOperation, setTailnetOperation] = useState('dns-patch');
  const [etag, setETag] = useState('rev-7');
  const [tailnetPlan, setTailnetPlan] = useState<TailnetTransactionPlan | null>(null);
  const [tailnetError, setTailnetError] = useState<string | null>(null);
  const [browserPlan, setBrowserPlan] = useState<BrowserProxyHandoffPlan | null>(null);
  const [browserError, setBrowserError] = useState<string | null>(null);
  const [profileID, setProfileID] = useState('default');
  const [proxyURL, setProxyURL] = useState('socks5://127.0.0.1:1080');
  const [browserFamily, setBrowserFamily] = useState('chrome');
  const [extensionID, setExtensionID] = useState('abcdefghijklmnopabcdefghijklmnop');

  async function planTailnet() {
    setTailnetError(null); setTailnetPlan(null);
    try { setTailnetPlan(await controlTransport.json('/api/system/tailnet-transaction-plan', parseTailnetTransactionPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ operation:tailnetOperation, etag, target_id:tailnetOperation === 'device-route' ? 'device-preview' : undefined }) })); }
    catch (caught) { setTailnetError(errorMessage(caught, 'Tailnet transaction planning failed.')); }
  }
  async function planBrowser() {
    setBrowserError(null); setBrowserPlan(null);
    try { setBrowserPlan(await controlTransport.json('/api/system/browser-proxy-handoff-plan', parseBrowserProxyHandoffPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ profile_id:profileID, proxy_url:proxyURL, permissions:['nativeMessaging','proxy','storage'], native_message_bytes:4096, native_host_installed:true, browser_family:browserFamily, extension_id:extensionID }) })); }
    catch (caught) { setBrowserError(errorMessage(caught, 'Browser proxy handoff planning failed.')); }
  }
  return <section className="card space-y-4" aria-labelledby="transaction-planning-title">
    <div><p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Read-only · no credentials or browser mutation</p><h3 id="transaction-planning-title" className="m-0 mt-1 text-lg text-text-primary">Tailnet & browser handoff planning</h3><p className="m-0 mt-1 text-xs text-text-muted">Preview CAS/ETag transaction semantics and profile-isolated loopback browser handoff. These planners make no Tailnet API request, register no native host, and change no browser proxy.</p></div>
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-3 rounded border border-border-color bg-bg-primary/50 p-3"><div className="grid grid-cols-2 gap-2"><select value={tailnetOperation} onChange={(e)=>setTailnetOperation(e.target.value)} className="field-input"><option value="acl-validate">ACL validate</option><option value="dns-patch">DNS patch</option><option value="dns-replace">DNS replace</option><option value="device-route">device route</option><option value="key-create">key create</option><option value="webhook-secret-rotate">webhook secret rotate</option></select><input value={etag} onChange={(e)=>setETag(e.target.value)} placeholder="ETag/revision" className="field-input mono" /></div><button type="button" onClick={()=>void planTailnet()} className="btn btn-secondary">Plan Tailnet transaction</button>{tailnetError && <p className="m-0 text-xs text-error">{tailnetError}</p>}{tailnetPlan && <div className="text-xs text-text-muted"><p className="m-0">{tailnetPlan.operation} · ETag {tailnetPlan.requiresETag?'required':'not required'} · API request {tailnetPlan.makesAPIRequest?'yes':'no'} · credentials accepted {tailnetPlan.credentialAccepted?'yes':'no'}</p><ol className="mb-0 mt-2 list-decimal space-y-1 pl-5">{tailnetPlan.steps.map((step)=><li key={step}>{step}</li>)}</ol></div>}</div>
      <div className="space-y-3 rounded border border-border-color bg-bg-primary/50 p-3"><div className="grid grid-cols-2 gap-2"><input value={profileID} onChange={(e)=>setProfileID(e.target.value)} placeholder="profile" className="field-input" /><input value={proxyURL} onChange={(e)=>setProxyURL(e.target.value)} placeholder="socks5://127.0.0.1:1080" className="field-input mono" /><select value={browserFamily} onChange={(e)=>setBrowserFamily(e.target.value)} className="field-input"><option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="generic">Generic</option></select><input value={extensionID} onChange={(e)=>setExtensionID(e.target.value)} placeholder="browser extension ID" className="field-input mono" /></div><button type="button" onClick={()=>void planBrowser()} className="btn btn-secondary">Check handoff readiness</button>{browserError && <p className="m-0 text-xs text-error">{browserError}</p>}{browserPlan && <div className="space-y-1 text-xs text-text-muted"><p className="m-0">state <strong className="text-text-primary">{browserPlan.state}</strong> · {browserPlan.browserFamily} · {browserPlan.proxyHost}:{browserPlan.proxyPort} · missing {browserPlan.missingPermissions.join(', ') || 'none'}</p><p className="m-0">native host <span className="mono text-text-primary">{browserPlan.nativeHost.name}</span> · commands {browserPlan.nativeCommands.join('/')}</p><p className="m-0">bypass {browserPlan.proxyBypass.join(', ')} · reconnect {browserPlan.reconnectBackoffMS.join('/')} ms · registers host {browserPlan.registersHost?'yes':'no'} · changes proxy {browserPlan.changesBrowserProxy?'yes':'no'}</p></div>}</div>
    </div>
  </section>;
}

function UpdateRolloutPlanner() {
  const [version, setVersion] = useState('229.0.0');
  const [rollout, setRollout] = useState(0.25);
  const [sequence, setSequence] = useState(42);
  const [highest, setHighest] = useState(41);
  const [plan, setPlan] = useState<UpdateRolloutPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function analyze() {
    setError(null); setPlan(null);
    try { setPlan(await controlTransport.json('/api/system/update-rollout-plan', parseUpdateRolloutPlan, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ version, rollout, cohort_seed:20260821, metadata_sequence:sequence, highest_seen_sequence:highest }) })); }
    catch (caught) { setError(errorMessage(caught, 'Update rollout planning failed.')); }
  }
  return <section className="card space-y-3" aria-labelledby="update-rollout-title"><div><p className="m-0 text-[10px] uppercase tracking-[0.14em] text-purple">Read-only · signed-update companion</p><h3 id="update-rollout-title" className="m-0 mt-1 text-lg text-text-primary">Update rollout & metadata replay posture</h3><p className="m-0 mt-1 text-xs text-text-muted">Preview deterministic cohort eligibility and monotonic signed-metadata sequence checks. Eligibility never bypasses LumiNet's existing signature, expiry, version-transition, size, digest, or staging authority. This planner persists no high-water mark and installs nothing.</p></div><div className="grid gap-2 md:grid-cols-4"><label className="text-xs text-text-muted">Version<input className="field-input mt-1" value={version} onChange={(e)=>setVersion(e.target.value)} /></label><label className="text-xs text-text-muted">Rollout 0..1<input type="number" min={0} max={1} step={0.05} className="field-input mt-1" value={rollout} onChange={(e)=>setRollout(Number(e.target.value))} /></label><label className="text-xs text-text-muted">Metadata sequence<input type="number" min={1} className="field-input mt-1" value={sequence} onChange={(e)=>setSequence(Math.max(1,Number(e.target.value)||1))} /></label><label className="text-xs text-text-muted">Highest seen<input type="number" min={0} className="field-input mt-1" value={highest} onChange={(e)=>setHighest(Math.max(0,Number(e.target.value)||0))} /></label></div><button type="button" className="btn btn-secondary" onClick={()=>void analyze()}>Evaluate rollout</button>{error && <p role="alert" className="m-0 text-xs text-error">{error}</p>}{plan && <div className="space-y-1 rounded border border-border-color bg-bg-secondary/40 p-3 text-xs text-text-muted"><p className="m-0"><strong className="text-text-primary">{plan.eligible?'eligible cohort':'not eligible'}</strong> · threshold {plan.cohortThreshold.toFixed(6)} · sequence {plan.sequenceFresh?'fresh':'stale'} · withdrawn {plan.withdrawn?'yes':'no'}</p><p className="m-0">persisted high-water mark required {plan.requiresPersistedHighWaterMark?'yes':'no'} · persisted here {plan.persistsHighWaterMark?'yes':'no'} · downloads {plan.downloadsArtifact?'yes':'no'} · installs {plan.installsUpdate?'yes':'no'}</p>{plan.reasons.map((reason)=><p key={reason} className="m-0 text-warning">{reason}</p>)}</div>}</section>;
}
