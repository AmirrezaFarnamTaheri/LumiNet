#!/usr/bin/env python3
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "src/packages/control-ui/src/pages/Settings.tsx": "2bd92c04c3b2c029a3594917465f2490094ad701",
    "src/apps/daemon/internal/adapters/api/handlers_warp_geosite.go": "13777e32955348b29a524cad5a7876012f3055a2",
}
for rel, expected in EXPECTED.items():
    actual = subprocess.check_output(["git", "hash-object", rel], cwd=ROOT, text=True).strip()
    if actual != expected:
        raise SystemExit(f"{rel} drifted: expected {expected}, got {actual}")


def replace_once(rel: str, old: str, new: str, label: str) -> None:
    path = ROOT / rel
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{rel}: {label}: expected one match, got {count}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")

settings = "src/packages/control-ui/src/pages/Settings.tsx"
replace_once(
    settings,
    '''const DEFAULT_WORKER_SCRIPT = `// Standard VLESS Workers script for Cloudflare
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response("OK", { status: 200 });
    }
    // Forward connections to target VLESS outbound
    return new Response("VLESS outbound active", { status: 200 });
  }
};`;''',
    '''const DEFAULT_WORKER_SCRIPT = `// Generic Cloudflare Worker upload template.
// This template is intentionally not presented as a VLESS implementation.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response("OK", { status: 200 });
    }
    return new Response("LumiNet custom Worker online", { status: 200 });
  }
};`;''',
    "worker template truth",
)
replace_once(
    settings,
    "      setMessage('Cloudflare Workers VLESS script successfully deployed.');",
    "      setMessage('Cloudflare accepted the Worker script upload. This action does not verify VLESS or other runtime protocol behavior.');",
    "worker success truth",
)
replace_once(
    settings,
    '''      {error && (
        <div className="p-4 bg-error/20 border border-error/50 text-text-primary rounded-md text-sm">
          {error}
        </div>
      )}

      {message && (
        <div className="p-4 bg-success/20 border border-success/50 text-text-primary rounded-md text-sm">
          {message}
        </div>
      )}''',
    '''      {error && (
        <div role="alert" aria-live="assertive" className="p-4 bg-error/20 border border-error/50 text-text-primary rounded-md text-sm">
          {error}
        </div>
      )}

      {message && (
        <div role="status" aria-live="polite" className="p-4 bg-success/20 border border-success/50 text-text-primary rounded-md text-sm">
          {message}
        </div>
      )}''',
    "announced feedback",
)
replace_once(
    settings,
    '''            <div>
              <div className="flex justify-between mb-1">
                <span className="text-text-secondary">ClientHello Split Offset</span>
                <span className="mono text-cyan">{splitBytes} bytes</span>
              </div>
              <input
                type="range"
                min="1"
                max="10"
                value={splitBytes}
                onChange={e => setSplitBytes(parseInt(e.target.value))}
                className="w-full accent-accent"
              />
            </div>''',
    '''            <label className="block">
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
            </label>''',
    "split range label",
)
replace_once(
    settings,
    '''            <div>
              <div className="flex justify-between mb-1">
                <span className="text-text-secondary">Inter-packet Desync Delay</span>
                <span className="mono text-cyan">{delayMs} ms</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={delayMs}
                onChange={e => setDelayMs(parseInt(e.target.value))}
                className="w-full accent-accent"
              />
            </div>''',
    '''            <label className="block">
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
            </label>''',
    "delay range label",
)
replace_once(
    settings,
    '''            {wsUseUtls && (
              <div className="p-2 space-y-1">
                <span className="text-text-secondary">Browser Fingerprint Type</span>
                <select
                  value={wsFingerprint}
                  onChange={e => setWsFingerprint(e.target.value)}
                  className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
                >''',
    '''            {wsUseUtls && (
              <label className="block p-2 space-y-1">
                <span className="text-text-secondary">Browser Fingerprint Type</span>
                <select
                  value={wsFingerprint}
                  onChange={e => setWsFingerprint(e.target.value)}
                  className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
                >''',
    "fingerprint label open",
)
replace_once(
    settings,
    '''                </select>
              </div>
            )}''',
    '''                </select>
              </label>
            )}''',
    "fingerprint label close",
)
replace_once(
    settings,
    '''        {/* Cloudflare Workers Deployer */}
        <div className="card space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-border-color pb-3">
            <h3 className="text-lg text-text-primary m-0 flex items-center gap-2">
              <Cloud size={18} className="text-yellow-500" /> Cloudflare Workers Deployer
            </h3>
            <button
              disabled={deployingWorker}
              onClick={deployWorkersScript}
              className="btn btn-primary px-3 py-1.5 flex items-center gap-1.5"
            >
              {deployingWorker ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />} Deploy Script
            </button>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            Deploy clean VLESS-on-Workers script nodes automatically to your Cloudflare account to bypass ISP blocks.
          </p>''',
    '''        {/* Generic Worker upload. This surface makes no protocol-readiness claim. */}
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
          </p>''',
    "worker surface truth",
)
replace_once(
    settings,
    '''            <div className="space-y-1">
              <span className="text-text-secondary">Auth Email</span>
              <input
                type="email"
                value={cfEmail}
                onChange={e => setCfEmail(e.target.value)}
                placeholder="user@example.com"
                className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
              />
            </div>
            <div className="space-y-1">
              <span className="text-text-secondary">Global API Token</span>
              <input
                type="password"
                value={cfToken}
                onChange={e => setCfToken(e.target.value)}
                placeholder="Paste API token..."
                className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
              />
            </div>
            <div className="space-y-1">
              <span className="text-text-secondary">Account ID</span>
              <input
                type="text"
                value={cfAccountId}
                onChange={e => setCfAccountId(e.target.value)}
                placeholder="Paste Account ID..."
                className="w-full bg-bg-secondary text-text-primary border border-border-color rounded p-2 outline-none"
              />
            </div>''',
    '''            <label className="space-y-1">
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
            </label>''',
    "credential labels",
)
replace_once(
    settings,
    '''          <div className="space-y-2 text-xs">
            <div className="flex justify-between items-center">
              <span className="text-text-secondary font-semibold">Worker Script Template</span>
              <input
                type="text"
                value={cfWorkerName}
                onChange={e => setCfWorkerName(e.target.value)}
                className="w-48 bg-bg-secondary text-text-primary border border-border-color rounded px-2 py-1 outline-none font-mono text-[10px]"
                title="Script Subdomain Route Name"
              />
            </div>
            <textarea
              value={cfScriptBody}
              onChange={e => setCfScriptBody(e.target.value)}
              className="w-full h-40 bg-bg-secondary text-text-primary border border-border-color rounded p-2 font-mono text-[11px] outline-none"
            />
          </div>''',
    '''          <div className="space-y-2 text-xs">
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
          </div>''',
    "worker source labels",
)

handler = "src/apps/daemon/internal/adapters/api/handlers_warp_geosite.go"
replace_once(
    handler,
    '''\tc.JSON(http.StatusOK, gin.H{
\t\t"status":  "success",
\t\t"message": "Script successfully deployed to Cloudflare Workers",
\t})''',
    '''\tc.JSON(http.StatusOK, gin.H{
\t\t"status":   "success",
\t\t"verified": false,
\t\t"message":  "Cloudflare accepted the Worker script upload; runtime protocol behavior was not verified",
\t})''',
    "handler success semantics",
)

print("Settings truth/accessibility remediation applied")
