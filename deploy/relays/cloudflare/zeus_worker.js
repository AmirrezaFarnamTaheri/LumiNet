/**
 * LumiNet Zeus Worker Panel Adapter
 * Ported from zeus-main/zeus.js (v1.4.8, 216KB, IR-NETLIFY)
 *
 * Platform: Cloudflare Workers + D1 SQLite + KV
 *
 * Active adapter features:
 *   - D1-backed VLESS subscription and JSON feed generation.
 *   - Atomic GB, validity-day, enabled-state, and request-cap checks.
 *   - Optional VLESS WebSocket delegation through the VLESS_RELAY service binding.
 *   - Clean IP selector: MCI/Irancell/Shatel list + GitHub auto-fetch fallback
 *   - CF GraphQL API: real-time request monitoring (today + 30d)
 *   - Upstream release availability checks.
 *   - Authenticated status lookup and D1 persistence schema.
 *
 * LumiNet adapter changes vs. upstream Zeus:
 *   - PANEL_AUTH_TOKEN env var replaces hardcoded password hash flow
 *   - KV namespace key convention: luminet:{key} prefix
 *   - wrangler.toml binding names: DB (D1), KV (KV namespace)
 *   - Anti-resale WebSocket path: /In_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh (unchanged)
 *   - Subscription paths: /sub/{username_or_uuid}, /feed/{username_or_uuid} (unchanged)
 *   - User status path: /status/{username_or_uuid} (unchanged)
 *
 * Usage:
 *   1. Copy zeus.js from PORTING/extracted/zeus-main/zeus-main/zeus.js into this directory.
 *   2. Wrap it using wrangler.toml below to bind luminet D1 + KV.
 *   3. Deploy: wrangler deploy --config wrangler.toml
 *
 * This file is a standalone LumiNet adapter. It does not include the upstream
 * Zeus panel UI or a native VLESS socket implementation.
 *
 * @module luminet-zeus-worker
 */

import { healthResponse, jsonResponse } from "./worker_contract.mjs";

// ─────────────────────────────────────────────────────────────────────────────
// Zeus D1 Schema (must be applied before first deploy via `wrangler d1 execute`)
// ─────────────────────────────────────────────────────────────────────────────
export const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  username       TEXT    NOT NULL UNIQUE,
  uuid           TEXT    NOT NULL UNIQUE,
  connection_type TEXT   NOT NULL DEFAULT 'vless',
  limit_gb       REAL    NOT NULL DEFAULT 0,
  expiry_days    INTEGER NOT NULL DEFAULT 0,
  max_requests   INTEGER NOT NULL DEFAULT 0,
  max_connections INTEGER NOT NULL DEFAULT 0,
  used_gb        REAL    NOT NULL DEFAULT 0,
  request_count  INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  last_seen      INTEGER NOT NULL DEFAULT 0,
  enabled        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
`;

// ─────────────────────────────────────────────────────────────────────────────
// LumiNet Zeus Shim — wraps upstream zeus.js with env normalisation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * normalizeEnv adapts LumiNet wrangler bindings to the names Zeus expects.
 * Zeus reads: env.DB (D1), env.KV (optional KV store).
 * LumiNet bindings: LUMINET_DB → DB, LUMINET_KV → KV (see wrangler.toml).
 */
function normalizeEnv(env) {
  return {
    ...env,
    DB: env.LUMINET_DB ?? env.DB,
    KV: env.LUMINET_KV ?? env.KV,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean IP list (Community D: MCI / Irancell / Shatel auto-fetch)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * fetchCleanIPs retrieves the latest clean Cloudflare IP list from GitHub.
 * Falls back to the bundled ips.txt list from zeus-main if the fetch fails.
 * Mirrors the Clean IP auto-fetch logic from zeus.js.
 *
 * @param {string} operator - One of: mci | irancell | shatel | all
 * @returns {Promise<string[]>} - Array of clean IP addresses / CIDR ranges
 */
export async function fetchCleanIPs(operator = "all") {
  const sources = {
    mci:      "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/actives.txt",
    irancell: "https://raw.githubusercontent.com/coldwater-10/V2Hub2/main/Irancell.txt",
    shatel:   "https://raw.githubusercontent.com/coldwater-10/V2Hub2/main/Shatel.txt",
    all:      "https://raw.githubusercontent.com/IR-NETLIFY/zeus/main/ips.txt",
  };
  const url = sources[operator] ?? sources.all;
  try {
    const resp = await fetch(url, { cf: { cacheTtl: 300 } });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    return text.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  } catch {
    // Bundled fallback — sourced from zeus-main/ips.txt
    return BUNDLED_CLEAN_IPS;
  }
}

// Bundled fallback clean IPs (subset from zeus-main/ips.txt for cold-start resilience).
const BUNDLED_CLEAN_IPS = [
  "104.16.0.0",  "104.17.0.0",  "104.18.0.0",  "104.19.0.0",
  "162.159.0.0", "162.159.36.0", "162.159.128.0",
  "172.64.0.0",  "172.65.0.0",  "172.66.0.0",  "172.67.0.0",
  "198.41.192.0", "198.41.200.0",
];

// ─────────────────────────────────────────────────────────────────────────────
// CF GraphQL API monitoring (Community D: real-time request metrics)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * fetchCFWorkerMetrics queries the Cloudflare GraphQL API for worker request counts.
 * Mirrors the CF GraphQL API integration from zeus.js (today + 30d rolling).
 *
 * @param {string} accountId - CF account ID
 * @param {string} apiToken  - CF API token with Workers:Read permission
 * @param {string} workerName - Name of the Worker
 * @returns {Promise<{today: number, last30d: number}>}
 */
export async function fetchCFWorkerMetrics(accountId, apiToken, workerName) {
  const now = new Date();
  const todayDate = now.toISOString().slice(0, 10);
  const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

  const query = `{
    viewer {
      accounts(filter: { accountTag: "${accountId}" }) {
        workersInvocationsAdaptive(
          limit: 10000
          filter: {
            scriptName: "${workerName}"
            datetime_geq: "${thirtyDaysAgo}T00:00:00Z"
            datetime_leq: "${todayDate}T23:59:59Z"
          }
          orderBy: [datetime_ASC]
        ) {
          dimensions { datetime scriptName }
          sum { requests }
        }
      }
    }
  }`;

  try {
    const resp = await fetch("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ query }),
    });
    if (!resp.ok) throw new Error(`GraphQL HTTP ${resp.status}`);
    const data = await resp.json();
    const invocations = data?.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive ?? [];
    let today = 0;
    let last30d = 0;
    for (const entry of invocations) {
      const requests = entry.sum?.requests ?? 0;
      last30d += requests;
      if (entry.dimensions?.datetime?.startsWith(todayDate)) {
        today += requests;
      }
    }
    return { today, last30d };
  } catch {
    return { today: 0, last30d: 0 };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VLESS Fragment + Fingerprint config generator (Community D)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * generateVLESSConfig produces a VLESS subscription link with Fragment and Fingerprint.
 * Mirrors the VLESS config generation from zeus.js verbatim.
 *
 * @param {object} user - D1 user row { uuid, username }
 * @param {string} host - Worker domain / clean IP
 * @param {object} opts - { fingerprint: "ios"|"chrome"|"random", fragment: bool }
 * @returns {string} - vless:// URI
 */
export function generateVLESSConfig(user, host, opts = {}) {
  const fingerprints = {
    ios:    "ios",
    chrome: "chrome",
    random: ["ios", "chrome", "firefox", "safari", "edge"][Math.floor(Math.random() * 5)],
  };
  const fp = fingerprints[opts.fingerprint] ?? fingerprints.random;

  const params = new URLSearchParams({
    type:       "ws",
    security:   "tls",
    sni:        host,
    fp:         fp,
    path:       encodeURIComponent("/In_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh"),
    host:       host,
    encryption: "none",
  });

  if (opts.fragment) {
    params.set("fragment", "1,1-1,tlshello");
  }

  return `vless://${user.uuid}@${host}:443?${params.toString()}#${encodeURIComponent(user.username)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Upstream release availability check
// ─────────────────────────────────────────────────────────────────────────────

/**
 * checkForUpdates queries the upstream Zeus GitHub release for a newer version.
 * Mirrors the OTA update check in zeus.js.
 *
 * @param {string} currentVersion - e.g. "1.4.8"
 * @returns {Promise<{hasUpdate: boolean, latest: string, url: string}>}
 */
export async function checkForUpdates(currentVersion) {
  try {
    const resp = await fetch(
      "https://api.github.com/repos/IR-NETLIFY/zeus/releases/latest",
      { headers: { "User-Agent": "LumiNet-Zeus-Worker" } }
    );
    if (!resp.ok) throw new Error(`GitHub API ${resp.status}`);
    const data = await resp.json();
    const latest = (data.tag_name ?? "").replace(/^v/, "");
    return {
      hasUpdate: latest !== "" && latest !== currentVersion,
      latest,
      url: data.html_url ?? "https://github.com/IR-NETLIFY/zeus/releases",
    };
  } catch {
    return { hasUpdate: false, latest: currentVersion, url: "" };
  }
}

function userLimitStatus(user, nowSeconds = Math.floor(Date.now() / 1000)) {
  const expiresAt = user.expiry_days > 0 ? user.created_at + user.expiry_days * 86400 : 0;
  const quotaExceeded = user.limit_gb > 0 && user.used_gb >= user.limit_gb;
  const requestsExceeded = user.max_requests > 0 && user.request_count >= user.max_requests;
  const expired = expiresAt > 0 && nowSeconds >= expiresAt;
  const enabled = Boolean(user.enabled) && !quotaExceeded && !requestsExceeded && !expired;
  return { enabled, quotaExceeded, requestsExceeded, expired, expiresAt };
}

async function findUserByUUID(db, uuid) {
  if (!db?.prepare) return null;
  return db
    .prepare("SELECT * FROM users WHERE uuid = ?1 LIMIT 1")
    .bind(uuid)
    .first();
}

function hasPanelAuthorization(request, env) {
  if (!env.PANEL_AUTH_TOKEN) return false;
  return request.headers.get("Authorization") === `Bearer ${env.PANEL_AUTH_TOKEN}`;
}

function subscriptionHost(request, env) {
  return env.SUBSCRIPTION_HOST || new URL(request.url).host;
}

async function consumeUserRequest(db, user, nowSeconds) {
  if (!db?.prepare) return false;
  const result = await db
    .prepare(`UPDATE users
      SET request_count = request_count + 1, last_seen = ?1
      WHERE id = ?2
        AND enabled = 1
        AND (limit_gb <= 0 OR used_gb < limit_gb)
        AND (max_requests <= 0 OR request_count < max_requests)
        AND (expiry_days <= 0 OR created_at + expiry_days * 86400 > ?1)`)
    .bind(nowSeconds, user.id)
    .run();
  return (result?.meta?.changes ?? result?.changes ?? 0) === 1;
}

async function handleUserRoute(request, env, kind, identity) {
  if (kind === "status" && !hasPanelAuthorization(request, env)) {
    return jsonResponse({ error: "unauthorized" }, { status: 401 });
  }
  if (kind !== "status" && !env.VLESS_RELAY?.fetch) {
    return jsonResponse({ error: "relay_unavailable" }, { status: 503 });
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(identity)) {
    return jsonResponse({ error: "invalid_identity" }, { status: 400 });
  }
  const user = await findUserByUUID(env.DB, identity);
  if (!user) return jsonResponse({ error: "user_not_found" }, { status: 404 });

  const limits = userLimitStatus(user);
  const status = {
    username: user.username,
    connectionType: user.connection_type,
    usedGB: user.used_gb,
    limitGB: user.limit_gb,
    requestCount: user.request_count,
    maxRequests: user.max_requests,
    maxConnections: user.max_connections,
    lastSeen: user.last_seen,
    ...limits,
  };
  if (kind === "status") return jsonResponse(status);
  if (!limits.enabled) return jsonResponse({ error: "user_disabled", status }, { status: 403 });

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!(await consumeUserRequest(env.DB, user, nowSeconds))) {
    return jsonResponse({ error: "user_disabled", status }, { status: 403 });
  }

  const host = subscriptionHost(request, env);
  const config = generateVLESSConfig(user, host, {
    fingerprint: new URL(request.url).searchParams.get("fp") || "chrome",
    fragment: new URL(request.url).searchParams.get("fragment") !== "0",
  });
  if (kind === "feed") return jsonResponse({ status, configs: [config] });
  return new Response(config + "\n", {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Cloudflare Worker export (shim entry point)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The handler exposes the adapter capabilities implemented in this file.
 * VLESS WebSocket traffic requires an explicit VLESS_RELAY service binding.
 */
export default {
  async fetch(request, env, ctx) {
    const normEnv = normalizeEnv(env);
    const url = new URL(request.url);
    const websocketPath = "/In_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh";

    if (url.pathname === websocketPath && request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      if (!normEnv.VLESS_RELAY?.fetch) return jsonResponse({ error: "relay_unavailable" }, { status: 503 });
      return normEnv.VLESS_RELAY.fetch(request);
    }

    // Health check endpoint for LumiNet integration verification.
    if (url.pathname === "/healthz") {
      return healthResponse("luminet-zeus");
    }

    // Clean IP endpoint — serves the bundled fallback list.
    if (url.pathname === "/clean-ips") {
      const operator = url.searchParams.get("op") ?? "all";
      const ips = await fetchCleanIPs(operator);
      return new Response(ips.join("\n"), {
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    const userRoute = url.pathname.match(/^\/(sub|feed|status)\/([^/]+)$/);
    if (userRoute && request.method === "GET") {
      let identity;
      try {
        identity = decodeURIComponent(userRoute[2]);
      } catch {
        return jsonResponse({ error: "invalid_identity" }, { status: 400 });
      }
      return handleUserRoute(request, normEnv, userRoute[1], identity);
    }

    if (url.pathname === "/" && request.method === "GET") {
      return jsonResponse({
        worker: "luminet-zeus",
        status: !normEnv.DB?.prepare
          ? "database_unavailable"
          : normEnv.VLESS_RELAY?.fetch
            ? "ready"
            : "configuration_only",
        routes: ["/healthz", "/clean-ips", "/sub/{uuid}", "/feed/{uuid}", "/status/{uuid}"],
      }, { status: normEnv.DB?.prepare ? 200 : 503 });
    }

    return jsonResponse({ error: "not_found" }, { status: 404 });
  },
};
