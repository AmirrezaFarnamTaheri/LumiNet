import assert from "node:assert/strict";
import test from "node:test";

import { handleWorkerRequest } from "./worker.mjs";
import { stripRoutePrefix } from "./worker_contract.mjs";

test("stripRoutePrefix preserves method, query, and request body", async () => {
  const request = new Request("https://edge.example/bpb/chain-proxy?mode=test", {
    method: "POST",
    body: "payload",
  });
  const routed = stripRoutePrefix(request, "/bpb");
  assert.equal(routed.method, "POST");
  assert.equal(new URL(routed.url).pathname, "/chain-proxy");
  assert.equal(new URL(routed.url).search, "?mode=test");
  assert.equal(await routed.text(), "payload");
});

test("dispatcher preserves Zeus default and exposes BPB and GSA relay namespaces", async () => {
  const zeus = await handleWorkerRequest(new Request("https://edge.example/healthz"), {}, {});
  assert.deepEqual(await zeus.json(), { status: "ok", worker: "luminet-zeus" });

  const bpb = await handleWorkerRequest(new Request("https://edge.example/bpb/chain-proxy"), { CHAIN_PROXY_IP: "198.51.100.7" }, {});
  assert.deepEqual(await bpb.json(), { status: "configured", chainIP: "198.51.100.7" });

  const relay = await handleWorkerRequest(new Request("https://edge.example/relay/healthz"), {}, {});
  const relayStatus = await relay.json();
  assert.equal(relayStatus.status, "ok");
  assert.deepEqual(relayStatus.features, ["tunnel", "doh-caching"]);
});

test("BPB exposes routing and validates Sing-box inputs", async () => {
  const root = await handleWorkerRequest(new Request("https://edge.example/bpb/"), {}, {});
  assert.equal(root.status, 200);
  assert.equal((await root.json()).status, "configuration_only");

  const rules = await handleWorkerRequest(new Request("https://edge.example/bpb/routing-rules"), {}, {});
  const routing = await rules.json();
  assert.equal(routing.blockQuic, true);
  assert.ok(routing.bypassRules.includes("geoip:ir"));

  const invalid = await handleWorkerRequest(new Request("https://edge.example/bpb/sing-box", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ uuid: "u" }),
  }), {}, {});
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, "missing_fields");

  const valid = await handleWorkerRequest(new Request("https://edge.example/bpb/sing-box", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      uuid: "00000000-0000-4000-8000-000000000000",
      host: "edge.example",
      sni: "front.example",
      reserved: [1, 2, 3],
      privateKey: "private-key",
    }),
  }), { VLESS_RELAY: { fetch() { throw new Error("not called by config generation"); } } }, {});
  const config = await valid.json();
  assert.deepEqual(config.outbounds.map((outbound) => outbound.type), ["vless", "wireguard"]);
  assert.equal(config.outbounds[0].tls.utls.fingerprint, "chrome");
});

function d1For(user) {
  const updates = [];
  return {
    updates,
    prepare(sql) {
      return {
        bind(...values) {
          return {
            async first() {
              return sql.startsWith("SELECT") ? user : null;
            },
            async run() {
              updates.push({ sql, values });
              return { success: true, meta: { changes: 1 } };
            },
          };
        },
      };
    },
  };
}

test("Zeus serves status and quota-checked subscriptions from D1", async () => {
  const db = d1For({
    id: 7,
    username: "alice",
    uuid: "00000000-0000-4000-8000-000000000007",
    connection_type: "vless",
    limit_gb: 10,
    used_gb: 2,
    expiry_days: 30,
    max_requests: 100,
    request_count: 4,
    max_connections: 2,
    created_at: Math.floor(Date.now() / 1000) - 60,
    last_seen: 0,
    enabled: 1,
  });
  const env = {
    DB: db,
    PANEL_AUTH_TOKEN: "panel-secret",
    SUBSCRIPTION_HOST: "front.example",
    VLESS_RELAY: { fetch() { throw new Error("not called by subscription generation"); } },
  };

  const status = await handleWorkerRequest(new Request("https://edge.example/status/00000000-0000-4000-8000-000000000007", {
    headers: { Authorization: "Bearer panel-secret" },
  }), env, {});
  assert.equal(status.status, 200);
  assert.equal((await status.json()).enabled, true);

  const subscription = await handleWorkerRequest(
    new Request("https://edge.example/sub/00000000-0000-4000-8000-000000000007?fp=ios&fragment=1"), env, {}
  );
  const link = await subscription.text();
  assert.match(link, /^vless:\/\//);
  assert.match(link, /front\.example/);
  assert.match(link, /fp=ios/);
  assert.match(link, /fragment=1%2C1-1%2Ctlshello/);
  assert.equal(db.updates.length, 1);
});

test("Zeus rejects exhausted users without incrementing requests", async () => {
  const db = d1For({
    id: 8,
    username: "spent",
    uuid: "00000000-0000-4000-8000-000000000008",
    connection_type: "vless",
    limit_gb: 1,
    used_gb: 1,
    expiry_days: 0,
    max_requests: 0,
    request_count: 0,
    max_connections: 0,
    created_at: 0,
    last_seen: 0,
    enabled: 1,
  });
  const response = await handleWorkerRequest(
    new Request("https://edge.example/sub/00000000-0000-4000-8000-000000000008"),
    { DB: db, VLESS_RELAY: { fetch() {} } },
    {}
  );
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, "user_disabled");
  assert.equal(db.updates.length, 0);
});

test("Zeus rejects username credential lookup and unauthenticated status", async () => {
  const db = d1For(null);
  const relay = { fetch() { throw new Error("not called"); } };
  const subscription = await handleWorkerRequest(
    new Request("https://edge.example/sub/alice"),
    { DB: db, VLESS_RELAY: relay },
    {}
  );
  assert.equal(subscription.status, 400);

  const status = await handleWorkerRequest(
    new Request("https://edge.example/status/00000000-0000-4000-8000-000000000007"),
    { DB: db, PANEL_AUTH_TOKEN: "secret" },
    {}
  );
  assert.equal(status.status, 401);
});

test("generated WebSocket paths delegate only when a relay binding exists", async () => {
  const request = new Request("https://edge.example/In_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh", {
    headers: { Upgrade: "websocket" },
  });
  const unavailable = await handleWorkerRequest(request, {}, {});
  assert.equal(unavailable.status, 503);

  const delegated = await handleWorkerRequest(request, {
    VLESS_RELAY: { fetch() { return new Response("delegated", { status: 202 }); } },
  }, {});
  assert.equal(delegated.status, 202);
});
