import assert from "node:assert/strict";
import test from "node:test";

import {
  FIXED_HTTP_CONTRACT_VERSION,
  authorized,
  fixedTarget,
  hopCount,
  rejectHop,
  sanitizedHeaders,
} from "./fixed_http_contract.mjs";

test("fixed-target contract sanitizes relay and forwarding headers", () => {
  const headers = sanitizedHeaders({
    Host: "attacker.example",
    "X-Forwarded-For": "10.0.0.1",
    "X-Relay-Hop": "7",
    Authorization: "Bearer relay-secret",
    Cookie: "session-secret",
    "X-Request-ID": "req-1",
    Accept: "application/octet-stream",
  });
  assert.equal(headers.has("host"), false);
  assert.equal(headers.has("x-forwarded-for"), false);
  assert.equal(headers.has("x-relay-hop"), false);
  assert.equal(headers.has("authorization"), false);
  assert.equal(headers.has("cookie"), false);
  assert.equal(headers.get("x-request-id"), "req-1");
});

test("fixed-target contract bounds loops and preserves target path/query", async () => {
  const request = new Request("https://relay.example/edge?x=1", {
    headers: { "X-LumiNet-Relay-Hop": "2" },
  });
  const response = rejectHop(request);
  assert.equal(response.status, 508);
  assert.equal((await response.json()).error.code, "loop_detected");
  assert.equal(hopCount(request.headers), 2);
  assert.equal(fixedTarget("https://origin.example/base", "/edge?x=1").toString(), "https://origin.example/base/edge?x=1");
});

test("fixed-target contract supports bearer and legacy relay auth", () => {
  const env = { RELAY_AUTH_KEY: "secret" };
  assert.equal(authorized(new Request("https://relay.example", { headers: { Authorization: "Bearer secret" } }), env, false), true);
  assert.equal(authorized(new Request("https://relay.example", { headers: { "X-GSA-Auth-Key": "secret" } }), env, false), true);
  assert.equal(authorized(new Request("https://relay.example?key=secret"), env, true), true);
  assert.equal(FIXED_HTTP_CONTRACT_VERSION, 1);
});
