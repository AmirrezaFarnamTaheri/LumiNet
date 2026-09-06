import assert from "node:assert/strict";
import test from "node:test";

import worker from "./cloudflare_worker.js";

const env = {
  AUTH_KEY: "secret",
  RELAY_URL: "https://origin.example/tunnel",
  MAX_BODY_BYTES: "64",
};

test("serverless relay propagates the fixed contract to the upstream", async () => {
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (input, init) => {
    captured = { input: String(input), init };
    return new Response("upstream", { status: 200 });
  };
  try {
    const response = await worker.fetch(new Request("https://relay.example/relay", {
      method: "POST",
      headers: {
        Authorization: "Bearer secret",
        "X-Request-ID": "req-1",
      },
      body: "payload",
    }), env, {});
    assert.equal(response.status, 200);
    assert.equal(captured.input, env.RELAY_URL);
    assert.equal(captured.init.headers["X-LumiNet-Relay-Contract"], "1");
    assert.equal(captured.init.headers["X-LumiNet-Relay-Hop"], "1");
    assert.equal(captured.init.headers["X-Request-ID"], "req-1");
    assert.equal(await new Response(captured.init.body).text(), "payload");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("serverless relay rejects unauthorized, looped, and oversized requests", async () => {
  const unauthorized = await worker.fetch(new Request("https://relay.example/relay", { method: "POST", body: "x" }), env, {});
  assert.equal(unauthorized.status, 401);
  assert.equal((await unauthorized.json()).error.code, "unauthorized");

  const looped = await worker.fetch(new Request("https://relay.example/relay", {
    method: "POST",
    headers: { Authorization: "Bearer secret", "X-LumiNet-Relay-Hop": "2" },
    body: "x",
  }), env, {});
  assert.equal(looped.status, 508);
  assert.equal((await looped.json()).error.code, "loop_detected");

  const oversized = await worker.fetch(new Request("https://relay.example/relay", {
    method: "POST",
    headers: { Authorization: "Bearer secret" },
    body: "x".repeat(65),
  }), env, {});
  assert.equal(oversized.status, 413);
  assert.equal((await oversized.json()).error.code, "body_too_large");
});
