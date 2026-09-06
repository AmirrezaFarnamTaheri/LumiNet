import assert from "node:assert/strict";
import test from "node:test";

process.env.TARGET_DOMAIN = "https://origin.example/base";
process.env.RELAY_AUTH_KEY = "secret";

const { default: handler } = await import(`./index.js?test=${Date.now()}`);

function responseRecorder() {
  return {
    statusCode: 200,
    headers: {},
    body: "",
    headersSent: false,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    end(value = "") { this.body = value; this.headersSent = true; },
  };
}

test("Vercel adapter forwards fixed target with sanitized headers", async () => {
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url: String(url), options };
    return new Response(null, { status: 204, headers: { "content-type": "text/plain" } });
  };
  try {
    const req = {
      method: "GET",
      url: "/path?q=1",
      headers: {
        host: "relay.example",
        authorization: "Bearer secret",
        "x-forwarded-for": "127.0.0.1",
        "x-request-id": "req-1",
      },
    };
    const res = responseRecorder();
    await handler(req, res);
    assert.equal(res.statusCode, 204);
    assert.equal(captured.url, "https://origin.example/base/path?q=1");
    assert.equal(captured.options.headers.get("x-forwarded-for"), null);
    assert.equal(captured.options.headers.get("x-luminet-relay-contract"), "1");
    assert.equal(captured.options.headers.get("x-luminet-relay-hop"), "1");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Vercel adapter rejects unauthorized and looped requests", async () => {
  const unauthorized = responseRecorder();
  await handler({ method: "GET", url: "/", headers: { host: "relay.example" } }, unauthorized);
  assert.equal(unauthorized.statusCode, 401);

  const looped = responseRecorder();
  await handler({ method: "GET", url: "/", headers: { host: "relay.example", authorization: "Bearer secret", "x-relay-hop": "2" } }, looped);
  assert.equal(looped.statusCode, 508);
});
