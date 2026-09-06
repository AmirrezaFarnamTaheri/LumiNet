import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import {
  FIXED_HTTP_CONTRACT_VERSION,
  authorized,
  fixedTarget,
  rejectHop,
  relayError,
  requestId,
  sanitizedHeaders,
} from "../../../relays/fixed_http_contract.mjs";

export const config = {
  api: { bodyParser: false },
  supportsResponseStreaming: true,
  maxDuration: 60,
};

const TARGET_BASE = (process.env.TARGET_DOMAIN || "").replace(/\/$/, "");

export default async function handler(req, res) {
  const incomingHeaders = {};
  for (const [key, value] of Object.entries(req.headers)) {
    incomingHeaders[key] = Array.isArray(value) ? value.join(", ") : value;
  }
  const relayRequest = new Request(`https://${req.headers.host || "vercel.invalid"}${req.url}`, {
    method: req.method,
    headers: incomingHeaders,
  });

  if (!TARGET_BASE) {
    const response = relayError("configuration_error", 500, requestId(relayRequest));
    res.statusCode = response.status;
    return res.end(await response.text());
  }

  const loopResponse = rejectHop(relayRequest, Number(process.env.RELAY_MAX_HOPS || 2));
  if (loopResponse) {
    res.statusCode = loopResponse.status;
    return res.end(await loopResponse.text());
  }
  if (!authorized(relayRequest, process.env, false)) {
    const response = relayError("unauthorized", 401, requestId(relayRequest));
    res.statusCode = response.status;
    return res.end(await response.text());
  }

  try {
    const targetUrl = fixedTarget(TARGET_BASE, req.url);
    if (targetUrl.protocol !== "https:" && process.env.ALLOW_INSECURE_TARGET !== "true") {
      const response = relayError("target_denied", 403, requestId(relayRequest));
      res.statusCode = response.status;
      return res.end(await response.text());
    }

    const headers = sanitizedHeaders(incomingHeaders);
    headers.set("x-luminet-relay-contract", String(FIXED_HTTP_CONTRACT_VERSION));
    headers.set("x-luminet-relay-hop", "1");
    headers.set("x-request-id", requestId(relayRequest));

    const method = req.method;
    const hasBody = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";

    const fetchOpts = { method, headers, redirect: "manual" };
    if (hasBody) {
      fetchOpts.body = Readable.toWeb(req);
      fetchOpts.duplex = "half";
    }

    const upstream = await fetch(targetUrl, fetchOpts);

    res.statusCode = upstream.status;
    for (const [k, v] of upstream.headers) {
      if (k.toLowerCase() === "transfer-encoding") continue;
      try { res.setHeader(k, v); } catch {}
    }

    if (upstream.body) {
      await pipeline(Readable.fromWeb(upstream.body), res);
    } else {
      res.end();
    }
  } catch (err) {
    console.error("relay error:", err);
    if (!res.headersSent) {
      const response = relayError("upstream_failure", 502, requestId(relayRequest));
      res.statusCode = response.status;
      res.end(await response.text());
    }
  }
}
