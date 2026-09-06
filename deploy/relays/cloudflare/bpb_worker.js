/**
 * BPB (Bia-Pain-Bache) Cloudflare Worker Panel Adapter
 * Ported from bia-pain-bache-main/bia-pain-bache-main/_worker.js (v2.7, 326KB)
 *
 * Platform: Cloudflare Workers
 *
 * Active adapter features:
 *   - Sing-box VLESS and WireGuard (Warp) configuration generation.
 *   - Advanced routing rules for ads, malware, QUIC, and regional bypasses.
 *   - Proxy-chain configuration discovery.
 *   - Optional VLESS WebSocket delegation through the VLESS_RELAY service binding.
 */

import { healthResponse, jsonResponse } from "./worker_contract.mjs";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const websocketPath = "/In_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh";

    if (url.pathname === websocketPath && request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      if (!env.VLESS_RELAY?.fetch) return jsonResponse({ error: "relay_unavailable" }, { status: 503 });
      return env.VLESS_RELAY.fetch(request);
    }

    // Health check endpoint for integration testing
    if (url.pathname === "/healthz") {
      return healthResponse("bpb-panel");
    }

    // Proxy IP Chain configuration endpoint
    if (url.pathname === "/chain-proxy") {
      const chainIP = env.CHAIN_PROXY_IP ?? "1.1.1.1";
      return jsonResponse({ status: "configured", chainIP });
    }

    if (url.pathname === "/routing-rules" && request.method === "GET") {
      return jsonResponse(generateBPBRoutingRules());
    }

    if (url.pathname === "/sing-box" && request.method === "POST") {
      let input;
      try {
        input = await request.json();
      } catch {
        return jsonResponse({ error: "invalid_json" }, { status: 400 });
      }
      const required = ["uuid", "host", "sni", "reserved", "privateKey"];
      const missing = required.filter((key) => input[key] === undefined || input[key] === "");
      if (missing.length > 0) {
        return jsonResponse({ error: "missing_fields", fields: missing }, { status: 400 });
      }
      const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
      if (!uuidPattern.test(input.uuid)) return jsonResponse({ error: "invalid_uuid" }, { status: 400 });
      if (!hostnamePattern.test(input.host) || !hostnamePattern.test(input.sni)) {
        return jsonResponse({ error: "invalid_hostname" }, { status: 400 });
      }
      if (!Array.isArray(input.reserved) || input.reserved.length !== 3 ||
          input.reserved.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
        return jsonResponse({ error: "invalid_reserved" }, { status: 400 });
      }
      if (!env.VLESS_RELAY?.fetch) {
        return jsonResponse({ error: "relay_unavailable" }, { status: 503 });
      }
      return jsonResponse(buildSingBoxConfig(
        input.uuid,
        input.host,
        input.sni,
        input.reserved,
        input.privateKey
      ));
    }

    if (url.pathname === "/" && request.method === "GET") {
      return jsonResponse({
        worker: "bpb-panel",
        status: env.VLESS_RELAY?.fetch ? "ready" : "configuration_only",
        routes: ["/healthz", "/chain-proxy", "/routing-rules", "/sing-box"],
        formats: ["sing-box"],
        transports: env.VLESS_RELAY?.fetch ? ["vless-ws-tls", "wireguard-warp"] : [],
      });
    }

    return jsonResponse({ error: "not_found" }, { status: 404 });
  },
};

/**
 * generateBPBRoutingRules builds standard BPB domain and IP block rules.
 * Preserves the exact Iran/China/Russia bypass list and ad block classes from worker.js.
 */
export function generateBPBRoutingRules() {
  return {
    blockRules: [
      "geosite:category-ads-all",
      "geosite:malware",
      "geosite:phishing",
      "geoip:private",
    ],
    bypassRules: [
      "geosite:cn",
      "geoip:cn",
      "geosite:ir",
      "geoip:ir",
      "geosite:ru",
      "geoip:ru",
    ],
    blockQuic: true,
  };
}

/**
 * buildSingBoxConfig generates the JSON subscription configuration for Sing-Box.
 * Supports uTLS fingerprint mapping and a VLESS_RELAY-backed WebSocket path.
 */
export function buildSingBoxConfig(uuid, host, sni, reserved, privateKey) {
  return {
    outbounds: [
      {
        type: "vless",
        tag: "VLESS-TLS",
        server: host,
        server_port: 443,
        uuid: uuid,
        tls: {
          enabled: true,
          server_name: sni,
          utls: {
            enabled: true,
            fingerprint: "chrome",
          },
        },
        transport: {
          type: "ws",
          path: "/bpb/In_Panel_Rayeghan_Ast_Va_Gheyre_Ghabele_Foroosh",
        },
      },
      {
        type: "wireguard",
        tag: "Warp-WireGuard",
        server: "162.159.192.1",
        server_port: 2408,
        local_address: ["172.16.0.2/32", "2606:4700:110:8f92:c7b9:6e18:b47d:bc6a/128"],
        private_key: privateKey,
        peer_public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        reserved: reserved,
      },
    ],
  };
}
