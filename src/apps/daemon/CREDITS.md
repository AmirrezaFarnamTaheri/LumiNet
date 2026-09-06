# LumiNet Server — Upstream Credits & Attribution

This file lists external projects that current LumiNet source references, adapts,
or retains attribution for. Current implementation paths use the canonical `src/`
layout. Historical-only references remain attributed here when provenance matters;
the detailed historical mapping lives under `docs/porting/` and `docs/audit/`.

> ⚠️ Files marked as GPL-3.0 derivatives are **interface-shape references only**
> (stub wrappers). No GPL source code was copied verbatim. See individual file
> headers for per-file attribution.

---

## Current References and Attributions

| Project | License | Current role / attribution |
|---------|---------|----------------------------|
| sing-box | GPL-3.0 (see note) | `internal/runtime/proxy/singbox_core_{embed,stub}.go`; subscription rule-shape references under `internal/integrations/sub/` |
| v2ray-core | MIT | Historical configuration/protocol reference; no dedicated current adapter file |
| Xray-core | MPL-2.0 | `internal/runtime/proxy/xray_core_{embed,stub}.go` |
| outline-ss-server / Outline client | Apache 2.0 | `internal/runtime/proxy/ss_prefix.go` |
| pion/dtls | MIT | Historical transport reference; no dedicated current adapter file |
| pion/transport | MIT | Historical transport reference; no dedicated current adapter file |
| naiveproxy | BSD-3 | `internal/networking/proxyconfig/parser_naive.go`, `internal/runtime/proxy/naive_auth.go` |
| wireguard-go (tailscale fork) | MIT | Historical WireGuard implementation reference; current WARP owner is `internal/runtime/warp/` |
| tailscale-client-go | BSD-3 | Historical compatibility reference; embedded Tailscale control is currently reported unavailable |
| lantern | Apache 2.0 | Historical IPC/process reference |
| caddy | Apache 2.0 | `internal/platform/system/caddy.go` |
| haproxy sFlow instrumentation | GPL-2.0 w/ runtime exception | Historical telemetry reference; retired active implementation is preserved by audit provenance |
| Scrapling | MIT | Historical anti-bot reference; retired active implementation is preserved by audit provenance |
| netns | MIT | `internal/platform/system/netns_helper*.go`, `internal/platform/system/netns_tunnel.go` |
| wazero | Apache 2.0 | Historical WASM reference; no current product adapter |
| UptimeFlare | MIT | `internal/platform/system/plimit_probe.go`, scanner uptime behavior |
| subconverter | GPL-2.0 | Subscription-shape concept reference under `internal/integrations/sub/` |
| MaybeScanner / MaybeEdgeScanner | Internal/proprietary | `internal/analysis/scanner/blackrock.go` and scanner orchestration concepts |
| WhiteDNS | Unknown | `internal/runtime/warp/warp_scanner.go` and DNS/scanner concept references |
| iproute2 | GPL-2.0 | Host-network traffic-control concept reference under `internal/platform/system/` |

## GPL-3.0 Referenced Projects (interface stubs only)

The following projects are GPL-3.0. LumiNet uses their **API shapes** as
scaffolding for its own implementations. No GPL source code was copied.
If this changes, GPL-3.0 compliance (source disclosure) is required.

- `sing-box` (SagerNet) — current sing-box core adapters under `internal/runtime/proxy/`
- `sing-mux` — historical interface-shape reference
- `sing-quic` — historical interface-shape reference
- `sing-dns` — historical DNS interface-shape reference
- `sing-tun` — historical TUN interface-shape reference
- `sing-vmess-for-meta` — historical VMess interface-shape reference
- `GreenTunnel` — TLS fragmentation concept reference; current implementation is `internal/protocols/tlsfragment/`

## Licenses Requiring Verification

The following upstream licenses have not been confirmed. Do not ship binaries
referencing these until licenses are verified:

- `REALITY-main` (custom/proprietary?)
- `PsiphonOverMITM-main`
- `vps-warp-main`
- `hawk-proxy`
- `wormhole-master`
- `eve-xui-manager`
- `bia-pain-bache`
- `Exclave-dev`

---

*Reviewed against current source layout: 2026-08-09. Update this file when adding, retiring, or relocating attributed implementation.*
