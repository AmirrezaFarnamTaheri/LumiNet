# Post-refactor-225 peer synthesis

## Current-wave donors

The 23 current donors are evaluated below by their strongest retained value, not by repository branding.

- **SNI-ByPass**: deployment/service ordering, DNS/TLS/HTTP conflict and rollback evidence. Broad installer mutation is rejected.
- **SNI-Spoofing-Go**: strongest structured ClientHello/SNI, TCP sequence wrap, path MTU/header sizing, connection-state and platform preflight oracles. Raw packet-injection runtimes are superseded by existing owners.
- **SNI-Spoofing Python**: parser/connection/cleanup comparison evidence; packet-spoofing authority is not duplicated.
- **SNISPF-HJ**: first-response-qualified success and active/reserve/drain pool lifecycle. Connect-only success is explicitly weaker evidence.
- **mitm-proxy**: secret-bearing artifact and fail-fast/config/logging negative evidence; bundled private CA key is quarantined evidence only.
- **mitm_relay**: relay lifecycle distinctions; arbitrary scriptable mutation, insecure TLS and magic-byte STARTTLS are rejected.
- **sing-box-rules**: generated routing-artifact provenance and digest asymmetry, recomposed into immutable provenance admission.
- **sing-dns**: DNS transport registry, fallback, cache/rejection, ECS, A/AAAA strategy and transport-loop semantics; correlation-ID cleanup and TTL inconsistencies become negative oracles.
- **sing-mux**: mux negotiation/session/admission/padding/application-byte semantics; existing SMUX runtime remains authoritative.
- **v2rayCustomRoutingList**: routing grammar/precedence/remote-descriptor fixtures; mutable lists remain non-authoritative.
- **v2rayNG**: Android config/lifecycle/UI/navigation/subscription/update/VPN/WebDAV/dialer oracles. LumiNet retains stronger identity continuity and transactional update staging; local profile/node search is adopted as product UX.
- **v2raya-scoop**: immutable artifact hashes, persistent data/service lifecycle and reversible install evidence; shell `Invoke-Expression` is a negative oracle.
- **tun2socket**: NAT/packet translation oracles; target userspace TUN is hardened instead of porting a second translator. Donor offset/broadcast defects are negative tests.
- **udp-ring-queue**: bounded oldest-first eviction, preallocation, batch export/restore and counters; unsafe framing/count assumptions are rejected.
- **UptimeFlare**: incident/maintenance/grace/recovery/persistence-cooldown lifecycle and status UX; credential-bearing templated webhook logging is rejected.
- **uTLS**: fingerprint synthesis/trial/reuse behavior and ClientHello comparison corpus; ECH/QUIC/session internals remain upstream/reference where existing target owners are stronger.
- **WarpScanner Android GUI**: endpoint ranking/export workflow and scan UX; copied evidence cannot activate a WARP endpoint.
- **Wintun**: session-ring capacity/alignment/acquire-release/corruption contracts; the actual target wrapper is hardened and the duplicate wrapper removed.
- **WireGuard-Go/Tailscale**: AllowedIPs, replay, rate/cookie, key/session timing and device lifecycle evidence; target gains readiness planning and key-material truth without another WireGuard device.
- **Wormhole**: declarative segment/chain/tunnel init-trigger-cleanup semantics, recomposed into a bounded non-executing workflow planner.
- **TT**: terminal width/input/progress primitives are explicitly superseded by the existing Bubble Tea/Lip Gloss TUI stack; typing-game domain is outside target responsibility.
- **TUIC implementation donor**: QUIC session/auth/UDP/congestion/0-RTT state machine and malformed-frame oracles; target codec/runtime bounds are hardened.
- **TUIC specification/reference donor**: wire grammar and command semantics; exact auth-frame and pre-auth behavior are used as compatibility evidence.

## Reopened inherited post-refactor-224 donors

The 15 immutable 224 donors were re-evaluated at product/UI/UX as well as backend level rather than assumed complete.

- kcp-go/libkcp: 224 KCP/FEC/policy/runtime ownership remains; no second implementation is added.
- l7mp/load-balancer: endpoint health/load strategy value is surfaced naturally in Connections.
- l7-protocols: offline signature admission is surfaced naturally in Rules.
- luci-app-https-dns-proxy: resolver-provider discovery now feeds DNS preset selection and DoH pool evidence.
- log-demultiplexer: backend drop/backpressure evidence now has Logs search/severity/export/backpressure UX.
- Marionette: declarative traffic profiles remain analysis-only; executable plugins are still rejected.
- JJ relay: adaptive polling remains the single shared HTTP relay polling owner.
- Iran rules/configs and libXray: provenance/parser/platform oracles remain; mutable account/rule corpora and duplicate platform runtimes are not imported.
- l7-snake: mesh/control-plane evidence remains superseded by target route planning.
- LACUNA: unsafe evasion/stack-spoofing remains a negative guardrail.
- mhurl: ambiguous multi-authority parser cases remain credential-free negative oracles.

## Second-order convergence conclusions

The strongest second-order result is consolidation, not feature count: duplicate/fake authorities were removed, natural product placement was improved, and donor mechanisms were decomposed into the smallest target-owned invariant. Higher-level planes were added only when multiple primitives cohered around one target responsibility: DNS policy, mux policy, incident lifecycle, queue/backpressure policy, WireGuard readiness, and declarative network workflow planning.
