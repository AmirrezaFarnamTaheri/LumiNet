# Post-refactor-225 all-history second-order convergence audit

This audit reopens every donor represented by the immutable post-refactor-224 wave and the current post-refactor-225 wave across backend/runtime, frontend/UI/UX, control-plane, data/config, tests/oracles, deployment/operations, and security/authority layers. It does not rewrite immutable 224 record IDs; it overlays current target ownership and product placement.

## Mechanical denominator

- Donors: **38** wave-scoped peers (15 from 224 + 23 from 225).
- Surfaces: **2461** (913 inherited 224 + 1548 current 225).
- Definition-level symbols: **9511** (2256 + 7255).
- Module/subtree audit groups: **202**.
- High-signal implementation/test/config/script/deployment/UI surfaces: **1572**.
- UI/product donor surfaces re-reviewed: **159**.
- Semantic records retained: **72 immutable 224 + 1133 current 225**.

## Cross-wave product/backend uplifts

- **Iran-configs-main** → test/security: proxy-format/parser oracles only; credential-bearing live endpoints never imported. Current surface: Proxy parser tests / governance.
- **Iran-v2ray-rules-main** → data/control-plane/product: routing corpus provenance and immutable-artifact admission, mutable donor lists remain non-authoritative. Current surface: Rules · routing artifact provenance.
- **JJTcpOverHttpRelayVpn-python_testing_tcp_relay** → runtime/control-plane: adaptive idle polling extracted; scripted/MITM relay authority rejected. Current surface: Runtime relay + Operations relay inspection.
- **LACUNA-Chain-main** → security/authority: negative guardrail: call-stack/EDR-spoofing capability removed from production surface. Current surface: No operator authority.
- **kcp-go-master** → runtime/control-plane: shared KCP policy + real Go KCP runtime; AES-GCM opt-in; bounded FEC/tuning. Current surface: Operations convergence lab; Connections runtime evidence.
- **l7-protocols-master** → security/control-plane/product: offline bounded RE2 signature admission; no DPI install authority. Current surface: Rules · L7 signature admission.
- **l7-snake-main** → control-plane: mesh route evidence with stale/unhealthy exclusion and bounded degraded penalty. Current surface: Operations mesh diagnostics.
- **l7mp-master** → control-plane/product: health/load/circuit dispatch semantics recomposed into bounded endpoint pool. Current surface: Connections · Endpoint dispatch evidence.
- **libXray-main** → runtime/test: format/config/platform utility oracles; target runtime/parser owners remain authoritative. Current surface: Proxy/runtime tests.
- **libkcp-master** → runtime/control-plane: KCP/FEC protocol/test oracles consolidated into shared KCP policy/runtime. Current surface: Operations convergence lab.
- **load-balancer-master** → control-plane/product: load/dispatch/failure semantics superseded by bounded quality-first endpoint pool. Current surface: Connections · Endpoint dispatch evidence.
- **log-demultiplexer-master** → observability/product: backpressure/drop evidence productized as local filter/export and websocket loss counters. Current surface: Logs.
- **luci-app-https-dns-proxy-main** → data/control-plane/product: resolver provider catalog + policy/fallback evidence exposed without UCI ownership. Current surface: DNS · presets, policy, DoH pool evidence.
- **marionette-master** → control-plane: bounded declarative traffic profile/state-graph planner; plugins/actions never execute. Current surface: Operations convergence lab.
- **mhurl-main** → security/test: ambiguous multi-authority URL cases become parser guardrails. Current surface: Proxy parser tests.

## Current-wave higher-level composition

- **mitm-proxy** → security/control-plane: private-key-bearing artifacts become quarantine guard; interception runtime rejected. Current surface: Operations artifact admission.
- **mitm-relay** → security/control-plane: relay/STARTTLS design inspection; arbitrary mutation/insecure TLS rejected. Current surface: Operations relay inspection.
- **routing-list** → data/control-plane/product: rule grammar/provenance fixtures without importing mutable lists. Current surface: Rules.
- **sing-box-rules** → data/control-plane/product: remote routing artifact provenance/digest admission without install authority. Current surface: Rules.
- **sing-dns** → data/control-plane/product: DNS transport/fallback/cache/ECS/truncation policy without a second resolver. Current surface: DNS.
- **sing-mux** → runtime/control-plane/product: multiplex admission/capacity/padding/accounting policy around single SMUX owner. Current surface: Connections.
- **sni-bypass** → deployment/control-plane: reversible DNS/TLS-router/redirect preflight, no installer mutation authority. Current surface: Operations SNI gateway planner.
- **sni-spoofing-go** → runtime/control-plane/product: structured ClientHello/SNI, path evidence and bounded diagnostic UX; packet injector not copied. Current surface: Dashboard/Operations.
- **sni-spoofing-python** → runtime/test: parser/connection/packet-template oracles; packet injection authority superseded. Current surface: SNI diagnostics.
- **snispf-hj** → control-plane: first-response-qualified SNI pool lifecycle and bounded discovery; insecure CERT_NONE rejected. Current surface: Operations/Dashboard.
- **tt** → product: terminal width/input/layout/progress primitives superseded by Bubble Tea/Lip Gloss TUI. Current surface: TUI.
- **tuic-impl** → runtime/security: TUIC wire/option bounds; false raw-TCP covert TUIC retired. Current surface: Core TUIC owner.
- **tuic-spec** → runtime/security: protocol framing/auth/0-RTT semantics used as target wire oracle. Current surface: Core TUIC owner.
- **tun2socket** → runtime/security: packet/NAT edge oracles harden actual userspace TUN owner; fake facades retired. Current surface: TUN runtime.
- **udp-ring-queue** → observability/control-plane: bounded eviction/batch/restore/counter policy; unsafe wire decoder rejected. Current surface: Operations queue planner.
- **uptimeflare** → observability/product: incident/maintenance lifecycle + recovery/grace/cooldown evidence. Current surface: Health; Logs.
- **utls** → runtime/control-plane: fingerprint trial/reuse policy while TLS/ECH/QUIC internals remain upstream/current-owner. Current surface: Operations; TLS runtime.
- **v2raya-scoop** → deployment/security: immutable package/hash/service lifecycle reference; dynamic expression execution rejected. Current surface: Update/install governance.
- **v2rayng** → product/runtime/security: profile search/mobile lifecycle/import/update/VPN oracles; stronger target owners retained. Current surface: Profiles; Rules; Settings.
- **warpscanner-android** → control-plane/product: ranked WARP scan evidence and export without activation/persistence authority. Current surface: Settings.
- **wintun** → runtime/security: ring/packet admission hardens live Wintun owner; duplicate wrapper removed. Current surface: Windows TUN runtime.
- **wireguard-go** → runtime/control-plane/security: AllowedIPs/replay/rate/cookie/key lifecycle readiness around existing WireGuard owner. Current surface: Operations WireGuard planner.
- **wormhole** → control-plane: bounded declarative network workflow with reverse cleanup; no shell/docker/netns execution. Current surface: Operations workflow planner.

## Second-order invariants

- A donor-wide or module-wide record is context, not proof that every small implementation/test/config/UI leaf was semantically reviewed. Current 225 high-signal leaves therefore retain focused file/module decisions.
- Product/UI convergence cannot create a second authority path: presets load drafts, planners are read-only, WARP scan output can be copied/exported but not activated, and routing/L7/DoH evidence cannot install runtime state.
- Runtime convergence prefers a single live owner: duplicate Wintun and fake TUN/TUIC/MITM facades were retired rather than retained alongside stronger owners.
- Negative donor evidence is first-class: insecure TLS, bundled private keys, unchecked frame counts, fabricated credentials, unverified restore/update paths, secret-bearing logs, and ambiguous authority are converted to guards or explicit rejection.
- Automatic config mutation retry remains single-owned: 3 default attempts, 8 maximum, fresh state for each conflict retry, revision-conflict-only replay, and explicit ExpectedRevision disables automatic replay.

## Evidence files

- `post-refactor-225-all-history-surface-audit.csv` — every 224/225 donor surface with current layer/product overlay.
- `post-refactor-225-all-history-module-audit.csv` — subtree composition and layer coverage.
- `post-refactor-225-all-history-symbol-index.csv` — normalized 9k+ definition index across both waves.
- `post-refactor-225-all-history-summary.json` — machine-readable denominators.
