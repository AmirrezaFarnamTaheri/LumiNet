# Post-refactor-224 peer synthesis

## Composition groups

- **KCP policy:** `kcp-go` + `libkcp` -> one bounded Go policy feeding the existing real KCP+SMUX runtime; upstream implementation internals are not forked.
- **Endpoint ownership:** `load-balancer` + `l7mp` + `l7-snake` -> health/circuit/capacity/load/stickiness/freshness evidence under existing diagnostics planners, subordinate to materially better measured quality.
- **Resolver evidence:** `luci-app-https-dns-proxy` -> HTTPS-only resolver admission, canary/circuit tiers, priority/RTT fallback ordering and explicit Quad9 variants, without installation authority.
- **Offline patterns:** `l7-protocols` -> bounded RE2 admission and hashes, without live DPI.
- **Relay efficiency:** JJ TCP-over-HTTP -> shared adaptive idle polling inside existing relay owners; unsupported server-held long polling and certificate bypass are rejected.
- **Parser oracles:** `Iran-configs` + `libXray` -> credential-free protocol-shape regression tests rather than volatile accounts/global wrapper runtime.
- **Routing provenance:** `Iran-v2ray-rules` -> normalization/provenance/category evidence and stable target-native intents, not copied mutable lists.
- **Traffic behavior:** Marionette -> bounded declarative profile/state analysis and four target-native presets; executable DSL/plugins/updater/runtime are rejected.
- **Backpressure truth:** `log-demultiplexer` -> monotonic transient fan-out loss counters while existing durable jobs remain authoritative.
- **Negative security evidence:** LACUNA -> removal/guardrail against false evasion authority.
- **Parser guardrail:** `mhurl` -> reject ambiguous multi-authority URL syntax while preserving ordinary single-host/bracketed-IPv6 links.

## l7mp

Health/session/load/freshness semantics are decomposed into target planners. Kubernetes/Helm/OpenAPI/listener/session/eBPF control-plane ownership is not transplanted.

## l7-snake

Typed health/status evidence contributes to mesh planning. Donor gRPC/server/bootstrap/deployment authority is superseded.

## l7-protocols

Runtime value is limited to bounded offline expression admission. Malware/file corpora, grouping/build scripts and speed/test assets remain reference evidence and do not become packet-inspection authority.

## log-demultiplexer

Bounded slow-consumer semantics inform the WebSocket owner. Its daemon/config/disk-spool architecture is superseded because LumiNet already has durable job truth.

## marionette

Versioned state/profile ideas and example behavior become declarative analysis/presets. Channel/record/multiplexer/runtime/plugin/update machinery remains reference or rejected evidence.

## libxray

Share/protocol shape informs parser tests. Global GC, port/file helpers, platform DNS/controller/download wrappers and multi-platform wrapper runtime are superseded by existing target owners.

## libkcp

C/C++ algorithm/FEC/server/build harnesses corroborate KCP policy semantics. They do not create a second native KCP runtime.
