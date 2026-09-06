# Post-refactor-226 all-history second-order convergence audit

The immutable 224/225 evidence is preserved and the 14-donor 226 wave is overlaid without rewriting historical record IDs.

## Mechanical denominator

- Wave-scoped donors: **52**.
- Surfaces: **3760** (913 + 1548 + 1299).
- Definition-level symbols: **25486** (2256 + 7255 + 15975).
- Top-level module/subtree groups: **284**.
- High-signal surfaces: **2317**.
- UI/product donor surfaces: **161**.
- Semantic records retained/appended: **72 + 1133 + 893**.

## 226 composition results

- **browser-ext** → control-plane/product: profile/native-host/loopback handoff readiness without mutation. Product surface: Settings.
- **mwgp** → security/control-plane: source-bound expiring receiver-index mappings + obfuscation claim guardrail. Product surface: Operations.
- **paas-gateway** → deployment/control-plane/product: immutable gateway DAG/start/rollback/recovery plan. Product surface: Operations.
- **reverse-tls** → deployment/control-plane/product: reverse/listener lifecycle recomposed into gateway DAG. Product surface: Operations.
- **shadowsocks-crypto** → runtime/security: SS2022 key admission + sole external-core runtime. Product surface: Profiles/Connections.
- **shadowsocks-rust** → runtime/security: runtime/crypto oracle; duplicate local authorities retired. Product surface: Profiles/Connections.
- **shadowsocksr** → security/runtime: unsupported SSR/unknown protocol fails closed. Product surface: Connections.
- **srsc** → data/control-plane/product: local bounded rule normalization only. Product surface: Rules.
- **ssh** → runtime/security: pre-network authentication admission around dependency-owned SSH. Product surface: Connections.
- **subconverter** → data/control-plane/product: local bounded rule normalization; remote/template/script server authority superseded. Product surface: Rules.
- **tailscale-client** → control-plane/product: credential-free transactional change plan. Product surface: Settings.
- **tinytun** → runtime/security: SOCKS wire bounds; TUN/eBPF/process runtime superseded. Product surface: Connections.
- **tools** → control-plane/product: HTTP 101 WebSocket protocol readiness evidence. Product surface: Connections.
- **tsheadroom** → control-plane/product: deterministic affinity/deadline/restart planning. Product surface: Health.

## Cross-wave invariants

- Existing 224/225 source/evidence identities are historical facts; successor changes are represented as a new wave rather than back-edited into old ledgers.
- Runtime/write authority remains single-owned. New 226 planners are non-executing and cannot dial, fetch, register browser hosts, call Tailnet, start processes, or install service configuration.
- Unsupported proxy protocols fail closed; SS2022 key material is validated before runtime handoff.
- Receiver-index translation never weakens WireGuard authentication/replay semantics and packet obfuscation is classified as traffic-shape modification only.
- Automatic configuration mutation retry remains single-owned with 3 default attempts, max 8, fresh state on revision conflicts, conflict-only replay, and one attempt under explicit ExpectedRevision.
