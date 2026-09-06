# Post-refactor-226 peer synthesis

## Current-wave disposition

The 893 semantic records resolve as: 434 hardened, 248 superseded, 63 adapted, 61 inspired-native, 60 guardrail-derived, 14 reference-only donor anchors, and 13 recomposed. The evidence pass gives every one of the 745 high-signal implementation/test/configuration/script/deployment/UI surfaces its own focused disposition.

## Donor-by-donor result

- `shadowsocks-crypto`: framing/key/replay behavior is a hardening oracle; execution remains core-manager-owned.
- `shadowsocksR`: legacy protocol/obfuscation behavior is guardrail evidence. Unsupported SSR remains unsupported rather than being mapped to a different protocol.
- `shadowsocks-rust`: broad TCP/UDP/replay/service/ACL/plugin/TUN/DNS behavior is used as a high-signal oracle, not as a second runtime.
- `srsc`: rule parsing/normalization value is adapted into local offline rule evidence; independent conversion/server authority is superseded.
- `ssh`: the upstream stack is already dependency-owned; target-specific authentication admission is hardened before dial.
- `subconverter`: useful rule/config normalization semantics are adapted; independent converter/service/template authority is superseded.
- `tailscale-client`: ETag/CAS, patch-vs-replace, key creation, route mutation and webhook rotation semantics inspire a credential-free transaction planner.
- `TinyTun`: SOCKS wire-boundary lessons harden existing owners; duplicate TUN/eBPF/process-routing runtime is superseded.
- `Tools`: TCP-open versus genuine WebSocket-101 distinction inspires protocol-readiness evidence; mutable proxy corpora are not runtime authority.
- `ts-browser-ext`: native-host/profile/loopback/permission state semantics inspire a non-registering handoff planner.
- `tsheadroom`: deterministic affinity, hard deadlines, saturation handling and capped recovery inspire worker-planning evidence; no supervisor process is adopted.
- `mwgp`: receiver-index lifetime/source identity and obfuscation claim limits become WireGuard guardrails.
- `PaaS-vmess-trojan-argo`: service composition/start/rollback/recovery relationships are recomposed into a bounded gateway DAG planner; installer mutation is not adopted.
- `Reverse_tls`: reverse-client/server/path-router/health composition contributes to the same target-native gateway planner without importing mutable deployment authority.

## Second-order synthesis

The pass deliberately converges mechanisms across donors rather than preserving donor package boundaries:

1. Shadowsocks crypto, shadowsocks-rust, ShadowsocksR and existing core-manager behavior resolve to one runtime owner plus stricter admission and explicit unsupported-protocol failure.
2. TinyTun and existing Go/Rust SOCKS paths resolve to one framing contract: validate before narrowing, reject unsupported response types.
3. SRSC/subconverter parsing value resolves to local offline Rules normalization rather than another remote conversion service.
4. Tailscale-client semantics resolve to transaction shape/ETag evidence without a second Tailnet client.
5. Browser-extension and worker-runtime mechanisms become operator evidence contracts without host/process authority.
6. PaaS and Reverse-TLS deployment patterns fuse into one role/dependency/rollback/recovery planner.
7. MWGP mechanics constrain the existing WireGuard policy owner instead of becoming a second device implementation.

## Historical preservation

Post-refactor-224 and 225 remain immutable evidence layers. The 52-donor overlay appends 226 evidence rather than rewriting earlier semantic records. Historical checkers use explicit successor-freeze/hash-chain logic only where 226 intentionally retires a previously valid target path.
