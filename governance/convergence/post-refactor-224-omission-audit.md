# Post-refactor-224 omission and contradiction audit

## Denominator

- Supplied donor archives: **15**
- Exact donor surfaces: **913**
- Regular files: **911**
- Symlink surfaces: **2**
- Donor directories/subdirectories: **153**
- Definition-level symbol evidence: **2256**
- Semantic records: **72**
- Focused surfaces: **773**

## Audit ladder

1. **Files/symlinks:** every ZIP member is represented; CRC/path safety/duplicates/case collisions/symlink confinement and archive↔extracted byte equality are checked before semantic claims.
2. **Folders/subfolders:** all 153 donor directories have descendant/direct counts and deterministic tree hashes.
3. **Symbols:** 2,256 extracted definition-level symbols inherit exact surface hashes and semantic links.
4. **High-signal leaves:** zero implementation/test/script/deployment/UI surfaces remain linked only to a donor-base record.
5. **Independent contracts:** KCP policy/runtime controls, endpoint/mesh evidence, DoH planning, L7 admission, traffic profiles, routing corpus, relay cadence, parser oracles, mutation retry and WebSocket pressure have focused records and acceptance evidence.
6. **State/recovery:** local CAS retry, relay idle-vs-error retry, endpoint eligibility/secondary ordering and durable-job-vs-transient-event ownership are explicit state/authority boundaries.
7. **Negative paths:** credential corpora, mutable route lists, TLS bypass, server-held long poll, eBPF donor fast path, Marionette execution, LACUNA shellcode/stack spoofing and parallel donor daemons are rejected/superseded explicitly.
8. **Operator surfaces:** one authenticated Operations lab exposes read-only planners and reliability metrics without donor-branded authority.
9. **Deep leaves:** package/admin/docs/fixture/media/config leaves remain individually surface-accounted; they do not masquerade as implemented semantic capability.
10. **Historical ownership:** the two pre-existing LumiCore eBPF paths are allowed; no new donor eBPF path is admitted. The obsolete Rust KCP and StackSpoofing surfaces are explicit topology deletions.
11. **Contradiction pass:** exact pinned kcp-go v5.6.72 AEAD support was rechecked and the stale “API unavailable” rationale was removed. AES-GCM is opt-in only; full runtime compile remains a disclosed toolchain boundary.

## Surface counts by donor

- `Iran-configs-main`: 3
- `Iran-v2ray-rules-main`: 39
- `JJTcpOverHttpRelayVpn-python_testing_tcp_relay`: 44
- `LACUNA-Chain-main`: 7
- `kcp-go-master`: 46
- `l7-protocols-master`: 297
- `l7-snake-main`: 20
- `l7mp-master`: 147
- `libXray-main`: 62
- `libkcp-master`: 29
- `load-balancer-master`: 28
- `log-demultiplexer-master`: 17
- `luci-app-https-dns-proxy-main`: 65
- `marionette-master`: 102
- `mhurl-main`: 7

## Classification counts

- `configuration`: 93
- `deployment`: 49
- `documentation`: 41
- `fixture`: 216
- `governance`: 11
- `implementation`: 232
- `media`: 22
- `repository-administration`: 43
- `script`: 19
- `test`: 184
- `ui-or-product`: 3

## Semantic dispositions

- `adapted`: 5
- `extracted`: 5
- `guardrail-derived`: 2
- `inspired-native`: 5
- `recomposed`: 3
- `reference-only`: 30
- `rejected-with-reason`: 8
- `superseded`: 11
- `synthesized`: 3

## Remaining claim boundary

- The only non-`verified` semantic record is the opt-in KCP AES-GCM runtime call, which is **statically-validated** against the exact pinned dependency API because the repository-wide Go 1.26 build cannot execute in the available Go 1.23.2 environment.
- This is not a default-path regression: legacy KCP cipher identifiers and defaults are unchanged.
- No unresolved critical donor-semantic gap is known after the second-order surface/symbol/folder/authority sweep.
