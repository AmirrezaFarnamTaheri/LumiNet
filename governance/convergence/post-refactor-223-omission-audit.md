# Post-refactor-223 omission and contradiction audit

## Denominator

- Supplied archives: **13**
- Exact archive surfaces: **10331**
- Archive symlink surfaces: **30** (recorded, never followed during extraction)
- Exact historical duplicate surfaces: **123** (`Aether-GUI-main.zip`)
- Fresh/changed surfaces requiring renewed disposition: **10208**
- Extracted symbol evidence (non-vendored/generated source): **51441**
- Semantic records: **56**
- Exact 222→223 target delta before evidence files: **84**

## Audit ladder

1. **Files/symlinks:** every archive member is represented in `post-refactor-223-surface-accountability.csv`; symlinks are represented by target hashes and were not materialized.
2. **Roots/packages:** all 13 supplied archives have an archive-accountability row and a donor remainder record plus focused records for promoted/high-risk mechanisms.
3. **Symbols:** code symbols are extracted from non-vendored/generated Go/Rust/Kotlin/Java/TS/JS/Python surfaces and inherit their surface semantic links.
4. **Independent contracts:** scanner bounds, strict REALITY evidence, host-route release, HTTP→SOCKS bridge, DNS reliability, transport truth, DNS integrity, provisioning transactionality/delegation, Android lifecycle, native async/raw FFI, subscription failure/catalogue/runtime, and command aliases have separate records and acceptance evidence.
5. **State/recovery:** host proxy release, VPS generation rollback, Android VPN stages, subscription runtime exact-owner start/stop, and catalogue hide/refresh semantics were separately reviewed/tested.
6. **Negative paths/trust:** open relay is rejected; donor helper binaries/runtime duplication are rejected/superseded; TLS bypass and fake handshake/location claims are explicitly guarded.
7. **Operator surfaces:** Operations exposes reliability/transport/DNS evidence; Profiles exposes redacted subscription health and node management; Android exposes truthful lifecycle/tile state; command palette aliases existing pages only.
8. **Deployment/scripts/presets:** WhiteDNS Wizard remote/delegation, CottenDNS presets, donor release/deploy/admin surfaces are explicitly classified and linked.
9. **Deep nested leaves:** vendored/generated/media trees remain surface-accounted but are not treated as target architectural components or implementation proof.
10. **Historical overlap:** Aether GUI exact duplicate is revalidated rather than reinterpreted; earlier post-refactor-222 checker is frozen to its successor baseline and passes.
11. **Contradictions:** no second VPN/TUN, native transport, DNS-tunnel, system-proxy, subscription runtime, or authentication authority was admitted.

## Surface counts by donor

- `aether`: 2198
- `aether_app`: 389
- `aether_gui`: 123
- `aether_whiteaesther`: 2199
- `cottendns`: 284
- `warp_relay`: 3
- `whiteaesther`: 87
- `whiteaesther_mobile`: 4195
- `whitedns_android`: 139
- `whitedns_cleanip`: 270
- `whitedns_wizard`: 61
- `whitevpn`: 271
- `whitewarpscout`: 112

## Classification counts

- `configuration`: 110
- `deployment`: 14
- `documentation`: 124
- `generated`: 15
- `governance`: 25
- `implementation`: 6852
- `media`: 244
- `repository-administration`: 51
- `script`: 53
- `test`: 320
- `ui-or-product`: 625
- `vendored`: 1898

## Dispositions

- `adapted`: 5
- `hardened`: 8
- `recomposed`: 3
- `reference-only`: 21
- `rejected-with-reason`: 2
- `superseded`: 9
- `synthesized`: 8

## Residual uncertainty

No unresolved critical/high semantic gap is known inside the requested 13-archive convergence scope. Full repository compilation remains bounded by unavailable host toolchains described in the validation report; those are evidence limitations, not silently converted into passes.
