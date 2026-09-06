# LumiNet post-refactor 117-donor omission and contradiction audit

## Corpus closure

The combined corpus is **117 unique donors**: 63 historical, 20 prior post-refactor, 14 Tor-focused, and 20 current-wave repositories. The combined matrices account for **27,333 file/link surfaces**, **5,481 directories**, **3,876 bounded groups**, **73,012 normalized declarations**, and **4,091 adoption/accountability rows**, including **215 fine semantic decisions**.

The current 20 archives were validated before extraction: 8,097 outer members, 6,742 regular-file surfaces plus six symlink surfaces, and 1,349 directory records. Symlinks were target/hash-accounted but never materialized. The only current nested archive is the Android sing-box Gradle wrapper JAR; all 33 inner members are regular files with no unsafe paths/types/links.

## Omission ladder

- **Files and symlinks:** every current regular file and all six links have SHA-256/target accountability and at least one bounded module record. A second byte-verification pass matched 6,748/6,748 current surfaces against extracted files or captured symlink-target bytes.
- **Roots/packages/deliverables:** manifests, build scripts, examples, deployment surfaces, tests, fixtures, binaries, UI, documentation and vendored trees remain classified even when they contribute no executable target semantics.
- **Exports/declarations:** 33,593 current donor-owned declarations are normalized and counted; generated/vendored/media/config/governance surfaces are excluded from semantic symbol credit but not from surface accountability.
- **Independent contracts:** 60 current fine decisions separate protocol behavior, evaluation methods, lifecycle rules, packaging, authority changes, test oracles, negative evidence and provenance instead of collapsing whole repositories into one row.
- **State/recovery:** SOCKS setup deadlines, single-winner association ownership, VLESS one-time response state and WebSocket deadline/bound semantics have discriminating target tests.
- **Negative/trust paths:** dynamic executable WASM transport admission, Xposed concealment, duplicate inbound/server planes, firewall callbacks from vendor code, broad installers and donor prebuilt executables receive explicit final rejection/guardrail rows.
- **Operator/UI/API:** dashboard and Clash-style API evidence is kept non-authoritative; existing target API/session/runtime ownership is unchanged.
- **Deep leaves/nested content:** the Gradle wrapper JAR is independently enumerated; donor symlinks, vendored pybind11, sing-box fork overlap and embedded tun2socks-Go duplication are explicit rather than skipped.
- **Historical claims:** the frozen 97 correction layer remains intact. No current semantic disposition is `pending`, `unverified`, `inferred`, or phrased as deferred/future work.

The current-wave ledger is valid under the convergence skill's present schema without exceptions. Historical 63/20/14 rows retain their immutable original forms; 74 rows with older evidence-pointer conventions are mapped through a successor-only normalization overlay into a strict 4,091-row ledger. This closes current-schema validation without rewriting historical evidence or silently changing prior decisions.

## Contradictions resolved

SOCKS UDP relay IPv6 support is **not** represented as IPv6 TUN/NAT support; `platform/system/nat` remains explicitly IPv4-only. Source-compatible WebSocket donor validation is **not** represented as exact `gorilla/websocket` v1.5.3 byte validation. Large GPL proxy projects are **not** treated as source donors. Shared sing-box and tun2socks code is **not** credited twice. Water/WATM concepts are **not** represented as an installed executable plugin feature. Vanguards is **not** represented as a second Tor controller or onion-service runtime.

## Residual environment boundary

Local Go is 1.23.2 versus the declared Go 1.26.x workspace; network/toolchain fetch is unavailable. Rust/Cargo/Miri are unavailable and the local Android wrapper is absent. These are explicit execution-environment limits, not postponed donor dispositions.
