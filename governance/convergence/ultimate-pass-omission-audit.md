# LumiNet ultimate omission audit

## Completion ladder

| Audit level | Result |
|---|---|
| Archive members | 239 outer current-wave members + 1 nested Lambda member; all strict archive checks passed. |
| File/symlink surfaces | 183 current-wave logical surfaces; cumulative 8,223; cumulative symlinks 38. |
| Directories | 78 current-wave directory records; cumulative 1,594. |
| Bounded modules | 48 new recursively bounded modules; cumulative 571; no splittable bucket exceeds the convergence bound. |
| Symbols/declarations | 374 current-wave parsed symbols; cumulative 18,098. |
| Semantic contracts | 22 new independently meaningful decisions; cumulative ledger 662. |
| Higher-level planes | 8 new major plane decisions; cumulative 26. |
| Supersession/composition | Cumulative 24 groups; every current-wave donor participates in an explicit semantic disposition. |
| Target delta | Exact source/governance delta is generated against the frozen 2,565-file all-43 baseline and checked by `check_ultimate_convergence.py`. |

## Deep-leaf and nested-artifact review
All current-wave repositories are small enough for complete direct surface inspection. Binary/media/repository-administration files remain hash-accounted even when they carry no runtime semantics. The nested `lambda_function_payload.zip` inside the EC2 manager was separately inspected; its `index.py` is byte-identical to the outer Lambda source and therefore does not hide a second implementation.

## State-machine/recovery audit
- Tor engine replacement now performs request normalization and environment-dependent transport preflight **before** stopping the current engine. Invalid transport names, paths, flags, or missing binaries fail closed without destructive replacement.
- Tor identity NEWNYM remains wired through the existing control-port owner; historical checker evidence was updated to follow `CookieAuthentication 1` into the canonical torrc builder.
- Encrypted DNS preserves NXDOMAIN separately from resolver failure for DNSEL. Context cancellation/deadlines remain bounded; bad proxy configuration cannot cause direct fallback.
- Filesystem observation owns notification/debounce only. It does not publish runtime configuration, avoiding two writers/reconcilers.
- Existing remote mutation retry state machine was re-executed for duplicate/retry/rate-limit/reconciliation/cancellation paths rather than merely assumed unchanged.

## Trust-boundary/negative-path audit
- API Tor transport requests cannot choose arbitrary process paths or arbitrary command arguments.
- Registered transport binaries must resolve to an executable environment path or an executable regular bundled file.
- DoT rejects non-SOCKS raw proxy configurations; DoH rejects invalid/unsupported proxy schemes and redirects are disabled.
- DNSEL loopback answers are diagnostic data only and are never treated as connection targets.
- Firewall/NAT/root installers, open proxies, relay installers, and broad Docker/cloud managers are not granted authority merely because peers implement them.
- Browser hardening is not claimed without a browser-owned implementation.

## Operator/product-surface audit
Live additions are limited to existing authenticated/capability-guarded owners: `POST /api/system/engines` accepts bridge and registered transport configuration, and `POST /api/system/tor/exit-check` exposes bounded read-only exit evidence. Endpoint-quality and TLS-peer enrichment remain internal evidence primitives. No new billing, firewall, relay, browser, cloud, or downloader product authority was introduced.

## Deployment/packaging audit
Donor deploy/bootstrap scripts were reviewed as operational evidence but were not copied into release authority. Final packaging is performed from the audited LumiNet source only. Release verification requires a safe archive, exact internal manifest, independent clean extraction, identical normalized tree digest, and rerun of the ultimate convergence/topology/remote-action/repo-audit gates on extracted bytes.

## Residual gaps
- Actual external obfs4/Snowflake/WebTunnel execution depends on binaries installed in the runtime environment and cannot be exercised in this container. Admission/preflight behavior is verified and fails closed.
- Real upstream DoH/DoT network exchanges are not exercised because the environment is offline and the repository requires a newer Go toolchain/dependencies than locally available. Exact target resolver source is compile/contract tested with dependency stubs.
- Unix firewall/DNS-leak support remains intentionally unsupported until it can participate in the durable host-network snapshot/verify/recover/rollback transaction.
- Browser fingerprint resistance, Tor relay hosting, cloud lifecycle control, and billing/user authority remain outside current LumiNet product ownership.
