# LumiNet post-refactor-180 peer analysis

## Decision summary

The 20 donors were treated as evidence, not packages to transplant. Implemented convergence is concentrated in existing authoritative owners: subscription HTTP resilience, path-quality diagnostics, provider prefix attribution, WARP endpoint quality, native IP parsing, and IPv4 NAT reassembly. Large donor control planes/runtimes are rejected or reference-only when they would duplicate authority.

## HTTP follow-up and source recovery

OkHttp's explicit retry/follow-up state machine exposed that a custom Go `CheckRedirect` callback disables the standard client's default redirect count protection. LumiNet now owns a finite 10-follow-up policy, redirect-loop detection, per-hop URL/DNS re-admission, and cross-origin conditional-validator stripping. `Retry-After` is honored for 429/503 only as a finite lower bound on source backoff, capped at 24 hours.

## Path quality and WARP stability

`mylg` demonstrated actual TTL-scoped path probing with repeated measurements. This invalidated the old LumiNet routine that incremented a TTL variable without applying it. The replacement delegates to bounded platform traceroute tools and parses per-hop addresses, timeouts, loss, latency, temporal jitter, load balancing, and destination reachability. WarpScanner contributed only the repeated-latency stability insight; LumiNet keeps real handshake qualification and ranks loss before jitter before median RTT.

## Longest-prefix attribution

`tailscale-rs/ts_bart` supplied a high-quality LPM reference. LumiNet does not copy the Rust trie. A target-native immutable Go index preserves the old corpus sort/priority/tie semantics while making lookup independent of corpus cardinality. Differential tests compare indexed results to the former linear reference.

## IP parsing and defragmentation

`libcrafter` exposed two correctness gaps. Rust IP parsing now validates declared IPv4 total length and IPv6 payload length before exposing exact declared payload slices. The Go NAT defragmenter now uses offset-aware byte placement, bounded flow/age/datagram state, complete-range tracking, first-fragment-header ownership, and fail-closed conflicting-overlap/final-length handling.

## Connection observability prerequisite

Yacd-meta, Throne, and IPRadar independently show the operator value of connection lists, process attribution, filters and close actions. LumiNet intentionally does not ship a universal connections UI in this wave: current session maps are runtime-local and global byte counters cannot establish per-flow authority. A future plane first needs one cross-runtime flow registry with explicit close ownership, lifecycle, authorization and recovery.

## Checkpoint replay and job idempotency

Scrapling's atomic checkpoint replacement and non-draining scheduler snapshots are sound primitives for replay-safe workloads. They do not justify resuming arbitrary LumiNet jobs. Current queued/running jobs remain failed on daemon restart until each job type can explicitly prove idempotent/checkpoint-safe replay semantics.

## Raw packet and SNI injection

SNI-Spoofing-Go and SNI-Spoofing-Pro rely on privileged raw fake-TCP/TLS injection, with the Pro tree also adding service/deployment authority. LumiNet already has a bounded evasion owner. A second live packet injector would amplify privilege and create conflicting mutation ownership, so both mechanisms are rejected as runtime additions.

## Legacy SSH obfuscation

The obfuscated OpenSSH branch describes weak anti-scanning rather than strong authentication and is tied to an old OpenSSH protocol tree and legacy SHA-1 iteration. LumiNet will not fork current SSH security/runtime ownership to preserve obsolete handshake obfuscation.

## Server admin and identity planes

Sanaei 3x-ui is a multi-user Xray server administration plane; tsidp is an OIDC/OAuth identity provider. Both create high-authority product state outside LumiNet's client/network scope. Neither is absorbed in this convergence wave.

## UI technology and generator donors

Gotk4 is a GTK/GIR binding generator. LumiNet's product surfaces are React/Wails and Kotlin. Adding a parallel GTK stack would increase build and state-model complexity without delivering peer semantics, so it is rejected.

## Untrusted configuration datasets

Shin-TG-V2ray-Collector contains scraped endpoint datasets and a collector. These are untrusted, rapidly stale external inputs with unclear root licensing. They are not shipped as built-in profiles or truth. LumiNet keeps explicit source admission, parser validation, source health and freshness ownership.

## Converter and external-runtime validation

Subconverter remains useful compatibility evidence for URL-safe base64, SIP002/SSR and multi-client formats, but the target already has a single typed proxy parser authority and observed-form tests. V2RayDAR's actual sing-box execution is a useful external verification oracle, but its AGPL runtime/subscription owner is not embedded.

## Cross-platform network monitoring

Tailscale-rs netmon contains mature interface/address/route/default-route event semantics. It is intentionally reference-only in this wave: introducing a daemon-wide cross-platform route observer would be a new supervision plane with ordering and reconciliation responsibilities. The prior Android `UnderlyingNetworkTracker` remains passive and platform-scoped.

## Remaining scanner and WARP donors

Vwarp and ipscan reinforce staged qualification, cancellation and fetcher decomposition, but LumiNet's existing scanner/WARP owners already provide bounded concurrency, typed diagnostics, liveness checks and real handshake quality. Donor frameworks are superseded rather than duplicated.
