# Post-refactor-226 architecture and ownership

## Scope and denominator

Post-refactor-226 converges 14 newly supplied donors onto the immutable post-refactor-225 source boundary. The current wave is mechanically accounted at 1,557 ZIP members, 1,299 regular-file surfaces, 244 donor subdirectories (258 Merkle records including donor roots), 15,975 extracted definitions, 134 focused module decisions, 745 focused high-signal file decisions, and 893 semantic records. The cumulative 224+225+226 overlay covers 52 donors, 3,760 donor surfaces, 25,486 definitions, 284 module/subtree groups, 2,317 high-signal surfaces, and 161 UI/product surfaces.

## Runtime authority plane

Post-refactor-226 reduces duplicate protocol authority rather than adding donor-shaped runtimes.

- `src/apps/daemon/internal/runtime/proxy/core_manager.go` remains the sole daemon owner for Shadowsocks execution through maintained external cores.
- The unused local Go Shadowsocks cipher/listener/server surfaces and unused Rust Shadowsocks/SS2022 facades are retired. Their removal is recorded in the canonical topology ledger and the 225->226 byte delta.
- Sing-box and Xray outbound builders now enumerate SOCKS and HTTP explicitly and fail closed on unsupported protocols; SSR or an unknown protocol can no longer fall through to SOCKS.
- `networking/proxyconfig` remains the protocol-admission owner. SS2022 validates exact decoded PSK component lengths and preserves multi-component identity/user PSKs.
- The canonical SSH dialer remains the SSH owner; the donor SSH implementation remains an oracle/dependency reference. Authentication preparation now rejects an empty or wholly invalid auth set before any network activity.
- Existing TUN/platform owners remain authoritative; TinyTun does not introduce a second TUN/eBPF/process-routing runtime.

## Wire-boundary hardening

TinyTun and Shadowsocks peers exposed narrow correctness gaps in existing live owners:

- Go SOCKS target encoding rejects empty/NUL hosts, domains above 255 bytes, and ports outside 1..65535 before one-byte/u16 encoding.
- Rust SOCKS target encoding rejects oversized/NUL domains and unknown reply ATYP values rather than silently accepting a zero-length bind address.
- SS2022 admission validates AES-128 16-byte PSKs and AES-256/ChaCha 32-byte PSKs component-by-component.

## Planning and evidence plane

Donor mechanisms that would expand network, browser, API, process, or installer authority are rederived as bounded read-only contracts under `internal/analysis/diagnostics`:

- local rule-set normalization;
- Tailnet transactional change planning;
- browser/native-host proxy handoff planning;
- worker affinity/recovery planning;
- WebSocket protocol-readiness evidence;
- gateway deployment composition planning.

These planners consume caller-supplied evidence and return deterministic proposals. They perform no Tailnet request, DNS fetch, browser registration, process start/restart, WebSocket dial, package download, service installation, systemd/cron/runit/Caddy write, or rule installation.

## WireGuard/MWGP composition

MWGP contributes a narrow lifecycle constraint rather than a parallel WireGuard implementation. Receiver-index translation mappings must be unique, source-identity-bound, and explicitly expiring, with at most 1,024 mappings and a maximum 24-hour lifetime. Packet obfuscation is classified as traffic-shape modification only; it never becomes authentication, confidentiality, replay protection, or a substitute for WireGuard cookie/MAC2 admission.

## Product placement

The new evidence contracts are exposed through existing authenticated `/api/system` planning routes and placed in natural product pages:

- Rules -> local rule normalization;
- Settings -> Tailnet transaction and browser handoff evidence;
- Health -> worker affinity/recovery evidence;
- Connections -> WebSocket backend/protocol readiness;
- Operations -> gateway deployment composition.

The UI remains non-authoritative. A planner result never becomes an implicit live write.

## Mutation ownership

Automatic configuration mutation retry remains single-owned by `foundation/config.Manager.Mutate`: three attempts by default, hard maximum eight, a fresh authoritative snapshot on every revision-conflict retry, no retry for unrelated failures, and exactly one attempt when `ExpectedRevision` is explicit. Post-refactor-226 adds no second mutation engine.
