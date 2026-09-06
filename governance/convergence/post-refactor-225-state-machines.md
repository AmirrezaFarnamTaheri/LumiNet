# Post-refactor-225 state-machine map

## Configuration mutation

`read authoritative revision -> attempt CAS -> committed | revision conflict -> fresh read -> retry`.

Default retry budget is 3; hard maximum is 8. Only revision conflict re-enters the loop. Explicit `ExpectedRevision` changes the machine to exactly one attempt. Calls, commits, conflicts, automatic retries and exhausted retries remain observable.

## SNI path lifecycle

`observed -> eligible` requires bounded freshness, response/payload evidence and strict TLS when TLS evidence is present. Eligible candidates are ranked and assigned to `active` up to the requested active-pool ceiling; additional eligible candidates become `reserve`. Previously active candidates that become stale/unhealthy/untrusted transition to `drain` for a bounded drain interval rather than being silently treated as healthy.

TCP-connect-only evidence is reachability, not successful service evidence.

## Incident lifecycle

`up -> failure-observed -> incident-open -> sustained/reason-change -> recover` with independent maintenance suppression and notification grace. Persistence write cooldown is separate from incident state. Maintenance may suppress notification without falsifying transition state.

## Queue lifecycle

`depth + incoming -> accepted/rejected/oldest-evicted -> bounded batch -> export success | export failure -> bounded restore`.

Wire decoder counts must fit the available payload before slicing or allocation. Eviction/drop counters are monotonic observations, not inferred from current depth.

## DNS policy

`request -> transport admission -> dependency/route graph check -> lookup-family strategy -> cache/rejection policy -> fallback plan`.

Transport loops are rejected. When secure transport is required, fallback may not silently cross to plaintext. UDP truncation can explicitly fall back to TCP when configured.

## Multiplex policy

`protocol/version admission -> connection ceiling -> streams-per-connection ceiling -> optional bounded padding -> estimated capacity`.

Application payload accounting is distinct from protocol framing/padding bytes. Peer-controlled padding is validated before use.

## Artifact lifecycle

`supplied bytes -> size/schema/digest check -> secret scan -> admitted evidence | quarantined evidence`.

Neither branch installs or persists the artifact. Secret-bearing content is never returned.

## Declarative network workflow

`parse actions -> validate IDs/kinds/targets -> dependency DAG -> init phase -> trigger phase -> reverse cleanup plan`.

Cycles, unknown dependencies, embedded credentials and executable mutation kinds fail admission. The planner never executes the plan.

## WireGuard readiness

`peer identity -> AllowedIPs ownership/overlap -> replay/rate/cookie readiness -> keepalive/rekey/reject/stale-key timing evidence`.

This is a readiness model around the existing WireGuard owner; it has no key-store, route-install, handshake or device authority.

## TUIC command lifecycle

The command codec may write an Authenticate frame and then 0-RTT-compatible command headers over an already established stream. `auth frame sent` is deliberately not `peer accepted`. The codec rejects malformed wire lengths/fragments before any partial write. Actual TUIC transport remains QUIC-owned by the normal outbound runtime; the old raw-TCP covert path fails closed.

## Userspace TUN translation

`packet -> IPv4/header/fragment validation -> transport bounds -> 5-tuple session lookup/create -> deterministic bounded eviction if needed -> header/port translation -> checksum repair -> output`.

Malformed or fragmented inputs leave without an unsafe port read or partial translated packet.
