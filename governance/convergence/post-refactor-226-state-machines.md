# Post-refactor-226 state machines and recovery contracts

## Configuration mutation retry

Authoritative owner: `foundation/config.Manager.Mutate`.

`read snapshot -> callback -> CAS commit -> success`

On revision conflict only: `conflict -> fresh authoritative snapshot -> callback -> CAS`, bounded to three attempts by default and eight maximum. Explicit `ExpectedRevision` forces a single attempt. Callback/non-conflict failures terminate without replay.

## Browser/native-host handoff

The planner distinguishes `install-required`, `offline`, `permission-incomplete`, and `ready`. Transition evidence depends on native-host installation, online status, required permissions, profile identity, message size, and loopback proxy admission. The planner performs no registration or proxy mutation.

## Tailnet transaction planning

- DNS patch: read authoritative state+ETag -> validate intended field delta -> compare If-Match evidence -> patch declared fields.
- DNS replace: read authoritative state+ETag -> validate complete replacement -> compare revision -> replace complete DNS configuration.
- device route change: read target revision -> validate route intent -> compare revision -> apply target-only change.
- key creation: validate capabilities/expiry -> create once -> hand secret to secret owner.
- webhook rotation: read revision -> compare revision -> rotate once -> invalidate prior secret after acknowledged replacement.

Every revision-bearing change requires explicit ETag/revision evidence. These are modeled transitions only; no API call occurs in the planner.

## Worker affinity and recovery

Observed workers enter the eligible set only when healthy and not saturated. Deterministic affinity selects from the bounded eligible set; saturation may spill to another eligible worker. No eligible worker produces fail-open evidence rather than an unbounded wait. Restart backoff is capped and bounded to at most eight planned restarts. No process is launched.

## WebSocket readiness

`tcp-unreachable -> not-ready`.

TCP reachability alone never reaches ready. Readiness requires all of: observed HTTP status 101, `Upgrade: websocket`, a Connection token containing `upgrade`, exact `Sec-WebSocket-Accept`, and verified TLS when TLS is expected. Any failed predicate remains not-ready.

## Gateway composition

Admitted roles are bounded to listener, reverse-client, reverse-server, path-router, detour, health, and tunnel. Dependencies form a DAG. Start order is topological; stop/rollback order is the exact reverse. Cycles or unknown dependencies fail admission. Health evidence is descriptive. Restart schedules are capped and deterministic; the planner writes no service configuration.

## WireGuard receiver-index mappings

A mapping is admissible only with a unique nonzero receiver index, bounded source identity, future expiry, and lifetime <=24h. Expired mappings are invalid rather than silently reusable. Packet obfuscation does not alter cryptographic session authority.

## Local rule normalization

Input is bounded and parsed into canonical rule evidence. Supported local syntax is normalized, CIDRs are masked, duplicate canonical rules are counted rather than multiplied, and ambiguous/unsupported input is rejected. No resulting rule is installed automatically.
