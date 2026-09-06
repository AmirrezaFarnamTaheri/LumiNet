# Post-refactor-229 state machines

## Tunnel safety

Desired: `secured|unsecured`. Observed: `disconnected|connecting|connected|disconnecting|error|offline`. Corrupt persisted secure intent resolves fail-closed. Connected plus any required leak guard missing/false resolves degraded-unsafe. Recovery action remains bounded nothing/block/reconnect planning only.

## Relay sequencing

Each request gets a request sequence; writes also get a write sequence. Legacy response sequence omission is accepted. A supplied mismatched response sequence is rejected. A failed write transmission rolls its write sequence back so retry retains logical identity.

## Endpoint quota

Observed limit/remaining/reserve -> usable headroom. Remaining <= reserve becomes `quota-guarded` and ineligible. Reset time is evidence only; the planner does not mutate provider quota state.

## Signed-update metadata

`unseen -> accepted(N) -> accepted(N retry) | accepted(M>N)`. Any `M<N` is stale and rejected.

## Split-tunnel intent

Raw entries -> bounded syntax/platform admission -> normalize/dedupe -> canonical manifest hash -> planning-only result. No planner transition claims installed OS enforcement.
