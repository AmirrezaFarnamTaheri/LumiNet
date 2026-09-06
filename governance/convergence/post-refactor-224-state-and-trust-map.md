# Post-refactor-224 state and trust map

| Plane | State owner | Write authority | Recovery / failure rule |
|---|---|---|---|
| Configuration | `foundation/config.Manager` | local CAS mutation path | retry revision conflicts only; explicit revisions single-attempt |
| Remote actions | existing remote action executor | classified provider/host operations | idempotent/reconcile/single-attempt policy remains separate |
| KCP runtime | Go proxy runtime | explicit start/listen/dial only | legacy defaults preserved; policy validation fails closed |
| Endpoint/mesh planning | diagnostics | none | invalid/stale/unhealthy evidence excludes or errors; no side effects |
| DNS pool planning | DNS planner | none | invalid/credential-bearing candidates quarantined; no resolver install |
| L7 signatures | diagnostics | none | invalid/empty/oversize patterns rejected; no classifier install |
| Traffic profiles | diagnostics | none | executable/unbounded actions rejected |
| Routing corpus | diagnostics | none | provenance/duplicate/missing-include evidence only |
| WebSocket | API hub | transient bounded fan-out | count drop/disconnect; do not create durable event spool |
| Jobs | workflows/jobs `JobManager` | durable job lifecycle | remains source of truth independent of WebSocket delivery |
| Operator UI | Control UI | authenticated API requests only | parser defaults missing 224 metrics to zero for version skew |

## Closed transitions

- KCP policy: parse -> validate bounds -> resolve explicit overrides/advice -> dial/listen; invalid policy never reaches runtime setup.
- Endpoint planning: admit measured candidate -> apply eligibility/health/circuit/capacity -> primary quality band -> optional secondary reorder; secondary evidence cannot cross the quality band.
- Relay polling: interactive -> successful-empty backoff -> max-idle; local write/downstream bytes -> interactive. Transport failure retry is independent.
- Local mutation: fresh snapshot -> apply intent -> CAS commit; conflict -> bounded fresh retry only when caller did not supply explicit revision.
