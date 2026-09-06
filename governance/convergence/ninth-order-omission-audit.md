# Ninth-order omission and contradiction audit

## Denominators
- Donor archives: **20**.
- Archive members: **2379**.
- File/symlink surfaces: **1954** (this batch contains no donor symlinks).
- Directories including roots: **425**.
- Parsed symbols/declarations: **8676**.
- Bounded recursive module groups: **137**; every group is <=100 surfaces.
- Adoption/evidence records: **168**, including **31** fine-grained semantic decisions.

## Repeated omission ladder
1. Every validated donor file is SHA-256-accounted in `ninth-order-surfaces.csv` and linked to a bounded ledger group.
2. Every donor root/directory is represented with exact direct/recursive surface counts.
3. Every declaration emitted by the deep parser resolves through its exact hashed surface.
4. Fine semantic records split transactional reload/CAS, WARP sampling/corpus, network-quality metrics/bounds, entitlement projection/authority vetoes, Tor revision overlap, evasion overlap, privileged deployment mutation, product references and revision deltas out of broad module rows.
5. State/recovery review covers config publication/rollback/retirement, stale config CAS, host-network single authority, WARP cancellation/resource caps, diagnostic byte/time/redirect bounds, profile refresh ownership and advisory entitlement semantics.
6. Negative paths include failed plugin staging, cleanup-after-commit, stale writer conflict, lossy endpoint early-stop, oversubscribed scanner/noise requests, Range-ignoring speed origins, redirect chains, provider counter overflow, billing/user-authority leakage, unlicensed root installers and duplicate packet mutation loops.
7. Operator surfaces are explicit: WARP scan/noise API, speedtest API, subscription profile API/UI; ConfigManager remains a dormant source owner and is not falsely described as a live control API.
8. Scripts/presets/deployment/media/docs are not excluded from surface accountability. x-ui-pro/BWLimiter/snowbox/serverless assets are classified even when rejected or reference-only.
9. Large Caddy/defyx/Marzban trees are deterministically subdivided rather than represented by one umbrella record.
10. Cross-wave overlap is explicit: Auto_Tor is byte-identical to its sixth-order donor; nahan and defyx are changed/newer revisions and were delta-reviewed instead of assumed covered.

## Second-order findings
The composition pass found additional target-local defects after first-order adoption: a Range-ignoring speedtest origin could bypass the intended download budget, redirect chains needed an explicit bound, provider upload+download counters could overflow and turn huge usage into zero, standalone WARP noise could bypass scanner bounds, and operator-provided WARP scan limits needed fail-fast validation rather than only internal clamping. These were fixed at their owning primitives and covered by focused tests.

No additional donor-shaped billing, OAuth, packet-interception, edge-worker, Tor-helper, traffic-shaper, or server-bootstrap authority is justified in this wave.
