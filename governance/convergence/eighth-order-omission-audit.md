# Eighth-order omission and contradiction audit

## Denominators

- Donor archives: **23**.
- Archive members: **7177**.
- File/symlink surfaces: **6057**.
- Directories (including each repository root): **1091**.
- Parsed declarations/symbols: **9072**.
- Recursive accountability modules: **395**; large subtrees are recursively split so no splittable group exceeds 100 file surfaces.
- Adoption/evidence records: **424**, including 29 fine-grained value/decision records.

## Repeated omission ladder

1. **Files and symlinks:** every validated extracted file/symlink resolves to at least one ledger record; Firewalla/CoreDNS archive symlinks are retained as surfaces rather than flattened.
2. **Roots/packages:** recursive groups split large donor trees; administrative, media, generated, test, configuration and deployment material are not silently excluded.
3. **Symbols:** every declaration extracted by the deep parser resolves through its owning surface.
4. **Independent semantics:** high-signal retry, cache, supervisor, scheduler, host-network, queue-durability, rule-data, deployment and safety mechanisms are split out of broad subtree records.
5. **State/recovery:** cross-call 429 cooldown, stale-if-error refresh, bounded cache lifetime, stable-ready restart debt, rolling failure-window pruning, unique scheduled ownership and host-network rollback were explicitly compared.
6. **Negative paths:** transient upstream error caching, cache growth, same-key refresh stampedes, empty provider sets, provider/client concurrent mutation, retry cancellation, cross-action rate-limit contamination, queue partial-commit ordering and offensive persistence/MITM/bounce paths were considered.
7. **Operator surfaces:** retry coordinator aggregate stats are exposed in `/api/system/status`; donor UI/panel material stays non-authoritative.
8. **Scripts/CI/deployment/presets:** surfaced in the complete matrices; WARP/V2Ray/system-proxy recipes were compared against target owners rather than ignored.
9. **Deep leaves:** recursive grouping and full hash inventory include nested mobile resources, tests, vendor/config and deployment leaves; large repositories do not receive sampling exemptions.
10. **Contradictions:** donor-specific schedulers/proxy mutators/cache maps are rejected when they would duplicate target authority; permissive licensing never overrides correctness/security vetoes, and copyleft/no-license surfaces are rederived or retained as evidence only.

## Second-order findings

The first pass would have been incomplete if it stopped at direct ports. The second-order composition audit produced seven target-local repairs: (a) cross-call provider rate-limit cooldown coordination, (b) rejection of upstream DoH HTTP errors from cache admission, (c) shared bounded DNS cache ownership plus cancellable maintenance, (d) same-key miss coalescing and malformed/oversized-key rejection before upstream work, (e) bounded/concurrency-safe weighted DoH provider selection with empty-set failure, (f) snapshot-safe failover resolver provider/client reconfiguration with empty-provider failure, and (g) stable-ready restart-debt semantics plus rolling-history pruning in process supervision.

No additional donor-shaped authority plane is justified: InviZible scheduling/state-loop semantics are already better placed in LumiNet's profile scheduler, process supervisor, host-network transaction owner and remote-action reconciliation contract.
