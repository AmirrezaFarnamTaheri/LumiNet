# LumiNet post-refactor 83-donor peer synthesis

## Scope

This incremental convergence starts from the frozen refactor-audited LumiNet release and adds 20 new donor archives. Historical 63-donor evidence is preserved by exact artifact digest rather than rewritten.

- New outer archives: 20
- New archive members: 456
- New file surfaces: 352
- New directories: 104
- Parsed new symbols/declarations: 1646
- New bounded accountability modules: 53
- New semantic decisions: 30
- New adoption/accountability records: 83
- Historical donors retained: 63
- Cumulative donors: 83
- Nested duplicate archive members re-opened: 18

## Delivered decisions

### Endpoint admission
Nova-Proxy-App's active pool excludes unchecked endpoints. LumiNet's planner previously allowed a zero-observation endpoint into dispatch. The target-native planner now requires at least one successful observation before eligibility; unknown/failed-only endpoints remain visible but inactive.

### Relay failure backoff
The same donor showed useful outage backoff. LumiNet independently rederived that invariant inside the existing deep relay state module. Both HTTP and GSA polling adapters now share bounded exponential failure backoff, reset on success, and cancellation-aware waits.

### F-014–F-018 closure
F-014 is revalidated. F-015 uses one explicit SSH SHA-256 host identity seam. F-016 removes mutable remote root installer execution. F-017 preserves all 42 C ABI exports while owning raw inputs immediately and centralizing typed/panic envelopes; Rust compilation remains unavailable. F-018 now has bounded buffers, real deadlines and wakeups.

## Major non-adoptions

- smux-dev fair scheduling: valuable, but dependency replacement deferred until protocol/performance differential proof.
- qtun: useful QUIC admission/mobile-protect reference, different product role; no duplicate server/mobile authority.
- OnionPerf/CellShift: retained as measurement/evaluation methodology, not production trace collection.
- multitor: negative evidence supports retaining one supervised Tor engine.
- QS-Tunnel and mullvad-tailscale: raw spoof/firewall paths rejected in favor of reversible HostNetworkChange ownership.
- MITM repositories/Nova MITM functionality: interception CA and trust bypass rejected.
- Pitraix: malicious capabilities rejected completely; negative security evidence only.
- qpp: custom cryptography rejected.
- Nginx/Marzban installers: operational reference only; no daemon root-installer authority.
- proxy-yoinker: existing target subscription ingress is stricter and supersedes it.
- mihomo: unrelated Honkai Star Rail data client; role mismatch.
- nahan-main(2) and three Nginx-embedded ZIPs: byte-identical to previously reviewed donors, revalidated without double-counting semantics.
