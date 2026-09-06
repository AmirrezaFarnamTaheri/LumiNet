# Post-refactor 141 semantic decision anchors

These anchors make peer decisions independently addressable. They are evidence pointers, not runtime tests unless a row points to an executable checker.

## semantic-PR141-S001
**geospoof-main / browser geolocation identity:** JavaScript geolocation API override
Final disposition: `reference-only`. Shows that browser geolocation is an application-layer identity surface distinct from VPN exit IP. LumiNet keeps that distinction explicit rather than claiming VPN geolocation spoofing.

## semantic-PR141-S002
**geospoof-main / timezone identity:** Date/Intl timezone override surface
Final disposition: `reference-only`. Timezone consistency is useful privacy-model evidence but is not a network transport responsibility.

## semantic-PR141-S003
**geospoof-main / WebRTC privacy:** WebRTC address-surface override
Final disposition: `reference-only`. WebRTC can expose network-adjacent identity outside ordinary proxy paths; retained as a diagnostic/privacy caveat.

## semantic-PR141-S004
**geospoof-main / iframe propagation:** propagate identity overrides into nested frames
Final disposition: `reference-only`. Cross-frame propagation illustrates completeness requirements for a browser extension, but LumiNet has no browser extension authority.

## semantic-PR141-S005
**geospoof-main / worker propagation:** propagate identity overrides into workers
Final disposition: `reference-only`. Worker propagation is retained as completeness evidence only.

## semantic-PR141-S006
**geospoof-main / concealment/evasion:** mask overridden JavaScript functions as native
Final disposition: `rejected-with-reason`. Native-looking function masking is an anti-detection/evasion mechanism and is outside LumiNet production authority.

## semantic-PR141-S007
**geospoof-main / permission semantics:** override geolocation permission query behavior
Final disposition: `rejected-with-reason`. Falsifying browser permission state would duplicate browser authority and can mislead callers.

## semantic-PR141-S008
**geospoof-main / cross-layer VPN sync:** synchronize browser location presets with observed VPN region
Final disposition: `reference-only`. Useful UX evidence that network exit and browser identity can drift and should be shown separately.

## semantic-PR141-S009
**geospoof-main / early injection lifecycle:** early-protection bootstrap before page scripts
Final disposition: `reference-only`. Early bootstrap timing is relevant only to a browser-injection product and does not justify a LumiNet extension plane.

## semantic-PR141-S010
**geospoof-main / Safari packaging:** Safari WebExtension native bridge and packaging boundary
Final disposition: `reference-only`. Cross-browser packaging is product reference only; LumiNet release authority remains its existing desktop/mobile packages.

## semantic-PR141-S011
**ZedSecure-main / Android VPN socket protection:** VpnService protect(fd) boundary
Final disposition: `superseded`. Explicit socket protection reinforces the existing LumiNet VpnService.protect bridge; no second VPN service is needed.

## semantic-PR141-S012
**ZedSecure-main / per-app routing UX:** application allow/disallow selection channel
Final disposition: `reference-only`. Per-app routing is useful product evidence, but LumiNet correctly reports it unsupported until packet/process routing can enforce it.

## semantic-PR141-S013
**ZedSecure-main / TUN route construction:** VPN TUN route/DNS/MTU construction around proxy endpoint
Final disposition: `superseded`. Route construction and server exclusion reinforce existing Android/TUN ownership; target keeps one TUN/NAT stack.

## semantic-PR141-S014
**ZedSecure-main / DNS/FakeDNS configuration:** proxy DNS and FakeDNS configuration builder
Final disposition: `reference-only`. Config UX is useful reference, but LumiNet DNS and proxy routing already have distinct owners and no V2Ray config authority is imported.

## semantic-PR141-S015
**ZedSecure-main / proxy URL configuration:** multi-protocol V2Ray configuration parsing
Final disposition: `reference-only`. Parser breadth is useful compatibility evidence; current proxy configuration owners remain authoritative.

## semantic-PR141-S016
**ZedSecure-main / HevTun lifecycle:** native hev-socks5-tunnel service lifecycle
Final disposition: `superseded`. Native tunnel lifecycle is already covered by LumiNet mobilehost/TUN ownership; importing HevTun would create a second data plane.

## semantic-PR141-S017
**ZedSecure-main / network diagnostics:** VPN-side ping/latency service
Final disposition: `reference-only`. Diagnostic sampling reinforces existing bounded endpoint diagnostics without changing dispatch authority.

## semantic-PR141-S018
**ZedSecure-main / bundled proxy binary supply chain:** prebuilt V2Ray Android AAR
Final disposition: `rejected-with-reason`. A 54 MB bundled runtime archive cannot become an unaudited executable input, especially under GPL/mixed component licensing.

## semantic-PR141-S019
**ZedSecure-main / mutable native build input:** build script clones/links external hev-socks5-tunnel source
Final disposition: `rejected-with-reason`. Mutable external-source build recipes conflict with LumiNet frozen-source release provenance.

## semantic-PR141-S020
**i2p.i2p-master / replay prevention:** time-decaying bounded Bloom filter for recent identifiers
Final disposition: `reference-only`. Time-decaying replay membership reinforces bounded replay windows; LumiNet already has bounded replay caches/one-shot tokens where needed.

## semantic-PR141-S021
**i2p.i2p-master / tunnel replay prevention:** duplicate tunnel IV detection with resource-sensitive filter sizing
Final disposition: `reference-only`. Shows replay filtering sized against memory/throughput and explicit duplicate telemetry; target uses existing replay owners.

## semantic-PR141-S022
**i2p.i2p-master / bandwidth admission:** FIFO bandwidth limiter and explicit throughput quotas
Final disposition: `reference-only`. Long-lived anonymity routing needs first-class bandwidth admission; LumiNet already bounds relay/TUN buffers and work queues.

## semantic-PR141-S023
**i2p.i2p-master / peer selection:** tunnel peer selection with exclusions/capability checks
Final disposition: `reference-only`. Selection policy reinforces that observed eligibility and exclusions belong ahead of dispatch; LumiNet endpoint planning already requires successful observation.

## semantic-PR141-S024
**i2p.i2p-master / peer quarantine:** router banlist with reason/expiry lifecycle
Final disposition: `reference-only`. Expiring quarantine and reason tracking are useful operator evidence; existing target health/cooldown owners remain authoritative.

## semantic-PR141-S025
**i2p.i2p-master / transport ownership:** multi-transport manager lifecycle and address selection
Final disposition: `rejected-with-reason`. A full I2P transport manager would duplicate LumiNet runtime/proxy/relay ownership.

## semantic-PR141-S026
**i2p.i2p-master / lease expiration:** LeaseSet v2 time/expiry representation
Final disposition: `reference-only`. Explicit lease expiry reinforces lifecycle modeling for ephemeral network state.

## semantic-PR141-S027
**i2p.i2p-master / router-info expiry:** remove or retain router information using expiration/freshness policy
Final disposition: `reference-only`. Freshness/expiry policy is useful state-management evidence; LumiNet does not import I2P NetDB.

## semantic-PR141-S028
**i2p.i2p-master / tunnel lifecycle:** TunnelController start/stop/restart configuration ownership
Final disposition: `reference-only`. Supervised tunnel lifecycle reinforces single-owner teardown/restart semantics already present in LumiNet.

## semantic-PR141-S029
**i2p.i2p-master / SOCKS proxying:** I2P SOCKS tunnel address/connection handling
Final disposition: `reference-only`. SOCKS semantics are compared as protocol evidence only; LumiNet already owns SOCKS/TUN paths.

## semantic-PR141-S030
**i2p.i2p-master / SOCKS UDP:** I2P SOCKS UDP tunnel handling
Final disposition: `reference-only`. UDP association lifecycle is useful comparison evidence; existing LumiNet association ownership remains authoritative.

## semantic-PR141-S031
**i2p.i2p-master / message freshness/replay:** router message validator expiration and duplicate policy
Final disposition: `reference-only`. Message freshness and duplicate rejection reinforce existing replay/idempotency boundaries.

## semantic-PR141-S032
**i2p.i2p-master / tunnel build admission:** tunnel build message validation and duplicate controls
Final disposition: `reference-only`. Build-request admission illustrates pre-authority validation for topology mutations.

## semantic-PR141-S033
**i2p.i2p-master / signed update/reseed provenance:** SU3 signed-file verification container
Final disposition: `reference-only`. Signed artifact verification is useful release/provisioning evidence; mixed I2P licensing prevents broad source adoption and LumiNet retains its existing integrity owners.

## semantic-PR141-S034
**i2p.i2p-master / router lifecycle:** full router startup/shutdown/restart lifecycle
Final disposition: `rejected-with-reason`. A full I2P router introduces persistent anonymity network, NetDB, transports and crypto authority outside LumiNet scope.

## semantic-PR141-S035
**i2p.i2p-master / operator control plane:** router console tunnel configuration surface
Final disposition: `reference-only`. Operator visibility/configuration is UX reference only; UI remains non-authoritative.

## semantic-PR141-S036
**i2p.i2p-master / cryptographic key lifecycle:** key generation and algorithm-specific material creation
Final disposition: `reference-only`. Algorithm/key lifecycle is security reference only; LumiNet does not adopt I2P cryptography or key formats.

## semantic-PR141-S037
**i2p.i2p-master / reseed/network bootstrap:** reseed acquisition lifecycle
Final disposition: `rejected-with-reason`. I2P reseed introduces a separate network-discovery trust root and persistent router state.

## semantic-PR141-S038
**metapi-main / endpoint/token routing:** observed-success/cooldown/latency-informed token router
Final disposition: `reference-only`. Rich routing evidence reinforces observed-success and cooldown principles already used by LumiNet endpoint planning; no second dispatcher is imported.

## semantic-PR141-S039
**metapi-main / circuit-breaker recovery:** failure decay, breaker levels and recovery probes
Final disposition: `reference-only`. Breaker/decay/probe mechanics are valuable recovery reference but operate in a different token-routing domain.

## semantic-PR141-S040
**metapi-main / first-byte timeout:** timeout before first streaming byte while replaying observed first chunk
Final disposition: `reference-only`. Streaming timeout semantics reinforce explicit first-byte bounds; target relay/WebSocket owners already enforce deadlines.

## semantic-PR141-S041
**metapi-main / retry classification:** failure action classification into retry/failover/terminal paths
Final disposition: `reference-only`. Explicit failure taxonomy is useful recovery design evidence.

## semantic-PR141-S042
**metapi-main / client-IP trust boundary:** unconditionally consume X-Forwarded-For for admin allowlist identity
Final disposition: `hardened`. The donor demonstrates an unsafe forwarded-header trust boundary. Gin documents the same unsafe default unless trusted proxies are configured, so LumiNet now disables forwarded-IP trust at router construction.

## semantic-PR141-S043
**metapi-main / query credential exposure:** accept proxy key from URL query parameter
Final disposition: `superseded`. LumiNet already rejects query-string API keys and redacts sensitive queries; donor pattern is retained as negative evidence.

## semantic-PR141-S044
**metapi-main / request rate limiting:** bounded per-key fixed-window rate-limit store
Final disposition: `reference-only`. Bounded operator API admission is relevant, while LumiNet retains its token-bucket middleware.

## semantic-PR141-S045
**metapi-main / downstream policy:** request-scoped downstream client policy context
Final disposition: `reference-only`. Request-scoped policy propagation is useful API architecture reference.

## semantic-PR141-S046
**metapi-main / session serialization:** per-session HTTP task queue with cleanup
Final disposition: `reference-only`. Per-session serialization and cleanup is useful concurrency evidence.

## semantic-PR141-S047
**metapi-main / stream completion:** SSE final-event normalization/termination
Final disposition: `reference-only`. Explicit stream termination is useful protocol evidence; target transport framers stay authoritative.

## semantic-PR141-S048
**metapi-main / provider registry:** typed provider profile registry
Final disposition: `reference-only`. Provider capability registration is useful modularity evidence while LumiNet keeps existing runtime/provider ownership.

## semantic-PR141-S049
**metapi-main / downstream key exclusions:** migration-backed per-key model/site exclusion policy
Final disposition: `reference-only`. Durable scoped policy is useful control-plane reference.

## semantic-PR141-S050
**metapi-main / projection leases:** database-backed projection lease state
Final disposition: `reference-only`. Lease-backed background ownership reinforces explicit durable lease semantics.

## semantic-PR141-S051
**metapi-main / billing/usage provenance:** proxy usage/billing detail persistence migration
Final disposition: `reference-only`. Usage attribution is operator/audit reference only; LumiNet does not import billing authority.

## semantic-PR141-S052
**metapi-main / OAuth provider lifecycle:** multi-provider OAuth migration and routes
Final disposition: `reference-only`. Versioned OAuth schema is useful control-plane reference but unrelated to LumiNet local API authentication.

## semantic-PR141-S053
**metapi-main / proxy/control-plane authority:** full multi-provider proxy orchestration and admin product
Final disposition: `rejected-with-reason`. Importing the complete control plane would duplicate proxy dispatch, credentials, billing, migrations and provider runtime ownership.
