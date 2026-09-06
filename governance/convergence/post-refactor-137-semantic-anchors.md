# Post-refactor 137 semantic decision anchors

These anchors make non-executable peer decisions independently addressable. They are evidence pointers, not runtime tests.

## semantic-PR137-S001
**Exclave-dev / Android VPN boundary:** explicit VpnService socket-protect IPC boundary
Final disposition: `reference-only`. Explicit FD protection reinforces that tunneled sockets need one platform-owned bypass boundary; LumiNet keeps its existing mobile/network owner.

## semantic-PR137-S002
**Exclave-dev / executable plugin admission:** discover/copy/execute native Android transport plugins
Final disposition: `rejected-with-reason`. The donor loads executable plugin providers and copies plugin binaries. LumiNet deliberately keeps executable extension authority closed.

## semantic-PR137-S003
**Exclave-dev / plugin configuration:** structured plugin option parsing and configuration UI boundary
Final disposition: `reference-only`. Configuration parsing/selection is useful product evidence without importing the executable plugin framework.

## semantic-PR137-S004
**Exclave-dev / Android binary packaging:** architecture-aware external proxy asset packaging
Final disposition: `reference-only`. Build-time asset selection reinforces ABI-specific packaging. LumiNet does not import GPL binaries or a second asset pipeline.

## semantic-PR137-S005
**Furious-main / TUN process lifecycle:** GUI-managed tun2socks child lifecycle and TUN settings
Final disposition: `reference-only`. Useful operator lifecycle reference; LumiNet already owns TUN process/data-plane behavior and keeps that authority singular.

## semantic-PR137-S006
**Furious-main / system proxy UX:** explicit system-proxy enable/disable operator action
Final disposition: `reference-only`. Operator workflow is retained as UX reference while LumiNet keeps platform proxy mutation behind its existing host-network owner.

## semantic-PR137-S007
**Furious-main / bundled runtime supply chain:** generated/frozen runtime and external-core packaging around process worker
Final disposition: `rejected-with-reason`. The archive contains thousands of generated/frozen surfaces and bundled core fixtures. They are accounted but do not become source of truth or executable inputs.

## semantic-PR137-S008
**HUNTX / bounded orchestration:** bounded connector/orchestrator worker execution
Final disposition: `reference-only`. Bounded fan-out and explicit orchestration reinforce target concurrency limits without importing the collection pipeline.

## semantic-PR137-S009
**HUNTX / durable deduplication:** SQLite-backed source state and deduplication lifecycle
Final disposition: `reference-only`. Durable state/dedup patterns are useful evidence; LumiNet retains its existing state owners and receipts.

## semantic-PR137-S010
**HUNTX / remote proxy collection:** Telegram/V2Ray remote configuration harvesting
Final disposition: `rejected-with-reason`. Arbitrary remote proxy scraping would introduce untrusted configuration supply and credential-bearing connector authority.

## semantic-PR137-S011
**Intercept-main / MITM attack surface:** ARP/DNS/RA and related interception procedures
Final disposition: `rejected-with-reason`. The document is offensive field guidance. Active interception/spoofing capabilities are outside LumiNet production scope.

## semantic-PR137-S012
**Intercept-main / host network mutation:** promiscuous/forwarding/firewall mutation as interception prerequisites
Final disposition: `guardrail-derived`. Negative evidence reinforces that privileged host-network mutation stays behind the existing registered owner and reversible actions.

## semantic-PR137-S013
**Intercept-main / trust-boundary analysis:** catalog of interception positions and protocol trust assumptions
Final disposition: `reference-only`. The attack taxonomy is retained only to improve defensive trust-boundary review.

## semantic-PR137-S014
**foghorn-main / DNS concurrency admission:** bounded running+queued network-triggered background work
Final disposition: `hardened`. The donor explicitly bounds accepted background work. LumiNet DoH now has a 32-slot fail-fast unique-host admission gate.

## semantic-PR137-S015
**foghorn-main / DNS shared work lifecycle:** concurrent upstream work is independent from any single requester
Final disposition: `hardened`. The failover design treats upstream attempts as bounded shared work. LumiNet singleflight execution is now detached from the first waiter cancellation and has its own five-second bound.

## semantic-PR137-S016
**foghorn-main / DNS response identity:** validate upstream TXID and echoed question before accepting response
Final disposition: `hardened`. The donor rejects upstream replies whose transaction ID or first question differs. LumiNet now performs bounded compression-aware identity validation before parsing A records.

## semantic-PR137-S017
**foghorn-main / DNS cache/policy:** configurable bounded DNS cache/policy mechanisms
Final disposition: `reference-only`. Cache eviction/policy examples are useful reference; LumiNet already has a bounded TTL cache and does not need a second cache authority.

## semantic-PR137-S018
**foghorn-main / DNS server/plugin authority:** full DNS server and executable resolver-plugin ecosystem
Final disposition: `rejected-with-reason`. Importing a second DNS server/plugin platform would duplicate runtime, configuration, and extension authority.

## semantic-PR137-S019
**freedom-main / privileged provisioning:** broad root-level server setup instructions
Final disposition: `rejected-with-reason`. The setup mutates packages, limits, services and host configuration broadly. LumiNet retains its guarded provisioning owner.

## semantic-PR137-S020
**freedom-main / firewall ownership:** iptables/firewall recipes for proxy routing
Final disposition: `rejected-with-reason`. A second firewall authority would conflict with LumiNet host-network mutation ownership and rollback guarantees.

## semantic-PR137-S021
**freedom-main / operator deployment knowledge:** manual censorship-circumvention deployment/runbook patterns
Final disposition: `reference-only`. Documentation is retained as operational context only; no executable installer or server role is imported.

## semantic-PR137-S022
**freenet-core-main / session state machine:** bounded actor/channel based client-session lifecycle
Final disposition: `reference-only`. Actor/state-machine handling provides recovery/concurrency evidence without importing the AGPL P2P core.

## semantic-PR137-S023
**freenet-core-main / deterministic simulation:** fault/time/network simulation as validation methodology
Final disposition: `reference-only`. Deterministic fault simulation is retained as evaluation methodology for future tests, not runtime authority.

## semantic-PR137-S024
**freenet-core-main / secret handling:** secrets-at-rest design and explicit secret-store boundary
Final disposition: `reference-only`. Secret separation reinforces existing LumiNet secret-reference/platform-store ownership.

## semantic-PR137-S025
**freenet-core-main / WASM contract runtime:** executable WASM contract/delegate runtime authority
Final disposition: `rejected-with-reason`. An executable WASM contract plane would materially expand code-execution and persistence authority; LumiNet keeps extension execution closed.

## semantic-PR137-S026
**freenet-core-main / decentralized P2P node authority:** whole Freenet node/contracts/network state ownership
Final disposition: `rejected-with-reason`. The AGPL distributed node is architecturally distinct and would duplicate transport/state/contract authorities.

## semantic-PR137-S027
**freenet-git-main / content-addressed cache:** verify cached pack bytes against BLAKE3 address and remove corrupt entries
Final disposition: `reference-only`. Read-time hash verification reinforces LumiNet immutable release/manifest checks. Existing SHA-256 release integrity remains authoritative.

## semantic-PR137-S028
**freenet-git-main / signed identity:** signed/encrypted repository identity representation
Final disposition: `reference-only`. Identity/signing patterns are useful provenance reference; LumiNet keeps its existing SSH/TLS/release identity owners.

## semantic-PR137-S029
**freenet-git-main / chunked transfer recovery:** chunked pack/recovery representation
Final disposition: `reference-only`. Chunk/retry recovery is useful operational evidence; no Freenet data plane is introduced.

## semantic-PR137-S030
**freenet-git-main / Git remote transport authority:** git-remote helper over Freenet network
Final disposition: `rejected-with-reason`. A new Git/Freenet transport plane is outside LumiNet runtime ownership and unnecessary for this release.

## semantic-PR137-S031
**freenet-telemetry-dashboard-main / WebSocket backpressure:** bounded per-client send queues with slow-client dropping
Final disposition: `superseded`. The donor reinforces bounded telemetry fan-out. LumiNet WebSocket Hub already has bounded global/per-client queues and removes stalled clients.

## semantic-PR137-S032
**freenet-telemetry-dashboard-main / bounded telemetry history:** hard-capped event history and initial replay window
Final disposition: `reference-only`. Bounded history/time-travel UX is useful reference; LumiNet already has telemetry ring-buffer ownership.

## semantic-PR137-S033
**freenet-telemetry-dashboard-main / topology/time-travel UX:** client-side event timeline/topology reconstruction
Final disposition: `reference-only`. The product affordance is retained as UI reference only; runtime state remains server-owned.

## semantic-PR137-S034
**freenet-telemetry-dashboard-main / telemetry server/database authority:** standalone WebSocket server and telemetry persistence process
Final disposition: `rejected-with-reason`. LumiNet already exposes bounded authenticated operator events; a second telemetry server/database would duplicate control/retention authority.

## semantic-PR137-S035
**frontend-wasm_2_ / WASM host boundary:** Go wasm_exec JavaScript host bridge
Final disposition: `reference-only`. The host bridge illustrates WASM/JS capability boundaries but has no verified source/provenance context in this archive.

## semantic-PR137-S036
**frontend-wasm_2_ / opaque executable provenance:** prebuilt tester.wasm without source or license evidence
Final disposition: `rejected-with-reason`. An opaque executable with no matching source/license provenance is not an admissible runtime or release input.

## semantic-PR137-S037
**frontend-wasm_2_ / executable WASM authority:** generic browser/WASM execution surface
Final disposition: `rejected-with-reason`. LumiNet does not need a new browser-side executable extension plane; the binary remains non-executed evidence only.

## semantic-PR137-S038
**fsociety-master / offensive exploitation toolkit:** integrated scanning/bruteforce/exploitation command set
Final disposition: `rejected-with-reason`. Active exploitation, credential attacks, and attack automation are outside LumiNet product scope and are not imported.

## semantic-PR137-S039
**fsociety-master / attack-surface taxonomy:** enumerated web/network attack categories
Final disposition: `reference-only`. Only defensive taxonomy is retained to inform security review; no offensive command implementation is used.

## semantic-PR137-S040
**fsociety-master / privileged install/update:** toolkit installation/update scripts
Final disposition: `rejected-with-reason`. Installer authority for an offensive tool would introduce broad host mutation unrelated to LumiNet runtime.

## semantic-PR137-S041
**fteproxy-master / record framing:** explicit record-layer encode/decode boundaries for format-transforming transport
Final disposition: `reference-only`. Record framing/size discipline is useful transport evidence; LumiNet keeps its existing relay/proxy framing owners.

## semantic-PR137-S042
**fteproxy-master / format transformation:** formal format definitions for censorship-resistant traffic shape
Final disposition: `reference-only`. Traffic-shape definitions are retained as conceptual evidence only; no custom FTE grammar is promoted into production.

## semantic-PR137-S043
**fteproxy-master / FTE client/server authority:** standalone FTE proxy client/server/relay stack
Final disposition: `rejected-with-reason`. Adding a new custom transport/client/server stack would duplicate proxy authority and cryptographic responsibility.

## semantic-PR137-S044
**fwlite-master / mutable source updater:** download mutable GitHub master archives and replace bundled code/lists
Final disposition: `rejected-with-reason`. Mutable unpinned remote archives/lists cannot define release source or dependencies. LumiNet release inputs remain hash-frozen.

## semantic-PR137-S045
**fwlite-master / proxy selection UX:** smart routing/block detection/response-time operator behavior
Final disposition: `reference-only`. Endpoint/routing UX is useful reference; LumiNet already owns endpoint admission/planning and health evidence.

## semantic-PR137-S046
**fwlite-master / external rule-list authority:** bundled gfwlist as externally maintained routing input
Final disposition: `rejected-with-reason`. A large external list must not become authoritative routing state without explicit provenance/update controls.

## semantic-PR137-S047
**go-tun2socks-master / TUN TCP lifecycle:** lwIP-backed TCP connection callbacks/lifecycle
Final disposition: `reference-only`. Connection lifecycle is useful reference, but LumiNet already owns TUN/TCP/UDP association semantics.

## semantic-PR137-S048
**go-tun2socks-master / IPv4/IPv6 stack split:** separate compiled IPv4 and IPv6 lwIP entry surfaces
Final disposition: `reference-only`. The split reinforces that relay endpoint IPv6 support is distinct from authoritative NAT payload-family support. LumiNet continues to state its IPv4 NAT limitation explicitly.

## semantic-PR137-S049
**go-tun2socks-master / second lwIP/TUN stack:** embedded C lwIP runtime and Go bridge
Final disposition: `superseded`. LumiNet already has a target TUN/NAT owner; importing another lwIP stack would duplicate packet/data-plane ownership.

## semantic-PR137-S050
**gost-master / proxy chain composition:** multi-node proxy chain/selector composition
Final disposition: `reference-only`. Chaining/selection mechanisms are useful comparison evidence; target proxy-core ownership remains unchanged.

## semantic-PR137-S051
**gost-master / permission/bypass policy:** explicit permission and bypass policy surfaces
Final disposition: `reference-only`. Permission/bypass structures are retained as policy reference; LumiNet keeps its existing routing/authorization owners.

## semantic-PR137-S052
**gost-master / embedded example credentials:** checked-in private keys/certificates and sample username/password data
Final disposition: `guardrail-derived`. The archive contains example private keys and plaintext sample credentials. Negative evidence reinforces that donor secrets are never production inputs and secrets remain externalized.

## semantic-PR137-S053
**gost-master / whole proxy/server engine:** general-purpose proxy/server runtime
Final disposition: `rejected-with-reason`. A second broad proxy/server engine would duplicate protocol/config/server authority despite its permissive license.

## semantic-PR137-S054
**grasshopper-main / UDP hopping/packetization:** UDP forwarding/hopping packet lifecycle
Final disposition: `reference-only`. Packetization/hopping behavior is useful transport research evidence only.

## semantic-PR137-S055
**grasshopper-main / custom cryptographic suite:** multi-cipher/QPP-based custom packet cryptography
Final disposition: `rejected-with-reason`. The donor exposes a large custom cipher surface and QPP dependency. LumiNet does not expand cryptographic authority for an unrequired transport.

## semantic-PR137-S056
**grasshopper-main / bundled QPP dependency:** vendored QPP and transitive dependencies
Final disposition: `superseded`. Vendored dependency bytes are fully accounted and overlap prior QPP evidence; they receive no new semantic credit or authority.

## semantic-PR137-S057
**hawk-proxy-main / domain allowlist boundary:** substring host allowlist that accepts unsafe superstrings
Final disposition: `hardened`. The donor demonstrates an unsafe substring host boundary; LumiNet WhiteDNS had the same class of error. Target bypass rules now match exact domain or dot-delimited subdomain and ignore empty rules.

## semantic-PR137-S058
**hawk-proxy-main / privileged installer:** root-mutating Docker install and unpinned Git clone
Final disposition: `rejected-with-reason`. The installer mutates apt/Docker/system paths and clones a mutable remote repository. LumiNet retains pinned/guarded provisioning ownership.

## semantic-PR137-S059
**hawk-proxy-main / standalone HTTP proxy authority:** small allowlisted HTTP proxy server
Final disposition: `rejected-with-reason`. Even a narrow proxy server would be a second inbound/runtime authority; its allowlist design is also unsafe.

## semantic-PR137-S060
**hping-master / raw packet generation:** raw crafted IP/TCP/UDP/ICMP packet engine
Final disposition: `rejected-with-reason`. Raw packet attack/generation authority is not needed for LumiNet production behavior.

## semantic-PR137-S061
**hping-master / spoofed scan methodology:** spoofed scanning/IPID analysis guidance
Final disposition: `reference-only`. Only defensive protocol/trust-boundary lessons are retained; active spoofed scanning is not operationalized.

## semantic-PR137-S062
**hping-master / promiscuous/network interface mutation:** interface promiscuous/raw-socket support
Final disposition: `rejected-with-reason`. Direct interface mutation/raw capture would conflict with the existing host-network ownership model.

## semantic-PR137-S063
**httun-main / HTTP relay response sequencing:** sliding-window sequence validation against duplicate/stale/replayed messages
Final disposition: `hardened`. Sequence evidence exposed that LumiNet sent a request sequence but never checked an echoed response sequence. Responses now fail closed on a mismatched optional Seq while legacy omission remains compatible.

## semantic-PR137-S064
**httun-main / replay window:** bounded duplicate/stale message rejection window
Final disposition: `reference-only`. The richer bidirectional replay window is retained as protocol evidence. LumiNet’s current HTTP relay contract is request/response sequenced rather than importing the donor protocol wholesale.

## semantic-PR137-S065
**httun-main / L7 admission policy:** server-side L7/net-list admission rules
Final disposition: `reference-only`. Network-list admission is useful server-policy reference; LumiNet keeps its own destination/admission owners.

## semantic-PR137-S066
**httun-main / whole HTTP tunnel/server:** standalone encrypted HTTP/TUN/FastCGI server stack
Final disposition: `rejected-with-reason`. A second tunnel server/TUN authority would duplicate existing relay/runtime ownership and protocol surface.

## semantic-PR137-S067
**hysteria-python-main / Python/native FFI packaging:** Python package boundary around native Hysteria bindings
Final disposition: `reference-only`. FFI/package layering is useful packaging reference; LumiNet retains its Rust/C and proxy core boundaries.

## semantic-PR137-S068
**hysteria-python-main / bundled upstream provenance:** embedded Hysteria Go and pybind11 source trees
Final disposition: `superseded`. Bundled upstream trees are hash-accounted as vendored content and receive no independent donor semantic credit.

## semantic-PR137-S069
**hysteria-python-main / Hysteria runtime authority:** embedded upstream Hysteria client/server engine
Final disposition: `rejected-with-reason`. LumiNet already owns supported proxy core integration; embedding another Hysteria engine/build chain is unnecessary.
