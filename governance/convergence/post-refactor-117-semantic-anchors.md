# LumiNet post-refactor 117 semantic decision anchors

## PR117-S001
- Donor: `serenity-dev`
- Target capability: proxy configuration validation
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/config_watcher.go`
- Final disposition: `reference-only`
- Invariant: generated configuration is filtered/validated before becoming runtime input
- Negative invariant: peer templates or subscription text never become authority merely by parsing

## PR117-S002
- Donor: `serenity-dev`
- Target capability: host provisioning guardrail
- Existing owner/substitute: `src/apps/daemon/internal/integrations/provision/vps.go`
- Final disposition: `rejected-with-reason`
- Invariant: privileged provisioning remains explicit and target-owned
- Negative invariant: donor root-mutating installer scripts are never executed or imported

## PR117-S003
- Donor: `shadow-main`
- Target capability: network evaluation methodology
- Existing owner/substitute: `src/apps/daemon/internal/analysis/diagnostics`
- Final disposition: `reference-only`
- Invariant: performance/correctness evidence must disclose controlled workload and network conditions
- Negative invariant: simulation results never grant runtime authority

## PR117-S004
- Donor: `shadow-main`
- Target capability: runtime authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/platform/system`
- Final disposition: `rejected-with-reason`
- Invariant: simulation instrumentation stays outside production mutation authority
- Negative invariant: syscall interposition is not introduced into production runtime

## PR117-S005
- Donor: `shadowsocks-libev-master`
- Target capability: mobile TUN SOCKS association
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost/tun2socks_adapter.go#installUDPAssoc`
- Final disposition: `hardened`
- Invariant: concurrent first packets converge on one installed association
- Negative invariant: duplicate first packets cannot overwrite or leak live associations

## PR117-S006
- Donor: `shadowsocks-libev-master`
- Target capability: mobile TUN SOCKS handshake
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost/tun2socks_adapter.go#writeFull`
- Final disposition: `hardened`
- Invariant: SOCKS control frames are written completely or fail
- Negative invariant: short writes cannot silently truncate protocol frames

## PR117-S007
- Donor: `shadowsocks-libev-master`
- Target capability: proxy runtime authority
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/ss_server.go`
- Final disposition: `superseded`
- Invariant: one target-native proxy lifecycle remains authoritative
- Negative invariant: donor plugin/server process authority is not added

## PR117-S008
- Donor: `simple-obfs-android-master`
- Target capability: Android transport packaging
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost`
- Final disposition: `reference-only`
- Invariant: native/mobile binaries remain explicit platform-owned dependencies
- Negative invariant: bundled plugin binaries never gain execution authority implicitly

## PR117-S009
- Donor: `simple-obfs-android-master`
- Target capability: Android executable-extension guardrail
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost`
- Final disposition: `rejected-with-reason`
- Invariant: mobile transport execution remains target-owned
- Negative invariant: peer APK/plugin registration is not imported

## PR117-S010
- Donor: `sing-box-dashboard-main`
- Target capability: WebSocket operator contract
- Existing owner/substitute: `src/apps/daemon/internal/adapters/api/websocket.go`
- Final disposition: `reference-only`
- Invariant: message framing and connection state remain explicit and bounded
- Negative invariant: UI connection state never becomes runtime authority

## PR117-S011
- Donor: `sing-box-dashboard-main`
- Target capability: operator presentation
- Existing owner/substitute: `src/apps/daemon/internal/adapters/api`
- Final disposition: `superseded`
- Invariant: UI consumes runtime state but does not own it
- Negative invariant: peer dashboard state cannot mutate runtime authority implicitly

## PR117-S012
- Donor: `sing-box-dev-next`
- Target capability: VLESS WebSocket response state
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/websocket_conn_helpers.go#vlessWSResponseState`
- Final disposition: `hardened`
- Invariant: protocol preface parsing survives WebSocket fragmentation
- Negative invariant: frame boundaries cannot corrupt protocol state

## PR117-S013
- Donor: `sing-box-dev-next`
- Target capability: VLESS WebSocket response state
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/websocket_conn_helpers.go#vlessWSResponseState`
- Final disposition: `hardened`
- Invariant: the VLESS response preface is consumed once per connection
- Negative invariant: later application payload is never reinterpreted as a VLESS response header

## PR117-S014
- Donor: `sing-box-dev-next`
- Target capability: VLESS WebSocket response state
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/websocket_conn_helpers.go#vlessWSResponseState`
- Final disposition: `hardened`
- Invariant: initial response version must match the supported VLESS version
- Negative invariant: malformed response metadata cannot be treated as application payload

## PR117-S015
- Donor: `sing-box-dev-next`
- Target capability: proxy runtime authority
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/core_manager.go`
- Final disposition: `rejected-with-reason`
- Invariant: one coherent target proxy runtime remains authoritative
- Negative invariant: peer whole-engine ownership is not imported

## PR117-S016
- Donor: `sing-box-dev-next`
- Target capability: operator API authority
- Existing owner/substitute: `src/apps/daemon/internal/adapters/api`
- Final disposition: `reference-only`
- Invariant: operator APIs remain authenticated through target-native authority
- Negative invariant: peer API tokens/routes do not become a parallel control plane

## PR117-S017
- Donor: `sing-box-extended-extended`
- Target capability: endpoint-pool planning
- Existing owner/substitute: `src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go`
- Final disposition: `reference-only`
- Invariant: dispatch authority remains conditioned by target observation/admission rules
- Negative invariant: peer failover policy cannot bypass target endpoint eligibility

## PR117-S018
- Donor: `sing-box-extended-extended`
- Target capability: inbound/server authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy`
- Final disposition: `rejected-with-reason`
- Invariant: new peer servers are not enabled by convergence evidence alone
- Negative invariant: SSH/MTProxy/domain-fronting/FakeTLS server authority is not added

## PR117-S019
- Donor: `sing-box-extended-extended`
- Target capability: inbound/server authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy`
- Final disposition: `rejected-with-reason`
- Invariant: externally reachable server surfaces require an explicit target requirement and owner
- Negative invariant: peer inbound camouflage features are not imported

## PR117-S020
- Donor: `sing-box-extended-extended`
- Target capability: proxy resource bounds
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/http_bounds.go`
- Final disposition: `reference-only`
- Invariant: connections/messages/retries remain explicitly bounded
- Negative invariant: resource-limiter evidence does not create a second scheduler/authority

## PR117-S021
- Donor: `sing-box-extended-extended`
- Target capability: DNS authority
- Existing owner/substitute: `src/apps/daemon/internal/adapters/api/handlers_dns.go`
- Final disposition: `reference-only`
- Invariant: DNS fallback remains inside the existing target owner
- Negative invariant: peer DNS transport cannot create a second resolver authority

## PR117-S022
- Donor: `sing-box-for-android-dev`
- Target capability: Android VPN lifecycle
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost`
- Final disposition: `reference-only`
- Invariant: VPN lifecycle remains explicit and platform-owned
- Negative invariant: peer service state does not become a parallel network authority

## PR117-S023
- Donor: `sing-box-for-android-dev`
- Target capability: Android integrity guardrail
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost`
- Final disposition: `rejected-with-reason`
- Invariant: platform integration remains transparent and target-owned
- Negative invariant: Xposed concealment hooks are not shipped or enabled

## PR117-S024
- Donor: `sing-box-for-android-dev`
- Target capability: build provenance
- Existing owner/substitute: `governance/convergence/post-refactor-117-nested-archives.csv`
- Final disposition: `reference-only`
- Invariant: nested donor archives are independently inspected and hash-bound
- Negative invariant: nested binaries never evade outer archive accountability

## PR117-S025
- Donor: `sing-cloudflared-main`
- Target capability: inbound exposure authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy`
- Final disposition: `rejected-with-reason`
- Invariant: external exposure remains target-owned and explicit
- Negative invariant: peer cloud-tunnel control planes are not introduced

## PR117-S026
- Donor: `sing-cloudflared-main`
- Target capability: relay WebSocket connection
- Existing owner/substitute: `src/apps/daemon/internal/integrations/relayclient/websocket_conn.go#NewWebSocketConn`
- Final disposition: `hardened`
- Invariant: relay WebSocket frames are bounded before application processing
- Negative invariant: oversized peer frames cannot allocate without the configured transport bound

## PR117-S027
- Donor: `tun2proxy-master`
- Target capability: TUN/NAT authority
- Existing owner/substitute: `src/apps/daemon/internal/platform/system/nat/nat.go`
- Final disposition: `reference-only`
- Invariant: target NAT capability claims match the actual IPv4-only owner
- Negative invariant: SOCKS relay IPv6 parsing must not be misrepresented as IPv6 payload/NAT support

## PR117-S028
- Donor: `tun2proxy-master`
- Target capability: mobile TUN SOCKS association
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost/tun2socks_adapter.go#readSocks5UDPRelay`
- Final disposition: `hardened`
- Invariant: SOCKS relay endpoints accept all SOCKS5 address types supported by the association protocol
- Negative invariant: IPv6 relay transport is never conflated with IPv6 tunneled-payload support

## PR117-S029
- Donor: `tun2proxy-master`
- Target capability: per-app routing
- Existing owner/substitute: `src/apps/daemon/internal/adapters/api/handlers_per_app_proxy.go`
- Final disposition: `reference-only`
- Invariant: application routing stays explicit and platform-owned
- Negative invariant: peer process/session metadata cannot bypass target routing policy

## PR117-S030
- Donor: `tun2proxy-master`
- Target capability: DNS authority
- Existing owner/substitute: `src/apps/daemon/internal/adapters/api/handlers_dns.go`
- Final disposition: `reference-only`
- Invariant: DNS/address mapping remains target-owned
- Negative invariant: peer virtual DNS is not introduced as a second source of truth

## PR117-S031
- Donor: `tun2socks-main`
- Target capability: TUN/NAT authority
- Existing owner/substitute: `src/apps/daemon/internal/platform/system/nat/nat.go`
- Final disposition: `reference-only`
- Invariant: one authoritative target NAT/TUN stack remains in production
- Negative invariant: donor dual-stack capability is not claimed as target behavior

## PR117-S032
- Donor: `tun2socks-main`
- Target capability: mobile TUN SOCKS handshake
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost/tun2socks_adapter.go#socksHandshakeDeadline`
- Final disposition: `hardened`
- Invariant: SOCKS negotiation cannot block indefinitely after dial
- Negative invariant: successful data-plane connections do not retain the setup deadline

## PR117-S033
- Donor: `tun2socks-main`
- Target capability: TUN architecture
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost/tun2socks_adapter.go`
- Final disposition: `reference-only`
- Invariant: packet ingress and proxy association have explicit ownership boundaries
- Negative invariant: peer device abstractions do not bypass target NAT authority

## PR117-S034
- Donor: `tun2socks-python-main`
- Target capability: donor provenance/accountability
- Existing owner/substitute: `governance/convergence/post-refactor-117-supersession-map.csv`
- Final disposition: `superseded`
- Invariant: byte-identical embedded donor code is counted once semantically
- Negative invariant: embedded copies cannot inflate donor-derived semantic credit

## PR117-S035
- Donor: `tun2socks-python-main`
- Target capability: language boundary
- Existing owner/substitute: `src/apps/daemon/internal/platform/mobilehost`
- Final disposition: `reference-only`
- Invariant: new language bindings require a target-owned contract and operational need
- Negative invariant: peer binding layers are not introduced without a target requirement

## PR117-S036
- Donor: `tun2socks-python-main`
- Target capability: dependency provenance
- Existing owner/substitute: `governance/convergence/post-refactor-117-license-map.csv`
- Final disposition: `reference-only`
- Invariant: vendored dependencies remain separately attributable
- Negative invariant: vendor code is not miscredited as donor-owned behavior

## PR117-S037
- Donor: `uquic-master`
- Target capability: QUIC transport authority
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/tuic_conn.go`
- Final disposition: `reference-only`
- Invariant: one target QUIC implementation remains authoritative
- Negative invariant: peer QUIC fork is not substituted without differential compatibility evidence

## PR117-S038
- Donor: `uquic-master`
- Target capability: fingerprint authority
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/ech.go`
- Final disposition: `reference-only`
- Invariant: fingerprint changes remain target-owned and testable
- Negative invariant: peer captured fingerprints do not grant runtime authority

## PR117-S039
- Donor: `uquic-master`
- Target capability: transport evaluation methodology
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/tuic_spec_test.go`
- Final disposition: `reference-only`
- Invariant: transport compatibility claims require protocol-level tests
- Negative invariant: peer popularity or feature breadth is not evidence of target compatibility

## PR117-S040
- Donor: `vanguards-master`
- Target capability: Tor defense reference
- Existing owner/substitute: `src/apps/daemon/internal/runtime/runtimecore/tor_engine.go`
- Final disposition: `reference-only`
- Invariant: Tor client/runtime authority remains singular
- Negative invariant: onion-service defense evidence does not imply onion-service server authority

## PR117-S041
- Donor: `vanguards-master`
- Target capability: Tor control authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/platform/system/tor_controller.go`
- Final disposition: `rejected-with-reason`
- Invariant: Tor control authority remains centralized
- Negative invariant: a second long-running Tor controller is not introduced

## PR117-S042
- Donor: `vanguards-master`
- Target capability: Tor diagnostics
- Existing owner/substitute: `src/apps/daemon/internal/runtime/runtimecore/tor_engine.go`
- Final disposition: `reference-only`
- Invariant: diagnostics may observe without silently changing path authority
- Negative invariant: peer verification state cannot override target Tor lifecycle/control

## PR117-S043
- Donor: `water-master`
- Target capability: executable-extension guardrail
- Existing owner/substitute: `src/apps/daemon/internal/runtime/routingplugin`
- Final disposition: `rejected-with-reason`
- Invariant: routing plugins remain metadata/policy integrations rather than arbitrary executable admission
- Negative invariant: remote/dynamic WATM bytes are never executed by this release

## PR117-S044
- Donor: `water-master`
- Target capability: executable-extension guardrail
- Existing owner/substitute: `src/apps/daemon/internal/runtime/routingplugin`
- Final disposition: `guardrail-derived`
- Invariant: untrusted executable content requires explicit sandbox/admission bounds
- Negative invariant: metadata plugins never escalate into executable plugins implicitly

## PR117-S045
- Donor: `water-master`
- Target capability: binary supply-chain guardrail
- Existing owner/substitute: `governance/convergence/post-refactor-117-surfaces.csv`
- Final disposition: `rejected-with-reason`
- Invariant: prebuilt donor binaries remain provenance evidence only
- Negative invariant: donor executable fixtures are not shipped into production

## PR117-S046
- Donor: `water-rs-main`
- Target capability: executable-extension guardrail
- Existing owner/substitute: `src/apps/daemon/internal/runtime/routingplugin`
- Final disposition: `rejected-with-reason`
- Invariant: plugin authority remains non-executable unless explicitly redesigned
- Negative invariant: second-language runtime evidence does not create an executable plugin plane

## PR117-S047
- Donor: `water-rs-main`
- Target capability: language/runtime ownership
- Existing owner/substitute: `src/apps/daemon/internal/runtime/routingplugin`
- Final disposition: `reference-only`
- Invariant: new language owners require concrete target need and operational validation
- Negative invariant: peer runtime language choice is not copied by default

## PR117-S048
- Donor: `water-rs-main`
- Target capability: binary supply-chain guardrail
- Existing owner/substitute: `governance/convergence/post-refactor-117-surfaces.csv`
- Final disposition: `rejected-with-reason`
- Invariant: donor executable fixtures remain evidence only
- Negative invariant: prebuilt test modules are not promoted into production

## PR117-S049
- Donor: `website-master`
- Target capability: measurement methodology
- Existing owner/substitute: `src/apps/daemon/internal/analysis/diagnostics`
- Final disposition: `reference-only`
- Invariant: measurement outputs remain reproducible and observational
- Negative invariant: metrics cannot silently mutate routing/control state

## PR117-S050
- Donor: `website-master`
- Target capability: deployment authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/analysis/diagnostics`
- Final disposition: `rejected-with-reason`
- Invariant: measurement evidence stays decoupled from production mutation authority
- Negative invariant: legacy server/deployment topology is not imported

## PR117-S051
- Donor: `website-master`
- Target capability: measurement test methodology
- Existing owner/substitute: `src/apps/daemon/internal/analysis/diagnostics`
- Final disposition: `reference-only`
- Invariant: diagnostic transformations should be testable against fixed fixtures
- Negative invariant: historical fixtures do not imply current network behavior

## PR117-S052
- Donor: `websocket-main`
- Target capability: WebSocket net.Conn contract
- Existing owner/substitute: `src/apps/daemon/internal/integrations/relayclient/websocket_conn.go#WebSocketConn`
- Final disposition: `hardened`
- Invariant: WebSocket adapters expose real addresses and deadlines through the underlying connection
- Negative invariant: net.Conn deadline methods cannot silently succeed without effect

## PR117-S053
- Donor: `websocket-main`
- Target capability: WebSocket validation methodology
- Existing owner/substitute: `src/apps/daemon/internal/integrations/relayclient/websocket_conn_test.go`
- Final disposition: `reference-only`
- Invariant: connection adapters require behavioral transport tests
- Negative invariant: compile-only evidence is insufficient for net.Conn semantics

## PR117-S054
- Donor: `websocket-main`
- Target capability: dependency provenance
- Existing owner/substitute: `governance/convergence/post-refactor-117-license-map.csv`
- Final disposition: `reference-only`
- Invariant: source identity remains explicit in validation claims
- Negative invariant: source-compatible donor evidence is never mislabeled as exact dependency-byte validation

## PR117-S055
- Donor: `wgsocks-main`
- Target capability: WireGuard/TUN authority
- Existing owner/substitute: `src/apps/daemon/internal/runtime/warp`
- Final disposition: `reference-only`
- Invariant: one target WireGuard/TUN ownership chain remains authoritative
- Negative invariant: peer WireGuard wrapper does not create a parallel dataplane

## PR117-S056
- Donor: `wgsocks-main`
- Target capability: NAT/DNS capability truth
- Existing owner/substitute: `src/apps/daemon/internal/platform/system/nat/nat.go`
- Final disposition: `reference-only`
- Invariant: capability documentation follows actual target behavior
- Negative invariant: peer dual-stack support is not credited to the target

## PR117-S057
- Donor: `wsnet-master`
- Target capability: routing-plugin boundary
- Existing owner/substitute: `src/apps/daemon/internal/runtime/routingplugin`
- Final disposition: `reference-only`
- Invariant: vendor integrations remain narrow adapters to target-owned runtime policy
- Negative invariant: routing plugins cannot become hidden host-network authorities

## PR117-S058
- Donor: `wsnet-master`
- Target capability: host-network authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/platform/system/firewall_unix.go`
- Final disposition: `rejected-with-reason`
- Invariant: firewall mutation remains centralized and auditable
- Negative invariant: vendor/routing code cannot directly whitelist firewall IPs or sockets

## PR117-S059
- Donor: `wsnet-master`
- Target capability: native dependency authority guardrail
- Existing owner/substitute: `src/apps/daemon/internal/runtime/proxy/ech.go`
- Final disposition: `rejected-with-reason`
- Invariant: native crypto/TLS dependencies remain explicit and target-owned
- Negative invariant: peer patched binary/dependency bundles are not imported

## PR117-S060
- Donor: `wsnet-master`
- Target capability: routing-plugin lifecycle
- Existing owner/substitute: `src/apps/daemon/internal/runtime/routingplugin`
- Final disposition: `reference-only`
- Invariant: vendor operations remain cancelable/bounded by target lifecycle
- Negative invariant: plugin callbacks cannot outlive or bypass target cancellation ownership
