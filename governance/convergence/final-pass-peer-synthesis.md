# LumiNet final all-peer convergence synthesis
## Decision summary
This final convergence re-opened all **43 previously supplied donor archives** against the current ninth-order LumiNet tree rather than trusting earlier wave labels. The reproducible accountability graph covers **9556 archive members**, **8040 file/symlink surfaces**, **1516 directories**, **37 symlinks**, **523 recursively bounded module groups**, and **17724 parsed declarations/symbols**. All **60 earlier fine-grained eighth/ninth-order semantic decisions** were revalidated against current donor hashes and current target/test anchors. The final pass adds **9 cross-wave semantic decisions**, producing **592 total final adoption/accountability records**.
The final pass did not maximize imported code volume. It maximized coherent target value: peer mechanisms were decomposed and recomposed into existing LumiNet owners, unsafe/dormant duplicate authorities were retired, and strong peer subsystems serving a different product role were marked reference-only instead of being falsely called superseded.
## Final target-native changes
### Provider-scoped automatic mutation retry and coordination
- `remoteaction.Policy` now separates **action identity/safety class** from an explicit **provider rate-limit scope**. Cloudflare provisioning/scanner/DDNS mutations share the Cloudflare quota scope; Google Drive mutations share their provider scope; WARP has its own scope. Arbitrary webhooks, portal actions, decoy traffic, and other semantically unrelated one-offs remain action-scoped.
- Provider throttling learned by one action suppresses other declared actions in that provider scope. State remains bounded and secret-free.
- Each provider scope has a bounded in-flight gate and the coordinator has bounded scope cardinality. Capacity exhaustion fails closed **before mutation I/O**.
- Locally selected exponential retry delay uses equal jitter to avoid synchronized herd re-entry; explicit provider `Retry-After` remains authoritative and exact.
- `Idempotent`, `ReconcileBeforeRetry`, and `SingleAttempt` replay classes remain authoritative. Provider-level coordination never implies payload equivalence or generic mutation coalescing.
- Aggregate operator telemetry reports cooldown keys, active scopes, in-flight count, cooldown/in-flight waits, capacity stops, provider rate limits, retry sleeps, and reconciliations without exposing URLs, payloads, or credentials.
### Canonical live configuration authority
- Caddy-style conditional mutation was **promoted from the dormant compatibility manager into the actual `foundation/config.Manager`** and a shared HTTP config-mutation adapter.
- Durable `_revision` generations survive restart, legacy files are migrated atomically, externally changed files cannot replay an old generation, and byte-identical watcher reloads do not churn revisions. This closes process-restart ABA and a discovered self-watch rewrite-loop edge case.
- `Get`/publication owns deep copies of nested mutable aggregates rather than leaking aliases to caller memory.
- Secret updates are copy-on-write: changed plaintext secrets stage under fresh references, failed file commits roll staged refs back, successful config publication happens before superseded refs are retired, and cleanup failure cannot invalidate committed state.
- Generated secret references stay in the authoritative in-memory snapshot; unchanged secret/ref pairs are reused.
- `HostsOverride` runtime mutation occurs only after durable config commit.
- Settings, DDNS, and proxy-directory writers all use the same CAS path. HTTP `If-Match` stale writers receive 412; body/snapshot revision conflicts use 409.
### Authority reduction and hardening
- Removed dormant `reverse_tls.go`: it defaulted to certificate-verification bypass, had an unsafe shared raw-relay retry lifecycle, and had no production caller.
- Removed dormant `api_key_reverse_proxy.go`: empty `API_SECRET` effectively disabled authentication, configuration parsing could terminate the daemon, and it duplicated proxy authority without a caller.
- The ninth-order dormant traffic shaper remains retired. Host proxy/routing/qdisc mutations continue to belong to the durable host-network transaction owner.
- Canonical repository verification now exports `PYTHONDONTWRITEBYTECODE=1` so the verification process cannot create `__pycache__` residue that its own final audit rejects.
## Higher-level plane convergence
| Plane | Representative peers | Target owner / outcome | Disposition | Residual gap |
|---|---|---|---|---|
| remote mutation coordination | firewalla-master, unique-queue-master | src/apps/daemon/internal/foundation/remoteaction/remoteaction.go | adopted-and-hardened | No known final-pass gap; provider-specific scopes must be declared by new mutation integrations. |
| canonical live configuration authority | caddy-master | src/apps/daemon/internal/foundation/config/config.go;src/apps/daemon/internal/adapters/api/config_mutation.go | promoted-and-hardened | No known live config writer bypasses the Manager CAS path. |
| DNS server/plugin runtime and load shedding | coredns-master | src/apps/daemon/internal/networking/dns/dnsproxy.go;src/apps/daemon/internal/networking/dns/dohcache.go | superseded-by-bounded-target-owners | Revisit only if profiling identifies a concrete uncovered write/concurrency bottleneck. |
| Unix firewall / DNS leak / broad network policy | InviZible-master, firewalla-master | src/apps/daemon/internal/platform/system/firewall_unix.go;src/apps/daemon/internal/platform/system/host_network.go | guardrail-deferred | Unix DNS-leak protection is intentionally unsupported; implementing it requires a reversible HostNetworkChange, not raw peer rules. |
| always-on IDS/alarm policy | firewalla-master | n/a | reference-only-outside-current-product-role | No general IDS plane in LumiNet; this is an explicit product-scope omission rather than missed code. |
| inbound reverse proxy / load balancer | caddy-master | n/a | reference-only-role-mismatch | No inbound general-purpose reverse-proxy product plane is claimed. |
| automatic inbound TLS certificate management | caddy-master | n/a | reference-only-role-mismatch | No general inbound ACME/certificate-serving plane is claimed. |
| service desired-state scheduling and restart recovery | InviZible-master | src/apps/daemon/internal/integrations/sub/profile_service.go;src/apps/daemon/internal/platform/system/process_supervisor.go | superseded-by-target-native-owners | No generic job scheduler is added; add one only when multiple independent durable workflows require a shared persisted queue. |
| panel user/billing/quota databases | Marzban-master, eve-xui-manager-main | src/apps/daemon/internal/integrations/sub/profile_entitlement.go | decomposed-and-recomposed | No multi-tenant billing/user-management product plane is claimed. |
| WARP endpoint quality / noise | BPB-Warp-Scanner-main | src/apps/daemon/internal/runtime/warp/warp_scanner.go;src/apps/daemon/internal/runtime/warp/noise.go | adapted-and-hardened | No separate WARP scanner/installer authority remains necessary. |
| network quality diagnostics | defyxVPN-main(1) | src/apps/daemon/internal/adapters/api/speedtest_runner.go;src/apps/daemon/internal/adapters/api/speedtest_metrics.go | recomposed | No upload benchmark plane is added without a safe endpoint/side-effect contract. |
| Tor lifecycle and identity rotation | Auto_Tor_IP_changer-master(2), torrequest-master | src/apps/daemon/internal/platform/system/tor_controller.go;src/apps/daemon/internal/platform/system/tor_guard_rotation.go;src/apps/daemon/internal/platform/system/tor_process.go | superseded-by-canonical-tor-owner | No independent auto-IP loop is retained. |
| packet/DPI evasion mechanisms | GoodbyeDPI-master | src/apps/daemon/internal/runtime/proxy/evasion_contract.go;src/apps/daemon/internal/runtime/proxy/evasion_tunnel.go | superseded-and-reference | Some donor tricks remain platform-specific reference material rather than claimed equivalence. |
| root deployment/bootstrap installers | x-ui-pro-master, V2ray-for-Doprax-main(1) | n/a | guardrail-and-reference-only | LumiNet still lacks a target-native replacement for every peer one-command VPS installer; this is deliberate. |
| OAuth/social login middleware | gologin-main | src/apps/daemon/internal/adapters/api/middleware.go;src/apps/daemon/internal/adapters/api/router.go | reference-only-no-current-identity-need | No social OAuth/OIDC login plane is claimed. |
| geodata and crypto data ownership | openssl-cffi-master, sing-geoip-main, sing-geosite-main | src/apps/daemon/internal/foundation/crypto;src/apps/daemon/internal/networking/geoip;src/apps/daemon/internal/networking/routing/domain_data | superseded-by-existing-high-assurance-owners | External dataset refresh remains subject to existing admission/provenance controls. |
| proxy client catalogs and presets | Proxy-client-collection-main | src/apps/daemon/internal/integrations/sub/profile_service.go;src/apps/daemon/internal/runtime/proxy/core_manager.go | reference-and-preset-evidence | Some catalog-only clients remain reference material. |
| offensive/persistence/interception safety-veto surfaces | DNS-Persist-master, ftpscan-master, InterceptSuite-main | n/a | rejected-production-capability | None; rejection is intentional and final for this scope. |

The table intentionally distinguishes **role mismatch** from supersession. For example, Caddy inbound reverse-proxy/load-balancing and certificate automation are strong implementations, but LumiNet currently has no general internet-facing application-server role that consumes them. They therefore remain reference evidence rather than being forced into the outbound client-proxy runtime.
## New cross-wave semantic decisions
| Record | Donor | Value unit | Disposition | Target capability | Validation |
|---|---|---|---|---|---|
| FP-S001 | firewalla-master | provider-scoped rate-limit memory shared across distinct mutation actions | inspired-native | provider-scoped automatic mutation retry coordinator | verified |
| FP-S002 | firewalla-master | bounded per-provider mutation concurrency with fail-closed coordinator capacity | inspired-native | bounded provider mutation concurrency | verified |
| FP-S003 | firewalla-master | de-synchronized local retry backoff while preserving authoritative Retry-After | guardrail-derived | de-synchronized automatic mutation retry | verified |
| FP-S004 | caddy-master | optimistic conditional mutation promoted from dormant compatibility manager into the canonical config owner and HTTP routes | adapted | canonical live configuration CAS | verified |
| FP-S005 | caddy-master | restart-safe durable configuration generation preventing validator ABA | inspired-native | restart-safe configuration generation | verified |
| FP-S006 | caddy-master | copy-on-write secret references composed transactionally with config publication | synthesized | atomic config/secret authority boundary | verified |
| FP-S007 | coredns-master | load-shed DNS responses when server write/concurrency budget is exhausted | superseded | bounded DNS admission and duplicate suppression | reviewed |
| FP-S008 | unique-queue-master | deduplication queue examined as a mutation-coalescing candidate and converted into a payload-identity guardrail | guardrail-derived | semantically safe mutation coordination | reviewed |
| FP-S009 | InviZible-master | broad Unix firewall/DNS-leak rules reviewed as a target-native transaction precondition rather than imported authority | guardrail-derived | single transactional host-network mutation authority | verified |

## Target repairs discovered during the final pass
- **FP-R001 — provider-scope mutation cooldown**: remoteaction cooldown now keys on declared provider quota scope across distinct actions
- **FP-R002 — bounded provider mutation concurrency**: per-scope in-flight limit and global active-scope capacity fail closed before side effects
- **FP-R003 — retry herd control**: local exponential backoff is jittered while explicit Retry-After remains exact
- **FP-R004 — live config CAS**: canonical Manager and all live config HTTP writers use revision compare-and-swap
- **FP-R005 — owned config snapshots**: Get/Save deep-copy nested proxy nodes, decoy targets and trusted-key maps; generated refs retained in published state
- **FP-R006 — copy-on-write secret commit**: staged secret refs roll back on config failure and superseded refs retire only after durable publication
- **FP-R007 — durable config generation**: _revision survives restart, legacy files migrate, reused changed external revisions advance to prevent ABA, and byte-identical self-reloads do not churn generations
- **FP-R008 — stop spurious load rewrites**: inline-secret migration detector excludes the deliberately inline-encrypted Upgen seed
- **FP-R009 — post-commit runtime side effect ordering**: HostsOverride applies only after durable config CAS succeeds
- **FP-R010 — retire unsafe dormant TLS relay**: removed unused default-InsecureSkipVerify/shared-raw-relay legacy port
- **FP-R011 — retire unsafe dormant API-key reverse proxy**: removed unused auth-bypass-on-empty-secret/process-fatal legacy proxy port
- **FP-R012 — historical successor layering**: ninth-order checker freezes its original target against final-pass successor baseline instead of reinterpreting history
- **FP-R013 — eighth current-anchor refresh**: historical E8 retry record points at the current coordinator helper after owner evolution
- **FP-R014 — topology retirement registration**: legacy reverse proxies explicitly retired in relocation provenance rather than silently deleted
- **FP-R015 — self-clean canonical verification**: Makefile exports PYTHONDONTWRITEBYTECODE so repository checks cannot create __pycache__ residue that the final audit must reject

## Donor-by-donor final accountability
| Donor | Members | Surfaces | Dirs | Symbols | License posture | Final convergence domains |
|---|---:|---:|---:|---:|---|---|
| 3xui-telegram-bot-main | 39 | 32 | 7 | 210 | MIT | operator entitlement evidence |
| AgentDNS-main | 16 | 13 | 3 | 26 | no explicit LICENSE in archive; README claims MIT, treated as unverified/no-license for source reuse | DNS resilience |
| Auto_Tor_IP_changer-master(2) | 4 | 3 | 1 | 2 | no explicit license; exact-byte duplicate of sixth-order donor archive | Tor routing |
| bia-pain-bache-main | 55 | 50 | 5 | 288 | GPL-2.0; evidence/independent comparison only | proxy/evasion |
| BPB-Warp-Scanner-main | 17 | 14 | 3 | 65 | GPL-3.0; selected semantics independently rederived, no source copied | WARP quality |
| BWLimiter-main | 9 | 7 | 2 | 157 | no explicit license; negative/guardrail evidence only | host-network mutation |
| caddy-master | 688 | 627 | 61 | 3733 | Apache-2.0 | remote mutation resilience, live configuration authority |
| coredns-master | 1103 | 985 | 118 | 4106 | Apache-2.0 | DNS resilience |
| defyxVPN-main(1) | 676 | 503 | 173 | 215 | MIT | network diagnostics/scanning |
| dns-over-https-proxy-master | 1294 | 1091 | 203 | 16 | Apache-2.0 | DNS resilience |
| DNS-Persist-master | 35 | 30 | 5 | 69 | MIT | negative security evidence |
| ev-master_(1) | 16 | 14 | 2 | 47 | no explicit license; evidence only | proxy/evasion |
| eve-xui-manager-main | 103 | 91 | 12 | 2087 | no explicit license; evidence only | operator entitlement evidence, live configuration authority |
| firewalla-master | 2599 | 2249 | 350 | 3542 | AGPL-3.0; target independently rederives selected semantics | remote mutation resilience, host-network mutation, WARP quality |
| ftpscan-master | 11 | 10 | 1 | 12 | no explicit license | negative security evidence |
| Go-netowrking-tools-main | 13 | 5 | 8 | 8 | no explicit license | network diagnostics/scanning |
| GodMode-main | 157 | 130 | 27 | 117 | MIT | deployment/process ownership |
| godnsagent-master(1) | 25 | 21 | 4 | 26 | MIT | DNS resilience |
| gologin-main | 92 | 75 | 17 | 208 | MIT | deployment/process ownership |
| GoodbyeDPI-master | 35 | 29 | 6 | 16 | Apache-2.0 | proxy/evasion |
| incy-platforms-main | 3 | 2 | 1 | 0 | no explicit license; descriptive reference only | proxy/evasion |
| InterceptSuite-main | 3 | 2 | 1 | 0 | no explicit license | negative security evidence |
| InviZible-master | 1563 | 1248 | 315 | 930 | GPL-family copyleft; target uses independent target-native semantics only | runtime supervision, host-network mutation, Tor routing |
| lossyconn-master | 10 | 9 | 1 | 46 | MIT | network diagnostics/scanning |
| Marzban-master | 557 | 434 | 123 | 1318 | AGPL-3.0; selected semantics independently rederived, no source copied | operator entitlement evidence, live configuration authority |
| nahan-main(1) | 17 | 14 | 3 | 200 | no explicit license; new revision evidence only | proxy/evasion |
| openssl-cffi-master | 5 | 4 | 1 | 5 | Apache-2.0 | crypto/geodata |
| Proxy-client-collection-main | 3 | 2 | 1 | 0 | no explicit license; descriptive reference only | proxy/evasion |
| Se7en-Pro-1.0.0 | 199 | 172 | 27 | 78 | MIT | runtime supervision, host-network mutation |
| Serverless-for-Iran-main | 9 | 7 | 2 | 0 | GPL-3.0; preset concepts only, no source/config copied | proxy/evasion |
| sing-geoip-main | 16 | 13 | 3 | 11 | GPL-family copyleft; target does not copy generator source | crypto/geodata |
| sing-geosite-main | 16 | 13 | 3 | 14 | GPL-family copyleft; target does not copy generator source | crypto/geodata |
| snowbox-master | 12 | 11 | 1 | 0 | no explicit license; test-environment reference only | proxy/evasion |
| Subnet-Divider-main | 3 | 2 | 1 | 3 | no explicit license | network diagnostics/scanning |
| sysproxy-main | 11 | 7 | 4 | 4 | MIT | host-network mutation |
| torrequest-master | 6 | 5 | 1 | 16 | metadata declares MIT | Tor routing |
| unique-queue-master | 9 | 8 | 1 | 28 | no explicit license | remote mutation resilience |
| V2ray-for-Doprax-main(1) | 11 | 9 | 2 | 0 | no explicit root license in archive | deployment/process ownership |
| V2RayN-PRO-main(1) | 72 | 61 | 11 | 0 | GPL-family copyleft plus bundled third-party binaries/notices; target does not copy source/binaries | proxy/evasion |
| v2rayng-panel-main(1) | 2 | 1 | 1 | 0 | no explicit license | proxy/evasion |
| vps-warp-main(1) | 4 | 3 | 1 | 7 | MIT | WARP quality |
| x-ui-pro-master | 27 | 25 | 2 | 11 | no explicit license; operational guardrail/reference only | deployment/process ownership |
| zeus-main(1) | 11 | 9 | 2 | 103 | no explicit license; selected concepts independently rederived only | operator entitlement evidence, live configuration authority |

## Composition conclusions
- **Many-to-one:** Firewalla retry/rate-limit behavior plus unique-queue negative evidence converge into one provider-scoped mutation coordinator without payload-blind deduplication.
- **One-to-many:** Caddy conditional mutation evidence distributes across durable config generation, secret transaction, and three live HTTP mutation surfaces.
- **Negative-to-guardrail:** InviZible/Firewalla firewall breadth becomes a requirement that Unix firewall support must enter through the reversible host-network transaction rather than raw iptables side effects.
- **Decomposition:** Marzban/3xui/eve/Zeus panel systems contribute quota/expiry operator semantics but not their user/billing databases.
- **Supersession:** CoreDNS general load-shedding, InviZible WorkManager, Tor auto-rotation loops, peer WARP scanners, raw DPI engines, and proxy catalogs remain either subsumed by narrower target owners or explicit reference material.
- **Safety veto:** DNS persistence/C2, FTP-bounce scanning, and interception/MITM peers remain negative evidence only.
## Residual gaps and explicit non-claims
- Unix DNS-leak protection remains intentionally unsupported. A future implementation must be a first-class `HostNetworkChange` with durable snapshot, apply, verification, recovery, and rollback.
- LumiNet does not claim a general inbound Caddy-like reverse-proxy/ACME server product, a Firewalla-like always-on IDS/policy engine, a multi-tenant panel billing/user database, social OAuth login, or one-command root-mutating VPS installer. These are explicit product-role decisions, not unreviewed omissions.
- Full dependency-bound Go/Rust/native builds remain subject to the toolchain limitations stated in the validation report.
