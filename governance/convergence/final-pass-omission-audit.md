# LumiNet final convergence omission audit
## Completeness denominators
- Donor archives: **43**
- Archive members: **9556**
- File/symlink surfaces: **8040**
- Directories: **1516**
- Symlinks: **37**
- Recursively bounded module groups: **523**
- Parsed declarations/symbols: **17724**
- Revalidated prior semantic decisions: **60**
- New final semantic decisions: **9**
- Final ledger/accountability records: **592**
- Cross-peer supersession/composition groups: **13**
- Higher-level plane decisions: **18**
- Target repairs: **15**
- Frozen ninth-order baseline entries: **2546**
- Current exact final-pass delta paths at report generation: **37** (the delta is regenerated after this report is written).

## Audit ladder
### 1. Archive safety and extraction
All 43 archives were validated before extraction for absolute paths, traversal, device nodes, duplicate members, case collisions, unsafe links, and bounded expansion. No archive failed the final safety gate. The extracted roots were then verified against the archive roster.
### 2. Files, symlinks, directories, and deep leaves
Every extracted file/symlink is represented in `final-pass-surfaces.csv` with SHA-256, size, type, classification, authority status, semantic/accountability IDs, and notes. Directory coverage is separately recorded. Large donors are recursively partitioned; no splittable final module bucket exceeds 100 surfaces.
The apparent 29-surface increase over the earlier cumulative eighth+ninth total was isolated to **Se7en-Pro-1.0.0 embedded shallow `.git` metadata/history**. The embedded commit was inspected and the tracked source set remains the same 143 source files previously analyzed; no runtime implementation surface had been silently missed.
### 3. Symbols and registrations
Authoritative text/code surfaces were re-parsed for declarations, exported symbols, handlers, state/retry/security/persistence signals, and runtime registrations. The final symbol corpus contains 17,724 declarations/symbols. Binary, media, generated, vendored, localization, and administrative surfaces remain hash-accounted even when they are not semantic source of truth.
### 4. Historical semantic claims
All 60 prior fine-grained eighth/ninth-order semantic decisions were rechecked against the all-43 donor hashes and current target/test anchors. Historical identities/dispositions were retained; only current target pointers were refreshed where an owner evolved.
### 5. State, recovery, and authority paths
The final pass specifically re-opened mutation retries, provider throttling, config CAS, secret persistence, process recovery, DNS bounds, WARP quality, host-network mutation, Tor lifecycle, panel entitlement, deployment, and privileged firewall surfaces. Cross-store config/secret failure, process-restart generation ABA, watcher self-reload, retry herd synchronization, provider-wide throttling, and coordinator-capacity exhaustion were treated as interaction-level failure modes rather than file-level features.
### 6. Negative paths and trust boundaries
Safety-class retry remains fail-closed for ambiguous/single-attempt mutations; provider coordination does not authorize payload deduplication. Config CAS rejects stale writers. Secret copy-on-write prevents failed file commits from changing old secret-ref meaning. Privileged Unix firewall behavior remains unsupported rather than bypassing host-network rollback. Safety-veto peers do not appear as production feature names.
### 7. Operator/product surfaces
New live semantics are exposed only where target ownership exists: mutation retry aggregate status, strong config ETag/revision mutation, ninth-order network diagnostics, WARP ranking, and advisory entitlement. UI state and provider quota metadata remain non-authoritative.
### 8. Scripts, CI, packaging, and deployment
Root-mutating/no-license deployment scripts were reviewed as operational evidence and guardrails, not imported. The canonical repository verification target now disables Python bytecode generation to prevent verification-created residue. Historical convergence gates remain layered through frozen successor baselines rather than rewritten to describe the final tree.
### 9. Higher-level planes
`final-pass-high-level-plane-audit.csv` records 18 architecture/product planes with exact donor hashes, target ownership or explicit role mismatch/rejection, invariant, residual gap, and validation status. This prevents a final pass from being “complete” only at primitive/file granularity while skipping entire peer subsystems.
### 10. Cross-peer contradictions and supersession
The 13 final supersession/composition groups cover all 43 donor identities at least once. They explicitly reconcile competing retry, DNS, scheduler, host-network, WARP, diagnostic, entitlement, proxy/evasion, Tor, deployment, crypto/geodata, safety-veto, and live-config responsibilities.

## All donors accounted
- `3xui-telegram-bot-main` — archive `aba0c1ac694e08186a17b9b4c412b2d3979cf0859f370d42a6246605620be778`, 32 surfaces; final groups: operator entitlement evidence.
- `AgentDNS-main` — archive `add33e8ac55099939a21258081c4beb9d6b2859f0cbef000cdabf71dcf15c608`, 13 surfaces; final groups: DNS resilience.
- `Auto_Tor_IP_changer-master(2)` — archive `2b14f6d735fa3932c25f779ebe5bb11f08294251ea14c709786484853e4080f3`, 3 surfaces; final groups: Tor routing.
- `bia-pain-bache-main` — archive `d3df5220f6041ef7a0f6e2d1258e50292899dbc7073e6e8e938701966f1a884e`, 50 surfaces; final groups: proxy/evasion.
- `BPB-Warp-Scanner-main` — archive `bbad6899e5ca76685ef362a2facf19cdd88bedaa51d77af34f431c2bdc704d1b`, 14 surfaces; final groups: WARP quality.
- `BWLimiter-main` — archive `e109e52d8743cdecd8fb14696f510e0fe7614a02f4788715151d76e74afbf7a6`, 7 surfaces; final groups: host-network mutation.
- `caddy-master` — archive `dc21aecbfd41e950074fc80da603198cba5f8e14c0aa6445447e2838b4b7a5eb`, 627 surfaces; final groups: remote mutation resilience, live configuration authority.
- `coredns-master` — archive `99a1da842b6a5144590f526e7fe65835077255bc17c2f413aaefddc9c3d030f9`, 985 surfaces; final groups: DNS resilience.
- `defyxVPN-main(1)` — archive `60c37bdee140394cf5bb7618a7e54917600946befda4b75fc7ac162002f2c33e`, 503 surfaces; final groups: network diagnostics/scanning.
- `dns-over-https-proxy-master` — archive `2aa075051e81ed0daae1d3bb3db666e16a9b4e4358f5b16043caed40bcfee84f`, 1091 surfaces; final groups: DNS resilience.
- `DNS-Persist-master` — archive `0396f84ecbd482d9e84ca7b9862513fdf5475740dfb7854e4cbebf2adedb0778`, 30 surfaces; final groups: negative security evidence.
- `ev-master_(1)` — archive `d936beca1266c8e4ab915732c05d89a515f4a5c50a3152c31f2e898060efb281`, 14 surfaces; final groups: proxy/evasion.
- `eve-xui-manager-main` — archive `e178da00b9d58f858132fceac6417f0a1b7905a53545c6ea645bf0892eff9ea2`, 91 surfaces; final groups: operator entitlement evidence, live configuration authority.
- `firewalla-master` — archive `3b2a30af746488484b4d7a0c6b335a20e268dfe07565ac7c598bbfab57083b04`, 2249 surfaces; final groups: remote mutation resilience, host-network mutation, WARP quality.
- `ftpscan-master` — archive `d6f7a61feaceb4205291070d20e4ba540af635c62afdd5e3e1970124e7fa2051`, 10 surfaces; final groups: negative security evidence.
- `Go-netowrking-tools-main` — archive `08c1cd69049b710afae52cffd390d7ac4a64046aaf69d08f288f30997926125d`, 5 surfaces; final groups: network diagnostics/scanning.
- `GodMode-main` — archive `b5dc0d8ab15ee4d702166a2ac80baa8b0cddc25b13bdaac0277f62405a94fea4`, 130 surfaces; final groups: deployment/process ownership.
- `godnsagent-master(1)` — archive `ff39d81b6cb5a1dd4269526efd121691d1b4cc8d9e2635c0f767fcfd70a1ff69`, 21 surfaces; final groups: DNS resilience.
- `gologin-main` — archive `da7b0d99e4ea62bf77c69f8083bd7cc301dba651ae4b680e97f02cf042d02d12`, 75 surfaces; final groups: deployment/process ownership.
- `GoodbyeDPI-master` — archive `aa7901bb23afcc7fddb7cbf0157a5b52d952f18e3b87fbf7207a1a0a15237eea`, 29 surfaces; final groups: proxy/evasion.
- `incy-platforms-main` — archive `c322a1eb91b52e8191ab76b4ac9c201161ada0c528efd9db3233a4291c28db1f`, 2 surfaces; final groups: proxy/evasion.
- `InterceptSuite-main` — archive `cc1b8f5a1c2c52aa7b26730b9f265a0e3a01546024db1d2e0768f887660a75c4`, 2 surfaces; final groups: negative security evidence.
- `InviZible-master` — archive `a4a2dbd2b99f1a618452b4f5bfb441809b39c686e0bbd6d772887f03a65573de`, 1248 surfaces; final groups: runtime supervision, host-network mutation, Tor routing.
- `lossyconn-master` — archive `b2ed9ec6f403bed4a8bdfb2d4c7149a12b83715c4458837df9320afecec97b02`, 9 surfaces; final groups: network diagnostics/scanning.
- `Marzban-master` — archive `df758c350081cd41def22cd62c079e21c2824e59d3b0c3575b15aa4c0f864e3c`, 434 surfaces; final groups: operator entitlement evidence, live configuration authority.
- `nahan-main(1)` — archive `faaa095b2e0f9e66a1a2abe57744eb66fc4b9207683ecf87e600f205f16c4848`, 14 surfaces; final groups: proxy/evasion.
- `openssl-cffi-master` — archive `99322671d546b84e1076ae304eabc1ddfd9edc600129f62beff52bbf14b4530a`, 4 surfaces; final groups: crypto/geodata.
- `Proxy-client-collection-main` — archive `4ff3369055dd0c600ec9b36cf9496e3949e73ccc2da250f6ae58281341aa6f0d`, 2 surfaces; final groups: proxy/evasion.
- `Se7en-Pro-1.0.0` — archive `39cd04fdc9b0c63e1c9315c47d9519e46c842bb5ee46feb4f237b26e237a0772`, 172 surfaces; final groups: runtime supervision, host-network mutation.
- `Serverless-for-Iran-main` — archive `e8a850592802028c60b84e8bac3fa3fea492d8b763d51be9f71bd0bf3d54d766`, 7 surfaces; final groups: proxy/evasion.
- `sing-geoip-main` — archive `3f7a90618be692321dada33b8ca52aa27571a157a38530d3ea063356bc8d13f7`, 13 surfaces; final groups: crypto/geodata.
- `sing-geosite-main` — archive `f054fa0081b791fc0787e9dd94404c54334a5b9edc46aebae38ace01c68e6001`, 13 surfaces; final groups: crypto/geodata.
- `snowbox-master` — archive `fb9a4abdc8f26aaa779cdbfd6addf7a0be8a63c8c342680913953413081643af`, 11 surfaces; final groups: proxy/evasion.
- `Subnet-Divider-main` — archive `4821c3c767b80e3008d3c36894ee8727426ef7ff909a9fa58e8bdc08295dafb0`, 2 surfaces; final groups: network diagnostics/scanning.
- `sysproxy-main` — archive `61a7ee336866edf6c019c473a74dbccf87a19929b41e3eb7b79748021e6f88db`, 7 surfaces; final groups: host-network mutation.
- `torrequest-master` — archive `d0a4dceabc6f7db99b4ea41799fc63475aacc16e9dbad3bf69fd7da64b9cc0b2`, 5 surfaces; final groups: Tor routing.
- `unique-queue-master` — archive `d2d7a3181b38df8464d37f0e17552b8347ee82d912232b08bd5f4ca08857b019`, 8 surfaces; final groups: remote mutation resilience.
- `V2ray-for-Doprax-main(1)` — archive `9395bd68bccfd6f86c80656285061a9da863fb98f20aeca3f8ba9035eedb3f37`, 9 surfaces; final groups: deployment/process ownership.
- `V2RayN-PRO-main(1)` — archive `5e5e3162c6aa3d2311266d738e396a9a15e7c68a9d06fbd2217e5dfd8c65589d`, 61 surfaces; final groups: proxy/evasion.
- `v2rayng-panel-main(1)` — archive `fe7b75817fc8cdc62c16025affd05327c39ec086508f551b394358017a83a454`, 1 surfaces; final groups: proxy/evasion.
- `vps-warp-main(1)` — archive `4466f36e5c9084a472f55b1b3cbd6ce93dfdac39b38c9213e2e5ef29f08c044c`, 3 surfaces; final groups: WARP quality.
- `x-ui-pro-master` — archive `d7011ed3a2065bb59993fd7c8a54e1c390a74c22254be3fb1a721cd20d573156`, 25 surfaces; final groups: deployment/process ownership.
- `zeus-main(1)` — archive `746d56b08c15e6b22305b2b35b67c01cee02d07c25bd84042be280fbeda603a9`, 9 surfaces; final groups: operator entitlement evidence, live configuration authority.

## Intentional exclusions versus omissions
- **Role mismatch, not omission:** Caddy general inbound reverse proxy and ACME/TLS server lifecycle.
- **Product-scope exclusion, not omission:** Firewalla always-on IDS/alarm policy and panel multi-tenant billing/user authorities.
- **Authority guardrail:** Unix firewall/DNS-leak rules remain unsupported until integrated into durable host-network transactions.
- **Operational guardrail:** no-license or broad root-mutation VPS installers remain reference evidence.
- **Safety rejection:** DNS C2/persistence, FTP-bounce scanning, and interception/MITM are not production capabilities.
- **Generated/media/vendor surfaces:** not ignored; they remain hash-accounted but cannot substitute for authoritative implementation/config/schema sources.

## Exact target-delta accountability
- `modified` `Makefile`
- `modified` `governance/convergence/eighth-order-adoption-ledger.csv`
- `added` `governance/convergence/final-pass-adoption-ledger.csv`
- `added` `governance/convergence/final-pass-baseline-files.csv`
- `added` `governance/convergence/final-pass-directories.csv`
- `added` `governance/convergence/final-pass-donors.csv`
- `added` `governance/convergence/final-pass-high-level-plane-audit.csv`
- `added` `governance/convergence/final-pass-license-map.csv`
- `added` `governance/convergence/final-pass-modules.csv`
- `added` `governance/convergence/final-pass-omission-audit.md`
- `added` `governance/convergence/final-pass-peer-synthesis.md`
- `added` `governance/convergence/final-pass-semantic-revalidation.csv`
- `added` `governance/convergence/final-pass-signals.csv`
- `added` `governance/convergence/final-pass-supersession-map.csv`
- `added` `governance/convergence/final-pass-surfaces.csv`
- `added` `governance/convergence/final-pass-symbols.csv`
- `added` `governance/convergence/final-pass-target-repairs.csv`
- `added` `governance/convergence/final-pass-validation.md`
- `modified` `governance/topology/relocations.json`
- `added` `scripts/checks/check_final_convergence.py`
- `modified` `scripts/checks/check_ninth_order_convergence.py`
- `added` `src/apps/daemon/internal/adapters/api/config_mutation.go`
- `added` `src/apps/daemon/internal/adapters/api/config_mutation_test.go`
- `modified` `src/apps/daemon/internal/adapters/api/handlers_proxy_directory.go`
- `modified` `src/apps/daemon/internal/adapters/api/handlers_system_ddns.go`
- `modified` `src/apps/daemon/internal/adapters/api/handlers_system_startup.go`
- `modified` `src/apps/daemon/internal/analysis/scanner/cloudflare_deployer.go`
- `modified` `src/apps/daemon/internal/foundation/config/config.go`
- `added` `src/apps/daemon/internal/foundation/config/revision_test.go`
- `modified` `src/apps/daemon/internal/foundation/remoteaction/remoteaction.go`
- `modified` `src/apps/daemon/internal/foundation/remoteaction/remoteaction_test.go`
- `modified` `src/apps/daemon/internal/integrations/provision/cloudflare.go`
- `modified` `src/apps/daemon/internal/networking/dns/ddns_updater.go`
- `deleted` `src/apps/daemon/internal/platform/system/api_key_reverse_proxy.go`
- `deleted` `src/apps/daemon/internal/platform/system/reverse_tls.go`
- `modified` `src/apps/daemon/internal/runtime/proxy/google_drive_actions.go`
- `modified` `src/apps/daemon/internal/runtime/warp/warp.go`

The final delta generator compares the current source tree against the frozen ninth-order manifest and rejects any unregistered path. It is rerun after final reports are written so this list/count is not used as a stale completion claim.
