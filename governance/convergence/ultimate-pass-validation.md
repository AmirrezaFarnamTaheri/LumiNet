# LumiNet ultimate validation report

## Claim boundary

`Verified` below means the named local command or checker executed successfully. Dependency-isolated harnesses copy the exact changed LumiNet source and provide only minimal stubs for unavailable external dependencies or unrelated package members; they validate the stated contracts but are not evidence of a full Go 1.26 workspace build or of real external network/provider behavior.

## Focused executable evidence

| Slice | Evidence | Status |
|---|---|---|
| Automatic mutation retry | Exact `remoteaction` source, `go test -race -count=100 ./...`; provider cooldown/in-flight/retry/reconcile/cancel behavior | verified |
| Tor runtime request/preflight | Exact runtimecore manager source + minimal system stub, `go test -race -count=100 ./...`; transport identity, path/flag rejection, replacement, preflight-before-stop | verified |
| Transport executable resolution | Exact adapters source + minimal unrelated stubs, `go test -race -count=100 ./...`; PATH/bundle/executable-bit/missing-binary cases | verified |
| Tor config builder | Exact builder source, `go test -race -count=100 ./...`; PT lines, bounds, quoting, injection rejection | verified |
| Tor process torrc publication | Exact process source + bounded-I/O/controller stubs, `go test -race -count=100 ./...` | verified |
| Encrypted DNS resolver | Exact resolver source + miekg/dns/x/net stubs, `go test -race -count=100 ./...`; validation/fail-closed/NXDOMAIN contracts | verified (network I/O not exercised) |
| Tor DNSEL | Exact diagnostics source, `go test -race -count=100 ./...`; query construction and tri-state semantics | verified |
| Filesystem watcher | Exact watcher source + synthetic fsnotify stub, `go test -race -count=100 ./...`; debounce/filter/atomic replacement | verified |
| Endpoint quality | Exact source, `go test -race -count=100 ./...`; partial loss, median/jitter, bounds, ordering | verified |
| TLS peer evidence | Exact scanner utility/test + one unrelated classifier stub, `go test -race -count=100 ./...` | verified |

All ten harness modules also pass `go vet ./...` with `GOTOOLCHAIN=local`.

## Repository-wide verification

On the final 45-path source state, `make verify-repo` executed from the beginning through the ultimate gate and then hit the external tool-call timeout as `native-degraded-truth` began; no checker had failed. The exact remaining Makefile tail was then executed separately through repository audit. Thus every command in the canonical Makefile sequence executed on the final source state without treating timeout as success. Results include:

- source structure/context: errors=0
- repository topology: **2442/2442 accounted**, errors=0
- LumiCore source purity/reachability/mobile/desktop/host product gates: errors=0
- request context, host-network ownership, runtime-core ownership, proxy facade ownership: errors=0
- scanner/telemetry/job/evasion/advanced capability/subscription ownership gates: errors=0
- remote HTTP action registry: **29 actions**, Python raw mutations=0, errors=0
- every historical convergence wave from second-order through the frozen final all-43 wave: errors=0
- ultimate 63-donor convergence: errors=0
- route/platform/native/proxy/ABI/FFI/pruning/qualification gates: errors=0
- convergence validation and peer convergence: errors=0; unresolved high-signal peer items=0
- repository audit: errors=0; one inherited environment warning for missing local Android Gradle wrapper

The sixth-order Tor checker initially failed because `CookieAuthentication 1` moved from the runtime implementation into the canonical Tor config builder. The live NEWNYM behavior remained intact. The historical checker was corrected to follow the current owner and then passed with all later gates. This original failure is preserved in the validation log rather than erased.

## Toolchain/environment
- local Go: 1.23.2 (`GOTOOLCHAIN=local`)
- repository Go declaration: 1.26.0 / toolchain 1.26.5; external download unavailable
- Python: 3.13.5
- Node: 22.16.0; npm 10.9.2
- Java: OpenJDK 21.0.11
- Rust/Cargo: unavailable
- local Android Gradle wrapper: absent; repository audit records the existing CI/release Gradle 9.5.0 provisioning note

## Unverified external behavior
No claim is made that external Tor transport binaries were actually executed, that an external DoH/DoT provider was reached, that credential-dependent cloud/VPN services were exercised, or that Android/Rust/native release builds were performed in this environment. These are environmental/product-scope limitations, not converted into passing evidence.
