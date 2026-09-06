# LumiNet post-refactor 141 donor convergence

## Outcome

Four additional donors were recursively investigated and converged against the frozen 137-donor LumiNet release. All four archive hashes are distinct from the prior donor inventory, giving **141 unique donor repositories**.

Combined accountability now covers **42,277 file/link surfaces, 7,210 repository directories, 4,789 bounded accountability groups, 143,859 normalized declarations, 5,126 adoption/accountability records, and 337 fine semantic decisions**.

The current wave contributes **7,491 outer archive members, 6,534 file surfaces, 952 repository directories, 333 bounded groups, 38,774 donor-owned declarations, 53 independently decidable semantic units, 92 recursively inspected nested archive nodes containing 10,145 members, and zero outer symlinks**. All 6,534 current-wave surfaces re-hash against the extracted evidence. Sixty-six current surfaces are byte-identical to prior-corpus surfaces and receive no duplicate semantic credit.

## Live target change

The only new runtime-policy hardening is the API client-IP trust boundary. LumiNet's Gin router used `ClientIP()` for rate-limit identity and request logging without explicitly configuring trusted proxies. The router now disables trusted proxies by default with `SetTrustedProxies(nil)` and fails closed if that configuration unexpectedly fails. Forwarded client-IP headers therefore do not become authoritative merely because they are present; any future reverse-proxy deployment must introduce an explicit reviewed trust policy.

The source contract was observed RED before the repair and GREEN afterward. Full API package execution is blocked by the local Go 1.23.2 versus declared Go 1.26.x/toolchain 1.26.5 boundary, so this repair is labeled **statically validated/source-contract verified**, not runtime-verified.

## Donor dispositions

- **GeoSpoof** supplies browser geolocation/timezone/WebRTC identity-completeness and anti-detection evidence. Browser identity remains deliberately separate from LumiNet's VPN/network identity; concealment/function-masking behavior is not granted production authority.
- **ZedSecure** reinforces Android `VpnService.protect`, TUN lifecycle, per-app UX, and binary-provenance lessons. Existing mobilehost/TUN owners remain authoritative; bundled V2Ray/HevTun artifacts do not become release authority, and per-app routing remains explicitly unavailable until it can actually be enforced.
- **I2P** supplies mature replay-window, expiry, bandwidth, tunnel-lifecycle, quarantine, signed-artifact, and recovery patterns. Its full router/NetDB/transport/crypto/reseed ecosystem is retained as reference/guardrail evidence rather than introduced as a second persistent network runtime.
- **Metapi** supplies routing, retry, cooldown, streaming, migration, billing, OAuth, and observability evidence. Its broad forwarded-IP/query-key trust patterns are negative evidence; its proxy/control plane is not imported as a parallel authority.

No donor package, JAR/AAR/native bundle, proxy engine, I2P router, browser extension, TUN stack, or control plane was imported wholesale.

## Verification

The current-wave and strict combined ledgers pass the convergence validator with zero warnings. The dependency-free declaration checker parses 1,524 Go files with zero syntax errors and zero active duplicate declarations across Linux, Windows, macOS, and Android selections. Frozen 83/97/117/137 gates and the new 141 gate all pass at their exact release boundaries.

The canonical `make verify-repo` hit the host execution ceiling after every command through ninth-order convergence passed; that monolithic invocation remains recorded as **unverified due to timeout**. The exact untouched remaining Makefile tail then passed command-for-command, including final/ultimate/refactor convergence, all successor gates, route/platform/native/proxy ownership, LumiCore/Rust-FFI static gates, five link tests, peer convergence with zero unresolved high-signal items, and repository audit with `errors=0`. The sole repository-audit warning is the inherited missing local Android Gradle wrapper.

## Release boundary

The release is packaged only after the source/evidence graph, final reports, successor delta, and validation receipts are frozen. Integrity metadata and archive hashes are regenerated from the exact delivered bytes; any later byte change invalidates this release evidence.
