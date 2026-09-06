# LumiNet post-refactor 137-donor omission and contradiction audit

## Corpus closure

The combined corpus is **137 unique donors** across five preserved waves: 63 historical, 20 prior post-refactor, 14 Tor-focused, 20 second post-refactor, and 20 current repositories. The combined matrices contain **35,743 file/link surfaces**, **6,258 directory-member records**, **4,456 bounded groups**, **105,085 normalized donor-owned declarations**, and **4,740 adoption/accountability rows**, including **284 fine semantic decisions**.

The current 20 archives were validated before extraction and contribute **9,187 outer members**, **8,410 file/link surfaces**, **777 archive directory members**, **580 normalized bounded groups**, **32,073 declarations**, two unmaterialized symlink surfaces, and one independently inspected nested Exclave Gradle wrapper JAR with 34 regular members. No current archive is byte-identical to a prior donor archive.

## Omission ladder

- **Files/links:** 8,408 regular files plus two captured symlink targets were independently rehashed after extraction: **8,410/8,410 matched, errors=0**. Links were never materialized.
- **Directories/packages:** exact ZIP directory members are retained instead of inferring extra filesystem directories created by extraction. Manifests, build files, tests, fixtures, deployment, UI, documentation, generated and vendored trees remain classified.
- **Bounded groups:** normalized donor-relative grouping splits generated/vendor trees as needed; every current group contains 1-100 surfaces. Grouping is accountability, not semantic credit.
- **Declarations:** 32,073 current donor-owned declarations are normalized; generated/vendor bodies remain surface-accounted but are not credited as donor semantics.
- **Independent contracts:** 69 current fine decisions distinguish executable behavior, policy, lifecycle, UX, tests/evaluation, supply-chain evidence, authority rejection and negative lessons. All 20 donors have at least one final fine disposition.
- **State/recovery:** relay sequence identity, DoH shared-work lifetime/admission/identity, and domain-boundary policy have discriminating target tests.
- **Negative/trust paths:** offensive interception/raw-packet tooling, arbitrary proxy scraping, executable WASM/plugin runtime, second proxy/server/firewall/TUN authorities, root installers, mutable-master updates, embedded credentials and generated runtimes have explicit final rejection/guardrail rows.
- **Deep leaves/nested content:** the Exclave Gradle wrapper JAR is independently enumerated; the two donor symlink targets, bundled Hysteria/pybind11/QPP/lwIP trees, Furious frozen assets, and 354 exact-byte historical overlaps are explicit.
- **Historical evidence:** frozen 117 evidence is not rewritten. The existing 74-row historical schema-normalization overlay is preserved in the 137 strict ledger. No current fine decision is pending, inferred, unverified, or phrased as deferred/future work.

## Contradictions resolved

DoH concurrency hardening is not represented as a new DNS server or plugin architecture. DNS response validation is not represented as cryptographic DNSSEC validation; it proves request/response transaction and question identity only. Domain bypass exact/subdomain matching does not broaden bypass authority. Freenet simulation/P2P/WASM ideas do not create a production Freenet node. Offensive donor capabilities do not become tools or runtime modules. Generated/vendor/common byte overlap does not increase semantic credit.

## Environment boundary

The host environment remains Go 1.23.2 while LumiNet declares Go 1.26.x/toolchain 1.26.5 and cannot fetch the newer workspace toolchain. Rust/Cargo/Miri are unavailable and the local Android wrapper is absent. These are execution-environment limitations, not deferred donor decisions.
