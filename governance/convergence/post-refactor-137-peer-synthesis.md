# LumiNet post-refactor 137-donor peer synthesis

## Strongest current-wave convergence

### HTTP relay sequencing

`httun` treats sequence identity as protocol state rather than transport decoration. LumiNet already emitted a request sequence in its serverless HTTP relay, but did not validate the optional echoed response sequence. The existing `integrations/relayclient` owner now rejects a non-nil response sequence that differs from the active request while preserving compatibility with legacy responses that omit the field. No `httun` client/server runtime or second relay authority is imported.

### DoH admission, cancellation, and response identity

`foghorn` provides two useful mechanisms: bounded background/admission work and explicit DNS query/response identity checking. LumiNet keeps its existing `FailoverDOHResolver` and absorbs only the stronger invariants. Unique-host shared work is admitted through a 32-slot fail-fast gate, shared singleflight work is detached from an individual waiter cancellation but capped at five seconds, and DoH bodies must match the request transaction ID plus qname/qtype/qclass before A-record parsing. Compressed DNS names are parsed with pointer bounds and a 128-step traversal ceiling. Foghorn's DNS server/plugin plane is rejected.

### Domain-policy boundary

Hawk's substring host allowlist is retained as negative evidence. LumiNet's WhiteDNS bypass policy had the same boundary class: `example.com` also matched `badexample.com`, and an empty rule matched everything. The existing policy owner now normalizes case/trailing-dot/whitespace, ignores empty rules, and accepts only the exact domain or a dot-delimited subdomain. Hawk's root installer and standalone proxy remain rejected.

## Reference/supersession synthesis

Freenet telemetry contributes bounded per-client queue/history and time-travel operator ideas, but LumiNet already owns bounded WebSocket client queues and telemetry state; no second telemetry server/database is created. Freenet Core contributes deterministic simulation/state/secrets methodology; its P2P node and executable WASM runtime authority are rejected. Freenet Git contributes content-addressed verification, signed identity, and chunked recovery ideas while the target's existing release manifest/checksum owner remains authoritative.

`go-tun2socks`, Furious and Exclave reinforce TUN lifecycle, socket-protection, ABI packaging, and operator workflow, but the 117-donor target already has the stronger single TUN/NAT owner. GOST, fteproxy, fwlite, Grasshopper and the Hysteria Python wrapper provide protocol, framing, packaging and chain references without becoming parallel proxy engines. Bundled Hysteria/pybind11/QPP/lwIP/generated Frozenlib content remains provenance/accountability evidence only.

## Negative and authority evidence

`fsociety`, `hping`, and `Intercept` contain offensive/raw-packet/spoofing/MITM capabilities. They are rejected as executable production capabilities and used only to strengthen defensive threat models and the existing host-network mutation boundary. Broad root installers, mutable-master updaters, arbitrary remote proxy scraping, opaque executable WASM, checked-in example credentials/private keys, second firewall/server authorities, and generated donor runtimes are final rejection/guardrail decisions rather than future work.

## Overlap truth

The current wave contains 354 surfaces whose SHA-256 bytes already existed in the frozen 117-donor corpus, primarily bundled/vendor/generated/common material. These bytes remain fully surface-accounted but receive no duplicate semantic credit. The machine-readable relationship summary is `post-refactor-137-overlap-provenance.csv`.
