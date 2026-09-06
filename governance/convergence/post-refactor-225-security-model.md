# Post-refactor-225 security model

## Trust boundaries

The convergence treats donor archives as untrusted evidence. Original ZIP bytes are hash-anchored, CRC/path/case/member validated, extracted into dedicated roots, and byte-compared before semantic use. Donor executable content is never granted authority merely because it exists or has tests.

## TLS and identity

- SNI/CDN candidate qualification requires certificate verification for the requested SNI.
- Pattern scanning for SNI is replaced with structured ClientHello parsing.
- Unauthenticated TLS measurement is not accepted as endpoint trust evidence.
- The two unused insecure scanner facades were retired so their success flags cannot be confused with trusted qualification.
- TLS fingerprint planning cannot opt into weak ciphers; QUIC-oriented profiles require appropriate ALPN evidence.
- WARP/WireGuard parsing requires explicit key material and no longer manufactures credentials for incomplete share links.

## Secrets and artifact admission

The `mitm-proxy` donor bundled a private CA key. That key is negative evidence, not a reusable asset. The target artifact-admission planner:

- accepts supplied bounded bytes rather than arbitrary filesystem paths;
- computes provenance SHA-256;
- detects private-key material;
- quarantines suspicious material;
- never echoes secret content;
- does not persist, install, or activate supplied artifacts.

Existing central redaction and secret-reference owners remain authoritative. Donor patterns that log rendered proxy/TProxy configuration, webhook bodies/headers, access tokens, or embedded credentials are explicit negative oracles.

## Network and host authority

- SNI gateway planning is reversible preflight only; it does not install DNS/TLS/HTTP redirect services.
- DNS policy and DoH pool planners do not issue DNS requests or mutate resolver configuration.
- routing-artifact provenance does not download or install rule databases.
- declarative workflow planning rejects Docker, shell/exec, namespace mutation, plugins, embedded credentials, cycles, and unknown dependencies.
- relay inspection rejects scriptable mutation, insecure TLS, magic-byte STARTTLS inference, and global “last UDP client” identity.
- no second eBPF, raw-packet, WireGuard, Wintun, TUIC, or mux authority is introduced.

## Bounds and exhaustion resistance

- CDN CIDR work is bounded before allocation by range, sample-per-/24, and total-candidate ceilings.
- queue policy bounds capacity, batch items, batch bytes, wire count and restoration.
- multiplex policy bounds connection/stream counts and peer-controlled padding.
- Wintun validates documented ring-capacity power-of-two/bounds and packet-size limits before the driver call.
- TUIC rejects oversized domain names, u16 payload overflows, and malformed fragment indices before writing a partial frame.
- SNI evidence has bounded candidate/concurrency/hostname sizes.
- artifact and routing evidence have explicit size/digest ceilings.

## Retry and replay

Automatic mutation retry remains single-owned by the existing configuration mutation state machine; post-refactor-225 does not add a second retry loop.

Configuration mutation retries only optimistic revision conflicts. Explicit revisions are never automatically replayed. WireGuard planning captures replay-window, cookie/rate admission, rekey/reject and stale-key cleanup semantics as readiness evidence without implementing a second cryptographic device.

## Negative donor mechanisms retained as guards

The evidence graph preserves, rather than silently discards, the following negative lessons: certificate verification disabled with `CERT_NONE`/`InsecureSkipVerify`; transparent/scriptable MITM; raw packet injection duplication; system-wide installer mutation; unchecked ring/frame counts; TUIC synchronous auth-length inconsistency; tun2socket NAT boundary bugs; direct WebDAV restore without staging/hash verification; cleartext WebView/browser dialer authority; logging credential-bearing generated configuration; mutable remote rule-list authority; unsafe shell `Invoke-Expression`; and unverified remote update artifacts.
