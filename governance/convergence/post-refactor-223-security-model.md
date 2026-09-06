# Post-refactor-223 security and trust model

## High-risk boundaries

1. **Host proxy:** restore only the exact route LumiNet still owns; server, bypass list and PAC state all participate in ownership. Recovery evidence is retained on failure.
2. **REALITY/SNI:** successful TLS evidence requires normal certificate-chain and hostname validation; `InsecureSkipVerify` is forbidden in the scanner.
3. **Subscription sources/nodes:** raw URLs may contain account credentials. Operator node views expose only redacted metadata; full `ProxyConfig` stays in daemon memory. Hidden nodes cannot resolve or activate.
4. **Android VPN:** only `VpnEngineService` declares `BIND_VPN_SERVICE`; the Quick Settings tile cannot establish TUN itself.
5. **Native ABI:** foreign pointers/lengths and shared-memory capacity/sequence state are validated before slice/arithmetic operations; callback delivery is nonblocking and host waits are bounded.
6. **Remote provisioning:** refuse unmanaged layouts before mutation; CSPRNG secrets are not put in the remote command line; publication is an atomic managed-generation pointer with rollback.
7. **Remote relay:** the unrestricted `warp-relay` pattern is rejected. Generic user-selected forwarding destinations are not admitted as an API authority.

## Evidence-truth rules

- Handshake-only does not imply connected.
- Advertised geography does not overwrite measured egress geography.
- UDP/TCP answer disagreement does not imply poisoning without explicit poisoning/injection evidence.
- Subscription TLS certificate failures are distinct from interference-shaped protocol failures; neither authorizes insecure TLS fallback.
