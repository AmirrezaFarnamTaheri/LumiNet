# LumiNet post-refactor 141 peer synthesis

## Outcome

Four additional donors were recursively inventoried and compared against the frozen 137-donor target. The denominator is 141 unique donors.

- **GeoSpoof** contributes browser geolocation/timezone/WebRTC identity-completeness evidence. LumiNet deliberately keeps network/VPN identity distinct and does not add browser-spoof authority.
- **ZedSecure** reinforces Android `VpnService.protect`, TUN lifecycle, per-app UX, and binary-provenance lessons. Existing mobilehost/TUN owners remain authoritative; per-app routing remains unavailable until enforcement exists.
- **I2P** contributes mature replay-window, expiry, bandwidth, tunnel-lifecycle, quarantine, and signed-artifact patterns. The full I2P router/NetDB/transport/crypto system is rejected as a second network runtime.
- **Metapi** contributes rich routing/recovery/stream/control-plane evidence. Its unconditional forwarded-IP use is retained as negative evidence; LumiNet now disables Gin trusted proxies by default so direct peer IP remains authoritative for rate limiting and logs.

No donor package, AAR, JAR, router, proxy engine, browser extension, TUN stack, or control plane was imported wholesale.
