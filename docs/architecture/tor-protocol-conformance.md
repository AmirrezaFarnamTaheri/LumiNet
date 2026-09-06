# Tor Protocol Conformance Reference

Source: external reference corpus `haskell-tor-master` (upstream `Tor/*.hs` modules).
Status: **REFERENCE ONLY** — this is a conformance cross-reference, not a live source-root map. LumiNet implementations live under `src/packages/lumicore/src/`.

## Module Map

| Haskell Module | LumiNet Rust Target | Notes |
|----------------|---------------------|-------|
| `Tor.hs` | `src/packages/lumicore/src/transport/tunnel_client.rs` | `startTor`, `torConnect`, `torWrite`, `torRead`, `torClose`, `torResolveName` |
| `Tor/Circuit.hs` | No direct live analogue | Cell primitives exist in `src/packages/lumicore/src/transport/tor_cells.rs`; `circuit_shift.rs` is timing obfuscation, not a Tor circuit state machine. |
| `Tor/Link.hs` | `src/packages/lumicore/src/tls/mod.rs` | TLS 1.x link layer; cipher negotiation via `Tor/Link/CipherSuites` + `Tor/Link/DH` |
| `Tor/HybridCrypto.hs` | `src/packages/lumicore/src/crypto/mod.rs` | Hybrid RSA-AES encryption for CREATE/CREATED cells |
| `Tor/DataFormat/TorCell.hs` | `src/packages/lumicore/src/transport/tor_cells.rs` | Cell parser for every cell type |
| `Tor/DataFormat/RelayCell.hs` | No direct one-to-one live analogue | Fixed Tor-cell framing lives in `src/packages/lumicore/src/transport/tor_cells.rs`; do not treat it as a complete relay-cell state implementation. |
| `Tor/DataFormat/RouterDesc.hs` | `src/packages/lumicore/src/relay/descriptor_parser.rs` | Router descriptor grammar and legacy raw-SHA1 PKCS1v15 signature verification. |
| `Tor/NetworkStack/Fetch.hs` | No direct live analogue | LumiCore does not expose this upstream fetch abstraction as a dedicated current module. |

## Wire Format References

- Cell layout: 2-byte circuit ID + 1-byte command + payload (variable)
- Relay cell: 2-byte stream ID + 1-byte relay command + 2-byte length + data
- Create/Created: RSA-encrypted key material per `Tor/HybridCrypto.hs`
- Versions cell: list of supported protocol versions

## Conformance Test Vectors

Use `chutney-main` and `torflow-main` extracted test networks to verify:

1. Basic circuit build: `START` → `CIRCUIT_ESTABLISHED`
2. Stream attach: `BEGIN` → `CONNECTED` → data transfer
3. Relay cell roundtrip: `RELAY_BEGIN` → `RELAY_CONNECTED`
4. Key rotation: `RELAY_DROP` on circuit → new circuit inherits stream

## Out of Scope (Already in LumiNet)

- `Tor/Control.hs` — control-port protocol; no separate live LumiNet control-port module is mapped here
- `Tor/Socks.hs` — SOCKS5 handshake; handled by Go daemon proxy layer
- `Tor/Config.hs` — torrc parsing; LumiNet uses own config system
