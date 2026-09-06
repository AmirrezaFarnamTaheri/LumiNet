# Post-refactor-226 security model

## Donor boundary

All 14 donor archives are evidence, not trusted executable inputs. Admission verifies path confinement, duplicate/case-collision absence, regular-member types, CRC, archive SHA-256, extraction containment, and extracted-byte equality. The convergence checker independently reopens the original ZIPs and rehashes every current-wave surface.

## Protocol identity and fail-closed dispatch

- Unknown/unsupported proxy protocols fail closed in both sing-box and Xray outbound construction.
- SOCKS and HTTP are explicit protocol cases; SSR is not silently reinterpreted as SOCKS.
- SS2022 PSKs must decode to the exact method-specific component length. Malformed base64, wrong-length components, and unknown `2022-blake3-*` methods fail admission.
- Duplicate local Shadowsocks cryptographic/runtime facades are removed so successful local helper behavior cannot be mistaken for the maintained runtime authority.

## SSH authentication boundary

An SSH dial attempt requires at least one valid authentication method. A malformed private key without a valid fallback fails before network activity. If a password fallback is explicitly present, key parse failure does not erase that valid method. The upstream SSH stack remains dependency-owned; no duplicate transport/KEX/channel implementation is embedded.

## SOCKS framing boundary

Destination serialization is bounded before narrowing conversion. Empty/NUL domains, domains exceeding the SOCKS one-byte length, and invalid ports are rejected. Rust response parsing rejects unknown address types. This closes wrap/truncation and silent-acceptance paths at the wire boundary.

## External-authority planners

The six new planning contracts deliberately do not receive the credentials or capabilities needed to perform their modeled operations:

- local rule normalization reads supplied text only and fetches no URL;
- Tailnet planning stores no credential and makes no API request; revision-bearing writes require explicit ETag/revision evidence;
- browser handoff requires loopback proxy targets, bounded profile identity, explicit permissions, and the 1 MiB native-message ceiling but registers no native host or browser proxy;
- worker planning starts/restarts no process and bounds deadlines/restarts;
- WebSocket readiness accepts observed handshake evidence rather than opening a socket;
- gateway composition downloads nothing and writes no service-manager configuration.

## Sensitive transitions

Tailnet key creation and webhook-secret rotation are classified as sensitive one-shot results. They remain plans only. Actual secret material belongs to a dedicated secret owner and cannot be treated as generic planner state.

## WireGuard/MWGP boundary

Translated receiver-index mappings require nonzero unique indices, bounded source identities, future expirations, and a maximum 24-hour lifetime. Obfuscation is explicitly non-security-bearing: it cannot replace WireGuard authentication, confidentiality, replay resistance, or cookie/MAC2 logic.

## Retry/replay boundary

Configuration CAS retry remains bounded and revision-specific. Explicit expected revisions are not replayed. No donor-derived external side effect is moved into the generic retry loop.

## Negative donor mechanisms

Mutable installer scripts, root/service-manager mutation, broad downloadable proxy/rule corpora, alternate SSR/Shadowsocks runtimes, independent Tailnet clients, browser-native registration authority, external worker supervisors, and packet-obfuscation-as-security claims are retained only as supersession/guardrail evidence where the target already has a stronger owner.
