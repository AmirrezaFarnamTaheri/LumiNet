# Daemon labs

`labs/daemon/` is the non-authoritative home for preserved daemon source that still has evidence, test, comparison, or design value but no live product ownership.

## Layout

The directory is organized by what the preserved code **is**, not by the wave or cleanup pass that moved it:

- `proxy/` — the large hash-accounted Wave 20/21 proxy capability corpus (`CAPABILITIES.csv`).
- `modules/` — preserved former Go package islands (`MODULE_ISLANDS.csv`), one directory per original package.
- `proxy-alternates/` — later non-live `package proxy` implementations and tests.
- `scanner-alternates/` — preserved `package scanner` implementations.
- `system-alternates/` — preserved `package system` implementations.
- `platform-alternates/`, `routing-alternates/`, `vpnstate-alternates/` — smaller package-specific preserved surfaces.
- `ffi-alternates/` — daemon-side FFI reference material.

Retirement reason and original location belong in governance/topology and the small CSV ledgers at this directory root, not in extra directory layers.

## Contract

- Nothing under `labs/` is production authority or a supported import target.
- Preserved bytes stay hash/provenance accountable where a ledger exists.
- Promotion requires a named live owner, explicit invariants, compatibility/security review, focused tests through that owner, and repository-wide verification.
- Prefer extracting a useful primitive into an existing deep module over reviving an old subsystem wholesale.
