# Keep WinDivert external until its supply chain is governed

Status: Accepted

## Context and Problem Statement

Windows raw packet injection dynamically loads WinDivert. Current Windows release artifacts do not bundle WinDivert. A disconnected fetch helper and Scoop installer survived in `scripts/`, but the fetch manifest contained placeholder integrity values treated as trusted SHA-256 hashes, while the installer contained placeholder release hashes, an unsupported Windows arm64 artifact, and obsolete CLI instructions.

The runtime itself already fails packet-injection startup when WinDivert cannot be loaded. The repository therefore had a truthful runtime failure mode but an untruthful acquisition/installation surface.

## Considered Options

- Keep the fetch/installer helpers despite unverifiable integrity and unsupported artifacts.
- Download WinDivert without pinned trusted integrity metadata.
- Treat WinDivert as an operator-supplied external runtime dependency until a governed acquisition and packaging contract exists.

## Decision Outcome

WinDivert-backed Windows packet injection is an optional external runtime capability. LumiNet does not fetch, track, or bundle WinDivert in the current source or Windows release artifact. Operators enabling those modes must supply a trusted WinDivert runtime themselves. Packet-injection startup remains fail-closed when the DLL/driver is unavailable.

The obsolete WinDivert fetch helper and unpublished Scoop installer are retired. Reintroducing a bundled/fetched WinDivert path requires, together:

1. trusted pinned artifact integrity rooted in an authoritative source;
2. explicit license/distribution review;
3. Windows packaging of the required runtime files;
4. CI/release verification of the packaged mode; and
5. current capability/install documentation matching the shipped artifact.

## Consequences

The normal Windows release remains self-consistent rather than implying a packet-driver dependency it does not ship. Raw packet modes are conditional, and their unavailable state is explicit. Future packaging work has a concrete evidence gate instead of inheriting an unsafe downloader.
