# Split-brain authority synthesis

This record captures the mechanism-level comparison used to collapse competing
runtime, build, release, and platform authorities without discarding distinct
peer value. `split-brain-synthesis.csv` is the machine-readable index; each
`SB-00x` row is also linked into `adoption-ledger.csv` and
`surface-accountability.csv` with an exact baseline SHA-256.

| ID | Domain | Selected authority |
|---|---|---|
| SB-001 | Runtime/source ownership | Supported roots contain only reachable shipped code; dormant peers are hash-preserved in governed labs. |
| SB-002 | Android VPN lifecycle | `VpnEngineService -> mobilebind AAR -> VPNEngine/CoreController -> system.StartTun2Socks`. |
| SB-003 | Local control/session | One versioned shared session descriptor; discovered local daemon is authoritative. |
| SB-004 | UI assets | `packages/control-ui` owns authored React source and the single production embed bundle used by daemon and desktop. |
| SB-005 | API routes | Gin registrations are runtime truth; the 60-row historical catalog is reference evidence only. |
| SB-006 | Public errors | Historical shared envelope synthesis is retired after zero-consumer proof; live routes own only their documented endpoint-specific error shapes. |
| SB-007 | Build identity | `packages/contracts/buildinfo` owns linked version/commit/build-date metadata. |
| SB-008 | Rust↔Go FFI | Rust owns implementation, Cargo owns native link flags, and one checked private Go ABI header owns declarations. |
| SB-009 | Release orchestration | `.github/workflows/release.yml` owns releases, including Android AAR + linked APK; GoReleaser is reference-only. |
| SB-010 | Desktop platform alternates | `apps/desktop` is one Wails product; unlinked platform mechanisms live hash-preserved in desktop labs. |

A synthesis is not considered complete merely because a folder moved. The
linked negative invariant and validation gate are the acceptance contract for
each decision.
