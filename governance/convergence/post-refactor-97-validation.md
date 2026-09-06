# LumiNet post-refactor 97-donor validation

## Focused executable validation

The changed Tor control/filter seam passed 100 repetitions under Go's race detector and go vet. The changed Tor runtime startup seam passed 100 race-enabled repetitions and go vet. The TorProcess compatibility seam compiled in the focused harness and passed go vet. These are dependency-isolated exact-source harnesses because the host Go 1.23.2 cannot load the repository's Go 1.26.x workspace.

Covered negative/edge behavior includes command control-character injection before write, standalone asynchronous control events before replies, continuation/data replies, dot-unstuffing, aggregate reply bounds, deadline expiry, bootstrap progress parsing, exact whitelist matching, delayed full bootstrap, never-bootstrap timeout, temporary control unavailability, and early child exit.

## Governance validation

The successor checker validates exact wave counts, 97-donor uniqueness, all combined surface/module/symbol/ledger denominators, hash-linked surfaces and representative modules, fine semantic donor hashes, allowed dispositions/statuses, nested-archive evidence, historical resolution rows, Tor source invariants, and Makefile wiring. The frozen post-refactor-83 checker remains in the chain and recognizes only successor-delta-accounted additions rather than silently accepting arbitrary drift.

## Release validation

The final source archive is structurally inspected before extraction, independently extracted into a fresh directory, checked against its complete SHA-256 source manifest with no missing/extra/mismatched files, and the successor plus historical repository gates are rerun against those extracted bytes. The separate release receipt records exact command outcomes and toolchain boundaries.

## Claim boundary

`verified` means execution succeeded here. `statically-validated` remains the ceiling for Rust FFI work because Rust/Cargo/Miri are unavailable. The local Android Gradle wrapper is absent. No full-workspace Go 1.26, Rust/Miri, or Android result is represented as executed.
