# Post-refactor-229 omission audit

- outer ZIP members: 10,933
- outer regular files: 7,531/7,531
- outer symlinks: 3/3 explicitly recorded
- outer directory/root Merkle records: 2,261/2,261
- outer indexed definitions: 30,602/30,602
- outer high-signal surfaces: 6,420/6,420 with file-accountability backlinks
- nested MITM members: 2,781
- nested MITM files: 1,477/1,477
- nested MITM directory/root Merkle records: 1,268/1,268
- nested MITM indexed definitions: 242/242
- focused behavior records: 118
- unresolved outer high-signal surfaces: 0

The audit separately checks roots/packages, definitions, state machines, authority/negative paths, operator surfaces, scripts/config/deployment/tests, deep leaves, generated/vendored/media/localization surfaces, symlinks, packaged binaries, fake-format artifacts, and the nested source corpus. File-level records are accountability, not implementation claims.
