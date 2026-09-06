# Post-refactor-232 omission audit

- outer archives: 4/4 admitted
- archive members: 1,036
- regular files: 750/750
- normalized directory/root Merkle records: 286/286
- archived symlinks: 0/0
- indexed donor-authored/non-vendored definitions: 611/611
- module/subtree groups: 218/218
- high-signal surfaces: 433
- UI/product surfaces: 57
- focused semantic records: 47
- unresolved high-signal surfaces: 0

Every regular file receives a file-level ledger record, every module receives a module-level record, and independently meaningful behavior/negative evidence is split into focused child records.
