# Post-refactor-231 omission audit

- outer archives: 5/5 admitted
- archive members: 43,384
- regular files: 35,331/35,331
- normalized directory/root Merkle records: 8,044/8,044
- archived symlinks: 7/7
- donor-authored/non-vendored indexed definitions: 2,163/2,163
- vendored files retained in byte/Merkle accountability: 33,047
- module/subtree groups: 562/562
- high-signal surfaces: 1,504
- unresolved high-signal surfaces: 0

The definition denominator intentionally excludes inherited Chromium/vendor definitions while retaining every vendor file in the surface and directory hashes. This prevents both omission and donor-semantic inflation.
