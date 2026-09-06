# Mobile Labs

`labs/mobile/` contains non-compiled Android evidence only:

- `fragments/` — quarantined porting/capability fragments catalogued by `CAPABILITIES.csv`.
- `runtime-alternates/` — pre-unification runtime peers grouped by their original package role without reproducing Gradle source-set/package-directory scaffolding.

Neither directory is part of a Gradle source set. The supported mobile product remains `src/apps/android/`.
