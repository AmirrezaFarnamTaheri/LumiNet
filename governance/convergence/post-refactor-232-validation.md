# Post-refactor-232 validation

- archive_admission: PASS — 4/4 donor archives admitted; 1036 members; 750 regular files; 286 directories; 0 symlinks
- canonical_verify_repo: PASS — monolithic prefix reached the 120-second host command ceiling after advanced-runtime-pruning; exact remaining Makefile order continued in bounded bands; every gate passed
- evidence_graph: PASS — 1019 ledger records; 47 focused semantic records; 0 unresolved high-signal surfaces
- focused_dnstt_go_harness: PASS — isolated Go 1.23.2 DNSTT deployment planner tests
- focused_outline_ingest_go_harness: PASS — isolated Go 1.23.2; compile-only YAML stub used because gopkg.in/yaml.v3 was unavailable; tested Outline invite path executes before YAML format detection
- focused_planner_go_harness: PASS — isolated Go 1.23.2 multipath, DNS campaign, and Outline planner tests
- go_declaration_integrity: PASS — 1666 parsed Go files; 0 syntax errors; 0 duplicate active declarations across selected linux/windows/darwin/android targets
- mutation_retry_authority: PASS — 1920 assertions
- post_refactor_232_checker: PASS — 21629 assertions
- predecessor_231_successor: PASS — 101 assertions
- repository_audit: PASS — errors=0 warnings=1; warning is missing local Android Gradle wrapper while CI/release explicitly provisions Gradle 9.5.0
- source_context: PASS — 127 required .context files; 0 errors
- toolchain_go: local Go 1.23.2; repository requests Go 1.26.0/toolchain 1.26.5; full pinned-workspace/native Go build not claimed
- toolchain_gradle: Gradle unavailable locally; Android production build not claimed
- toolchain_rust: cargo/rustc unavailable; Rust/native production build not claimed
- typescript_semantic: PASS — TypeScript 5.8.3 tsc --noEmit
- ui_characterization: PASS — 1027 checks
