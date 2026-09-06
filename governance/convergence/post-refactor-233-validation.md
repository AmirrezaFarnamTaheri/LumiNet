# Post-refactor-233 validation

- canonical_verify_repo: verified in exact Makefile order; monolithic run hit host 120s ceiling at post-refactor-117, remainder executed in bounded ordered bands; no failing gate
- control_ui_characterization: verified: 1132 checks across inherited suites through post-refactor-233
- environment_boundaries: repository requests Go 1.26/toolchain 1.26.5 while local Go is 1.23.2; Rust/Cargo and local Gradle unavailable; unavailable full native builds are not claimed
- go_declaration_integrity: verified: 1669 Go files parsed; 0 syntax errors; 0 duplicate active declarations on linux/amd64, windows/amd64, darwin/amd64, android/arm64
- mutation_retry_authority: verified: 1927 assertions
- native_ffi_tail: verified: route/platform/native/proxy/ABI/FFI checks, 22 native verification coverage checks, and 5 LumiCore link tests passed
- post_refactor_225: verified: 35762 assertions
- post_refactor_229: verified from rehydrated exact original donor bytes: 333606 assertions
- post_refactor_232_successor: verified: 102 assertions
- post_refactor_233: verified: 559551 assertions before final evidence regeneration
- post_refactor_233_go_planners: verified: isolated Go 1.23-compatible harness 7/7 tests
- repository_audit: verified: 0 errors; 1 environment-only warning for absent local Android Gradle wrapper; CI/release provisions Gradle 9.5.0
- typescript_semantic_check: verified: TypeScript 5.8.3 tsc --noEmit exit 0
