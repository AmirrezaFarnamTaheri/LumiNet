# Post-refactor-234 validation

- control_ui_product_security: PASS 52 checks
- evidence_determinism: PASS 23/23 generated governance artifacts byte-identical across two complete cycles
- focused_go_planners: PASS 6/6 tests under isolated Go 1.23.2 compatibility harness
- full_control_ui_tsc_no_emit: ENVIRONMENT-BLOCKED clean source intentionally lacks vite/client and node type packages
- go_declaration_integrity: PASS parsed_files=1672 syntax_errors=0 duplicate_active_declarations=0 linux/windows/darwin/android
- mutation_retry_authority: PASS assertions=1934
- peer_convergence: PASS errors=0
- pinned_go_workspace: ENVIRONMENT-BLOCKED repository requests Go 1.26/toolchain 1.26.5; network download unavailable
- post_refactor_234_convergence: PASS assertions=157246 errors=0
- repository_audit: PASS errors=0 warnings=1 environment-only Android Gradle wrapper warning
- source_context: PASS required=127 errors=0
- topology: PASS baseline_accounted=2442/2442 errors=0
- typescript_5_8_3_modified_tsx_transpile: PASS 0 syntax/transpile errors
