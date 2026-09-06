# Post-refactor-222 omission and contradiction audit

## Denominators

- Uploaded artifacts accounted: **28/28**.
- Donor ZIP uploads: **25** files representing **23** unique archive hashes.
- Exact duplicate upload aliases collapsed after hashing: **2** (`Kloak_platform-master.zip`, `stealthspanner-master.zip`).
- Donor file/symlink surfaces: **6253/6253**.
- Archive symlinks: **20/20**; recorded as link metadata and never followed.
- Extracted symbols: **13006/13006**.
- Semantic decision records: **81**.
- Exact historical regular-file matches: **4960**.
- Reopened/unmatched current surfaces (including symlinks): **1293**.

## Surface classification

- configuration: 174
- deployment: 6
- documentation: 232
- fixture: 35
- implementation: 912
- media: 826
- operational: 2166
- repository-administration: 70
- script: 152
- test: 425
- ui-or-product: 98
- vendored: 1157

Authority/source status: authoritative=5096, derived=1157.

## Semantic dispositions

- adapted: 9
- extracted: 3
- guardrail-derived: 9
- hardened: 4
- inspired-native: 1
- recomposed: 3
- reference-only: 30
- rejected-with-reason: 9
- superseded: 13

Implemented/derived records requiring target ownership and acceptance evidence: **29**. High/critical records: **41**. Explicit rejections: **9**.

## Audit ladder

1. **Files and symlinks — closed.** Every supplied donor surface has a content/link-target hash and one or more semantic record IDs. No archive symlink is silently treated as regular historical content.
2. **Roots, packages and deliverables — closed.** All 23 unique current donor roots are represented in cross-wave accountability; all 28 uploaded archive artifacts are classified; two duplicate donor aliases are explicit.
3. **Exported symbols/runtime registrations — closed for static inventory.** 13,006 extracted symbols backlink the same semantic IDs and source hashes as their containing surfaces. Non-symbol assets remain covered at file level.
4. **Independent semantic contracts — closed for the current corpus.** Umbrella “reviewed” rows were split where behavior has different authority/risk/target ownership. Historical bridges apply only to unchanged bytes and preserve earlier fine-grained records.
5. **State machines/recovery — reviewed and promoted where material.** Configuration CAS retry, signed-update staging/publication, peer admission/planning, endpoint failover/diversity, log tail-follow, appearance state and diagnostic composition have explicit allowed/forbidden behavior.
6. **Negative paths/trust boundaries — closed for identified current risks.** Offensive/dual-use execution, hidden query/path authority, weak custom crypto, plaintext/general secret persistence, weak service identity, opaque helper binaries, country-scored trust and destructive firewall/device mutation are explicit rejection/guardrail records.
7. **API/CLI/UI/diagnostics/operator workflows — closed for promoted behavior.** Peer planner, endpoint planner, command palette, Health/diagnostics, appearance and log-tail surfaces are wired to existing target owners; UI remains non-authoritative.
8. **Presets/scripts/CI/package/deploy/update — accounted.** Configuration/preset/build/deployment/repository-administration surfaces are linked even when reference-only or superseded. Signed-update publication is separately hardened.
9. **Deep nested leaves — closed by exhaustive tree inventory.** Vendored/generated/media/localization/fixture/deep paths are not silently skipped; classification distinguishes them from authoritative source.
10. **Cross-version/history — closed.** 4,960 unchanged regular-file surfaces reuse exact-hash historical evidence; 1,293 changed/unmatched/link surfaces are reopened. The predecessor 221 target is frozen by archive SHA-256 and the post-220 checker is frozen to the 222 successor baseline.
11. **Cross-mechanism contradictions/orphans — machine-gated.** The post-222 checker rejects unlinked surfaces, unknown semantic IDs, unresolved target/test anchors, duplicate non-`n/a` test nodes, missing high-risk rejection evidence, denominator drift and target-delta drift.

## Saturation findings

The second-order pass continued below feature labels and recovered several method-level details: invalid peer candidates must not reserve identity/endpoint slots; previous-success cannot outrank a materially better endpoint; shared public IP must be NAT-safe evidence rather than automatic rejection; peer deny policy must be local/bounded rather than active DNSBL/probing; live logs must respect operator scroll intent; diagnostic bundles must avoid free-form backend text; Unix staged publication should avoid remove-before-rename and synchronize the parent directory.

No remaining current-corpus surface is known to be unclassified or unlinked. This statement is limited to the uploaded/current donor corpus and the historical evidence explicitly bridged by content identity; runtime claims remain bounded by the validation/toolchain limitations recorded separately.
