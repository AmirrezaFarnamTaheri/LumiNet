#!/usr/bin/env python3
"""Lock the post-refactor-228 automatic mutation retry authority boundaries."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
errors: list[str] = []
assertions = 0


def require(path: str, *needles: str) -> str:
    global assertions
    text = (ROOT / path).read_text(encoding="utf-8")
    for needle in needles:
        assertions += 1
        if needle not in text:
            errors.append(f"{path}: missing {needle!r}")
    return text


config = require(
    "src/apps/daemon/internal/foundation/config/config.go",
    "DefaultMutationAttempts = 3",
    "MaxMutationAttempts     = 8",
    "func (m *Manager) Mutate(options MutationOptions",
    "maxAttempts = 1",
    "cfg, revision := m.GetWithRevision()",
    "newRevision, err := m.SaveIfRevision(cfg, revision)",
    "if !errors.Is(err, ErrRevisionConflict)",
    "m.mutationAutomaticRetries.Add(1)",
    "m.mutationExhaustedRetries.Add(1)",
)

api = require(
    "src/apps/daemon/internal/adapters/api/config_mutation.go",
    "ExpectedRevision: &revision",
    "MaxAttempts: config.DefaultMutationAttempts",
    "result, err := manager.Mutate(options, mutate)",
    "X-LumiNet-Config-Mutation-Attempts",
)

remote = require(
    "src/apps/daemon/internal/foundation/remoteaction/remoteaction.go",
    'Idempotent SafetyClass = "idempotent"',
    'ReconcileBeforeRetry SafetyClass = "reconcile-before-retry"',
    'SingleAttempt SafetyClass = "single-attempt"',
    "maxAutomaticAttempts = 8",
    "policy.Class == ReconcileBeforeRetry && reconcile == nil",
    "reached, reconcileErr := reconcile(ctx)",
    "waitForCooldownAndAcquire",
    "defaultMaxInFlight",
)

# Call-site ownership: SaveIfRevision and saveUnlocked remain foundation/config
# internals except direct unit tests, and HTTP adapters cannot call Manager.Mutate
# outside the single helper.
for path in ROOT.glob("src/apps/daemon/internal/**/*.go"):
    rel = path.relative_to(ROOT).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    if "SaveIfRevision(" in text and not (
        rel.startswith("src/apps/daemon/internal/foundation/config/")
        or rel.endswith("_test.go")
    ):
        errors.append(f"{rel}: direct SaveIfRevision bypasses mutation authority")
    assertions += 1
    if "saveUnlocked(" in text and rel != "src/apps/daemon/internal/foundation/config/config.go":
        errors.append(f"{rel}: saveUnlocked escaped config owner")
    assertions += 1
    if rel.startswith("src/apps/daemon/internal/adapters/api/") and rel != "src/apps/daemon/internal/adapters/api/config_mutation.go":
        if re.search(r"\b(?:s\.)?configManager\.Mutate\s*\(", text):
            errors.append(f"{rel}: API adapter bypasses commitConfigMutation")
        assertions += 1

# Known live config mutation handlers must keep using the shared helper. This
# list is intentionally explicit so adding a new mutating adapter makes review
# of its retry/side-effect ordering visible rather than silently widening regex
# heuristics.
for path in (
    "src/apps/daemon/internal/adapters/api/handlers_system_startup.go",
    "src/apps/daemon/internal/adapters/api/handlers_system_ddns.go",
    "src/apps/daemon/internal/adapters/api/handlers_proxy_directory.go",
):
    text = require(path, "commitConfigMutation(")
    assertions += 1
    if "configManager.Save(" in text or "configManager.SaveIfRevision(" in text:
        errors.append(f"{path}: direct persistence bypasses commitConfigMutation")

# Mutation callbacks are replayable only while side-effect free. The helper's
# contract must remain explicit because the checker cannot prove semantic purity
# of arbitrary future callback bodies.
assertions += 1
if "runtime/network side effects belong\n// strictly after this function reports a durable commit" not in api:
    errors.append("config_mutation.go: replay-safe side-effect contract missing")

if errors:
    print(f"post-refactor-228 mutation retry authority: FAIL ({assertions} assertions, {len(errors)} errors)")
    for err in errors:
        print("-", err)
    sys.exit(1)

print(f"post-refactor-228 mutation retry authority: PASS ({assertions} assertions)")
