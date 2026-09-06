#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance" / "convergence"
P = "post-refactor-220"
DELTA_REL = f"governance/convergence/{P}-target-delta.csv"
SUCCESSOR_BASELINE = G / "post-refactor-222-baseline-files.csv"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED = {
    "projects": 40,
    "donors": 39,
    "historical_surfaces": 18517,
    "post160_surfaces": 12285,
    "post180_surfaces": 6232,
    "baseline_files": 2811,
    "ledger": 17,
}
FINAL_STATUS = {"verified", "statically-validated", "reviewed"}
VALID_DISPOSITIONS = {
    "adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized",
    "inspired-native", "guardrail-derived", "superseded", "rejected-with-reason", "reference-only",
}


def rows(name: str) -> list[dict[str, str]]:
    path = G / name
    if not path.is_file():
        raise AssertionError(f"missing {path.relative_to(ROOT)}")
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def digest(path: Path) -> tuple[str, str, str]:
    if path.is_symlink():
        target = os.readlink(path)
        return "symlink", hashlib.sha256(target.encode()).hexdigest(), target
    return "file", hashlib.sha256(path.read_bytes()).hexdigest(), "n/a"


def scan_current() -> dict[str, tuple[str, str, str]]:
    # Historical post-220 evidence is immutable. Once post-222 exists, compare
    # this wave against the successor's frozen pre-change snapshot rather than
    # today's descendant source tree.
    if SUCCESSOR_BASELINE.is_file():
        current: dict[str, tuple[str, str, str]] = {}
        with SUCCESSOR_BASELINE.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                rel = row["path"].strip()
                if rel == DELTA_REL:
                    continue
                current[rel] = (row["file_type"].strip(), row["sha256"].strip(), row.get("link_target", ""))
        return current

    current: dict[str, tuple[str, str, str]] = {}
    for path in sorted(ROOT.rglob("*")):
        if not (path.is_file() or path.is_symlink()):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel == DELTA_REL:
            continue
        if rel.startswith(".git/") or "/__pycache__/" in "/" + rel or rel.endswith(".pyc"):
            continue
        if "/node_modules/" in "/" + rel or "/.gradle/" in "/" + rel:
            continue
        current[rel] = digest(path)
    return current


def anchor_exists(node: str) -> bool:
    node = (node or "").strip()
    if not node or node == "n/a":
        return True
    if "#" not in node:
        return (ROOT / node).exists()
    rel, anchor = node.split("#", 1)
    path = ROOT / rel
    return path.is_file() and anchor in path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    errors: list[str] = []
    try:
        baseline_rows = rows(f"{P}-baseline-files.csv")
        accountability = rows(f"{P}-cross-wave-accountability.csv")
        ledger = rows(f"{P}-adoption-ledger.csv")
        delta_rows = rows(f"{P}-target-delta.csv")
        summary = json.loads((G / f"{P}-summary.json").read_text(encoding="utf-8"))
        s160 = rows("post-refactor-160-surface-accountability.csv")
        s180 = rows("post-refactor-180-surface-accountability.csv")
        l160 = rows("post-refactor-160-new-adoption-ledger.csv")
        l180 = rows("post-refactor-180-adoption-ledger.csv")
    except Exception as exc:
        print(f"{P} convergence: load failure: {exc}")
        return 1

    donor_rows = [r for r in accountability if r["role"] == "donor"]
    target_rows = [r for r in accountability if r["role"] == "target"]
    require(errors, len(accountability) == EXPECTED["projects"], f"project universe {len(accountability)} != {EXPECTED['projects']}")
    require(errors, len(donor_rows) == EXPECTED["donors"], f"donor universe {len(donor_rows)} != {EXPECTED['donors']}")
    require(errors, len(target_rows) == 1 and target_rows[0]["project"] == "LumiNet", "exactly one LumiNet target row is required")
    require(errors, len({r["project"] for r in accountability}) == len(accountability), "duplicate project accountability row")
    require(errors, sum(int(r["surface_count"]) for r in donor_rows) == EXPECTED["historical_surfaces"], "cross-wave donor surface rollup mismatch")
    require(errors, len(s160) == EXPECTED["post160_surfaces"], "post-160 surface matrix denominator drift")
    require(errors, len(s180) == EXPECTED["post180_surfaces"], "post-180 surface matrix denominator drift")
    require(errors, len(baseline_rows) == EXPECTED["baseline_files"], "post-220 baseline file count drift")
    require(errors, int(summary.get("project_universe", -1)) == EXPECTED["projects"], "summary project universe mismatch")
    require(errors, int(summary.get("uploaded_donor_archives", -1)) == EXPECTED["donors"], "summary donor count mismatch")
    require(errors, int(summary.get("historically_accounted_uploaded_donor_surfaces", -1)) == EXPECTED["historical_surfaces"], "summary surface denominator mismatch")

    historical_ids = {r["record_id"] for r in l160 + l180}
    for row in donor_rows:
        require(errors, row["historical_root_record"] in historical_ids, f"{row['project']}: historical root record not found")
        for rid in [x for x in row["historical_fine_records"].split(";") if x and x != "n/a"]:
            require(errors, rid in historical_ids, f"{row['project']}: historical fine record {rid} not found")
        require(errors, bool(row["post220_resolution"].strip()), f"{row['project']}: missing post-220 resolution")
        require(errors, bool(row["post220_boundary"].strip()), f"{row['project']}: missing post-220 boundary")

    surface_by_key = {(r["donor"], r["path"]): r for r in s160 + s180}
    require(errors, len(ledger) == EXPECTED["ledger"], f"post-220 ledger {len(ledger)} != {EXPECTED['ledger']}")
    require(errors, {r["record_id"] for r in ledger} == {f"PR220-S{i:03d}" for i in range(1, EXPECTED["ledger"] + 1)}, "post-220 record identity mismatch")
    require(errors, len({r["record_id"] for r in ledger}) == len(ledger), "duplicate post-220 record ID")
    for row in ledger:
        rid = row["record_id"]
        require(errors, row["disposition"] in VALID_DISPOSITIONS, f"{rid}: invalid disposition {row['disposition']}")
        require(errors, row["validation_status"] in FINAL_STATUS, f"{rid}: non-final validation status {row['validation_status']}")
        require(errors, bool(row["decision_rationale"].strip()), f"{rid}: missing rationale")
        require(errors, bool(row["invariant"].strip()) and bool(row["negative_invariant"].strip()), f"{rid}: missing invariant")
        for node in row["target_nodes"].split(";"):
            require(errors, anchor_exists(node), f"{rid}: unresolved target node {node}")
        for node in row["test_node"].split(";"):
            require(errors, anchor_exists(node), f"{rid}: unresolved test node {node}")
        if row["donor"].startswith("LumiNet/"):
            path = ROOT / row["donor_path"]
            require(errors, path.is_file(), f"{rid}: target evidence path missing")
            if path.is_file():
                require(errors, hashlib.sha256(path.read_bytes()).hexdigest() == row["donor_sha256"], f"{rid}: target evidence hash mismatch")
        else:
            source = surface_by_key.get((row["donor"], row["donor_path"]))
            require(errors, source is not None, f"{rid}: peer evidence surface not found {row['donor']}:{row['donor_path']}")
            if source is not None:
                require(errors, source["sha256"] == row["donor_sha256"], f"{rid}: peer evidence hash mismatch")

    # Automatic configuration mutation retry remains the authority invariant.
    cfg = text("src/apps/daemon/internal/foundation/config/config.go")
    require(errors, "DefaultMutationAttempts = 3" in cfg and "MaxMutationAttempts     = 8" in cfg, "automatic mutation retry bounds changed")
    require(errors, "options.ExpectedRevision != nil" in cfg and "maxAttempts = 1" in cfg, "explicit revision no longer forces single attempt")
    require(errors, "errors.Is(err, ErrRevisionConflict)" in cfg, "mutation retry is not revision-conflict-specific")
    require(errors, "attempt == maxAttempts" in cfg, "mutation retry exhaustion bound missing")
    adapter = text("src/apps/daemon/internal/adapters/api/config_mutation.go")
    require(errors, "func commitConfigMutation" in adapter and "func configMutationOptions" in adapter, "single HTTP mutation adapter missing")

    # Canonical flow registry: declared coverage before registration, delegated close, finite capacity.
    flow = text("src/apps/daemon/internal/foundation/flowregistry/registry.go")
    require(errors, "MaxBulkCloseFlows = 256" in flow and "bulk close exceeds" in flow, "bulk flow-close bound missing")
    require(errors, "ErrOwnerUndeclared" in flow and "coverage is undeclared" in flow, "undeclared flow owners can register")
    require(errors, "validateCoverage" in flow and "CloseFunc" in flow, "flow coverage/delegated close contract missing")
    require(errors, "r.mu.Unlock()" in flow and "closeFn(ctx)" in flow, "flow close callback no longer executes outside registry lock")
    flowtests = text("src/apps/daemon/internal/foundation/flowregistry/registry_test.go")
    for token in ["undeclared", "coverage", "bulk", "close"]:
        require(errors, token.lower() in flowtests.lower(), f"flow registry tests missing {token} evidence")

    # Passive daemon network epochs and derived path intelligence.
    netmon = text("src/apps/daemon/internal/platform/system/network_monitor.go")
    require(errors, "fingerprintNetwork" in netmon and "MTU" in netmon and "HardwareAddr" in netmon and "Flags" in netmon, "network fingerprint does not cover link shape")
    require(errors, "net.DialUDP" in netmon and "Write(" not in netmon[netmon.find("func inferDefaultInterface"):netmon.find("func interfaceFlagNames")], "network route inference ceased to be passive")
    require(errors, "historyLimit" in netmon and "DefaultNetworkHistoryLimit" in netmon and "len(m.history) > m.historyLimit" in netmon, "network history is unbounded")
    intel = text("src/apps/daemon/internal/analysis/netintel/summary.go")
    require(errors, "func Build" in intel and "PreHandoffFlows" in intel and "UnknownEpochFlows" in intel, "derived path intelligence summary missing")
    require(errors, "net.Dial" not in intel and "http." not in intel and "exec." not in intel, "derived network intelligence performs active I/O")
    require(errors, "ProviderCorpusStale" in intel, "provider-corpus freshness is not exposed")

    # Compatibility, shaping and strict generated-output re-ingest proof.
    convert = text("src/apps/daemon/internal/integrations/sub/convert.go")
    transform = text("src/apps/daemon/internal/integrations/sub/transform.go")
    roundtrip = text("src/apps/daemon/internal/integrations/sub/roundtrip.go")
    ch = text("src/apps/daemon/internal/adapters/api/handlers_subscription_convert.go")
    require(errors, all(x in convert for x in ["uri-list", "base64", "luminet-json", "clash-meta", "sing-box"]), "five conversion targets are not retained")
    require(errors, "maxConversionNodes" in convert and "maxConversionOutputBytes" in convert, "conversion bounds missing")
    require(errors, "TransformConfigs" in transform and "maxTransformPatterns" in transform and "spec.Limit > maxConversionNodes" in transform, "local transform bounds missing")
    require(errors, "orphan" in transform.lower() and "DialerProxy" in transform, "detour-safe transform guard missing")
    require(errors, "ValidateRoundTrip" in roundtrip and "detour_change" in roundtrip and "semantic_change" in roundtrip, "round-trip semantic/graph comparator missing")
    require(errors, "ValidateRoundTrip(configs, result.Content, sub.ParseContent)" in ch, "conversion handler does not re-ingest generated output")
    require(errors, "strict conversion failed local round-trip validation" in ch, "strict round-trip rejection missing")
    require(errors, "Fetch" not in ch and "http.Get" not in ch, "local conversion handler gained remote fetch authority")
    ingest = text("src/apps/daemon/internal/integrations/sub/ingest.go")
    require(errors, "luminet.proxy-bundle.v1" in ingest, "canonical LumiNet bundle is not re-ingestable")
    uri = text("src/apps/daemon/internal/networking/proxyconfig/types.go")
    require(errors, 'case "tls", "reality":' in uri and 'q.Set("security", security)' in uri, "VLESS explicit TLS/Reality URI preservation missing")

    # Interrupted-job recovery: redacted persistence, whitelist reconstruction, explicit new lineage.
    recovery = text("src/apps/daemon/internal/workflows/jobs/recovery.go")
    intents = text("src/apps/daemon/internal/workflows/jobs/intents.go")
    require(errors, "operator-confirmed-new-job" in recovery and "RecoveredFrom" in recovery, "recovery is not explicit new-job lineage")
    require(errors, "recoveryMu" in recovery and "activeRecoveryDescendant" in recovery, "duplicate active recovery serialization missing")
    require(errors, "ProxyTest" in recovery and "not reconstructible" in recovery, "secret-bearing proxy test replay is not rejected")
    require(errors, "URITransportPreview" in intents and "scrubLegacyConfig" in intents, "persisted proxy intent redaction/legacy scrub missing")
    require(errors, "init()" not in recovery, "recovery gained automatic init-time replay")

    # Product surfaces remain typed/non-authoritative and characterize all new planes.
    ui_check = text("src/packages/control-ui/scripts/test-eighth-order-promotions.mjs")
    capability_handler = text("src/apps/daemon/internal/adapters/api/handlers_capabilities.go")
    capability_page = text("src/packages/control-ui/src/pages/Capabilities.tsx")
    capability_parser = text("src/packages/control-ui/src/api/capabilities.ts")
    require(errors, '"schema_version": 4' in capability_handler and "flowregistry.Default().Coverage()" in capability_handler and "GetNetworkMonitor().Status(0)" in capability_handler and "DefaultService.Status" in capability_handler, "unified capability evidence dimensions missing from API")
    require(errors, "Capability & coverage center" in capability_page and "Runtime flow coverage" in capability_page and "Passive network observation" in capability_page and "Provider corpus" in capability_page, "Capability & Coverage Center product surface missing")
    require(errors, "parseCapabilityReport" in capability_parser and "Number.isSafeInteger" in capability_parser, "typed capability-report parser missing")
    require(errors, "Local re-ingest proof" in text("src/packages/control-ui/src/pages/Profiles.tsx"), "Compatibility Lab round-trip evidence missing")
    require(errors, "Runtime coverage truth" in text("src/packages/control-ui/src/pages/Connections.tsx"), "Connections coverage truth missing")
    require(errors, "Interrupted job recovery" in text("src/packages/control-ui/src/pages/Operations.tsx"), "Recovery operator widget missing")
    require(errors, "strict conversion requires local re-ingest proof" in ui_check and "no UI close-all affordance" in ui_check, "UI characterization misses authority/round-trip guards")

    # Historical post-180 evidence is frozen against this wave's pre-change baseline.
    post180 = text("scripts/checks/check_post_refactor_180_convergence.py")
    require(errors, "post-refactor-220-baseline-files.csv" in post180, "post-180 checker is not frozen to post-220 successor baseline")
    make = text("Makefile")
    require(errors, "check_post_refactor_220_convergence.py" in make, "Makefile missing post-220 gate")
    require(errors, SUCCESSOR_BASELINE.is_file(), "post-220 historical checker is not frozen to the post-222 successor baseline")

    baseline = {r["path"]: (r["file_type"], r["sha256"], r.get("link_target", "n/a") or "n/a") for r in baseline_rows}
    require(errors, len(baseline) == EXPECTED["baseline_files"], "duplicate post-220 baseline path")
    require(errors, all(HEX64.fullmatch(v[1]) for v in baseline.values()), "invalid post-220 baseline hash")
    current = scan_current()
    expected_delta: dict[str, tuple[str, str, str]] = {}
    for path in sorted(set(baseline) | set(current)):
        before = baseline.get(path)
        after = current.get(path)
        if before == after:
            continue
        if before is None:
            expected_delta[path] = ("added", "n/a", after[1])
        elif after is None:
            expected_delta[path] = ("deleted", before[1], "n/a")
        else:
            expected_delta[path] = ("modified", before[1], after[1])

    delta: dict[str, dict[str, str]] = {}
    for row in delta_rows:
        path = row["path"].strip()
        require(errors, path and path not in delta, f"duplicate/empty target delta path {path!r}")
        delta[path] = row
        expected = expected_delta.get(path)
        require(errors, expected is not None, f"target delta contains unchanged/unexpected path {path}")
        if expected:
            actual = (row["change_type"], row["baseline_sha256"], row["current_sha256"])
            require(errors, actual == expected, f"target delta mismatch {path}: {actual} != {expected}")
        require(errors, bool(row.get("reason", "").strip()), f"target delta reason missing {path}")
    missing = sorted(set(expected_delta) - set(delta))
    extra = sorted(set(delta) - set(expected_delta))
    if missing:
        errors.append(f"target delta missing {len(missing)} paths: {missing[:100]}")
    if extra:
        errors.append(f"target delta has {len(extra)} extra paths: {extra[:100]}")

    if errors:
        print(f"{P} convergence: FAIL ({len(errors)} errors)")
        for error in errors[:500]:
            print("ERROR:", error)
        return 1
    dc = Counter(r["change_type"] for r in delta_rows)
    print(
        f"{P} convergence: PASS projects={len(accountability)} donors={len(donor_rows)} "
        f"historical_surfaces={sum(int(r['surface_count']) for r in donor_rows)} ledger={len(ledger)} "
        f"delta={len(delta_rows)} added={dc['added']} modified={dc['modified']} deleted={dc['deleted']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
