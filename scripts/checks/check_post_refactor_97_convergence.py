#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance" / "convergence"
P = "post-refactor-97"
BASELINE_REL = f"governance/convergence/{P}-baseline-files.csv"
DELTA_REL = f"governance/convergence/{P}-target-delta.csv"
BASELINE_SHA256 = "0a3335e637941e7367a5d0bfb3205fb254e322b3c0570337b9bd8817ca6a616f"
EXPECTED = {
    "donors": 97,
    "surfaces": 20585,
    "directories": 4132,
    "modules": 2701,
    "symbols": 39419,
    "ledger": 2856,
    "semantics": 155,
    "licenses": 97,
    "nested": 11,
    "historical_resolutions": 11,
    "repairs": 5,
    "planes": 12,
    "baseline_files": 2625,
    "new_donors": 14,
    "new_members": 14444,
    "new_surfaces": 12010,
    "new_directories": 2434,
    "new_modules": 2077,
    "new_symbols": 19675,
    "new_symlinks": 24,
    "new_nested": 7,
    "new_nested_members": 153,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VALID_DISPOSITIONS = {
    "adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized",
    "inspired-native", "guardrail-derived", "superseded", "rejected-with-reason", "reference-only",
}
FINAL_STATUS = {"verified", "statically-validated", "reviewed"}
NEW_DONORS = {
    "Tor-IP-Changer-main", "TorOverVPN-main", "Tor_Onion_Proxy_Library-master",
    "onion-grater-master", "onionbalance-develop", "onionoo-master", "tor-android-master",
    "tor-controller-master", "tor-ramdisk-master", "torflow-main", "torps-master",
    "torsocks-main", "tun2tor-master", "txtorcon-main",
}
RESOLUTION_IDS = {
    "U-S017", "E9-0003", "E9-0017", "E9-0023", "E9-0027", "E9-0031",
    "FP-S009", "PR83-S010", "PR83-S011", "PR83-S014", "PR83-S017",
}

# Explicit semantic decision anchors used by non-executable guardrail/reference/rejection rows.
# They make each decision independently addressable without pretending reference evidence is a runtime test.
SEMANTIC_DECISION_ANCHORS = {
    "semantic-PR97-S007",
    "semantic-PR97-S008",
    "semantic-PR97-S009",
    "semantic-PR97-S010",
    "semantic-PR97-S011",
    "semantic-PR97-S012",
    "semantic-PR97-S013",
    "semantic-PR97-S014",
    "semantic-PR97-S015",
    "semantic-PR97-S016",
    "semantic-PR97-S017",
    "semantic-PR97-S018",
    "semantic-PR97-S019",
    "semantic-PR97-S020",
    "semantic-PR97-S021",
    "semantic-PR97-S022",
    "semantic-PR97-S023",
    "semantic-PR97-S024",
    "semantic-PR97-S025",
    "semantic-PR97-S026",
    "semantic-PR97-S027",
    "semantic-PR97-S028",
    "semantic-PR97-S029",
    "semantic-PR97-S030",
    "semantic-PR97-S031",
    "semantic-PR97-S032",
    "semantic-PR97-S033",
    "semantic-PR97-S034",
 }


def read_csv(name: str):
    p = G / name
    if not p.is_file():
        raise AssertionError(f"missing {p.relative_to(ROOT)}")
    with p.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def digest(p: Path):
    if p.is_symlink():
        target = os.readlink(p)
        return ("symlink", hashlib.sha256(target.encode()).hexdigest(), target)
    return ("file", hashlib.sha256(p.read_bytes()).hexdigest(), "n/a")


def scan_current():
    out = {}
    for p in sorted(ROOT.rglob("*")):
        if not (p.is_file() or p.is_symlink()):
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel == DELTA_REL or rel.startswith(".git/") or "/__pycache__/" in "/" + rel or rel.endswith(".pyc"):
            continue
        out[rel] = digest(p)
    return out


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def require(errors: list[str], condition: bool, message: str):
    if not condition:
        errors.append(message)


def anchor_exists(node: str) -> bool:
    node = (node or "").strip()
    if not node or node == "n/a":
        return True
    if "#" not in node:
        return (ROOT / node).exists()
    rel, anchor = node.split("#", 1)
    p = ROOT / rel
    if not p.is_file():
        return False
    raw = p.read_text(encoding="utf-8", errors="replace")
    candidates = {anchor, anchor.split(".")[-1], anchor.replace("-", "_"), anchor.replace("-", " ")}
    return any(c and re.search(r"(?<![A-Za-z0-9_])" + re.escape(c) + r"(?![A-Za-z0-9_])", raw, re.I) for c in candidates)


def main() -> int:
    errors: list[str] = []
    try:
        donors = read_csv(f"{P}-donors.csv")
        surfaces = read_csv(f"{P}-surfaces.csv")
        dirs = read_csv(f"{P}-directories.csv")
        modules = read_csv(f"{P}-modules.csv")
        symbols = read_csv(f"{P}-symbols.csv")
        ledger = read_csv(f"{P}-adoption-ledger.csv")
        licenses = read_csv(f"{P}-license-map.csv")
        nested = read_csv(f"{P}-nested-archives.csv")
        resolutions = read_csv(f"{P}-historical-resolutions.csv")
        repairs = read_csv(f"{P}-target-repairs.csv")
        planes = read_csv(f"{P}-high-level-plane-audit.csv")
        new_donors = read_csv(f"{P}-new-donors.csv")
        new_nested = read_csv(f"{P}-new-nested-archives.csv")
        baseline_rows = read_csv(f"{P}-baseline-files.csv")
        delta_rows = read_csv(f"{P}-target-delta.csv")
    except Exception as exc:
        print("post-refactor-97 convergence:", exc)
        return 1

    counts = {
        "donors": len(donors), "surfaces": len(surfaces), "directories": len(dirs),
        "modules": len(modules), "symbols": len(symbols), "ledger": len(ledger),
        "licenses": len(licenses), "nested": len(nested),
        "historical_resolutions": len(resolutions), "repairs": len(repairs), "planes": len(planes),
        "baseline_files": len(baseline_rows), "new_donors": len(new_donors), "new_nested": len(new_nested),
    }
    for key, actual in counts.items():
        require(errors, actual == EXPECTED[key], f"{key} count {actual} != {EXPECTED[key]}")

    # The baseline snapshot is hash-frozen to the delivered 83-donor source archive.
    baseline_path = G / f"{P}-baseline-files.csv"
    require(errors, hashlib.sha256(baseline_path.read_bytes()).hexdigest() == BASELINE_SHA256, "post-refactor-83 baseline snapshot hash drift")
    baseline = {}
    for row in baseline_rows:
        path = row["path"].strip()
        require(errors, path and path not in baseline, f"duplicate/empty baseline path {path!r}")
        require(errors, bool(HEX64.fullmatch(row.get("sha256", ""))), f"baseline {path}: invalid sha256")
        baseline[path] = (row["file_type"], row["sha256"], row["link_target"])

    # Three explicit waves; the prior 20 are part of the 83 baseline, never double-counted.
    wave_counts = Counter(r["wave"] for r in donors)
    require(errors, wave_counts == Counter({"ultimate-63": 63, "post-refactor-20": 20, "tor-wave-14": 14}), f"donor wave counts mismatch: {dict(wave_counts)}")
    donor_names = [r["donor"] for r in donors]
    require(errors, len(set(donor_names)) == EXPECTED["donors"], "duplicate donor identity in 97-donor inventory")
    actual_new = {r["donor"] for r in donors if r["wave"] == "tor-wave-14"}
    require(errors, actual_new == NEW_DONORS, f"new Tor donor set mismatch missing={sorted(NEW_DONORS-actual_new)} extra={sorted(actual_new-NEW_DONORS)}")

    # New-wave archive/file/symbol denominators must reconcile exactly.
    nd = [r for r in donors if r["wave"] == "tor-wave-14"]
    require(errors, sum(int(r["member_count"]) for r in nd) == EXPECTED["new_members"], "new-wave archive-member denominator mismatch")
    require(errors, sum(int(r["file_surfaces"]) for r in nd) == EXPECTED["new_surfaces"], "new-wave surface rollup mismatch")
    require(errors, sum(int(r["directories"]) for r in nd) == EXPECTED["new_directories"], "new-wave directory rollup mismatch")
    require(errors, sum(int(r["symbols"]) for r in nd) == EXPECTED["new_symbols"], "new-wave symbol rollup mismatch")
    require(errors, sum(int(r["symlinks"]) for r in nd) == EXPECTED["new_symlinks"], "new-wave symlink rollup mismatch")
    require(errors, sum(int(r.get("nested_members", "0") or 0) for r in nd) == EXPECTED["new_nested_members"], "new-wave nested-member rollup mismatch")
    require(errors, all((r.get("archive_issues") or "").lower().startswith("none") for r in nd), "new-wave archive safety issue is not closed")

    # Every surface is independently hash-accounted and points to an existing ledger record.
    ledger_ids = {r["record_id"] for r in ledger}
    module_ids = {r["module_id"] for r in modules}
    require(errors, len(ledger_ids) == len(ledger), "duplicate adoption/accountability record ids")
    require(errors, len(module_ids) == len(modules), "duplicate module ids")
    require(errors, module_ids <= ledger_ids, "module accountability record missing from adoption ledger")
    require(errors, len(ledger) - len(modules) == EXPECTED["semantics"], f"fine semantic count {len(ledger)-len(modules)} != {EXPECTED['semantics']}")
    statuses = {r.get("validation_status", "") for r in ledger}
    require(errors, statuses <= FINAL_STATUS, f"non-final validation statuses remain: {sorted(statuses-FINAL_STATUS)}")
    require(errors, all(r.get("disposition") in VALID_DISPOSITIONS for r in ledger), "invalid disposition present in combined ledger")

    surface_map = {}
    for row in surfaces:
        key = (row["donor"], row["path"])
        require(errors, key not in surface_map, f"duplicate surface {key}")
        surface_map[key] = row
        require(errors, bool(HEX64.fullmatch(row.get("sha256", ""))), f"surface {key}: invalid sha256")
        refs = [x for x in row.get("semantic_record_ids", "").split(";") if x]
        require(errors, bool(refs), f"surface {key}: no accountability record")
        for rid in refs:
            require(errors, rid in ledger_ids, f"surface {key}: unknown record {rid}")
    require(errors, sum(1 for r in surfaces if r["wave"] == "tor-wave-14") == EXPECTED["new_surfaces"], "new-wave surface matrix denominator mismatch")
    require(errors, sum(1 for r in surfaces if r["wave"] == "tor-wave-14" and r["file_type"] == "symlink") == EXPECTED["new_symlinks"], "new-wave symlink surface denominator mismatch")

    for row in modules:
        require(errors, 0 < int(row["surface_count"]) <= 100, f"module {row['module_id']}: invalid surface bound")
        key = (row["donor"], row["representative_path"])
        sr = surface_map.get(key)
        require(errors, sr is not None, f"module {row['module_id']}: representative surface missing")
        if sr:
            require(errors, sr["sha256"] == row["representative_sha256"], f"module {row['module_id']}: representative hash mismatch")
    require(errors, sum(1 for r in modules if r["wave"] == "tor-wave-14") == EXPECTED["new_modules"], "new-wave module denominator mismatch")
    require(errors, sum(1 for r in symbols if r["wave"] == "tor-wave-14") == EXPECTED["new_symbols"], "new-wave symbol denominator mismatch")

    # Every fine semantic row resolves to exact donor bytes; new adopted/hardened rows also resolve target/test anchors.
    fine = [r for r in ledger if r["record_id"] not in module_ids]
    for row in fine:
        sr = surface_map.get((row["donor"], row["donor_path"]))
        require(errors, sr is not None, f"semantic {row['record_id']}: donor surface missing")
        if sr:
            require(errors, sr["sha256"] == row["donor_sha256"], f"semantic {row['record_id']}: donor hash mismatch")
    new_semantics = [r for r in fine if r["record_id"].startswith("PR97-S")]
    require(errors, len(new_semantics) == 34, f"new semantic decision count {len(new_semantics)} != 34")
    for row in new_semantics:
        for node in [x for x in row.get("target_nodes", "").split(";") if x and x != "n/a"]:
            require(errors, anchor_exists(node), f"semantic {row['record_id']}: target anchor missing {node}")
        test_node = row.get("test_node", "")
        if test_node and test_node != "n/a":
            require(errors, anchor_exists(test_node), f"semantic {row['record_id']}: test anchor missing {test_node}")
        # No open convergence work is encoded as a future/deferred status; path names such as TODO are evidence, not status.
        final_text = " ".join([row.get("disposition", ""), row.get("decision_rationale", ""), row.get("validation_status", "")])
        require(errors, not re.search(r"\b(pending|defer(?:red)?|implement later|future work)\b", final_text, re.I), f"semantic {row['record_id']}: open-ended future/deferred wording remains")

    # Nested archive handling: 4 prior byte-identical embedded duplicates + 7 current nested payloads.
    new_nested_rows = [r for r in nested if r["wave"] == "tor-wave-14"]
    require(errors, len(new_nested_rows) == EXPECTED["new_nested"], "new nested archive count mismatch")
    require(errors, sum(int(r["members"]) for r in new_nested_rows) == EXPECTED["new_nested_members"], "new nested member denominator mismatch")
    require(errors, all((r.get("issues") or "none") == "none" for r in new_nested_rows), "new nested archive safety issue remains")
    require(errors, len(new_nested) == EXPECTED["new_nested"], "new nested raw evidence count mismatch")
    require(errors, sum(int(r["members"]) for r in new_nested) == EXPECTED["new_nested_members"], "new nested raw member denominator mismatch")
    require(errors, all(not (r.get("issues") or "").strip() for r in new_nested), "new nested raw evidence contains safety issue")

    # Historical correction layer must close every identified stale/future overclaim without rewriting frozen rows.
    resolution_ids = {r["prior_record_id"] for r in resolutions}
    require(errors, resolution_ids == RESOLUTION_IDS, f"historical resolution set mismatch missing={sorted(RESOLUTION_IDS-resolution_ids)} extra={sorted(resolution_ids-RESOLUTION_IDS)}")
    require(errors, all("final" in r["final_disposition"] or r["prior_record_id"] in {"U-S017", "PR83-S014"} for r in resolutions), "historical resolution lacks explicit final disposition")

    # Live Tor successor invariants.
    controller = text("src/apps/daemon/internal/platform/system/tor_controller.go")
    control_filter = text("src/apps/daemon/internal/platform/system/control_filter.go")
    tor_engine = text("src/apps/daemon/internal/runtime/runtimecore/tor_engine.go")
    tor_process = text("src/apps/daemon/internal/platform/system/tor_process.go")
    runtime_tests = text("src/apps/daemon/internal/runtime/runtimecore/engine_lifecycle_unix_test.go")
    protocol_tests = text("src/apps/daemon/internal/platform/system/tor_controller_protocol_test.go")
    filter_tests = text("src/apps/daemon/internal/platform/system/control_filter_exact_test.go")

    for marker in ["maxTorControlCommandBytes", "maxTorControlReplyBytes", "SetDeadline", 'status == 650', "case '+'", 'strings.ContainsAny(cmd, "\\r\\n\\x00")', "BootstrapProgress", "TakeOwnership"]:
        require(errors, marker in controller, f"Tor controller invariant missing: {marker}")
    require(errors, controller.find("validateTorControlCommand(cmd)") < controller.find('fmt.Fprintf(conn, "%s\\r\\n", cmd)'), "Tor control command admission no longer occurs before socket write")
    require(errors, 'regexp.Compile("(?i)^(?:" + p + ")$")' in control_filter, "Tor control whitelist is not exact/full-line anchored")
    require(errors, 'regexp.Compile("(?i)^" + p)' not in control_filter, "legacy prefix-only Tor control whitelist returned")
    for marker in ["startupTimeout", "60 * time.Second", "startupPollInterval", "progress == 100", "stopCommand", "probeTorBootstrap"]:
        require(errors, marker in tor_engine, f"Tor startup invariant missing: {marker}")
    require(errors, "300 * time.Millisecond" not in tor_engine, "legacy 300 ms Tor liveness readiness inference returned")
    require(errors, "controller.BootstrapProgress()" in tor_process and 'controller.TakeOwnership("__luminet")' in tor_process, "TorProcess deep-controller delegation missing")
    for marker in ["TestTorControllerRejectsInjectedCommandBeforeWrite", "TestTorControllerSkipsAsyncEventBeforeReply", "TestTorControllerConsumesDataReplyAndDotUnstuffs", "TestTorControllerBoundsWholeReply", "TestTorControllerCommandTimeoutBreaksConnection"]:
        require(errors, marker in protocol_tests, f"Tor controller regression test missing: {marker}")
    for marker in ["TestControlFilterRequiresWholeCommandMatch"]:
        require(errors, marker in filter_tests, f"Tor control exact-match regression missing: {marker}")
    for marker in ["TesttorEngineWaitsForFullBootstrap", "TesttorEngineRejectsLiveProcessThatNeverBootstraps", "TesttorEngineRetriesTemporaryBootstrapProbeErrors"]:
        require(errors, marker in runtime_tests, f"Tor startup regression missing: {marker}")

    # Correct historical SOCKS isolation truth: builder can support it, production owner does not currently enable it.
    require(errors, "SocksPort(e.socksPort, false, false)" in tor_engine, "production SOCKS isolation truth changed; historical resolution must be revisited")
    require(errors, any(r["prior_record_id"] == "U-S017" and "claim corrected" in r["final_disposition"] for r in resolutions), "U-S017 SOCKS-isolation correction missing")

    # Exact successor delta from frozen 83-donor baseline to the exact 97-donor successor state.
    # When a later release exists, freeze this historical gate at the next release baseline instead
    # of silently widening the old delta to include later source changes.
    successor_baseline_path = G / "post-refactor-117-baseline-files.csv"
    if successor_baseline_path.is_file():
        with successor_baseline_path.open(encoding="utf-8-sig", newline="") as f:
            successor_baseline_rows = list(csv.DictReader(f))
        current = {
            row["path"].strip(): (row["file_type"], row["sha256"], row["link_target"])
            for row in successor_baseline_rows
            if row["path"].strip() != DELTA_REL
        }
        require(errors, len(current) == len(successor_baseline_rows) - 1, "duplicate successor-baseline paths or missing historical self-delta")
    else:
        current = scan_current()
    expected_delta = {}
    for path in sorted(set(baseline) | set(current)):
        before, after = baseline.get(path), current.get(path)
        if before == after:
            continue
        if before is None:
            expected_delta[path] = ("added", "n/a", after[1])
        elif after is None:
            expected_delta[path] = ("deleted", before[1], "n/a")
        else:
            expected_delta[path] = ("modified", before[1], after[1])
    delta = {}
    for row in delta_rows:
        path = row["path"].strip()
        require(errors, path and path not in delta, f"duplicate/empty successor delta path {path!r}")
        delta[path] = row
        exp = expected_delta.get(path)
        if exp is None:
            errors.append(f"successor delta {path}: not changed")
            continue
        got = (row["change_type"], row["baseline_sha256"], row["current_sha256"])
        require(errors, got == exp, f"successor delta {path}: mismatch got={got} expected={exp}")
        require(errors, bool(row.get("reason", "").strip()), f"successor delta {path}: missing reason")
    missing = sorted(set(expected_delta) - set(delta))
    extra = sorted(set(delta) - set(expected_delta))
    if missing:
        errors.append(f"successor delta missing {len(missing)} paths: {missing[:100]}")
    if extra:
        errors.append(f"successor delta extra {len(extra)} paths: {extra[:100]}")

    # Makefile preserves historical gate and adds this successor gate.
    makefile = text("Makefile")
    require(errors, "check_post_refactor_83_convergence.py" in makefile, "historical post-refactor-83 gate removed from verify-repo")
    require(errors, "check_post_refactor_97_convergence.py" in makefile, "verify-repo does not execute post-refactor-97 successor gate")
    old_checker = text("scripts/checks/check_post_refactor_83_convergence.py")
    require(errors, "post-refactor-97-baseline-files.csv" in old_checker, "historical post-refactor-83 checker is not frozen at the 83-donor successor baseline")
    if successor_baseline_path.is_file():
        require(errors, "post-refactor-117-baseline-files.csv" in text("scripts/checks/check_post_refactor_97_convergence.py"), "historical post-refactor-97 checker is not frozen at the 97-donor successor baseline")

    # Summary file is a machine-readable cross-check, not an alternate source of truth.
    summary_path = G / f"{P}-summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        for key in ["donors", "surfaces", "modules", "symbols", "ledger_records", "semantic_records", "historical_resolutions"]:
            expected_key = "ledger" if key == "ledger_records" else "semantics" if key == "semantic_records" else key
            require(errors, int(summary[key]) == EXPECTED[expected_key], f"summary {key} mismatch")
    except Exception as exc:
        errors.append(f"invalid successor summary: {exc}")

    if errors:
        print(f"post-refactor-97 convergence: donors={len(donors)} surfaces={len(surfaces)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} delta={len(delta_rows)} errors={len(errors)}")
        for error in errors[:500]:
            print("ERROR:", error)
        return 1
    print(f"post-refactor-97 convergence: donors={len(donors)} waves=63+20+14 surfaces={len(surfaces)} directories={len(dirs)} modules={len(modules)} symbols={len(symbols)} semantics={len(fine)} records={len(ledger)} symlinks_new={EXPECTED['new_symlinks']} nested_new={EXPECTED['new_nested']} delta={len(delta_rows)} errors=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
