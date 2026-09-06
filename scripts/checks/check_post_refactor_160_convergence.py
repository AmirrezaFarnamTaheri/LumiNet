#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance" / "convergence"
P = "post-refactor-160"
DELTA_REL = f"governance/convergence/{P}-target-delta.csv"
SUCCESSOR_BASELINE = G / "post-refactor-180-baseline-files.csv"
HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED = {
    "donors": 19,
    "surfaces": 12285,
    "directories": 2185,
    "modules": 44,
    "symbols": 70594,
    "nested_archives": 2,
    "ledger": 410,
    "roots": 19,
    "categories": 382,
    "fine": 9,
    "target_decisions": 4,
    "hash_overlap_groups": 584,
    "capability_profiles": 19,
    "semantic_tags": 24,
    "baseline_files": 2758,
}

EXPECTED_DONORS = {
    "LEGION2-main",
    "OnionHop-master",
    "SIMORGH-main",
    "Xray-core-main",
    "Xray-docs-next-main",
    "Xray-tun-main",
    "iperf-master",
    "lantern-main",
    "metacubexd-main",
    "nexvpn-main",
    "rethink-app-main",
    "sing-box-testing",
    "v2board-master",
    "v2ray-core-main",
    "v2ray-core-master",
    "v2ray-go-main",
    "v2rayA-main",
    "v2rayN-master",
    "v2ray_client-master",
}

FINAL_STATUS = {"verified", "statically-validated", "reviewed"}
VALID_DISPOSITIONS = {
    "adopted",
    "adapted",
    "hardened",
    "extracted",
    "recomposed",
    "synthesized",
    "inspired-native",
    "guardrail-derived",
    "superseded",
    "rejected-with-reason",
    "reference-only",
}


def read_csv(name: str) -> list[dict[str, str]]:
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
    # Historical post-160 evidence is immutable. Once a successor wave exists,
    # compare the post-160 baseline/delta against that successor's frozen
    # pre-change source snapshot rather than today's descendant working tree.
    if SUCCESSOR_BASELINE.is_file():
        current: dict[str, tuple[str, str, str]] = {}
        with SUCCESSOR_BASELINE.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                rel = row["path"].strip()
                if rel == DELTA_REL:
                    continue
                current[rel] = (row["file_type"].strip(), row["sha256"].strip(), row.get("link_target", ""))
        return current

    current = {}
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
    if not path.is_file():
        return False
    return anchor in path.read_text(encoding="utf-8", errors="replace")


def count_manifest_entries(rows: list[dict[str, str]]) -> int:
    total = 0
    for row in rows:
        value = row.get("manifests", "").strip()
        if value and value != "n/a":
            total += len([part for part in value.split(";") if part])
    return total


def main() -> int:
    errors: list[str] = []
    try:
        donors = read_csv(f"{P}-new-donors.csv")
        surfaces = read_csv(f"{P}-surface-accountability.csv")
        directories = read_csv(f"{P}-directories.csv")
        modules = read_csv(f"{P}-modules.csv")
        symbols = read_csv(f"{P}-symbols.csv")
        nested = read_csv(f"{P}-nested-archives.csv")
        ledger = read_csv(f"{P}-new-adoption-ledger.csv")
        decisions = read_csv(f"{P}-target-decisions.csv")
        overlaps = read_csv(f"{P}-hash-overlaps.csv")
        capabilities = read_csv(f"{P}-capability-counts.csv")
        baseline_rows = read_csv(f"{P}-baseline-files.csv")
        delta_rows = read_csv(f"{P}-target-delta.csv")
    except Exception as exc:
        print(f"{P} convergence: load failure: {exc}")
        return 1

    counts = {
        "donors": len(donors),
        "surfaces": len(surfaces),
        "directories": len(directories),
        "modules": len(modules),
        "symbols": len(symbols),
        "nested_archives": len(nested),
        "ledger": len(ledger),
        "roots": sum(r["record_id"].startswith("PR160-M") for r in ledger),
        "categories": sum(r["record_id"].startswith("PR160-C") for r in ledger),
        "fine": sum(r["record_id"].startswith("PR160-S") for r in ledger),
        "target_decisions": len(decisions),
        "hash_overlap_groups": len(overlaps),
        "capability_profiles": len(capabilities),
        "semantic_tags": len({tag for row in surfaces for tag in row.get("notes", "").removeprefix("semantic_tags=").split(";") if tag}),
        "baseline_files": len(baseline_rows),
    }
    for key, value in counts.items():
        require(errors, value == EXPECTED[key], f"{key} count {value} != {EXPECTED[key]}")

    donor_names = {r["donor"] for r in donors}
    require(errors, donor_names == EXPECTED_DONORS, f"donor set mismatch: {sorted(donor_names ^ EXPECTED_DONORS)}")
    require(errors, len(donor_names) == len(donors), "duplicate donor summary row")
    require(errors, sum(int(r["file_surfaces"]) for r in donors) == EXPECTED["surfaces"], "donor surface rollup mismatch")
    require(errors, sum(int(r["directories"]) for r in donors) == EXPECTED["directories"], "donor directory rollup mismatch")
    require(errors, sum(int(r["symbols"]) for r in donors) == EXPECTED["symbols"], "donor symbol rollup mismatch")
    require(errors, sum(int(r["nested_archives"]) for r in donors) == EXPECTED["nested_archives"], "donor nested-archive rollup mismatch")
    require(errors, 0 < count_manifest_entries(donors) <= EXPECTED["modules"], "donor manifest summary is inconsistent with module inventory")

    ledger_ids = [r["record_id"] for r in ledger]
    ledger_set = set(ledger_ids)
    require(errors, len(ledger_set) == len(ledger_ids), "duplicate ledger record id")
    require(errors, {r["validation_status"] for r in ledger} <= FINAL_STATUS, "non-final ledger validation status remains")
    require(errors, all(r["disposition"] in VALID_DISPOSITIONS for r in ledger), "invalid ledger disposition remains")

    roots_by_donor: dict[str, str] = {}
    category_by_id: dict[str, dict[str, str]] = {}
    for row in ledger:
        rid = row["record_id"]
        if rid.startswith("PR160-M"):
            require(errors, row["donor"] not in roots_by_donor, f"duplicate donor root for {row['donor']}")
            roots_by_donor[row["donor"]] = rid
        elif rid.startswith("PR160-C"):
            category_by_id[rid] = row
        parent = row["parent_record_id"]
        if parent != "n/a":
            require(errors, parent in ledger_set, f"{rid}: unknown parent {parent}")
        for dep in [x for x in row.get("dependency_record_ids", "").split(";") if x and x != "n/a"]:
            require(errors, dep in ledger_set, f"{rid}: unknown dependency {dep}")
    require(errors, set(roots_by_donor) == EXPECTED_DONORS, "not every donor has exactly one root accountability record")

    surface_map: dict[tuple[str, str], dict[str, str]] = {}
    surface_ids_by_record: defaultdict[str, int] = defaultdict(int)
    for row in surfaces:
        key = (row["donor"], row["path"])
        require(errors, key not in surface_map, f"duplicate surface {key}")
        surface_map[key] = row
        require(errors, row["donor"] in EXPECTED_DONORS, f"surface unknown donor {key}")
        require(errors, bool(HEX64.fullmatch(row["sha256"])), f"invalid surface hash {key}")
        refs = [x for x in row.get("semantic_record_ids", "").split(";") if x]
        require(errors, len(refs) >= 2, f"surface lacks root plus semantic bucket {key}")
        expected_root = roots_by_donor.get(row["donor"])
        require(errors, expected_root in refs, f"surface lacks donor root record {key}")
        for rid in refs:
            require(errors, rid in ledger_set, f"surface {key}: unknown record {rid}")
            surface_ids_by_record[rid] += 1
        category_refs = [rid for rid in refs if rid.startswith("PR160-C")]
        require(errors, bool(category_refs), f"surface lacks category accountability {key}")
        for rid in category_refs:
            record = category_by_id.get(rid)
            require(errors, bool(record) and record["donor"] == row["donor"], f"surface category donor mismatch {key} -> {rid}")
    require(errors, len(surface_map) == EXPECTED["surfaces"], "surface map denominator mismatch")
    for donor, rid in roots_by_donor.items():
        require(errors, surface_ids_by_record[rid] > 0, f"root record has no linked surface {donor} {rid}")
    for rid in category_by_id:
        require(errors, surface_ids_by_record[rid] > 0, f"category record has no linked surface {rid}")

    fine = [r for r in ledger if r["record_id"].startswith("PR160-S")]
    require(errors, {r["record_id"] for r in fine} == {f"PR160-S{i:03d}" for i in range(1, 10)}, "fine record identity mismatch")
    require(errors, {r["disposition"] for r in fine} <= {"adapted", "hardened", "extracted", "recomposed", "inspired-native", "guardrail-derived"}, "fine record has non-adoption disposition")
    for row in fine:
        key = (row["donor"], row["donor_path"])
        surface = surface_map.get(key)
        require(errors, surface is not None, f"{row['record_id']}: donor surface missing {key}")
        if surface:
            require(errors, surface["sha256"] == row["donor_sha256"], f"{row['record_id']}: donor hash mismatch")
        require(errors, bool(HEX64.fullmatch(row["donor_sha256"])), f"{row['record_id']}: invalid donor hash")
        target_nodes = [x for x in row.get("target_nodes", "").split(";") if x and x != "n/a"]
        require(errors, bool(target_nodes), f"{row['record_id']}: no target ownership")
        for node in target_nodes:
            require(errors, anchor_exists(node), f"{row['record_id']}: target anchor missing {node}")
        tests = [x for x in row.get("test_node", "").split(";") if x and x != "n/a"]
        require(errors, bool(tests), f"{row['record_id']}: no acceptance evidence")
        for node in tests:
            require(errors, anchor_exists(node), f"{row['record_id']}: test/check anchor missing {node}")

    require(errors, {r["record_id"] for r in decisions} == {"PR160-T001", "PR160-T002", "PR160-T003", "PR160-T004"}, "target decision identity mismatch")
    for row in decisions:
        require(errors, anchor_exists(row["target_node"]), f"{row['record_id']}: target decision anchor missing {row['target_node']}")
        require(errors, anchor_exists(row["test_node"]), f"{row['record_id']}: target decision test anchor missing {row['test_node']}")
        require(errors, row["validation_status"] in FINAL_STATUS, f"{row['record_id']}: target decision validation status invalid")

    require(errors, {r["donor"] for r in directories} <= EXPECTED_DONORS, "directory inventory contains unknown donor")
    require(errors, {r["donor"] for r in modules} <= EXPECTED_DONORS, "module inventory contains unknown donor")
    require(errors, {r["donor"] for r in symbols} <= EXPECTED_DONORS, "symbol inventory contains unknown donor")
    require(errors, {r["donor"] for r in nested} <= EXPECTED_DONORS, "nested archive inventory contains unknown donor")
    require(errors, all(HEX64.fullmatch(r["manifest_sha256"]) for r in modules), "module manifest hash invalid")
    require(errors, all(HEX64.fullmatch(r["file_sha256"]) for r in symbols), "symbol source hash invalid")
    require(errors, all(HEX64.fullmatch(r["sha256"]) for r in nested), "nested archive hash invalid")

    config_src = text("src/apps/daemon/internal/foundation/config/config.go")
    require(errors, "DefaultMutationAttempts = 3" in config_src, "automatic mutation retry default is not 3")
    require(errors, "MaxMutationAttempts     = 8" in config_src, "automatic mutation retry cap is not 8")
    require(errors, "options.ExpectedRevision != nil" in config_src and "maxAttempts = 1" in config_src, "explicit mutation preconditions do not force one attempt")
    require(errors, "errors.Is(err, ErrRevisionConflict)" in config_src, "mutation retry is not conflict-specific")
    adapter = text("src/apps/daemon/internal/adapters/api/config_mutation.go")
    require(errors, "func commitConfigMutation" in adapter and "func configMutationOptions" in adapter, "HTTP mutation adapter ownership missing")
    require(errors, "X-LumiNet-Config-Mutation-Attempts" in adapter, "mutation attempt telemetry missing")

    per_app = text("src/apps/android/app/src/main/java/com/luminet/android/PerAppVpnPolicy.kt")
    require(errors, "MAX_PACKAGES = 256" in per_app, "Android per-app package bound missing")
    require(errors, "PerAppVpnMode.INCLUDE" in per_app and "PerAppVpnMode.EXCLUDE" in per_app, "Android per-app mode separation missing")
    underlay = text("src/apps/android/app/src/main/java/com/luminet/android/UnderlyingNetworkTracker.kt")
    require(errors, "NET_CAPABILITY_NOT_VPN" in underlay, "underlay tracker does not exclude VPN networks")
    require(errors, "registerNetworkCallback" in underlay and "setUnderlyingNetworks" in underlay, "passive underlay tracking missing")
    require(errors, "connectivity.requestNetwork(" not in underlay, "underlay tracker improperly holds a physical network")

    bridge = text("src/apps/daemon/internal/analysis/diagnostics/tor_bridge_probe.go")
    require(errors, "PlanTorBridgeProbe" in bridge and "fronted" in bridge and "netpolicy.IsPublicAddress" in bridge, "Tor bridge hardening anchors missing")
    public_policy = text("src/apps/daemon/internal/foundation/netpolicy/public_endpoint.go")
    require(errors, "func IsPublicAddress" in public_policy and "func IsDocumentationAddress" in public_policy, "shared public endpoint policy missing")

    iperf = text("src/apps/daemon/internal/analysis/diagnostics/iperf_probe.go")
    require(errors, "selectPublicIperfAddress" in iperf and '"-J"' in iperf, "real bounded iperf3 adapter/pinning missing")
    require(errors, "exec.CommandContext" in iperf, "iperf3 child is not context-bounded")
    iperf_api = text("src/apps/daemon/internal/adapters/api/handlers_diagnostic_iperf.go")
    require(errors, "IPERF_AUTHORIZATION_REQUIRED" in iperf_api and "AuthorizationConfirmed" in iperf_api, "iperf per-operation authorization missing")

    stun = text("src/apps/daemon/internal/analysis/diagnostics/stun_nat_probe.go")
    require(errors, '"endpoint-independent"' in stun and '"endpoint-dependent-or-port-dependent"' in stun and '"unknown"' in stun, "STUN claim vocabulary changed")
    for forbidden in ["full-cone", "restricted-cone", "symmetric-nat"]:
        require(errors, forbidden not in stun.lower(), f"STUN diagnostic overclaims {forbidden}")

    profile = text("src/apps/daemon/internal/integrations/sub/profile_service.go")
    egress = text("src/apps/daemon/internal/integrations/sub/egress.go")
    require(errors, "SourceValidatorsByURL" in profile and "FetchConditional" in profile, "subscription conditional refresh state missing")
    require(errors, "normalizeSourceETag" in egress and "If-None-Match" in egress, "subscription ETag admission missing")
    require(errors, "netpolicy.IsPublicAddress" in egress, "subscription egress no longer shares public endpoint policy")

    post141 = text("scripts/checks/check_post_refactor_141_convergence.py")
    require(errors, "post-refactor-160-baseline-files.csv" in post141, "post-141 historical checker is not frozen at post-160 baseline")
    final_checker = text("scripts/checks/check_final_convergence.py")
    ultimate_checker = text("scripts/checks/check_ultimate_convergence.py")
    require(errors, "commitConfigMutation" in final_checker and "configMutationOptions" in final_checker, "final convergence checker lacks mutation successor anchors")
    require(errors, "commitConfigMutation" in ultimate_checker and "configMutationOptions" in ultimate_checker, "ultimate convergence checker lacks mutation successor anchors")

    make = text("Makefile")
    require(errors, "check_post_refactor_160_convergence.py" in make, "Makefile missing post-160 convergence gate")
    require(errors, "check_post_refactor_141_convergence.py" in make, "Makefile lost post-141 convergence gate")

    baseline = {r["path"]: (r["file_type"], r["sha256"], r["link_target"]) for r in baseline_rows}
    require(errors, len(baseline) == EXPECTED["baseline_files"], "duplicate post-160 baseline path")
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
        require(errors, bool(path) and path not in delta, f"duplicate/empty target delta path {path!r}")
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
        print(
            f"{P} convergence: donors={len(donors)} surfaces={len(surfaces)} "
            f"directories={len(directories)} modules={len(modules)} symbols={len(symbols)} "
            f"records={len(ledger)} fine={len(fine)} delta={len(delta_rows)} errors={len(errors)}"
        )
        for error in errors[:500]:
            print("ERROR:", error)
        return 1

    print(
        f"{P} convergence: donors={len(donors)} surfaces={len(surfaces)} "
        f"directories={len(directories)} modules={len(modules)} symbols={len(symbols)} "
        f"records={len(ledger)} fine={len(fine)} overlaps={len(overlaps)} delta={len(delta_rows)} errors=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
