#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance" / "convergence"
P = "post-refactor-180"
DELTA_REL = f"governance/convergence/{P}-target-delta.csv"
SUCCESSOR_BASELINE = G / "post-refactor-220-baseline-files.csv"
HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED = {
    "donors": 20,
    "surfaces": 6232,
    "directories": 1290,
    "modules": 125,
    "symbols": 36779,
    "nested_file_payloads": 142,
    "symlinks": 2,
    "ledger": 289,
    "roots": 20,
    "categories": 245,
    "fine": 24,
    "baseline_files": 2791,
    "skill_inventory_non_git_surfaces": 6202,
}

EXPECTED_DONORS = {
    "IPRadar2ForLinux",
    "SNI-Spoofing-Go",
    "SNI-Spoofing-Pro",
    "Sanaei-3xui-v2ray",
    "Scrapling",
    "Shin-TG-V2ray-Collector",
    "Throne",
    "V2RayDAR",
    "Vwarp",
    "WarpScanner",
    "Yacd-meta",
    "gotk4",
    "ipscan",
    "libcrafter",
    "mylg",
    "obfuscated-openssh",
    "okhttp",
    "subconverter",
    "tailscale-rs",
    "tsidp",
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
IMPLEMENTED_DISPOSITIONS = {
    "adopted",
    "adapted",
    "hardened",
    "extracted",
    "recomposed",
    "synthesized",
    "inspired-native",
    "guardrail-derived",
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
    # Historical post-180 evidence is immutable. Once a successor wave exists,
    # compare post-180 against that successor's frozen pre-change snapshot
    # rather than today's descendant source tree.
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
    if not path.is_file():
        return False
    return anchor in path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    errors: list[str] = []
    try:
        donors = read_csv(f"{P}-new-donors.csv")
        archives = read_csv(f"{P}-archive-safety.csv")
        surfaces = read_csv(f"{P}-surface-accountability.csv")
        directories = read_csv(f"{P}-directories.csv")
        modules = read_csv(f"{P}-modules.csv")
        symbols = read_csv(f"{P}-symbols.csv")
        nested = read_csv(f"{P}-nested-archive-contents.csv")
        ledger = read_csv(f"{P}-adoption-ledger.csv")
        licenses = read_csv(f"{P}-license-map.csv")
        capabilities = read_csv(f"{P}-capability-counts.csv")
        baseline_rows = read_csv(f"{P}-baseline-files.csv")
        delta_rows = read_csv(f"{P}-target-delta.csv")
        summary = json.loads((G / f"{P}-summary.json").read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"{P} convergence: load failure: {exc}")
        return 1

    counts = {
        "donors": len(donors),
        "surfaces": len(surfaces),
        "directories": len(directories),
        "modules": len(modules),
        "symbols": len(symbols),
        "nested_file_payloads": len(nested),
        "symlinks": sum(r.get("file_type") == "symlink" for r in surfaces),
        "ledger": len(ledger),
        "roots": sum(r["record_id"].startswith("PR180-M") for r in ledger),
        "categories": sum(r["record_id"].startswith("PR180-C") for r in ledger),
        "fine": sum(r["record_id"].startswith("PR180-S") for r in ledger),
        "baseline_files": len(baseline_rows),
        "skill_inventory_non_git_surfaces": int(summary.get("skill_inventory_non_git_surfaces", -1)),
    }
    summary_keys = {
        "ledger": "ledger_records",
        "roots": "root_records",
        "categories": "category_records",
        "fine": "fine_records",
    }
    for key, expected in EXPECTED.items():
        require(errors, counts[key] == expected, f"{key} count {counts[key]} != {expected}")
        summary_key = summary_keys.get(key, key)
        require(errors, int(summary.get(summary_key, -1)) == expected, f"summary {summary_key} {summary.get(summary_key)!r} != {expected}")

    donor_names = {r["donor"] for r in donors}
    require(errors, donor_names == EXPECTED_DONORS, f"donor set mismatch: {sorted(donor_names ^ EXPECTED_DONORS)}")
    require(errors, len(archives) == EXPECTED["donors"], f"archive safety rows {len(archives)} != {EXPECTED['donors']}")
    require(errors, {r["donor"] for r in archives} == EXPECTED_DONORS, "archive safety donor set mismatch")
    require(errors, all(HEX64.fullmatch(r["sha256"]) for r in archives), "archive safety contains invalid SHA-256")
    require(errors, sum(int(r["regular_files"]) for r in archives) == EXPECTED["surfaces"] - EXPECTED["symlinks"], "archive regular-file rollup mismatch")
    require(errors, sum(int(r["symlinks"]) for r in archives) == EXPECTED["symlinks"], "archive symlink rollup mismatch")
    require(errors, max(float(r["ratio"]) for r in archives) < 10.0, "archive expansion-ratio admission bound changed unexpectedly")
    archive_hash_by_donor = {r["donor"]: r["sha256"] for r in archives}
    for row in donors:
        require(errors, archive_hash_by_donor.get(row["donor"]) == row["archive_sha256"], f"{row['donor']}: donor/archive safety hash mismatch")
    require(errors, len(donor_names) == len(donors), "duplicate donor summary row")
    for field, expected in [
        ("file_surfaces", EXPECTED["surfaces"]),
        ("directories", EXPECTED["directories"]),
        ("manifests", EXPECTED["modules"]),
        ("symbols", EXPECTED["symbols"]),
        ("nested_file_payloads", EXPECTED["nested_file_payloads"]),
        ("symlinks", EXPECTED["symlinks"]),
    ]:
        require(errors, sum(int(r[field]) for r in donors) == expected, f"donor {field} rollup mismatch")

    require(errors, {r["donor"] for r in directories} <= EXPECTED_DONORS, "directory inventory contains unknown donor")
    require(errors, {r["donor"] for r in modules} <= EXPECTED_DONORS, "module inventory contains unknown donor")
    require(errors, {r["donor"] for r in symbols} <= EXPECTED_DONORS, "symbol inventory contains unknown donor")
    require(errors, {r["donor"] for r in nested} <= EXPECTED_DONORS, "nested archive inventory contains unknown donor")
    require(errors, all(HEX64.fullmatch(r["sha256"]) for r in modules), "module manifest hash invalid")
    require(errors, all(HEX64.fullmatch(r["file_sha256"]) for r in symbols), "symbol source hash invalid")
    require(errors, all(HEX64.fullmatch(r["sha256"]) for r in nested), "nested payload hash invalid")

    # The semantic profile and exact surface denominators are intentionally
    # different: capability rows are donor/classification rollups, not files.
    cap_total = sum(int(r["surfaces"]) for r in capabilities)
    require(errors, cap_total == EXPECTED["surfaces"], f"capability surface rollup {cap_total} != {EXPECTED['surfaces']}")
    require(errors, {r["donor"] for r in capabilities} == EXPECTED_DONORS, "capability profiles do not cover all donors")

    ledger_ids = [r["record_id"] for r in ledger]
    ledger_set = set(ledger_ids)
    require(errors, len(ledger_set) == len(ledger_ids), "duplicate ledger record id")
    require(errors, {r["validation_status"] for r in ledger} <= FINAL_STATUS, "non-final ledger validation status remains")
    require(errors, all(r["disposition"] in VALID_DISPOSITIONS for r in ledger), "invalid ledger disposition remains")

    roots_by_donor: dict[str, str] = {}
    category_by_id: dict[str, dict[str, str]] = {}
    for row in ledger:
        rid = row["record_id"]
        if rid.startswith("PR180-M"):
            require(errors, row["donor"] not in roots_by_donor, f"duplicate donor root for {row['donor']}")
            roots_by_donor[row["donor"]] = rid
        elif rid.startswith("PR180-C"):
            category_by_id[rid] = row
        parent = row.get("parent_record_id", "")
        if parent and parent != "n/a":
            require(errors, parent in ledger_set, f"{rid}: unknown parent {parent}")
        for dep in [x.strip() for x in row.get("dependency_record_ids", "").split(";") if x.strip() and x.strip() != "n/a"]:
            require(errors, dep in ledger_set, f"{rid}: unknown dependency {dep}")
    require(errors, set(roots_by_donor) == EXPECTED_DONORS, "not every donor has exactly one root accountability record")

    surface_map: dict[tuple[str, str], dict[str, str]] = {}
    links_by_record: defaultdict[str, int] = defaultdict(int)
    for row in surfaces:
        key = (row["donor"], row["path"])
        require(errors, key not in surface_map, f"duplicate surface {key}")
        surface_map[key] = row
        require(errors, row["donor"] in EXPECTED_DONORS, f"surface unknown donor {key}")
        require(errors, bool(HEX64.fullmatch(row["sha256"])), f"invalid surface hash {key}")
        refs = [x.strip() for x in row.get("semantic_record_ids", "").split(";") if x.strip()]
        root_refs = [rid for rid in refs if rid.startswith("PR180-M")]
        category_refs = [rid for rid in refs if rid.startswith("PR180-C")]
        require(errors, len(root_refs) == 1, f"surface must have exactly one donor root {key}: {root_refs}")
        require(errors, len(category_refs) == 1, f"surface must have exactly one semantic category {key}: {category_refs}")
        require(errors, roots_by_donor.get(row["donor"]) in root_refs, f"surface donor root mismatch {key}")
        for rid in refs:
            require(errors, rid in ledger_set, f"surface {key}: unknown record {rid}")
            links_by_record[rid] += 1
        for rid in category_refs:
            category = category_by_id.get(rid)
            require(errors, category is not None and category["donor"] == row["donor"], f"surface category donor mismatch {key} -> {rid}")
    require(errors, len(surface_map) == EXPECTED["surfaces"], "surface denominator mismatch")
    symlinks = {(r["donor"], r["path"]): r for r in surfaces if r.get("file_type") == "symlink"}
    expected_symlinks = {
        ("libcrafter", ".claude/skills"): "link_target=../.agents/skills",
        ("libcrafter", "CLAUDE.md"): "link_target=AGENTS.md",
    }
    require(errors, set(symlinks) == set(expected_symlinks), f"symlink surface set mismatch: {sorted(set(symlinks) ^ set(expected_symlinks))}")
    for key, expected_note in expected_symlinks.items():
        if key in symlinks:
            require(errors, symlinks[key].get("notes") == expected_note, f"symlink target drift {key}: {symlinks[key].get('notes')!r}")
    for donor, rid in roots_by_donor.items():
        require(errors, links_by_record[rid] > 0, f"root record has no linked surface {donor} {rid}")
    for rid in category_by_id:
        require(errors, links_by_record[rid] > 0, f"category record has no linked surface {rid}")

    fine = [r for r in ledger if r["record_id"].startswith("PR180-S")]
    require(errors, {r["record_id"] for r in fine} == {f"PR180-S{i:03d}" for i in range(1, 25)}, "fine record identity mismatch")
    for row in fine:
        rid = row["record_id"]
        key = (row["donor"], row["donor_path"])
        source = surface_map.get(key)
        require(errors, source is not None, f"{rid}: exact donor source missing {key}")
        if source:
            require(errors, source["sha256"] == row["donor_sha256"], f"{rid}: donor hash mismatch")
            refs = [x.strip() for x in source.get("semantic_record_ids", "").split(";") if x.strip()]
            require(errors, rid in refs, f"{rid}: exact donor source lacks fine-record backlink")
        require(errors, bool(HEX64.fullmatch(row["donor_sha256"])), f"{rid}: invalid donor hash")
        targets = [x.strip() for x in row.get("target_nodes", "").split(";") if x.strip() and x.strip() != "n/a"]
        tests = [x.strip() for x in row.get("test_node", "").split(";") if x.strip() and x.strip() != "n/a"]
        if row["disposition"] in IMPLEMENTED_DISPOSITIONS:
            require(errors, bool(targets), f"{rid}: implemented/derived record has no target ownership")
            require(errors, bool(tests), f"{rid}: implemented/derived record has no acceptance evidence")
        if row["disposition"] in {"superseded", "rejected-with-reason", "guardrail-derived"}:
            require(errors, bool(tests), f"{rid}: disposition has no acceptance/decision evidence")
        for node in targets:
            require(errors, anchor_exists(node), f"{rid}: target anchor missing {node}")
        for node in tests:
            require(errors, anchor_exists(node), f"{rid}: test/check anchor missing {node}")

    license_by_donor = {r["donor"]: r for r in licenses}
    require(errors, set(license_by_donor) == EXPECTED_DONORS, "license map donor coverage mismatch")
    for donor, row in license_by_donor.items():
        restricted = row["license"].startswith(("GPL", "AGPL", "unknown"))
        if restricted:
            require(errors, row["direct_source_reuse"] == "no", f"{donor}: restricted/unclear license does not prohibit direct reuse")

    # Source-level convergence invariants. These deliberately test mechanism
    # shape, not only the presence of evidence rows.
    config_src = text("src/apps/daemon/internal/foundation/config/config.go")
    require(errors, "DefaultMutationAttempts = 3" in config_src and "MaxMutationAttempts     = 8" in config_src, "post-160 automatic mutation retry bounds missing")
    require(errors, "options.ExpectedRevision != nil" in config_src and "maxAttempts = 1" in config_src, "explicit config revision no longer forces one attempt")
    require(errors, "errors.Is(err, ErrRevisionConflict)" in config_src, "configuration mutation retry is no longer conflict-specific")
    mutation_adapter = text("src/apps/daemon/internal/adapters/api/config_mutation.go")
    require(errors, "func configMutationOptions" in mutation_adapter and "func commitConfigMutation" in mutation_adapter, "post-160 mutation adapter ownership missing")

    egress = text("src/apps/daemon/internal/integrations/sub/egress.go")
    require(errors, "maxSubscriptionRedirects         = 10" in egress, "subscription redirect cap is not 10")
    require(errors, "len(via) >= maxSubscriptionRedirects" in egress, "subscription redirect cap is not enforced")
    require(errors, "subscriptionRedirectIdentity" in egress and "ErrSubscriptionRedirectLimit" in egress, "subscription redirect loop identity/rejection missing")
    require(errors, 'req.Header.Del("If-None-Match")' in egress, "cross-origin conditional validator stripping missing")
    egress_tests = text("src/apps/daemon/internal/integrations/sub/egress_test.go")
    require(errors, "TestEgressRedirectPolicyRestoresFiniteBudget" in egress_tests and "TestEgressRedirectPolicyRejectsLoop" in egress_tests, "redirect budget/loop tests missing")

    profile = text("src/apps/daemon/internal/integrations/sub/profile_service.go")
    require(errors, "profileSourceRetryAfterCap = 24 * time.Hour" in profile, "Retry-After cap is not 24 hours")
    require(errors, "func sourceRetryAfterDelay" in profile and "func (s *ProfileService) recordSourceFailureWithMinimumDelay" in profile, "Retry-After/backoff ownership missing")
    profile_tests = text("src/apps/daemon/internal/integrations/sub/profile_source_health_test.go")
    require(errors, "TestSourceRetryAfterDelayParsesAndBoundsServerHints" in profile_tests and "TestRecordSourceFailureHonorsServerMinimumDelay" in profile_tests, "Retry-After tests missing")

    diagnostics = text("src/apps/daemon/internal/analysis/diagnostics/diagnostics.go")
    trace = text("src/apps/daemon/internal/analysis/diagnostics/trace_route.go")
    trace_tests = text("src/apps/daemon/internal/analysis/diagnostics/trace_route_test.go")
    require(errors, "return runPlatformTraceRoute(ctx, job, result)" in diagnostics, "diagnostics still owns or bypasses the platform traceroute seam")
    require(errors, 'exec.LookPath("traceroute")' in trace and 'exec.LookPath("tracert")' in trace, "truthful traceroute platform backends missing")
    require(errors, "exec.CommandContext" in trace and "maxTraceOutputBytes" in trace and "maxTraceMaxHops" in trace, "traceroute bounds/context execution missing")
    require(errors, 'strings.ContainsAny(target, "/\\\\?#")' in trace, "traceroute URL/path-shaped target rejection missing")
    require(errors, "TestNormalizeTraceTargetRejectsOptionLikeAndPathTargets" in trace_tests and "TestParseTraceRouteOutputPreservesLossJitterAndLoadBalancing" in trace_tests, "traceroute negative/statistical tests missing")
    require(errors, "DialContext" not in diagnostics[diagnostics.find("func (p *Pipeline) runTraceRoute"): diagnostics.find("type arqUDPSender")], "old TCP-connect pseudo-traceroute survived in runTraceRoute")

    provider = text("src/apps/daemon/internal/analysis/provider/corpus.go")
    provider_tests = text("src/apps/daemon/internal/analysis/provider/corpus_test.go")
    require(errors, "ipv4Index        [33]map[netip.Addr]record" in provider and "ipv6Index        [129]map[netip.Addr]record" in provider, "immutable provider prefix indexes missing")
    require(errors, "func lookupPrefixIndex" in provider and "func (s *Snapshot) indexRecord" in provider, "provider LPM index ownership missing")
    require(errors, "TestSnapshotPrefixIndexMatchesReferenceLinearLookup" in provider_tests, "provider index differential test missing")

    warp = text("src/apps/daemon/internal/runtime/warp/warp_scanner.go")
    warp_tests = text("src/apps/daemon/internal/runtime/warp/warp_scanner_test.go")
    require(errors, "Jitter             time.Duration" in warp and "func meanAbsoluteRTTDelta" in warp, "WARP temporal jitter metric missing")
    require(errors, "results[i].Jitter != results[j].Jitter" in warp, "WARP ranking no longer discriminates same-loss endpoints by jitter")
    require(errors, "TestWarpScannerRanksJitterBeforeMedianLatencyWhenLossMatches" in warp_tests, "WARP jitter ranking test missing")

    rust_ip = text("src/packages/lumicore/src/transport/ip_packet.rs")
    require(errors, "if total_len < ihl" in rust_ip and "if buf.len() < total_len" in rust_ip, "Rust IPv4 declared-length guards missing")
    require(errors, "let total_len = Ipv6Header::LEN + payload_len" in rust_ip and "&buf[Ipv6Header::LEN..total_len]" in rust_ip, "Rust IPv6 declared-length slice missing")
    for name in ["rejects_truncated_ipv4_declared_length", "ipv4_payload_stops_at_declared_total_length", "rejects_truncated_ipv6_declared_payload", "ipv6_payload_stops_at_declared_payload_length"]:
        require(errors, name in rust_ip, f"Rust IP parser regression test missing {name}")

    packet_ip = text("src/apps/daemon/internal/platform/system/nat/packet_ip.go")
    require(errors, "headerLen <= totalLen" in packet_ip and "int(totalLen) <= len(p)" in packet_ip, "Go IPv4 packet declared-length validity guards missing")
    defrag = text("src/apps/daemon/internal/platform/system/nat/packet_defrag.go")
    defrag_tests = text("src/apps/daemon/internal/platform/system/nat/packet_defrag_test.go")
    require(errors, "defaultDefragMaxFlows = 256" in defrag and "ErrConflictingFragment" in defrag, "bounded/conflict-aware defragmentation missing")
    require(errors, "received    []byte" in defrag and "bitmapRangeComplete" in defrag and "evictOldest" in defrag, "offset-aware bounded reassembly state missing")
    for name in ["TestIPv4DefragmenterRejectsConflictingOverlapAndDropsFlow", "TestIPv4DefragmenterOutOfOrderUsesFirstFragmentHeader", "TestIPv4DefragmenterEvictsOldestAtFlowBound", "TestIPv4DefragmenterUsesDatagramPayloadLimitNotCurrentFragmentIHL"]:
        require(errors, name in defrag_tests, f"defragmenter regression test missing {name}")

    post160 = text("scripts/checks/check_post_refactor_160_convergence.py")
    require(errors, "post-refactor-180-baseline-files.csv" in post160, "post-160 historical checker is not frozen to the post-180 successor baseline")
    make = text("Makefile")
    require(errors, "check_post_refactor_180_convergence.py" in make, "Makefile missing post-180 convergence gate")
    require(errors, "check_post_refactor_220_convergence.py" in make, "Makefile missing post-220 convergence gate")
    require(errors, SUCCESSOR_BASELINE.is_file(), "post-180 historical checker is not frozen to the post-220 successor baseline")
    require(errors, "check_post_refactor_160_convergence.py" in make, "Makefile lost post-160 convergence gate")

    baseline = {r["path"]: (r["file_type"], r["sha256"], r.get("link_target", "n/a") or "n/a") for r in baseline_rows}
    require(errors, len(baseline) == EXPECTED["baseline_files"], "duplicate post-180 baseline path")
    require(errors, all(HEX64.fullmatch(v[1]) for v in baseline.values()), "invalid post-180 baseline hash")
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
        print(f"{P} convergence: FAIL ({len(errors)} errors)")
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    delta_counts = Counter(row["change_type"] for row in delta_rows)
    print(
        f"{P} convergence: PASS donors={counts['donors']} surfaces={counts['surfaces']} "
        f"directories={counts['directories']} modules={counts['modules']} symbols={counts['symbols']} "
        f"nested_file_payloads={counts['nested_file_payloads']} symlinks={counts['symlinks']} "
        f"ledger={counts['ledger']} fine={counts['fine']} delta={len(delta_rows)} "
        f"added={delta_counts['added']} modified={delta_counts['modified']} deleted={delta_counts['deleted']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
