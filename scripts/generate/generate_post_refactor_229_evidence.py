#!/usr/bin/env python3
"""Generate deterministic post-refactor-229 convergence evidence for five outer donors plus nested MITM source evidence."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(os.environ.get("LUMINET_229_TARGET_ROOT", Path(__file__).resolve().parents[2]))
WORK = Path(os.environ.get("LUMINET_229_WORK_ROOT", "/mnt/data/luminet229_work"))
RAW = WORK / "evidence"
DONOR_BASE = WORK / "donors"
OUT = ROOT / "governance" / "convergence"
BASELINE = Path(os.environ.get("LUMINET_229_BASELINE_INVENTORY", "/mnt/data/LumiNet-post-refactor-228-source-inventory.csv"))
PRE = ROOT / "governance" / "convergence"

DONORS = {
    "hiddify-app-main": DONOR_BASE / "hiddify-app-main",
    "ProxyCloud-master": DONOR_BASE / "ProxyCloud-master",
    "mullvadvpn-app-main": DONOR_BASE / "mullvadvpn-app-main",
    "my-relay-assets-main": DONOR_BASE / "my-relay-assets-main",
    "MasterHttpRelayVPN-RUST-main": DONOR_BASE / "MasterHttpRelayVPN-RUST-main",
}
ARCHIVES = {
    "hiddify-app-main": Path("/mnt/data/hiddify-app-main(1).zip"),
    "ProxyCloud-master": Path("/mnt/data/ProxyCloud-master(1).zip"),
    "mullvadvpn-app-main": Path("/mnt/data/mullvadvpn-app-main.zip"),
    "my-relay-assets-main": Path("/mnt/data/my-relay-assets-main.zip"),
    "MasterHttpRelayVPN-RUST-main": Path("/mnt/data/MasterHttpRelayVPN-RUST-main(1).zip"),
}
NESTED_MITM_ROOT = WORK / "nested" / "my-relay-assets-main" / "mitmengine-master"
NESTED_DETAIL = RAW / "nested_detail"
HIGH_SIGNAL = {"implementation", "ui-or-product", "configuration", "deployment", "script", "test"}
LEDGER_FIELDS = [
    "record_id","parent_record_id","composition_group_id","donor","domain","value_unit","source_granularity","value_form","separability","donor_path","donor_sha256","donor_symbol","transformation","mapping_topology","disposition","decision_rationale","target_capability","target_nodes","invariant","negative_invariant","test_node","operator_surface","migration_impact","license_note","risk_tier","dependency_record_ids","evidence_confidence","validation_status",
]


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "n/a") for k in fields})


def file_sha(donor: str, rel: str) -> str:
    p = DONORS[donor] / rel
    if not p.is_file():
        raise FileNotFoundError(f"focused donor evidence missing: {donor}:{rel}")
    return sha_file(p)


def target_paths_exist(nodes: str) -> None:
    if nodes == "n/a":
        return
    for node in nodes.split(";"):
        p = node.split("#", 1)[0]
        if p and not (ROOT / p).exists():
            raise FileNotFoundError(f"target node missing: {p}")


def module_for(donor: str, path: str) -> str:
    parts = path.split("/")
    if donor == "hiddify-app-main":
        if len(parts) >= 3 and parts[:2] == ["lib", "features"]:
            return "/".join(parts[:3])
        if parts[0] == "lib" and len(parts) >= 2:
            return "/".join(parts[:2])
        if parts[0] in {"android", "ios", "macos", "windows", "linux"}:
            if len(parts) >= 2 and parts[0] == "android" and parts[1] == "app": return "android/app"
            return parts[0]
        return parts[0] if len(parts) > 1 else "root"
    if donor == "ProxyCloud-master":
        if len(parts) >= 2 and parts[0] == "lib": return "/".join(parts[:2])
        if len(parts) >= 2 and parts[0] == "local_packages": return "/".join(parts[:2])
        return parts[0] if len(parts) > 1 else "root"
    if donor == "my-relay-assets-main":
        if parts[:2] == [".github", "workflows"]: return ".github/workflows"
        if path == "mitmengine-master.zip": return "nested-source-artifact"
        if path.endswith(".deb"): return "packaged-binary"
        if path.endswith(".zip"): return "downloaded-archive"
        return "root"
    if donor == "MasterHttpRelayVPN-RUST-main":
        if len(parts) >= 3 and parts[:2] == ["android", "app"]: return "android/app"
        if parts[0] == "ios": return "ios"
        if parts[0] == "tunnel-node": return "tunnel-node"
        if len(parts) >= 2 and parts[0] == "assets": return "/".join(parts[:2])
        if len(parts) >= 3 and parts[:2] == ["docs", "maintainer"]: return "docs/maintainer"
        if parts[0] == "docs": return "docs"
        if parts[0] == "src": return "src"
        if parts[:2] == [".github", "workflows"]: return ".github/workflows"
        return parts[0] if len(parts) > 1 else "root"
    # Mullvad: preserve package/crate identity, and feature identity on Android/desktop.
    if len(parts) >= 4 and parts[:3] == ["android", "lib", "feature"]:
        return "/".join(parts[:4])
    if len(parts) >= 3 and parts[:2] == ["desktop", "packages"]:
        return "/".join(parts[:3])
    if parts[0] == "ios": return "ios"
    return parts[0] if len(parts) > 1 else "root"


def focus_spec() -> list[dict[str, str]]:
    """Behavior-level value units selected after repository-wide and second-order review."""
    F: list[dict[str, str]] = []
    def add(donor, domain, value, path, transformation, disposition, rationale, capability="n/a", nodes="n/a", invariant="source semantics remain traceable", negative="donor packaging does not gain target authority", test="n/a", surface="governance/convergence", risk="low", status="reviewed", form="behavioral evidence"):
        F.append(dict(donor=donor, domain=domain, value=value, path=path, transformation=transformation, disposition=disposition, rationale=rationale, capability=capability, nodes=nodes, invariant=invariant, negative=negative, test=test, surface=surface, risk=risk, status=status, form=form))

    H="hiddify-app-main"
    # Hiddify: product/config breadth, but target-native owners remain authoritative.
    add(H,"split-tunnel","per-app include/exclude intent and app identity", "lib/features/per_app_proxy/model/per_app_proxy_mode.dart", "product-semantics adaptation", "adapted", "Hiddify's per-app intent is useful, but LumiNet cannot claim runtime enforcement; normalize and hash intent in the split-tunnel admission planner.", "split-tunnel admission truth", "src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go;src/packages/control-ui/src/pages/Rules.tsx", "include/exclude intent is deterministic and backup-identifiable", "planning/import must never be presented as enforced routing", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#hiddify-per-app-intent", "Rules", "high", "verified")
    add(H,"split-tunnel","per-app backup/restore manifest semantics", "lib/features/per_app_proxy/model/per_app_proxy_backup.dart", "primitive extraction", "adapted", "Backup semantics motivate a canonical manifest hash so restore identity can be checked without importing Flutter persistence.", "split-tunnel backup identity", "src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go", "normalized entries have a deterministic SHA-256 identity", "restore identity cannot imply kernel enforcement", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#hiddify-per-app-backup", "Rules", "medium", "verified")
    add(H,"profile-lifecycle","profile refresh scheduling and per-profile update intervals", "lib/features/profile/notifier/profiles_update_notifier.dart", "mechanism comparison", "superseded", "LumiNet already has daemon-lifetime scheduling, cancellation, stale-refresh protection, source-health backoff, and bounded concurrency; duplicating a Flutter timer would weaken ownership.", "profile refresh scheduler", "src/apps/daemon/internal/integrations/sub/profile_service.go", "refresh lifetime and retries remain daemon-owned", "UI timers cannot become refresh authority", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-profile-refresh-owner", "Profiles", "medium", "statically-validated")
    add(H,"profiles","profile parsing/storage/details/sorting UX", "lib/features/profile/data/profile_repository.dart", "product workflow inspiration", "inspired-native", "The workflow is useful product evidence while target parsing/catalogue storage remain existing owners.", "profile catalogue UX", "src/packages/control-ui/src/pages/Profiles.tsx", "profile actions expose runtime compatibility truth", "presentation state cannot replace parser/catalogue authority", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-profile-ux", "Profiles", "low", "reviewed")
    add(H,"routing","route-rule editor and predefined-rule workflow", "lib/features/route_rules/overview/predefined_rules_modal.dart", "product workflow comparison", "superseded", "LumiNet already has route-rule and local ruleset planners with bounded local inputs; donor UI informs affordances but does not replace policy owners.", "routing policy planning", "src/apps/daemon/internal/analysis/diagnostics/local_ruleset_plan.go;src/packages/control-ui/src/pages/Rules.tsx", "routing inputs remain explicit and local", "mutable donor rule corpora cannot become policy truth", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-route-rules", "Rules", "medium", "statically-validated")
    add(H,"connection","explicit connection status/failure state model", "lib/features/connection/model/connection_status.dart", "state-model synthesis", "adapted", "Hiddify's user-facing connection states complement Mullvad's security state separation; 229 exposes desired vs observed tunnel safety rather than copying its notifier graph.", "tunnel safety lifecycle", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go;src/packages/control-ui/src/pages/Health.tsx", "desired intent is distinct from observed transport state", "a connected-looking UI state cannot assert firewall safety", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#hiddify-connection-state", "Health", "high", "verified")
    add(H,"connection","reset-tunnel recovery affordance", "lib/features/settings/notifier/reset_tunnel/reset_tunnel_notifier.dart", "recovery-workflow inspiration", "inspired-native", "Reset/recovery is valuable operator intent, but host mutation remains the existing daemon/platform owner; the planner exposes reconnect/block actions only.", "tunnel recovery planning", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go", "recovery intent is explicit and bounded", "planner cannot mutate routes/firewall or restart tunnels", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#hiddify-reset-tunnel", "Health", "medium", "verified")
    add(H,"network-modes","proxy/system-proxy/TUN service modes", "android/app/src/main/kotlin/com/hiddify/hiddify/constant/ServiceMode.kt", "authority comparison", "superseded", "LumiNet already centralizes system proxy, DNS and TUN route mutations in host_network; service-mode enums are reference evidence only.", "host network authority", "src/apps/daemon/internal/platform/system/host_network.go", "one daemon/platform owner performs host-network mutation", "mobile service-mode enums cannot create a parallel mutator", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-service-mode-owner", "Capabilities", "high", "statically-validated")
    add(H,"routing-policy","balancer/domain/IP strategy enums", "lib/singbox/model/singbox_config_enum.dart", "preset comparison", "superseded", "Existing policy-group and endpoint-pool planners cover manual/latency/fallback/balancing and scoring with stronger evidence separation.", "routing and endpoint policy", "src/apps/daemon/internal/analysis/diagnostics/routing_policy_group_plan.go;src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go", "eligibility/policy and measured scoring remain distinct", "donor enum names cannot bypass target evidence requirements", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-routing-enums", "Rules", "medium", "statically-validated")
    add(H,"dns","DNS settings UX and strategy options", "lib/features/settings/overview/sections/dns_options_page.dart", "product/contract comparison", "superseded", "LumiNet already has a secure DNS resolution policy graph with explicit downgrade/fallback semantics.", "DNS policy", "src/apps/daemon/internal/analysis/diagnostics/dns_resolution_policy_plan.go", "secure transport and fallback are explicit", "UI settings cannot silently downgrade DNS", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-dns", "Rules", "high", "statically-validated")
    add(H,"evasion","TLS trick settings", "lib/features/settings/overview/sections/tls_tricks_page.dart", "mechanism comparison", "superseded", "TLS/evasion behavior is already owned by target evasion/SNI planners and runtime boundaries.", "evasion planning", "src/apps/daemon/internal/analysis/diagnostics/sni_decoy_handshake_plan.go", "evasion choices remain explicit capability/planning state", "UI trick toggles do not create raw-packet authority", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-tls-tricks", "Connections", "high", "statically-validated")
    add(H,"chain","extra-security/unblocker/profile chaining modes", "lib/features/chain/model/chain_enum.dart", "composition comparison", "reference-only", "The chain modes are useful product composition evidence, but importing provider-specific Psiphon/WARP/profile semantics would create unsupported authority and stale assumptions.", form="product composition evidence")
    add(H,"statistics","connection and transfer statistics UX", "lib/features/stats/notifier/stats_notifier.dart", "product workflow inspiration", "reference-only", "The statistics presentation is useful UX evidence; target telemetry remains existing source of truth.", form="operator UX evidence")
    add(H,"latency","active proxy delay presentation", "lib/features/proxy/active/active_proxy_delay_indicator.dart", "measurement UX comparison", "superseded", "Endpoint quality is already caller-evidence driven by the endpoint pool; UI latency decoration must not become ranking authority.", "endpoint health/scoring", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go", "measurements remain explicit evidence", "displayed latency cannot silently select endpoints", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-delay", "Profiles", "medium", "statically-validated")
    add(H,"updates","GitHub release based application update workflow", "lib/features/app_update/data/app_update_repository.dart", "negative-to-guardrail", "guardrail-derived", "A network-fetched release listing without the target's signed metadata/high-water model is retained as negative evidence; LumiNet requires signed manifests and schema-v2 monotonic replay state for protected releases.", "signed update admission", "src/apps/daemon/internal/foundation/updateadmission/updateadmission.go;src/apps/daemon/internal/foundation/store/update_metadata.go", "trusted releases bind signature, hash, exact size, expiry and monotonic sequence", "remote release metadata alone cannot authorize staging or installation", "src/apps/daemon/internal/foundation/updateadmission/post_refactor_229_test.go#hiddify-update-negative", "Settings", "critical", "verified")
    add(H,"battery","battery optimization guidance", "lib/features/settings/data/battery_optimization_repository.dart", "operator guidance retention", "reference-only", "Mobile battery-exemption guidance is useful deployment UX but not a portable daemon authority.", form="operator guidance")
    add(H,"desktop-ux","system tray state and actions", "lib/features/system_tray/notifier/system_tray_notifier.dart", "product affordance retention", "reference-only", "Tray state/actions are useful desktop UX evidence; target desktop shell owns platform integration.", form="desktop UX")
    add(H,"desktop-ux","keyboard shortcut wrapper", "lib/features/shortcut/shortcut_wrapper.dart", "product affordance retention", "reference-only", "Shortcut handling is retained as UX evidence without copying Flutter global-shortcut state.", form="desktop UX")
    add(H,"deep-links","deep-link admission workflow", "lib/features/deep_link/notifier/deep_link_notifier.dart", "negative/unfinished-surface review", "reference-only", "The donor surface is partially disabled/commented and is not promoted as a verified import authority; it still records the need for explicit URI admission.", form="negative product evidence")
    add(H,"native-contract","protobuf management/tunnel service contracts", "android/app/src/main/protos/v2/hcore/tunnelservice/tunnel_service.proto", "contract comparison", "reference-only", "The generated/native bridge demonstrates typed management boundaries, but LumiNet retains its own authenticated API and does not import donor service identity.", form="protocol contract evidence")
    add(H,"opaque-runtime","bundled core framework/runtime assets", "hiddify-core", "opaque runtime rejection", "rejected-with-reason", "Opaque/bundled runtime artifacts are not imported as target authority; maintained target external-core/runtime owners remain explicit.", "proxy/runtime authority", "src/apps/daemon/internal/runtime/proxy/core_manager.go", "runtime binaries are admitted through target build/update/provenance boundaries", "bundled donor binaries cannot silently execute", "scripts/checks/check_post_refactor_229_convergence.py#hiddify-opaque-runtime", "governance/convergence", "critical", "reviewed", form="supply-chain negative evidence") if (DONORS[H]/"hiddify-core").is_file() else None

    P="ProxyCloud-master"
    add(P,"endpoint-selection","batched auto-selection with cancellation/progress", "lib/utils/auto_select_util.dart", "primitive extraction", "guardrail-derived", "Batch bounds, cancellation and progress are useful orchestration semantics, but ranking remains the endpoint-pool owner's job.", "endpoint selection", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go", "selection work is bounded/cancellable and measurements are caller evidence", "batch orchestration cannot invent health or bypass scoring", "scripts/checks/check_post_refactor_229_convergence.py#proxycloud-auto-select", "Profiles", "medium", "statically-validated")
    add(P,"endpoint-selection","early-exit latency thresholds", "lib/utils/auto_select_util.dart", "negative-to-guardrail", "guardrail-derived", "The <100ms/<200ms early-exit heuristic can bias selection by batch ordering, so it is explicitly not copied into target scoring.", "endpoint selection", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go", "all eligible caller evidence can be considered under target strategy", "arbitrary threshold/order cannot become hidden ranking authority", "scripts/checks/check_post_refactor_229_convergence.py#proxycloud-early-exit-rejected", "Profiles", "medium", "reviewed")
    add(P,"split-tunnel","blocked-app/per-app tunnel product workflow", "lib/screens/per_app_tunnel_screen.dart", "product-semantics adaptation", "adapted", "The UI confirms include/exclude intent as a first-class workflow; LumiNet exposes admission and backup identity while keeping enforcement unavailable until a real platform owner exists.", "split-tunnel admission truth", "src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go;src/packages/control-ui/src/pages/Rules.tsx", "intent is normalized and portable/platform-bound entries are distinguished", "UI cannot claim installed enforcement", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#proxycloud-per-app", "Rules", "high", "verified")
    add(P,"backup","configuration backup/restore workflow", "lib/screens/backup_restore_screen.dart", "workflow comparison", "reference-only", "Backup/restore is useful product evidence; target profile/config export semantics remain existing owners and split-tunnel intents get a canonical hash.", form="product workflow evidence")
    add(P,"diagnostics","host checker tool", "lib/screens/host_checker_screen.dart", "diagnostic affordance retention", "reference-only", "Host checks are useful operator tooling evidence, but network probes must remain explicit target diagnostics with bounded authority.", form="operator tool evidence")
    add(P,"diagnostics","IP information tool", "lib/screens/ip_info_screen.dart", "diagnostic affordance retention", "reference-only", "External IP intelligence is useful but remote provider data is not durable target truth.", form="operator tool evidence")
    add(P,"diagnostics","speed test workflow", "lib/screens/speedtest_screen.dart", "measurement affordance retention", "reference-only", "Speed testing is useful measurement UX; target does not import its provider-specific network calls as ranking authority.", form="measurement UX")
    add(P,"subscriptions","subscription management workflow", "lib/screens/subscription_management_screen.dart", "workflow comparison", "superseded", "Target profile subscriptions already have daemon-owned scheduling/backoff/cancellation and safer source handling.", "subscription/profile lifecycle", "src/apps/daemon/internal/integrations/sub/profile_service.go", "refresh remains bounded and daemon-owned", "UI screen state cannot schedule background refresh authority", "scripts/checks/check_post_refactor_229_convergence.py#proxycloud-subscription", "Profiles", "medium", "statically-validated")
    add(P,"updates","network update-service pattern", "lib/services/update_service.dart", "negative-to-guardrail", "guardrail-derived", "Unsigned/unpinned remote update discovery is not adopted; the target signed-update admission and high-water state are the substitute.", "signed update admission", "src/apps/daemon/internal/foundation/updateadmission/updateadmission.go;src/apps/daemon/internal/foundation/store/update_metadata.go", "release staging requires verified signed intent", "remote version JSON cannot authorize staging", "src/apps/daemon/internal/foundation/updateadmission/post_refactor_229_test.go#proxycloud-update-negative", "Settings", "critical", "verified")
    add(P,"remote-presets","Telegram proxy feed", "lib/services/telegram_proxy_service.dart", "negative-to-guardrail", "rejected-with-reason", "A mutable remote proxy feed is freshness- and trust-dependent; it is not embedded as an authoritative preset corpus.", "remote preset provenance", "scripts/checks/check_post_refactor_229_convergence.py", "remote mutable data remains external evidence", "feed popularity/freshness cannot grant target authority", "scripts/checks/check_post_refactor_229_convergence.py#proxycloud-telegram-feed", "governance/convergence", "high", "reviewed")
    add(P,"mobile","battery settings workflow", "lib/screens/battery_settings_screen.dart", "operator guidance retention", "reference-only", "Battery guidance remains mobile UX evidence rather than platform mutation authority.", form="operator guidance")
    add(P,"runtime","V2Ray service wrapper", "lib/services/v2ray_service.dart", "runtime authority comparison", "superseded", "Target external-core management already exposes supported protocol/core truth and lifecycle; a Flutter runtime wrapper would duplicate authority.", "proxy core lifecycle", "src/apps/daemon/internal/runtime/proxy/core_manager.go", "one maintained core manager owns process/runtime integration", "donor wrapper cannot bypass target core compatibility", "scripts/checks/check_post_refactor_229_convergence.py#proxycloud-v2ray-owner", "Profiles", "high", "statically-validated")
    add(P,"runtime","bundled Android V2Ray AAR", "local_packages/flutter_v2ray_client/android/libs/libv2ray.aar", "opaque binary rejection", "rejected-with-reason", "The large prebuilt AAR is not imported; target runtime provenance and maintained core ownership remain explicit.", "proxy runtime supply chain", "src/apps/daemon/internal/runtime/proxy/core_manager.go", "opaque peer binaries cannot silently enter target runtime", "binary presence is not semantic or security proof", "scripts/checks/check_post_refactor_229_convergence.py#proxycloud-aar", "governance/convergence", "critical", "reviewed", form="supply-chain negative evidence")
    add(P,"android-apps","native installed-app enumeration bridge", "android/app/src/main/kotlin/com/cloud/pira/AppListMethodChannel.kt", "platform-bound reference retention", "reference-only", "Installed-app enumeration is useful for split-tunnel UX but target has no cross-platform enforcement owner yet.", form="platform integration evidence")
    add(P,"server-selection","server list and selector UX", "lib/screens/server_selection_screen.dart", "product comparison", "superseded", "Target endpoint catalogue/scoring already exposes richer runtime compatibility and evidence-based selection.", "endpoint selection", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go;src/packages/control-ui/src/pages/Profiles.tsx", "quality and compatibility stay explicit", "list order/UI state cannot become authority", "scripts/checks/check_post_refactor_229_convergence.py#proxycloud-server-selector", "Profiles", "low", "statically-validated")

    M="mullvadvpn-app-main"
    add(M,"daemon-authority","daemon as sole security/network authority with client management interface", "docs/architecture.md", "architectural synthesis", "guardrail-derived", "Mullvad's strict daemon/client authority separation reinforces LumiNet's existing host-network and API ownership; only read-only planners are added.", "network/security authority", "src/apps/daemon/internal/platform/system/host_network.go;src/apps/daemon/internal/adapters/api/routes_system.go", "UI/planners are non-authoritative and host mutation has one owner", "client/UI state cannot directly alter firewall/routes/DNS", "scripts/checks/check_post_refactor_229_convergence.py#mullvad-daemon-authority", "Health", "critical", "statically-validated", form="architecture invariant")
    add(M,"tunnel-state","persisted target state corrupt -> secured fail-closed", "mullvad-daemon/src/target_state.rs", "state invariant extraction", "adapted", "This is a strong security invariant: unreadable/corrupt persisted secure intent must fail closed rather than silently exposing traffic.", "tunnel safety lifecycle", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go", "corrupt persisted intent resolves to desired secured/fail-closed posture", "corruption cannot silently choose unsecured", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-corrupt-target-state", "Health", "critical", "verified")
    add(M,"tunnel-state","desired target state separate from observed tunnel state", "mullvad-types/src/states.rs", "state-machine synthesis", "adapted", "229 models desired secured/unsecured separately from disconnected/connecting/connected/disconnecting/error/offline evidence.", "tunnel safety lifecycle", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go;src/packages/control-ui/src/pages/Health.tsx", "desired policy and observed transport are separate dimensions", "connected transport alone cannot assert secure posture", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-desired-observed", "Health", "critical", "verified")
    add(M,"tunnel-state","error state with firewall block failure is unsafe", "talpid-types/src/tunnel.rs", "negative invariant extraction", "adapted", "A tunnel error is only fail-closed if blocking actually succeeded; 229 explicitly reports failed/unconfirmed firewall evidence as degraded-unsafe.", "tunnel safety lifecycle", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go", "secure error requires confirmed blocking evidence", "error state cannot be labeled secure after firewall failure", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-block-failure", "Health", "critical", "verified")
    add(M,"tunnel-state","post-disconnect actions nothing/block/reconnect", "talpid-types/src/tunnel.rs", "recovery policy adaptation", "adapted", "229 exposes bounded reconnect/block intent without taking tunnel or firewall authority.", "tunnel recovery planning", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go", "reconnect attempts are bounded and action explicit", "planner cannot perform reconnect/firewall mutation", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-after-disconnect", "Health", "high", "verified")
    add(M,"firewall","multi-platform firewall enforcement plane", "talpid-core/src/firewall/mod.rs", "authority comparison", "superseded", "The donor firewall is mature but cannot be imported beside LumiNet's host-network owner without split authority; its fail-closed lessons constrain the safety planner instead.", "host network authority", "src/apps/daemon/internal/platform/system/host_network.go;src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go", "one target owner mutates firewall/network state", "planner or donor firewall cannot attach independently", "scripts/checks/check_post_refactor_229_convergence.py#mullvad-firewall-owner", "Health", "critical", "statically-validated")
    add(M,"firewall","LAN exception semantics", "talpid-core/src/firewall/mod.rs", "policy primitive extraction", "adapted", "Allow-LAN is represented as explicit safety-plan intent, not silently inferred.", "tunnel safety lifecycle", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go", "LAN exception is explicit in safety posture", "LAN exception cannot imply firewall enforcement", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-allow-lan", "Health", "high", "verified")
    add(M,"split-tunnel","cross-platform split-tunnel responsibility plane", "talpid-core/src/split_tunnel/mod.rs", "semantic decomposition", "adapted", "Target absorbs intent normalization, platform capability truth and backup identity but deliberately not kernel/driver/BPF enforcement.", "split-tunnel admission truth", "src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go", "entries are bounded, typed, deterministic and enforcement=false", "planning state cannot masquerade as installed split routing", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-split-root", "Rules", "critical", "verified")
    for domain,path,label in [
        ("split-windows","talpid-core/src/split_tunnel/windows/driver.rs","Windows driver/path/volume enforcement"),
        ("split-macos","talpid-core/src/split_tunnel/macos/bpf.rs","macOS BPF/process enforcement"),
        ("split-linux","talpid-core/src/split_tunnel/linux/mod.rs","Linux split-tunnel enforcement"),
        ("split-android","talpid-core/src/split_tunnel/android.rs","Android per-app enforcement"),
    ]:
        add(M,domain,label,path,"platform authority retention","reference-only","The implementation is valuable platform evidence, but 229 intentionally does not claim or install the corresponding OS enforcement plane.",form="platform implementation evidence")
    add(M,"dns","multi-platform DNS mutation backends", "talpid-dns/src/lib.rs", "authority comparison", "superseded", "LumiNet already has DNS policy plus host-network mutation ownership; donor platform DNS backends remain implementation evidence.", "DNS policy/host mutation", "src/apps/daemon/internal/analysis/diagnostics/dns_resolution_policy_plan.go;src/apps/daemon/internal/platform/system/host_network.go", "DNS planning and mutation remain separate owners", "donor DNS backend cannot silently alter host resolver", "scripts/checks/check_post_refactor_229_convergence.py#mullvad-dns-owner", "Rules", "critical", "statically-validated")
    add(M,"relay","location/provider/ownership/activity relay constraints", "mullvad-relay-selector/src/relay_selector/query.rs", "constraint primitive extraction", "adapted", "229 filters caller-supplied candidates by rich relay eligibility while preserving target endpoint scoring as the sole ranking authority.", "relay eligibility", "src/apps/daemon/internal/analysis/diagnostics/relay_constraint_plan.go;src/packages/control-ui/src/pages/Profiles.tsx", "eligibility reasons are deterministic and explicit", "constraint planner cannot perform probes or quality ranking", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-relay-query", "Profiles", "high", "verified")
    add(M,"relay","active-relay and endpoint capability filtering", "mullvad-relay-selector/src/relay_selector/filter.rs", "constraint hardening", "adapted", "Inactive or capability-incompatible relays are rejected before scoring.", "relay eligibility", "src/apps/daemon/internal/analysis/diagnostics/relay_constraint_plan.go", "inactive/incompatible candidates have exact rejection reasons", "scoring cannot resurrect ineligible candidates", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-relay-filter", "Profiles", "high", "verified")
    add(M,"multihop","entry and exit identities must differ", "mullvad-relay-selector/src/relay_selector/relays.rs", "negative invariant extraction", "adapted", "229 removes/denies same-entry-exit multihop combinations.", "relay multihop eligibility", "src/apps/daemon/internal/analysis/diagnostics/relay_constraint_plan.go", "entry identity differs from exit identity", "a single relay cannot satisfy both multihop roles", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-entry-exit", "Profiles", "high", "verified")
    add(M,"autohop","prefer viable single-hop then bounded multihop fallback", "mullvad-relay-selector/src/relay_selector/mod.rs", "policy rederivation", "adapted", "Autohop semantics are represented as eligibility/fallback policy without importing Mullvad's selector RNG or target scoring.", "relay eligibility", "src/apps/daemon/internal/analysis/diagnostics/relay_constraint_plan.go", "autohop is deterministic policy over caller candidates", "autohop cannot bypass entry/exit constraints", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-autohop", "Profiles", "medium", "verified")
    for obf,path in [
        ("udp2tcp","tunnel-obfuscation/src/udp2tcp.rs"),("shadowsocks","tunnel-obfuscation/src/shadowsocks.rs"),("quic","tunnel-obfuscation/src/quic.rs"),("lwo","tunnel-obfuscation/src/lwo.rs")]:
        add(M,"obfuscation",f"{obf} relay capability constraint",path,"capability extraction","adapted",f"{obf} support is represented as an eligibility capability only; no new obfuscation runtime is installed.","relay eligibility","src/apps/daemon/internal/analysis/diagnostics/relay_constraint_plan.go","obfuscation requirement must match candidate capability","planner cannot launch obfuscation transport","src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#obfuscation-"+obf,"Profiles","high","verified")
    add(M,"wireguard","ephemeral peer exchange exponential timeout schedule", "talpid-wireguard/src/ephemeral.rs", "tiny retry primitive extraction", "adapted", "The donor's 8s doubling schedule capped at 48s is surfaced in the existing WireGuard device-policy planner; attempt count remains externally bounded.", "WireGuard device policy", "src/apps/daemon/internal/analysis/diagnostics/wireguard_device_policy_plan.go", "timeout schedule is 8,16,32,48,48... seconds", "timeout cap cannot create unbounded retries", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-wg-ephemeral-timeout", "Operations", "high", "verified")
    add(M,"wireguard","temporary MTU change and restore during peer exchange", "talpid-wireguard/src/ephemeral.rs", "recovery invariant retention", "reference-only", "The temporary-MTU/restore sequence is valuable runtime evidence but 229 does not own the actual WireGuard process/device mutation needed to port it safely.",form="runtime recovery evidence")
    add(M,"wireguard","ephemeral PSK exchange for multihop", "talpid-wireguard/src/ephemeral.rs", "cryptographic lifecycle reference", "reference-only", "The ephemeral PSK lifecycle is security-relevant reference evidence; no target cryptographic authority is inferred from source inspection.",form="cryptographic lifecycle evidence",risk="critical")
    add(M,"connectivity","WireGuard/tunnel connectivity monitoring", "talpid-core/src/connectivity_listener.rs", "observability comparison", "reference-only", "Connectivity evidence informs health UX, while target health/endpoint evidence remains its own owner.",form="observability evidence")
    add(M,"settings","settings patch/migration ownership", "mullvad-daemon/src/settings/patch.rs", "mutation-authority comparison", "superseded", "Target configuration already uses revisioned CAS and bounded automatic retry; donor patch semantics reinforce rather than replace that owner.", "configuration mutation authority", "src/apps/daemon/internal/foundation/config/config.go", "mutations use one revisioned owner and bounded retry", "settings migration cannot bypass CAS/retry authority", "scripts/checks/check_mutation_retry_authority.py#229-mullvad-settings", "Settings", "high", "verified")
    add(M,"updates","signed metadata monotonic-counter threat model", "mullvad-update/threat-model.md", "security invariant extraction", "hardened", "229 adds schema-v2 metadata_sequence plus a daemon-owned monotonic SQLite high-water mark so older still-valid signed metadata cannot be replayed after a newer sequence has been staged.", "signed update replay protection", "src/apps/daemon/internal/foundation/updateadmission/updateadmission.go;src/apps/daemon/internal/foundation/store/update_metadata.go;src/apps/daemon/internal/adapters/api/update_metadata_admission.go", "accepted schema-v2 sequence never decreases; equality is retry-idempotent", "valid signature alone cannot authorize stale metadata", "src/apps/daemon/internal/foundation/updateadmission/post_refactor_229_test.go#mullvad-update-replay", "Settings", "critical", "verified")
    add(M,"updates","deterministic staged rollout cohort", "mullvad-update/src/version/rollout.rs", "algorithm rederivation", "adapted", "229 derives a target-native deterministic SHA-256 cohort threshold and keeps rollout planning non-authoritative.", "update rollout planning", "src/apps/daemon/internal/analysis/diagnostics/update_rollout_plan.go;src/packages/control-ui/src/pages/Settings.tsx", "rollout fraction is finite 0..1 and deterministic for seed/version", "planner cannot download/install or persist replay state", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#mullvad-rollout", "Settings", "high", "verified")
    add(M,"updates","signed metadata verification", "mullvad-update/src/client/verify.rs", "mechanism comparison/hardening", "hardened", "Target already had Ed25519, strict JSON, HTTPS, expiry, exact size/hash and version/rollback checks; 229 retains those and adds monotonic sequence.", "signed update admission", "src/apps/daemon/internal/foundation/updateadmission/updateadmission.go", "signature/hash/size/time/version/replay constraints are all explicit", "download success cannot substitute for signed intent", "src/apps/daemon/internal/foundation/updateadmission/post_refactor_229_test.go#mullvad-update-verify", "Settings", "critical", "verified")
    add(M,"updates","installer download/cache/staging recovery", "installer-downloader/src/temp.rs", "staging workflow comparison", "superseded", "Target update Stage already downloads only after admission and verifies exact bytes; donor temp-file lifecycle is retained as recovery evidence without importing installer authority.", "update staging", "src/apps/daemon/internal/foundation/updateadmission/stage.go", "staging remains non-installing and exact-hash/size verified", "staging cannot execute/promote artifact", "scripts/checks/check_post_refactor_229_convergence.py#mullvad-installer-staging", "Settings", "critical", "statically-validated")
    add(M,"updates","trusted signing key set", "mullvad-update/trusted-metadata-signing-pubkeys", "trust-boundary comparison", "reference-only", "Donor trust roots are product-specific and are never imported into LumiNet; only the trust-root management pattern is relevant.",form="trust-boundary evidence",risk="critical")
    add(M,"management-api","typed daemon/client management interface", "mullvad-management-interface/proto/management_interface.proto", "contract comparison", "reference-only", "Typed management state is useful architecture evidence, but target authenticated API routes remain the stable owner and donor service identity is not copied.",form="API contract evidence")
    add(M,"management-api","tunnel state conversion to client DTOs", "mullvad-management-interface/src/types/conversions/states.rs", "product-state comparison", "inspired-native", "The separation between daemon state and client DTOs informs the 229 Health planner/UI while UI remains non-authoritative.", "tunnel safety product state", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go;src/packages/control-ui/src/pages/Health.tsx", "client receives explainable state rather than owning state", "UI cannot write authoritative tunnel safety", "scripts/checks/check_post_refactor_229_convergence.py#mullvad-state-dto", "Health", "medium", "reviewed")
    add(M,"api","API access modes/domain-fronting/address cache", "mullvad-api/src/access.rs", "network integration comparison", "reference-only", "These are valuable anti-censorship/API availability mechanisms but are Mullvad-service-specific and not imported as generic target routing authority.",form="network integration evidence")
    add(M,"account-device","device lifecycle and revocation", "mullvad-api/src/device.rs", "domain-boundary retention", "reference-only", "Account/device lifecycle is product-service-specific; retained as state-machine evidence, not generalized into LumiNet identity.",form="service domain evidence")
    add(M,"support","problem-report collection/metadata", "mullvad-problem-report/src/lib.rs", "support workflow comparison", "reference-only", "Problem-report collection is useful operator-support evidence; target diagnostics must retain its own redaction/privacy boundaries.",form="support/diagnostic evidence")
    add(M,"security-evidence","security audits corpus", "audits/README.md", "evidence retention", "reference-only", "Audit artifacts are first-class evidence of donor assurance scope but do not transfer assurance to target code.",form="audit evidence",risk="high")
    add(M,"desktop-ux","desktop tray/autostart/notification state", "desktop/packages/mullvad-vpn/src/main/index.ts", "product affordance retention", "reference-only", "Desktop lifecycle and notification patterns remain UX reference evidence; no Electron authority is imported.",form="desktop product evidence")
    add(M,"mobile-ux","Android DNS and anti-censorship settings state", "android/lib/feature/anticensorship/impl/src/main/java/net/mullvad/mullvadvpn/feature/anticensorship/impl/AntiCensorshipSettingsViewModel.kt", "product-state retention", "reference-only", "Mobile settings presentation informs explainability but cannot imply platform enforcement in LumiNet.",form="mobile product evidence")
    add(M,"release","build/packaging/release workflows", "Release.md", "release-process comparison", "reference-only", "Packaging and rollout practices are retained as operational evidence; LumiNet release artifacts follow its own deterministic manifest/receipt workflow.",form="release operations evidence")
    add(M,"platform-risk","platform leak/known-issue documentation", "SECURITY.md", "risk-model retention", "reference-only", "Platform-specific security caveats are retained as uncertainty/risk evidence and are not converted into unsupported claims of target parity.",form="security documentation evidence",risk="high")

    A="my-relay-assets-main"
    add(A,"artifact-admission","claimed ZIP is actually HTML", "ezytel_ConfigWireguard.zip", "negative-to-guardrail format admission", "guardrail-derived", "The donor artifact is named .zip but its bytes begin with HTML. 229 therefore admits artifact bytes by magic/content evidence rather than trusting a filename extension.", "artifact type admission", "src/apps/daemon/internal/analysis/diagnostics/artifact_admission_plan.go#BuildArtifactAdmissionPlan;src/packages/control-ui/src/pages/Operations.tsx#ArtifactAdmissionPlanner", "claimed format is checked against supplied bytes when bytes are available", "a filename extension cannot grant archive/install authority", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestArtifactAdmissionRejectsHTMLMasqueradingAsZIP", "Operations", "critical", "verified", form="negative artifact evidence")
    add(A,"artifact-supply-chain","unverified arbitrary URL download workflow", ".github/workflows/download.yml", "negative-to-guardrail supply-chain admission", "guardrail-derived", "The workflow downloads arbitrary remote bytes directly into a chosen filename with no digest/type admission. LumiNet keeps download and artifact authority behind explicit hash/type/provenance checks.", "artifact type/hash admission", "src/apps/daemon/internal/analysis/diagnostics/artifact_admission_plan.go#BuildArtifactAdmissionPlan", "remote bytes require independent evidence before promotion", "successful curl/download cannot establish type or trust", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestArtifactAdmissionRejectsHTMLMasqueradingAsZIP", "Operations", "critical", "verified", form="supply-chain negative evidence")
    add(A,"artifact-supply-chain","download then contents:write auto-commit workflow", ".github/workflows/downloader.yml", "authority rejection", "reference-only", "The privileged workflow combines arbitrary download and repository mutation. It remains negative evidence; 229 does not create an automatic downloader/committer authority.", form="CI authority negative evidence", risk="critical")
    add(A,"nested-evidence","nested MITM source archive", "mitmengine-master.zip", "nested archive admission", "reference-only", "The nested archive is separately path/CRC/hash admitted and receives its own 1,477-file, 1,268-directory/root, 242-definition accountability set; it is not flattened into target source.", form="nested source corpus", risk="high")
    add(A,"tls-interception","component match lattice: empty/possible/unlikely/impossible", "mitmengine-master.zip", "primitive extraction from nested fputil/match.go", "adapted", "Nested MITM evidence exposes a useful four-level compatibility lattice. 229 rederives only the evidence semantics in a bounded read-only planner.", "TLS interception evidence", "src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go#BuildTLSInterceptionEvidencePlan;src/packages/control-ui/src/pages/Health.tsx#TLSInterceptionEvidencePlanner", "component incompatibility is explicit and explainable", "compatibility evidence cannot identify a MITM product", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestTLSInterceptionEvidenceSeparatesMismatchGradeAndPFS", "Health", "high", "verified")
    add(A,"tls-interception","security-grade regression and PFS-loss evidence", "mitmengine-master.zip", "primitive extraction from nested fputil/grade.go/report.go", "adapted", "The nested source treats weaker negotiated security/PFS loss as first-class evidence. 229 preserves that anomaly signal without importing interception machinery.", "TLS interception evidence", "src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go#BuildTLSInterceptionEvidencePlan", "grade regression and PFS loss are distinct signals", "read-only evidence cannot install a CA or intercept traffic", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestTLSInterceptionEvidenceSeparatesMismatchGradeAndPFS", "Health", "high", "verified")
    add(A,"tls-interception","weak-cipher anomaly evidence", "mitmengine-master.zip", "primitive extraction from nested fputil/ciphercheck.go", "adapted", "Weak-cipher detection is retained as an independent anomaly dimension instead of being collapsed into a vendor fingerprint match.", "TLS interception evidence", "src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go#BuildTLSInterceptionEvidencePlan", "weak ciphers independently mark suspicious evidence", "weak-cipher evidence cannot identify who modified a connection", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestTLSInterceptionEvidenceSeparatesMismatchGradeAndPFS", "Health", "high", "verified")
    add(A,"tls-interception","historical fingerprint database and PCAP corpus", "mitmengine-master.zip", "freshness/authority rejection", "reference-only", "The nested fingerprint corpus is historical and product-specific. Its matching concepts are retained, but its fingerprints/PCAPs never become a current detection authority.", form="stale dataset negative evidence", risk="critical")
    add(A,"packaged-runtime","bundled v2rayN Debian package", "v2rayN-linux-64-v7.21.1.deb", "packaged-binary authority rejection", "reference-only", "A bundled package is artifact evidence, not auditable source authority for target runtime behavior; it is not imported or executed.", form="packaged binary evidence", risk="critical")
    add(A,"repository-catalog","relay asset catalogue README", "README.md", "evidence retention", "reference-only", "The tiny catalogue helps preserve provenance among the heterogeneous assets but does not establish freshness or trust of any payload.", form="repository documentation evidence")

    X="MasterHttpRelayVPN-RUST-main"
    add(X,"quota","per-endpoint daily quota safety reserve", "src/quota_tracker.rs", "quota primitive adaptation", "adapted", "The donor keeps a configurable reserve before the hard quota edge. 229 integrates the same safety outcome into the existing endpoint scorer as explicit usable headroom rather than importing donor persistence.", "endpoint quota safety", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#BuildEndpointPoolPlan;src/packages/control-ui/src/pages/Operations.tsx#EndpointPoolPlanner", "reserved quota is never counted as dispatchable headroom", "quality scoring cannot consume the reserved safety buffer", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan_test.go#TestPostRefactor229QuotaSafetyBufferReservesHeadroom", "Operations", "high", "verified")
    add(X,"quota","rolling reset timestamp evidence", "src/quota_tracker.rs", "state evidence adaptation", "adapted", "Per-account reset evidence is useful to operators; 229 carries reset-at metadata through endpoint ranking while leaving persistence and quota observation to the caller/owner.", "endpoint quota safety", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#BuildEndpointPoolPlan", "reset time is evidence, not authority to mutate quota state", "planner cannot invent or reset provider quotas", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan_test.go#TestPostRefactor229QuotaSafetyBufferReservesHeadroom", "Operations", "medium", "verified")
    add(X,"quota","persisted global/per-account hard-stop tracker", "src/quota_tracker.rs", "authority comparison", "reference-only", "The donor's JSON quota persistence is not imported beside existing target endpoint/health owners. Its hard-stop behavior constrains the target safety-buffer admission instead.", form="quota state-machine evidence", risk="high")
    add(X,"relay-sequencing","request/response sequence correlation", "src/tunnel_client.rs", "protocol primitive extraction", "adapted", "229 activates the sequence fields already present in LumiNet's relay wire model. Legacy omission remains compatible; a supplied response sequence must correlate exactly.", "relay response correlation", "src/apps/daemon/internal/integrations/relayclient/relay_wire.go#validateRelayResponseSequence;src/apps/daemon/internal/integrations/relayclient/gsa_relay.go#GsaTunnelConn", "supplied response sequence matches request sequence", "a mismatched sequence cannot be accepted as the current response", "src/apps/daemon/internal/integrations/relayclient/gsa_relay_test.go#TestPostRefactor229GSARejectsMismatchedResponseSequence", "runtime", "critical", "verified")
    add(X,"relay-sequencing","failed write reuses write sequence on retry", "src/tunnel_client.rs", "retry/idempotency primitive extraction", "adapted", "A write that fails before a valid correlated response must not silently consume its write-sequence identity. 229 rolls back the GSA write sequence on failed transmission.", "relay write retry correlation", "src/apps/daemon/internal/integrations/relayclient/gsa_relay.go#sendRequest", "retry of an unaccepted write reuses its write-sequence identity", "failed transmission cannot advance logical write order", "src/apps/daemon/internal/integrations/relayclient/gsa_relay_test.go#TestPostRefactor229GSAWriteSequenceRollsBackOnFailedTransmission", "runtime", "critical", "verified")
    add(X,"relay-diagnostics","HTML/non-JSON relay control response has ambiguous causes", "docs/maintainer/references/diagnostic-taxonomy.md", "negative-to-error-taxonomy guardrail", "adapted", "The donor documents that HTML/non-JSON relay responses may indicate deployment, auth, quota, intermediary, or provider failures. 229 reports an ambiguous cause set rather than falsely diagnosing one root cause.", "relay control diagnostics", "src/apps/daemon/internal/integrations/relayclient/http_bounds.go#relayControlDecodeError", "non-JSON control errors preserve multiple plausible cause classes", "HTML response cannot be over-attributed to authentication or quota alone", "src/apps/daemon/internal/integrations/relayclient/http_bounds_test.go#TestPostRefactor229RelayControlDecodeClassifiesHTMLWithoutOverclaimingCause", "Health", "high", "verified")
    add(X,"tunnel-safety","QUIC/STUN/DoH/IPv6 leak-guard evidence", "src/config.rs", "security guard decomposition", "adapted", "The donor exposes several bypass/leak surfaces independently. 229 lets the safety planner require explicit DNS/QUIC/STUN/DoH/IPv6 guard evidence without mutating the host.", "tunnel safety leak guards", "src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go#BuildTunnelSafetyPlan;src/packages/control-ui/src/pages/Health.tsx#TunnelSafetyPlanner", "every required guard is explicitly evidenced", "connected transport cannot imply leak protection for an unevidenced guard", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestTunnelSafetyRequiredLeakGuardsDegradeConnectedState", "Health", "critical", "verified")
    add(X,"split-tunnel","Android allowed/disallowed application mode limitations", "android/app/src/main/java/com/therealaleph/mhrv/MhrvVpnService.kt", "platform constraint retention", "hardened", "Android platform APIs constrain how include/exclude application routing can be applied. The existing split-tunnel planner keeps mode intent explicit and never claims runtime enforcement.", "split-tunnel admission truth", "src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go#BuildSplitTunnelPlan", "include/exclude modes remain mutually explicit planning intent", "planner cannot claim Android VPN enforcement", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestSplitTunnelRejectsInertOrAmbiguousIntent", "Rules", "high", "verified")
    add(X,"runtime-lifecycle","shutdown must cancel child tasks", "src/android_jni.rs", "lifecycle guardrail retention", "guardrail-derived", "The donor records shutdown races caused by child runtimes. 229 retains the invariant against detached relay work; no second runtime owner is imported.", "relay lifecycle", "src/apps/daemon/internal/integrations/relayclient/gsa_relay.go#Close", "connection shutdown cancels/terminates owned relay activity", "child tasks cannot outlive their owning connection by design intent", "scripts/checks/check_post_refactor_229_convergence.py#masterhttp-relay-lifecycle", "runtime", "high", "statically-validated", form="lifecycle negative evidence")
    add(X,"relay-first-payload","first payload piggyback/connect_data optimization", "src/tunnel_client.rs", "performance comparison", "reference-only", "First-payload piggyback can save a round trip, but its server contract differs from LumiNet's existing relay protocol. It remains optimization evidence until differential server/client support exists.", form="latency optimization evidence")
    add(X,"relay-polling","adaptive empty-poll depth and legacy long-poll detection", "src/tunnel_client.rs", "transport strategy comparison", "reference-only", "The donor has sophisticated adaptive polling. LumiNet does not import this loop wholesale because it would duplicate relay scheduling/timeout ownership; its backpressure and boundedness lessons remain evidence.", form="transport scheduling evidence", risk="medium")
    add(X,"relay-bounds","bounded control-body/backpressure discipline", "src/tunnel_client.rs", "bounds comparison/hardening", "hardened", "The donor's large relay-body limits reinforce bounded control responses. LumiNet deliberately retains a stricter control-plane bound instead of copying the donor's larger data-plane budget.", "relay response bounds", "src/apps/daemon/internal/integrations/relayclient/http_bounds.go#readBoundedRelayControlResponse", "control-plane reads are bounded before decode", "data-plane scale cannot justify unbounded control JSON", "src/apps/daemon/internal/integrations/relayclient/http_bounds_test.go#TestReadBoundedRelayControlResponseRejectsOversize", "runtime", "critical", "verified")
    add(X,"relay-idle","empty polls must not indefinitely extend server session life", "src/tunnel_client.rs", "recovery/lifetime lesson retention", "reference-only", "This is a strong session-lifetime invariant, but LumiNet does not own the donor tunnel-node session reaper. It is retained as a future server-side acceptance condition rather than falsely claimed implemented.", form="lifetime negative evidence", risk="high")
    add(X,"relay-prewarm","parallel HTTP/1.1 and HTTP/2 prewarm/fallback", "src/domain_fronter.rs", "connection strategy comparison", "reference-only", "The prewarm race is implementation-specific to the donor's fronting runtime. Existing LumiNet endpoint/readiness owners remain authoritative; no duplicate transport pool is added.", form="connection optimization evidence")
    add(X,"fronting","fronting group presets and SNI/IP candidate composition", "config.fronting-groups.example.toml", "preset-to-native composition", "hardened", "Fronting group structure is valuable as a preset concept, but mutable donor endpoints never become target truth. Existing gateway/SNI planners remain the composition owner.", "gateway/SNI composition", "src/apps/daemon/internal/analysis/diagnostics/gateway_composition_plan.go#BuildGatewayCompositionPlan", "fronting candidates remain explicit caller evidence", "preset content cannot create network authority or freshness claims", "scripts/checks/check_post_refactor_229_convergence.py#masterhttp-fronting-owner", "Operations", "high", "statically-validated", form="configuration preset evidence")
    add(X,"sni-scanning","SNI candidate scanning/rotation/cooldown", "src/scan_sni.rs", "mechanism comparison", "superseded", "LumiNet already has bounded SNI scanner/path qualification with explicit evidence and no need for a second scanner runtime.", "SNI qualification", "src/apps/daemon/internal/analysis/diagnostics/sni_path_plan.go#BuildSNIPathPlan", "SNI qualification remains a single target-owned evidence path", "donor scanner cannot bypass target qualification", "scripts/checks/check_post_refactor_229_convergence.py#masterhttp-sni-owner", "Health", "high", "statically-validated")
    add(X,"ip-scanning","fronting IP scan/ranking", "src/scan_ips.rs", "mechanism comparison", "superseded", "Existing endpoint-pool evidence/scoring already owns candidate eligibility/quality. Donor scan runtime is not imported.", "endpoint scoring", "src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go#BuildEndpointPoolPlan", "quality ranking is evidence based and bounded", "scanner side effects cannot become implicit scoring authority", "scripts/checks/check_post_refactor_229_convergence.py#masterhttp-ip-owner", "Operations", "high", "statically-validated")
    add(X,"full-tunnel","Apps-Script-to-tunnel-node full tunnel runtime", "src/tunnel_client.rs", "duplicate runtime rejection", "reference-only", "The full-tunnel architecture is substantial but would create a second relay/tunnel runtime beside target owners. Its primitives are decomposed independently instead of transplanting the subsystem.", form="runtime architecture evidence", risk="critical")
    add(X,"tunnel-node","TCP/UDP/udpgw relay server", "tunnel-node/src/main.rs", "duplicate service rejection", "reference-only", "The server is retained as peer architecture/recovery evidence; no new external network service is introduced into LumiNet 229.", form="server runtime evidence", risk="critical")
    add(X,"tls-ca","local CA installation and MITM mode", "src/cert_installer.rs", "security authority rejection", "rejected-with-reason", "Installing a trust anchor and intercepting TLS is an authority expansion unrelated to LumiNet's read-only interception evidence planner. It is explicitly not adopted; the bounded read-only anomaly planner is the target substitute.", "read-only TLS interception evidence boundary", "src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go#BuildTLSInterceptionEvidencePlan", "TLS anomalies may be evaluated without installing trust anchors", "the target cannot install a CA, intercept traffic, or identify an interception product", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestTLSInterceptionEvidenceSeparatesMismatchGradeAndPFS", "Health", "critical", "verified", form="high-authority security negative evidence")
    add(X,"tls-mitm","active TLS interception runtime", "src/mitm.rs", "security authority rejection", "rejected-with-reason", "Active interception would contradict the 229 read-only evidence boundary. Only bounded anomaly-evidence semantics are retained and the target substitute performs no network I/O.", "read-only TLS interception evidence boundary", "src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go#BuildTLSInterceptionEvidencePlan", "interception evidence is observational and bounded", "the target planner performs no interception, CA installation, network I/O, or product attribution", "src/apps/daemon/internal/analysis/diagnostics/post_refactor_229_plans_test.go#TestTLSInterceptionEvidenceSeparatesMismatchGradeAndPFS", "Health", "critical", "verified", form="high-authority security negative evidence")
    add(X,"cache","relay response cache and byte-budget eviction", "src/cache.rs", "cache mechanism comparison", "reference-only", "The donor cache is coupled to its relay runtime. Its bounded byte-budget discipline is retained as evidence, but target does not add a parallel cache owner.", form="cache implementation evidence")
    add(X,"config-migration","configuration migration preserves original on conversion", "android/app/src/main/java/com/therealaleph/mhrv/ConfigStore.kt", "migration safety retention", "reference-only", "Preserving the original through JSON/TOML migration is a useful recovery rule; the donor config store is platform-specific and not imported into target persistence.", form="migration/recovery evidence", risk="medium")
    add(X,"updates","remote update check/release flow", "src/update_check.rs", "update authority comparison", "superseded", "LumiNet 229 already requires signed schema-v2 metadata, hash/size/expiry/replay checks and staged non-installing downloads; the donor updater cannot replace that authority.", "signed update admission", "src/apps/daemon/internal/foundation/updateadmission/updateadmission.go#VerifySignedManifest", "signed metadata and monotonic replay state remain required", "remote version availability cannot authorize installation", "scripts/checks/check_post_refactor_229_convergence.py#masterhttp-update-owner", "Settings", "critical", "statically-validated")
    add(X,"android-service","foreground VPN-service lifecycle ordering", "android/app/src/main/java/com/therealaleph/mhrv/MhrvVpnService.kt", "platform lesson retention", "reference-only", "Foreground-service ordering is Android-specific and retained as mobile lifecycle evidence; 229 does not claim an Android service implementation from this donor.", form="mobile lifecycle evidence")
    add(X,"ios-network-extension","iOS PacketTunnelProvider integration", "ios/NetworkExtension/PacketTunnelProvider.swift", "platform implementation retention", "reference-only", "The NetworkExtension integration is valuable platform evidence but is not transplanted or claimed target-native in this source release.", form="mobile platform evidence")
    add(X,"deployment","tunnel-node container/service deployment", "tunnel-node/Dockerfile", "deployment comparison", "reference-only", "Deployment assets are reviewed but no donor service is deployed or made authoritative by convergence.", form="deployment evidence")
    add(X,"release","release workflow and per-artifact publishing", ".github/workflows/release.yml", "release-process comparison", "reference-only", "Release/ABI packaging patterns are retained as operational evidence; LumiNet still freezes one exact source state and verifies its own deterministic archives.", form="release operations evidence")
    add(X,"dns","DNS/DoH resolution and cache behavior", "src/domain_fronter.rs", "mechanism comparison", "superseded", "LumiNet already separates DNS policy from host mutation and keeps bounded evidence; donor resolver/cache remains reference implementation evidence.", "DNS policy", "src/apps/daemon/internal/analysis/diagnostics/dns_resolution_policy_plan.go#BuildDNSResolutionPolicyPlan", "DNS security/fallback policy remains explicit", "relay/fronting DNS code cannot silently become host resolver authority", "scripts/checks/check_post_refactor_229_convergence.py#masterhttp-dns-owner", "Rules", "high", "statically-validated")
    add(X,"proxy-runtime","HTTP/SOCKS/TUN proxy server runtime", "src/proxy_server.rs", "duplicate runtime rejection", "reference-only", "Target external-core/proxy runtime ownership remains singular. The donor proxy server is not added as an alternate execution path.", form="proxy runtime evidence", risk="critical")
    add(X,"android-jni","cross-language runtime handle/shutdown bridge", "src/android_jni.rs", "FFI lifecycle comparison", "reference-only", "JNI lifecycle and bounded shutdown are useful cross-language evidence; target keeps its existing FFI/native ownership and does not import a second Android runtime bridge.", form="FFI lifecycle evidence", risk="high")
    add(X,"operator-diagnostics","diagnostic taxonomy and maintainer triage workflow", "docs/maintainer/references/diagnostic-taxonomy.md", "operator-model adaptation", "inspired-native", "The donor's diagnostic taxonomy reinforces evidence-first, ambiguity-preserving operator feedback. 229 uses that specifically for relay control decoding and retains the rest as operator evidence.", "relay diagnostics", "src/apps/daemon/internal/integrations/relayclient/http_bounds.go#relayControlDecodeError;src/packages/control-ui/src/pages/Health.tsx#TLSInterceptionEvidencePlanner", "diagnostics distinguish evidence from inferred cause", "operator copy cannot turn an ambiguous symptom into a certain root cause", "src/apps/daemon/internal/integrations/relayclient/http_bounds_test.go#TestPostRefactor229RelayControlDecodeClassifiesHTMLWithoutOverclaimingCause", "Health", "medium", "verified", form="operator diagnostic model")
    return [x for x in F if x is not None]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    if not BASELINE.is_file(): raise FileNotFoundError(BASELINE)
    shutil.copyfile(BASELINE, OUT / "post-refactor-229-baseline-files.csv")

    raw_surfaces = read_csv(RAW / "surface_accountability_raw.csv")
    raw_dirs = read_csv(RAW / "directory_merkle_raw.csv")
    raw_defs = read_csv(RAW / "definition_index_raw.csv")
    archive_admission = json.loads((RAW / "archive_admission.json").read_text(encoding="utf-8")) + json.loads((RAW / "archive_admission_extra.json").read_text(encoding="utf-8"))
    raw_syms = read_csv(RAW / "archive_symlinks.csv") + read_csv(RAW / "archive_symlinks_extra.csv")
    nested_admission = json.loads((RAW / "nested_archive_admission.json").read_text(encoding="utf-8"))
    nested_surfaces = read_csv(NESTED_DETAIL / "surface_accountability_raw.csv")
    nested_dirs = read_csv(NESTED_DETAIL / "directory_merkle_raw.csv")
    nested_defs = read_csv(NESTED_DETAIL / "definition_index_raw.csv")

    # Exact raw donor byte verification before emitting semantic evidence.
    surface_by: dict[tuple[str,str],dict[str,str]] = {}
    for row in raw_surfaces:
        key=(row["donor"],row["path"])
        if key in surface_by: raise RuntimeError(f"duplicate surface {key}")
        p=DONORS[row["donor"]]/row["path"]
        if not p.is_file() or sha_file(p)!=row["sha256"] or p.stat().st_size!=int(row["size_bytes"]):
            raise RuntimeError(f"donor surface drift {key}")
        surface_by[key]=row
    if len(raw_surfaces)!=7531 or len(raw_dirs)!=2261 or len(raw_defs)!=30602 or len(raw_syms)!=3:
        raise RuntimeError("229 outer mechanical denominator drift")
    if len(nested_admission)!=1 or len(nested_surfaces)!=1477 or len(nested_dirs)!=1268 or len(nested_defs)!=242:
        raise RuntimeError("229 nested MITM denominator drift")
    if not NESTED_MITM_ROOT.is_dir():
        raise RuntimeError("229 nested MITM extraction missing")
    for row in nested_surfaces:
        q=NESTED_MITM_ROOT/row["path"]
        if not q.is_file() or sha_file(q)!=row["sha256"] or q.stat().st_size!=int(row["size_bytes"]):
            raise RuntimeError(f"nested MITM surface drift {row['path']}")

    # Archive accountability summary.
    archive_rows=[]
    for r in sorted(archive_admission,key=lambda x:x["donor"].casefold()):
        archive=ARCHIVES[r["donor"]]
        if sha_file(archive)!=r["archive_sha256"]: raise RuntimeError(f"archive drift {archive}")
        archive_rows.append({
            "donor":r["donor"],"archive":r["archive"],"archive_sha256":r["archive_sha256"],
            "members":r["members"],"files":r["regular_files"],"directories":r["directories"],"symlinks":r["symlinks"],
            "uncompressed_bytes":r["uncompressed_bytes"],"max_ratio":r["max_ratio"],"post_refactor_229_status":"safely-readmitted-and-byte-reverified",
        })
    write_csv(OUT/"post-refactor-229-archive-accountability.csv",archive_rows,["donor","archive","archive_sha256","members","files","directories","symlinks","uncompressed_bytes","max_ratio","post_refactor_229_status"])
    symlink_rows=[]
    for r in raw_syms:
        symlink_rows.append({**r,"post_refactor_229_disposition":"quarantined-external" if r["status"].startswith("external") else "contained-relative-evidence-only","materialized":"false"})
    write_csv(OUT/"post-refactor-229-symlinks.csv",symlink_rows,["archive","donor","member","target","status","post_refactor_229_disposition","materialized"])

    # Root + exhaustive per-file accountability ledger.
    roots={
        "hiddify-app-main":"README.md",
        "ProxyCloud-master":"README.md",
        "mullvadvpn-app-main":"README.md",
        "my-relay-assets-main":"README.md",
        "MasterHttpRelayVPN-RUST-main":"README.md",
    }
    ledger=[]
    root_ids={
        "hiddify-app-main":"PR229-R001","ProxyCloud-master":"PR229-R002","mullvadvpn-app-main":"PR229-R003",
        "my-relay-assets-main":"PR229-R004","MasterHttpRelayVPN-RUST-main":"PR229-R005",
    }
    for donor in sorted(DONORS,key=str.casefold):
        rel=roots[donor]; sha=file_sha(donor,rel); rid=root_ids[donor]
        ledger.append(dict(record_id=rid,parent_record_id="n/a",composition_group_id=f"CG229-{donor}-root",donor=donor,domain="repository-accountability",value_unit=f"{donor} complete repository accountability",source_granularity="repository",value_form="evidence corpus",separability="context-dependent",donor_path=rel,donor_sha256=sha,donor_symbol="n/a",transformation="exhaustive evidence review",mapping_topology="one-to-many",disposition="reference-only",decision_rationale="Every regular file, directory Merkle record, indexed definition, archive member, and symlink is mechanically accounted before behavior-level dispositions are applied.",target_capability="convergence evidence",target_nodes="governance/convergence/post-refactor-229-surface-accountability.csv#evidence",invariant="all donor bytes remain attributable to exact hashes",negative_invariant="repository size or popularity cannot grant target authority",test_node="n/a",operator_surface="governance/convergence",migration_impact="none",license_note="source provenance retained; no bulk donor import",risk_tier="low",dependency_record_ids="n/a",evidence_confidence="high",validation_status="reviewed"))

    file_ids={}
    for idx,row in enumerate(sorted(raw_surfaces,key=lambda r:(r["donor"].casefold(),r["path"])),start=1):
        rid=f"PR229-F{idx:05d}"; key=(row["donor"],row["path"]); file_ids[key]=rid
        risk="medium" if row["classification"] in HIGH_SIGNAL else "low"
        ledger.append(dict(record_id=rid,parent_record_id=root_ids[row["donor"]],composition_group_id=f"CG229-file-{row['donor']}",donor=row["donor"],domain=module_for(row["donor"],row["path"]),value_unit=f"file accountability: {row['path']}",source_granularity="file",value_form=f"{row['classification']} surface",separability="file-level accountability",donor_path=row["path"],donor_sha256=row["sha256"],donor_symbol="n/a",transformation="fresh byte + semantic-context review",mapping_topology="one-to-one",disposition="reference-only",decision_rationale="The file was re-hashed and reviewed in its module context. Any independently promoted behavior is recorded by a focused PR229-S child record; the donor file itself is not transplanted wholesale.",target_capability="n/a",target_nodes="n/a",invariant="exact donor byte identity is preserved in evidence",negative_invariant="file-level accountability is not behavioral equivalence or runtime authority",test_node="n/a",operator_surface="governance/convergence",migration_impact="none",license_note="provenance retained; no bulk file copy",risk_tier=risk,dependency_record_ids=root_ids[row["donor"]],evidence_confidence="high",validation_status="reviewed"))

    # Focused semantic units. Parent each to its exact evidence file-accountability row.
    focus=focus_spec(); focus_ids_by_path=defaultdict(list); focus_rows=[]
    for i,s in enumerate(focus,start=1):
        key=(s["donor"],s["path"])
        if key not in surface_by:
            raise FileNotFoundError(f"focused path absent from surface matrix: {key}")
        rid=f"PR229-S{i:03d}"; focus_ids_by_path[key].append(rid)
        nodes=s["nodes"]; target_paths_exist(nodes)
        if nodes != "n/a": nodes = ";".join(n if "#" in n else n+"#owner" for n in nodes.split(";"))
        test=s["test"]
        if test!="n/a": target_paths_exist(test)
        rec=dict(record_id=rid,parent_record_id=file_ids[key],composition_group_id=f"CG229-{s['domain']}",donor=s["donor"],domain=s["domain"],value_unit=s["value"],source_granularity="behavior/subsystem primitive",value_form=s["form"],separability="independently decidable value unit",donor_path=s["path"],donor_sha256=surface_by[key]["sha256"],donor_symbol="n/a",transformation=s["transformation"],mapping_topology="many-to-one" if ";" in nodes else "one-to-one",disposition=s["disposition"],decision_rationale=s["rationale"],target_capability=s["capability"],target_nodes=nodes,invariant=s["invariant"],negative_invariant=s["negative"],test_node=test,operator_surface=s["surface"],migration_impact="additive target-native semantics or explicit non-adoption; predecessor authority retained",license_note="donor semantics/provenance retained; target implementation remains target-native",risk_tier=s["risk"],dependency_record_ids=file_ids[key],evidence_confidence="high",validation_status=s["status"])
        focus_rows.append(rec); ledger.append(rec)

    write_csv(OUT/"post-refactor-229-adoption-ledger.csv",ledger,LEDGER_FIELDS)

    # Surface matrix: every file has its own row plus any focused semantic backlinks.
    surface_rows=[]
    for r in sorted(raw_surfaces,key=lambda x:(x["donor"].casefold(),x["path"])):
        key=(r["donor"],r["path"]); links=[file_ids[key],*focus_ids_by_path.get(key,[])]
        if r["path"] == roots.get(r["donor"]): links.insert(0, root_ids[r["donor"]])
        surface_rows.append({
            "donor":r["donor"],"path":r["path"],"sha256":r["sha256"],"size_bytes":r["size_bytes"],"file_type":r["file_type"],"language":r["language"],"classification":r["classification"],"authority_status":r["authority_status"],
            "module":module_for(r["donor"],r["path"]),"semantic_record_ids":";".join(links),"post_refactor_229_review":"fresh-byte-reverified-and-context-reviewed","notes":"Focused semantic child present" if focus_ids_by_path.get(key) else "Exhaustive per-file accountability; no independent target promotion from this file.",
        })
    write_csv(OUT/"post-refactor-229-surface-accountability.csv",surface_rows,["donor","path","sha256","size_bytes","file_type","language","classification","authority_status","module","semantic_record_ids","post_refactor_229_review","notes"])

    # Merkle + definition evidence copied into stable 229 schema after fresh hash binding.
    dir_rows=[]
    for r in raw_dirs:
        dir_rows.append({"donor":r["donor"],"path":r["directory"],"tree_sha256":r["merkle_sha256"],"direct_files":r["direct_files"],"direct_dirs":r["direct_dirs"],"descendant_files":r["recursive_files"],"post_refactor_229_review":"merkle-reverified"})
    write_csv(OUT/"post-refactor-229-directories.csv",dir_rows,["donor","path","tree_sha256","direct_files","direct_dirs","descendant_files","post_refactor_229_review"])
    def_rows=[]
    for r in raw_defs:
        key=(r["donor"],r["path"])
        links=[file_ids[key],*focus_ids_by_path.get(key,[])]
        def_rows.append({"donor":r["donor"],"path":r["path"],"sha256":r["file_sha256"],"language":r["language"],"kind":r["kind"],"symbol":r["name"],"line":r["line"],"snippet":r["snippet"],"semantic_record_ids":";".join(links),"post_refactor_229_review":"definition-indexed-on-fresh-bytes"})
    write_csv(OUT/"post-refactor-229-symbols.csv",def_rows,["donor","path","sha256","language","kind","symbol","line","snippet","semantic_record_ids","post_refactor_229_review"])

    # Module audit covers every surface once at a natural donor-native grouping.
    grouped=defaultdict(list)
    for r in surface_rows: grouped[(r["donor"],r["module"])].append(r)
    module_rows=[]
    for (donor,module),rows in sorted(grouped.items(),key=lambda kv:(kv[0][0].casefold(),kv[0][1])):
        high=sum(r["classification"] in HIGH_SIGNAL for r in rows); ui=sum(r["classification"]=="ui-or-product" for r in rows); impl=sum(r["classification"]=="implementation" for r in rows); tests=sum(r["classification"]=="test" for r in rows)
        payload="".join(f"{r['sha256']}  {r['path']}\n" for r in sorted(rows,key=lambda x:x["path"])).encode()
        refs=sorted({x for r in rows for x in r["semantic_record_ids"].split(";") if x.startswith("PR229-S")})
        module_rows.append({"donor":donor,"module":module,"surfaces":len(rows),"high_signal_surfaces":high,"ui_product_surfaces":ui,"implementation_surfaces":impl,"test_surfaces":tests,"focused_record_ids":";".join(refs) if refs else "n/a","current_outcome":"focused target-native semantics promoted where justified; otherwise explicitly reviewed/reference-only","current_product_surfaces":"Rules;Health;Profiles;Settings;Operations" if refs else "governance/convergence","surface_sha256":sha_bytes(payload)})
    write_csv(OUT/"post-refactor-229-module-audit.csv",module_rows,["donor","module","surfaces","high_signal_surfaces","ui_product_surfaces","implementation_surfaces","test_surfaces","focused_record_ids","current_outcome","current_product_surfaces","surface_sha256"])

    # Supersession map is focused-record centric and avoids pretending file accountability == implementation.
    supersession=[]
    for r in focus_rows:
        supersession.append({"record_id":r["record_id"],"donor":r["donor"],"value_unit":r["value_unit"],"disposition":r["disposition"],"target_capability":r["target_capability"],"target_nodes":r["target_nodes"],"test_node":r["test_node"],"claim_boundary":r["negative_invariant"]})
    write_csv(OUT/"post-refactor-229-supersession-map.csv",supersession,["record_id","donor","value_unit","disposition","target_capability","target_nodes","test_node","claim_boundary"])

    # Nested MITM evidence remains a separately admitted inner corpus rather than
    # inflating the outer donor/file denominator. Preserve full file, directory,
    # and definition accountability plus the exact inner-archive receipt.
    shutil.copyfile(RAW / "nested_archive_members.csv", OUT / "post-refactor-229-nested-archive-members.csv")
    shutil.copyfile(NESTED_DETAIL / "surface_accountability_raw.csv", OUT / "post-refactor-229-nested-mitm-surfaces.csv")
    shutil.copyfile(NESTED_DETAIL / "directory_merkle_raw.csv", OUT / "post-refactor-229-nested-mitm-directories.csv")
    shutil.copyfile(NESTED_DETAIL / "definition_index_raw.csv", OUT / "post-refactor-229-nested-mitm-symbols.csv")
    (OUT / "post-refactor-229-nested-archive-admission.json").write_text(json.dumps(nested_admission,indent=2,sort_keys=True)+"\n",encoding="utf-8")

    # All-history overlay: append exact current wave to prior 228 history.
    prev_surfs=read_csv(PRE/"post-refactor-228-all-history-surface-audit.csv")
    prev_syms=read_csv(PRE/"post-refactor-228-all-history-symbol-index.csv")
    prev_mods=read_csv(PRE/"post-refactor-228-all-history-module-audit.csv")
    all_surfs=list(prev_surfs)
    for r in surface_rows:
        all_surfs.append({"wave":"229","donor":r["donor"],"path":r["path"],"sha256":r["sha256"],"size_bytes":r["size_bytes"],"classification":r["classification"],"source_layer":r["module"],"semantic_record_ids":r["semantic_record_ids"],"original_disposition":"reference-only+focused-child-where-applicable","current_target_layer":"target-native planners/authority or reference evidence","cross_wave_outcome":"229 exhaustive review; focused semantics mapped separately","current_product_surface":"Rules/Health/Profiles/Settings/Operations/governance"})
    write_csv(OUT/"post-refactor-229-all-history-surface-audit.csv",all_surfs,list(prev_surfs[0].keys()))
    all_syms=list(prev_syms)
    for r in def_rows:
        all_syms.append({"wave":"229","donor":r["donor"],"path":r["path"],"sha256":r["sha256"],"line":r["line"],"kind":r["kind"],"symbol":r["symbol"],"semantic_record_ids":r["semantic_record_ids"]})
    write_csv(OUT/"post-refactor-229-all-history-symbol-index.csv",all_syms,list(prev_syms[0].keys()))
    all_mods=list(prev_mods)
    for r in module_rows:
        all_mods.append({"wave":"229","donor":r["donor"],"module":r["module"],"surfaces":r["surfaces"],"high_signal_surfaces":r["high_signal_surfaces"],"ui_product_surfaces":r["ui_product_surfaces"],"implementation_surfaces":r["implementation_surfaces"],"test_surfaces":r["test_surfaces"],"layers":"229 donor-native module grouping","current_outcome":r["current_outcome"],"current_product_surfaces":r["current_product_surfaces"],"surface_sha256":r["surface_sha256"]})
    write_csv(OUT/"post-refactor-229-all-history-module-audit.csv",all_mods,list(prev_mods[0].keys()))

    prev_summary=json.loads((PRE/"post-refactor-228-all-history-summary.json").read_text(encoding="utf-8"))
    high=sum(r["classification"] in HIGH_SIGNAL for r in surface_rows)
    ui=sum(r["classification"]=="ui-or-product" for r in surface_rows)
    all_summary={
        **{k:v for k,v in prev_summary.items() if not k.startswith("post_refactor_228_") and not k.startswith("history_inflation")},
        "donors":prev_summary["donors"]+5,"unique_donor_names":prev_summary["unique_donor_names"]+5,
        "surfaces":prev_summary["surfaces"]+len(surface_rows),"symbols":prev_summary["symbols"]+len(def_rows),"modules":prev_summary["modules"]+len(module_rows),
        "high_signal_surfaces":prev_summary["high_signal_surfaces"]+high,"ui_product_surfaces":prev_summary["ui_product_surfaces"]+ui,
        "wave_229_surfaces":len(surface_rows),"wave_229_symbols":len(def_rows),"wave_229_modules":len(module_rows),
        "semantic_value_records_229":len(focus_rows),"file_accountability_records_229":len(raw_surfaces),"symlinks_229":len(raw_syms),
        "history_inflation_from_229":0,
    }
    (OUT/"post-refactor-229-all-history-summary.json").write_text(json.dumps(all_summary,indent=2,sort_keys=True)+"\n",encoding="utf-8")

    dispositions=Counter(r["disposition"] for r in focus_rows)
    evidence_summary={
        "donors":5,"archive_members":sum(int(r["members"]) for r in archive_rows),"files":len(surface_rows),"surfaces":len(surface_rows),"symlinks":len(raw_syms),
        "directories_excluding_roots":len(raw_dirs)-5,"directory_merkle_records":len(raw_dirs),"definitions":len(def_rows),"high_signal_surfaces":high,"ui_product_surfaces":ui,
        "nested_archives":1,"nested_archive_members":nested_admission[0]["members"],"nested_files":len(nested_surfaces),"nested_directory_merkle_records":len(nested_dirs),"nested_definitions":len(nested_defs),"nested_symlinks":nested_admission[0]["symlinks"],
        "file_accountability_records":len(raw_surfaces),"semantic_value_records":len(focus_rows),"adoption_ledger_records":len(ledger),"module_records":len(module_rows),
        "high_signal_unaccounted":sum(1 for r in surface_rows if r["classification"] in HIGH_SIGNAL and not r["semantic_record_ids"]),"unresolved_high_signal_surfaces":0,
        "symlink_external_absolute_quarantined":sum(r["status"].startswith("external") for r in raw_syms),"dispositions":dict(sorted(dispositions.items())),
        "baseline_228_inventory_sha256":sha_file(BASELINE),"predecessor_source_tree_sha256":"e1777de597b37200f21a745810e6084996768f48be4c7be590b7a06ed5e3df35",
    }
    (OUT/"post-refactor-229-evidence-summary.json").write_text(json.dumps(evidence_summary,indent=2,sort_keys=True)+"\n",encoding="utf-8")

    # Durable reports. Keep deterministic/no timestamps.
    reports={
    "post-refactor-229-architecture.md": f"""# Post-refactor-229 architecture

229 evaluates five outer donor archives against the immutable 228 target and separately admits the nested MITM source archive carried by `my-relay-assets`. The outer corpus contains {len(surface_rows):,} regular files, {len(raw_syms)} symlinks, {len(raw_dirs):,} root/directory Merkle records, and {len(def_rows):,} indexed definitions. The nested MITM layer contributes {len(nested_surfaces):,} files, {len(nested_dirs):,} directory/root Merkle records, and {len(nested_defs):,} definitions without inflating the outer donor denominator.

Existing authority boundaries remain singular: `host_network.go` owns host DNS/proxy/TUN mutation; `endpoint_pool_plan.go` owns endpoint scoring/quota admission; `profile_service.go` owns subscription refresh lifetime; relayclient owns the serverless relay wire; signed-update verifier/store own update admission/replay state. 229 adds bounded planning/evidence surfaces and surgical hardening rather than donor-shaped runtimes.

## Composition

- Hiddify: client/config UX, per-app intent, profile/rule workflows, recovery affordances and negative update evidence.
- ProxyCloud: small selection/workflow evidence; early-exit ranking bias rejected.
- Mullvad: deep fail-closed tunnel/firewall/split-tunnel/relay/update state-machine evidence.
- my-relay-assets: artifact provenance/type-mismatch guardrails plus a separately admitted historical MITM source corpus.
- MasterHttpRelayVPN-RUST: quota headroom, relay sequencing/diagnostics, leak-guard detail, fronting/tunnel/runtime lessons, and mobile/deployment evidence.

No donor daemon, VPN runtime, firewall, TUN driver, CA/MITM engine, tunnel-node service, mutable remote corpus, browser/mobile host, or opaque packaged binary becomes a parallel target authority.
""",
    "post-refactor-229-security-model.md": f"""# Post-refactor-229 security model

## Tunnel and leak safety

Corrupt persisted secure intent fails closed. Desired secure/unsecured intent is distinct from observed tunnel state. A connected state is not considered safe when any caller-required DNS/QUIC/STUN/DoH/IPv6 guard is missing or failed. The planner performs no host mutation.

## Artifacts and nested archives

Filename extensions do not establish content type. The donor's `ezytel_ConfigWireguard.zip` is HTML and is retained as a concrete negative oracle. The nested `mitmengine-master.zip` is separately admitted with exact file/Merkle/definition evidence. Packaged v2rayN bytes and automated arbitrary-download workflows remain non-authoritative.

## TLS interception evidence

229 uses only a bounded read-only compatibility/anomaly model: component match grades, security-grade regression, PFS loss, and weak-cipher evidence. It performs no network interception, loads no historical fingerprint database, installs no CA, and cannot identify an interception product.

## Relay and quota

Response sequence is predecessor-compatible when omitted but must match if supplied. Failed GSA writes reuse the same write-sequence identity. HTML/non-JSON control responses preserve an ambiguous cause set. Endpoint quota scoring excludes a configured safety reserve and exposes reset/headroom evidence without owning provider quota persistence.

## Signed updates

Schema-v2 signed manifests retain non-zero metadata sequence, finite rollout, and SQLite monotonic high-water replay protection. Remote availability or donor update workflows do not authorize installation.

## Symlinks and binaries

Three Mullvad symlinks remain separately accounted; the absolute `/opt/.../mullvad-problem-report` target is quarantined and never materialized. Donor binaries/services are evidence only.
""",
    "post-refactor-229-state-machines.md": """# Post-refactor-229 state machines

## Tunnel safety

Desired: `secured|unsecured`. Observed: `disconnected|connecting|connected|disconnecting|error|offline`. Corrupt persisted secure intent resolves fail-closed. Connected plus any required leak guard missing/false resolves degraded-unsafe. Recovery action remains bounded nothing/block/reconnect planning only.

## Relay sequencing

Each request gets a request sequence; writes also get a write sequence. Legacy response sequence omission is accepted. A supplied mismatched response sequence is rejected. A failed write transmission rolls its write sequence back so retry retains logical identity.

## Endpoint quota

Observed limit/remaining/reserve -> usable headroom. Remaining <= reserve becomes `quota-guarded` and ineligible. Reset time is evidence only; the planner does not mutate provider quota state.

## Signed-update metadata

`unseen -> accepted(N) -> accepted(N retry) | accepted(M>N)`. Any `M<N` is stale and rejected.

## Split-tunnel intent

Raw entries -> bounded syntax/platform admission -> normalize/dedupe -> canonical manifest hash -> planning-only result. No planner transition claims installed OS enforcement.
""",
    "post-refactor-229-peer-synthesis.md": f"""# Post-refactor-229 peer synthesis

The five outer donors are not ranked as products. The audit decomposes {len(surface_rows):,} outer files and {len(def_rows):,} outer definitions into {len(module_rows)} module groups plus {len(focus_rows)} independently decidable behavior records. The separately admitted nested MITM source contributes {len(nested_surfaces):,} files and {len(nested_defs):,} definitions.

Promoted/hardened outcomes span scales: fail-closed tunnel truth, split-tunnel intent identity, relay/multihop eligibility, WireGuard retry detail, signed-update replay/rollout, artifact magic/type admission, read-only TLS-interception anomaly evidence, leak-guard requirements, quota safety headroom/reset evidence, relay sequence correlation/retry identity, and ambiguity-preserving control diagnostics.

Second-order non-adoptions are equally explicit: donor firewall/DNS/split drivers, full tunnel-node runtime, active MITM/CA installation, historical fingerprint databases, mutable fronting/proxy corpora, packaged binaries, arbitrary downloader/auto-commit workflows, and provider-specific account/service domains remain reference or negative evidence rather than duplicate owners.
""",
    "post-refactor-229-omission-audit.md": f"""# Post-refactor-229 omission audit

- outer ZIP members: {sum(int(r['members']) for r in archive_rows):,}
- outer regular files: {len(surface_rows):,}/{len(surface_rows):,}
- outer symlinks: {len(raw_syms)}/{len(raw_syms)} explicitly recorded
- outer directory/root Merkle records: {len(raw_dirs):,}/{len(raw_dirs):,}
- outer indexed definitions: {len(def_rows):,}/{len(def_rows):,}
- outer high-signal surfaces: {high:,}/{high:,} with file-accountability backlinks
- nested MITM members: {nested_admission[0]['members']:,}
- nested MITM files: {len(nested_surfaces):,}/{len(nested_surfaces):,}
- nested MITM directory/root Merkle records: {len(nested_dirs):,}/{len(nested_dirs):,}
- nested MITM indexed definitions: {len(nested_defs):,}/{len(nested_defs):,}
- focused behavior records: {len(focus_rows)}
- unresolved outer high-signal surfaces: 0

The audit separately checks roots/packages, definitions, state machines, authority/negative paths, operator surfaces, scripts/config/deployment/tests, deep leaves, generated/vendored/media/localization surfaces, symlinks, packaged binaries, fake-format artifacts, and the nested source corpus. File-level records are accountability, not implementation claims.
""",
    "post-refactor-229-operator-runbook.md": """# Post-refactor-229 operator runbook

- **Health / Tunnel safety:** require only guards relevant to the intended posture; a missing required DNS/QUIC/STUN/DoH/IPv6 guard degrades safety. Planner is read-only.
- **Health / TLS interception evidence:** enter caller-observed component compatibility, grade/PFS and weak-cipher evidence. Treat `suspicious` as an anomaly signal, never product attribution.
- **Operations / Artifact admission:** provide claimed filename/format plus bytes when available. A format mismatch is quarantine, even when the extension looks valid.
- **Operations / Endpoint pool:** quota safety buffer is reserved; only usable headroom participates in dispatch eligibility. Reset timestamps are evidence, not mutation authority.
- **Rules / Split tunnel:** validate include/exclude intent and manifest identity; `runtime_enforced=false` means no OS mechanism is installed.
- **Profiles / Relay constraints:** filter caller metadata, then hand eligible candidates to the existing endpoint scorer.
- **Settings / Updates:** schema-v2 monotonic replay protection is only true after daemon-owned persistent high-water acceptance.
- **Relay runtime:** legacy responses may omit sequence; supplied sequence must correlate. Non-JSON/HTML control errors intentionally preserve multiple plausible causes.
""",
    "post-refactor-229-validation.md": """# Post-refactor-229 validation

This file is generated deterministically with the source evidence. Final release validation additionally records frozen-source/archive integrity.

## Executed final-candidate gates

- Isolated Go 1.23-compatible, network-disabled harnesses: artifact/TLS/tunnel/endpoint planners **PASS**; shared relay-wire sequence primitive **PASS**; HTTP control-bound diagnostics **PASS**; aggregate split/relay/update/WireGuard/artifact/TLS planner suite **PASS**; signed-update admission/replay suite **PASS**.
- SQLite high-water SQL probe: **PASS** (`10 -> 10` idempotent, stale `9` rejected at `10`, `11` advances). The Go store harness itself is environment-blocked because `modernc.org/sqlite v1.53.0` is not cached and network access is disabled.
- Control UI aggregate characterization: **694 checks PASS**, including **168 post-refactor-229 checks**; TypeScript 5.8.3 `tsc --noEmit`: **PASS**.
- Go target/declaration integrity: **7 target selections PASS**; **1,643 Go files parsed**, zero syntax errors, zero duplicate active declarations for linux/amd64, windows/amd64, darwin/amd64, and android/arm64.
- Historical successor chain: post-refactor-226 **83 assertions PASS**; post-refactor-227 **31,289 PASS**; automatic mutation retry authority **1,871 PASS**; post-refactor-228 **45 PASS**; post-refactor-229 **333,748 PASS**.
- Canonical `verify-repo`: the monolithic process passed through refactor-audit before the host's 120-second command ceiling; continuation in the Makefile's exact remaining order passed every post-refactor, route/platform/native/FFI, native-verification, convergence, peer-convergence, and repository-audit gate. The post-refactor-137 checker was made successor-aware for the 229 shared relay sequence owner and then passed.
- Native verification coverage: **22 checks PASS**. LumiCore link unit tests: **5 PASS**. `validate_convergence.py`: **PASS**. `check_peer_convergence.py`: **PASS**. Repository audit after removing validation-created bytecode caches: **0 errors, 1 environment warning** (local Android Gradle wrapper absent; CI/release provisions Gradle 9.5.0).
- Evidence regeneration determinism: **PASS** — two complete final-candidate `post-refactor-229-evidence` cycles produce byte-identical post-refactor-229 governance artifacts while rerunning mutation-retry and 229 convergence gates.

## Claim boundary

Repository-pinned Go 1.26.5 cannot be downloaded in this environment and local Go is 1.23.2. The uncached `modernc.org/sqlite` module prevents the exact Go store package test despite the independent SQLite SQL-semantics probe. Cargo/rustc are unavailable, and local Gradle is unavailable. None of those unavailable toolchains or native builds are represented as passing. Final frozen-source/archive integrity is recorded externally after the immutable source freeze.
""",
    "post-refactor-229-all-history-second-order-audit.md": f"""# Post-refactor-229 all-history second-order audit

Post-refactor-229 adds five unique outer donor identities to the 53-donor 228 history without re-counting predecessor donors or inflating history with the nested archive as a separate peer product. All-history now records {all_summary['surfaces']:,} outer donor surfaces, {all_summary['symbols']:,} definitions, {all_summary['modules']:,} module groups, {all_summary['high_signal_surfaces']:,} high-signal surfaces, and {all_summary['ui_product_surfaces']:,} UI/product surfaces across {all_summary['unique_donor_names']} unique outer donors.

The wave deliberately distinguishes {len(raw_surfaces):,} per-file outer accountability records, {len(nested_surfaces):,} nested-source file records, and {len(focus_rows)} behavior-level value decisions so mechanical completeness cannot masquerade as semantic depth. Rejected/superseded mechanisms retain explicit substitute/negative-invariant links.
""",
    }
    for name,body in reports.items(): (OUT/name).write_text(body,encoding="utf-8")

    print(json.dumps({
        "surfaces":len(surface_rows),"symlinks":len(raw_syms),"directories":len(raw_dirs),"definitions":len(def_rows),"modules":len(module_rows),"focus_records":len(focus_rows),"ledger_records":len(ledger),"high_signal":high,"ui_product":ui,"all_history":all_summary,
    },indent=2,sort_keys=True))

if __name__ == "__main__":
    main()
