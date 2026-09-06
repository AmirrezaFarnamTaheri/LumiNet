#!/usr/bin/env python3
"""Generate concise, navigational .context files for LumiNet source folders."""
from __future__ import annotations
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
DAEMON = SRC / "apps" / "daemon"
INTERNAL = DAEMON / "internal"
MODULE = "github.com/maybeknott/luminet/"

BAND_INFO = {
    "foundation": (0, "Deep shared state and policy primitives: configuration, cryptography, persistence, evidence, secrets, redaction, traffic accounting, and caches."),
    "native": (0, "Deep host/native seam. Owns Go↔Rust/C ABI declarations, memory ownership, and native bridge calls."),
    "protocols": (1, "Reusable transport/protocol implementations built on foundation/native primitives; no product orchestration or HTTP knowledge."),
    "platform": (1, "Host-OS implementation. Owns host-network mutations, process integration, and mobile platform adapters."),
    "networking": (2, "Network data-plane primitives: DNS, routing, canonical proxy parsing, CIDR math, and geolocation support."),
    "analysis": (3, "Observation and diagnosis modules: scanner execution, network diagnosis, and provider-corpus classification."),
    "integrations": (3, "External-system adapters and ingestion modules: subscriptions, provisioning, notifications, relays, presets, and CAPTCHA solving."),
    "runtime": (4, "Runtime owners for live network behavior. Hides long-lived/ephemeral engine lifecycle and evasion/proxy execution behind deep interfaces."),
    "workflows": (5, "Application workflows that coordinate lower modules: typed async jobs and scheduling."),
    "adapters": (6, "Product adapters. Translate HTTP/gomobile input into lower-module interfaces; must not become competing state owners."),
}

PURPOSES = {
"capabilities":"Capability/workflow registry and availability classification used to keep public capability truth explicit.",
"config":"Daemon configuration schemas, defaults, templates, and config normalization; configuration knowledge is centralized here rather than duplicated in callers.",
"crypto":"Go cryptographic and TPM helpers used by configuration/runtime code; contains key wrapping, obfuscation, and platform-backed cryptographic support.",
"evidence":"Evidence-domain types and repository-facing helpers for durable diagnostic/job evidence.",
"pingcache":"Bounded ping-result cache used to avoid repeating recent reachability work.",
"redact":"Central value redaction helpers for logs, public responses, and persisted safe snapshots.",
"secrets":"Secret-store interface plus platform/file adapters; secret persistence and retrieval stay behind this module.",
"store":"SQLite ownership, append-only migrations, job/evidence persistence, and related durable storage adapters.",
"trafficstats":"Authoritative cumulative traffic accounting and rate sampling used by telemetry truth.",
"bridge":"Go↔LumiCore native bridge, private C ABI header, shared-memory helpers, callback ownership, and compatibility calls.",
"arq":"Automatic-repeat-request primitives for reliable packet/tunnel delivery.",
"asyncreactor":"Small asynchronous reactor primitive used by runtime networking code.",
"reliable":"Reliable transport helpers used by DNS/networking implementations.",
"tarpit":"Platform-aware socket tarpit behavior, rate/lifecycle control, native bridge integration, and local structured logging.",
"tlsfragment":"uTLS/TLS fragmentation primitive used by diagnostics/runtime evasion.",
"system":"Host platform authority: transactional DNS/proxy/firewall/TUN mutations, recovery, OS inspection, and platform-specific network adapters.",
"dns":"DNS resolution, DoH, DNS tunneling/support, preflight checks, and stateless smart fallback resolution.",
"geoip":"GeoIP and blocklist lookup primitives used by DNS and transport adapters.",
"proxyconfig":"Canonical per-node proxy configuration types and URI parsers. Other modules consume these types instead of maintaining parser facades.",
"routing":"Domain, per-app, and rule-based routing policy/data ownership, including embedded domain lists and dynamic override matching.",
"diagnostics":"Network diagnosis and analysis owner: censorship diagnosis, clean-IP probing, IP posture, CDN/anti-bot inspection, TLS/SNI/HTTP/throughput checks, and result interpretation.",
"provider":"Immutable provider corpus, lookup, manifest, and activation primitives used by scanner/API provider workflows.",
"scanner":"Active scanner implementation: supported scan/session logic, throttling, protocol probes, progress, and result models.",
"captchaclient":"External CAPTCHA-solving adapter used by subscription/mobile/product flows.",
"notifier":"Notification adapter invoked by daemon command/workflow composition.",
"presets":"Curated configuration/preset data exposed through product adapters.",
"provision":"VPS/Cloudflare/Terraform provisioning implementation and billing schema.",
"relayclient":"External relay adapters (GSA/serverless), relay wire types, and their dial behavior behind one integration module.",
"sub":"Subscription ingestion owner: safe remote fetch, format detection/normalization, profile state, and daemon-owned refresh lifetime.",
"proxy":"Primary evasion and proxy-qualification runtime. Owns evasion lifecycle/dialing/transports plus Xray/sing-box qualification; mobile platform/runtime, safety, trust, routing-provider policy, and decoy traffic are separate owners.",
"runtimecore":"Long-lived daemon runtime-engine owner for Tor/Psiphon lifecycle and status; intentionally separate from temporary proxy qualification cores.",
"warp":"WireGuard/WARP scanning, configuration, and runtime support used by proxy/API flows.",
"mobilehost":"Shared mobile platform seam: socket protection, process lookup, and protected dialing used by both proxy and mobile runtime owners.",
"decoy":"Daemon-owned background decoy-traffic runtime with explicit start/cancel/join lifecycle and bounded request work.",
"mobilecore":"Deep mobile runtime owner: CoreController, TUN lifecycle, canonical mobile/evasion config translation, callbacks, status, and stats. Mobilebind remains only an adapter.",
"routingplugin":"Routing-provider policy owner: provider registry/validation, readiness policy, and concrete provider adapters such as Psiphon and Windscribe.",
"safety":"Canonical safety-policy owner shared by HTTP, mobile, and runtime sidecars; one policy truth across adapters.",
"trust":"Canonical peer trust/reputation state and scoring owner used by runtime routing and diagnostic feedback.",
"jobs":"Typed async job-intent owner, queue/worker lifecycle, secret-safe history, progress/events, completion evidence, and execution adapters.",
"scheduler":"Job/workflow scheduling and runner coordination.",
"api":"Gin HTTP/WebSocket adapter and served-route inventory. Translates requests into lower-module intent and reports capability truth without owning competing runtime state.",
"mobilebind":"Gomobile adapter over canonical runtime/evasion/safety owners; only JSON/string/platform translation belongs here.",
}

SPECIAL_INVARIANTS = {
"api":["Gin registration plus GET /api/routes is served-route truth.","Request-scoped work propagates request context; handlers do not create daemon lifetime.","Disconnected/simulated features fail closed instead of reporting operational success."],
"jobs":["Execution-only credentials stay in in-memory Job intent and never enter public/persisted history.","Runners consume typed intents; no private JSON execution schema may return."],
"proxy":["Evasion configuration/defaulting/redaction/lifecycle stay owned by the evasion runtime.","Xray/sing-box qualification is ephemeral and remains separate from long-lived runtimecore engines."],
"runtimecore":["Tor/Psiphon are long-lived daemon-owned runtime adapters.","Runtime engine lifetime is started/stopped/joined by daemon lifetime, never HTTP request lifetime."],
"sub":["Remote subscription fetch, parsing/normalization, profile state, and refresh lifetime have one owner.","Per-node semantics use networking/proxyconfig rather than another parser representation."],
"mobilebind":["Adapter-only: no duplicate runtime/evasion/safety state or defaults.","Public JSON must use redacted canonical snapshots."],
"bridge":["Rust owns native implementations/layout; lumicore_abi.h is the single Go declaration authority.","Terminal stream completion owns callback/channel release ordering."],
"scanner":["Only product-reachable scanner behavior remains active; preserved dormant corpus stays under labs/.","Retirement requires symbol/build-tag/registration/reflection/native proof."],
"system":["Host-network mutations use the durable snapshot → recovery record → apply → verify → commit/rollback transaction.","Private TUN mutation seams do not escape this module."],
"proxyconfig":["This is the canonical per-node parser/type owner; parser compatibility facades must not return."],
"trafficstats":["Rates derive from authoritative cumulative counters; unknown measurements remain unknown."],
"store":["Database migrations are append-only compatibility history.","Persisted job configuration must remain secret-safe."],
"capabilities":["Capability truth distinguishes implemented/available from unavailable, degraded, simulated, or unverified behavior."],
"mobilehost":["Platform socket/process hooks have one owner shared by proxy and mobile runtime.","Protected dialing propagates caller context rather than creating detached lifetime."],
"mobilecore":["Mobile runtime lifecycle and TUN ownership live here; mobilebind is translation only.","Canonical evasion configuration is translated without creating a second default/state authority."],
"decoy":["Background work is daemon-owned, cancellation-aware, and joined before Stop returns."],
"routingplugin":["Provider policies are internal adapters behind one routing-provider interface.","Scanner/readiness facts are consumed, not re-owned."],
"safety":["HTTP, mobile, and runtime callers consult the same safety policy state."],
"trust":["Peer trust scores and ratings have one process owner; adapters do not duplicate reputation state."],
}

ROOT_PURPOSES = {
"src":"Authoritative product source root. Operational tooling, deployment assets, docs, governance evidence, labs, and third-party reference material intentionally live outside this tree.",
"src/apps":"Runnable product hosts and platform applications.",
"src/apps/daemon":"Primary Go daemon module: CLI composition roots, deep internal modules, and daemon-owned runtime behavior.",
"src/apps/daemon/cmd":"Cobra command composition roots. Commands wire dependencies and daemon lifetime; domain behavior belongs in internal modules.",
"src/apps/daemon/cmd/watchdog":"Standalone watchdog command and platform process/recovery adapters.",
"src/apps/daemon/internal":"Private daemon implementation organized by dependency band. Paths intentionally expose dependency direction, not feature popularity.",
"src/apps/desktop":"Wails desktop host. It embeds/serves the canonical shared control UI rather than owning a second frontend.",
"src/apps/android":"Android application build root and Gradle configuration for the generated Go mobile binding.",
"src/apps/android/app":"Android application module.",
"src/apps/android/app/libs":"Generated/external AAR placement. Binary artifacts are build inputs, not authoritative source.",
"src/apps/android/app/src":"Android application source sets.",
"src/apps/android/app/src/main":"Android main source set. Resource subtrees are documented here but excluded from .context injection to avoid packaging side effects.",
"src/apps/android/app/src/main/java":"Android JVM/Kotlin/Java source namespace root.",
"src/apps/android/app/src/main/java/com":"Java package namespace segment.",
"src/apps/android/app/src/main/java/com/luminet":"LumiNet Java package namespace.",
"src/apps/android/app/src/main/java/com/luminet/android":"Android Activity/VpnService product implementation and generated-binding integration.",
"src/packages":"Shared modules consumed by one or more product hosts.",
"src/packages/contracts":"Small dependency-neutral Go contracts shared by daemon and desktop hosts.",
"src/packages/contracts/buildinfo":"Build/version identity contract injected at build time.",
"src/packages/contracts/session":"Local session descriptor publication/discovery/parsing contract.",
"src/packages/control-ui":"Canonical authored React/Vite control UI plus a checked fail-closed bootstrap; CI/release builds replace dist/ with the production bundle.",
"src/packages/control-ui/scripts":"Frontend contract-test/build helper scripts.",
"src/packages/control-ui/src":"Authored React application source.",
"src/packages/control-ui/src/api":"Browser-side daemon API/WebSocket clients and request types.",
"src/packages/control-ui/src/pages":"Route-level UI pages and product workflows.",
"src/packages/control-ui/src/store":"Client-side application state stores.",
"src/packages/lumicore":"Rust native-core crate. Cargo is the compile/link authority; host ABI changes require Cargo plus Go ABI verification.",
"src/packages/lumicore/src":"Reachable Rust crate source graph. Unreachable/foreign alternates belong under labs/lumicore, not here.",
"src/packages/lumicore/tests":"Rust integration/ABI behavior tests outside individual modules.",
}

RUST_PURPOSE = {
"cidr":"CIDR parsing/range primitives.","crypto":"Native cryptographic primitives and key-exchange implementations.","data":"Native data structures/static data helpers.","diagnostics":"Native network diagnostic routines.","dns":"Native DNS parsing/probing logic.","evasion":"Native censorship/evasion algorithms that are actually reachable from the crate graph.","ffi":"C ABI envelopes, exports, versioning, streaming ownership, and host-call dispatch.","hs":"Hidden-service/onion-service primitives.","http":"Native HTTP probing/client helpers.","icmp":"ICMP scanning/probing engine.","netutil":"Low-level network utilities.","obfuscation":"Traffic/protocol obfuscation implementations.","protocol_detect":"Protocol-detection algorithms used by obfuscation.","platform":"OS-specific native platform abstractions.","proxy":"Native proxy protocol/runtime helpers.","relay":"Native relay support.","routing":"Native routing primitives.","scanner":"Native scanner engines/planning primitives.","security":"Native security-analysis primitives.","sni":"SNI/TLS hostname probing helpers.","socks":"SOCKS protocol support.","speed":"Throughput/speed measurement primitives.","system":"Native system/runtime helpers.","tcp":"TCP probing/transport primitives.","tls":"TLS probing, PQC, and certificate handling.","cert_installer":"Platform certificate-installation helpers used by TLS tooling.","transport":"Native transport implementations.","wg":"WireGuard probing/auditing primitives.",
}

GO_IMPORT_BLOCK = re.compile(r'import\s*\((.*?)\)', re.S)
GO_IMPORT_LINE = re.compile(r'import\s+(?:[._A-Za-z][\w.]*)?\s*"([^"]+)"')
QUOTED = re.compile(r'"([^"]+)"')
EXPORT_RE = re.compile(r'(?m)^\s*(?:type|func|var|const)\s+([A-Z][A-Za-z0-9_]*)')
PACKAGE_RE = re.compile(r'(?m)^\s*package\s+(\w+)')

def excluded(path: Path) -> bool:
    rel_path = path.relative_to(ROOT)
    rel = rel_path.as_posix()
    if rel == "src/packages/control-ui/dist" or rel.startswith("src/packages/control-ui/dist/"): return True
    if rel == "src/packages/control-ui/public" or rel.startswith("src/packages/control-ui/public/"): return True
    if rel == "src/apps/android/app/src/main/res" or rel.startswith("src/apps/android/app/src/main/res/"): return True
    # Inspect only repository-relative parts. Absolute checkout/workspace names
    # such as /.../target/... must not cause the entire source tree to be
    # mistaken for generated build output.
    if any(part in {"node_modules","target","build",".gradle"} for part in rel_path.parts): return True
    return False

def parse_imports(text: str) -> set[str]:
    out=set(GO_IMPORT_LINE.findall(text))
    for block in GO_IMPORT_BLOCK.findall(text): out.update(QUOTED.findall(block))
    return out

def source_files(d: Path):
    return sorted(p for p in d.iterdir() if p.is_file() and p.name != '.context')

# Build Go package dependency/caller metadata by directory.
go_dirs={}
for d in [p for p in SRC.rglob('*') if p.is_dir()]:
    gos=sorted(p for p in d.glob('*.go') if not p.name.endswith('_test.go'))
    if not gos: continue
    package=None; deps=set(); exports=[]
    for p in gos:
        text=p.read_text(encoding='utf-8',errors='replace')
        m=PACKAGE_RE.search(text)
        if m and package is None: package=m.group(1)
        deps.update(i for i in parse_imports(text) if i.startswith('github.com/maybeknott/luminet/'))
        exports.extend(EXPORT_RE.findall(text))
    go_dirs[d]={'package':package or d.name,'deps':sorted(deps),'exports':sorted(dict.fromkeys(exports))}
reverse=defaultdict(set)
# Resolve only daemon-local internal import paths to directories for caller display.
for d,meta in go_dirs.items():
    for imp in meta['deps']:
        if imp.startswith(MODULE+'internal/'):
            rel=imp[len(MODULE):]
            target=DAEMON/rel
            if target in go_dirs: reverse[target].add(d)

required=[SRC]+sorted(p for p in SRC.rglob('*') if p.is_dir() and not excluded(p))
for d in required:
    rel=d.relative_to(ROOT).as_posix()
    files=source_files(d)
    children=sorted(p.name for p in d.iterdir() if p.is_dir() and not excluded(p))
    purpose=ROOT_PURPOSES.get(rel)
    band=None; pkg_name=None
    try:
        ir=d.relative_to(INTERNAL)
        if ir.parts:
            band=ir.parts[0] if ir.parts[0] in BAND_INFO else None
            if len(ir.parts)>=2: pkg_name=ir.parts[1]
    except ValueError: pass
    if purpose is None and band and len(d.relative_to(INTERNAL).parts)==1:
        rank, purpose=BAND_INFO[band]
    if purpose is None and pkg_name:
        purpose=PURPOSES.get(pkg_name, f"Daemon {pkg_name} implementation module.")
    if purpose is None and 'src/packages/lumicore/src' in rel:
        purpose=RUST_PURPOSE.get(d.name, f"Reachable Rust `{d.name}` implementation module within LumiCore.")
    if purpose is None:
        purpose=f"Source folder `{rel}`. It groups the files and child modules listed below; behavior ownership stays with the nearest named module."

    lines=[f"# {rel}","", "## Purpose", purpose]
    if band:
        rank=BAND_INFO[band][0]
        lines += ["", "## Architectural role", f"- Daemon dependency band: `{band}` (rank {rank}; lower rank = deeper implementation).",
                  "- Cross-band imports may point only to a lower rank. Same-band imports are allowed when they remain within one architectural layer."]
    lines += ["", "## Contents"]
    if files:
        suffix=[]
        for p in files[:12]:
            suffix.append(f"`{p.name}`")
        lines.append(f"- Direct files ({len(files)}): " + ", ".join(suffix) + (" …" if len(files)>12 else ""))
    else: lines.append("- No direct source files; this folder is a namespace/organization node for child modules.")
    if children: lines.append("- Child folders: " + ", ".join(f"`{c}/`" for c in children) + ".")
    # Explicitly describe excluded packaged trees at nearest parent.
    if rel=='src/packages/control-ui': lines.append("- `dist/` is a checked fail-closed bootstrap that CI/release replaces with generated output; `public/` contains copied static assets. Neither receives nested `.context` files to avoid changing bundle contents.")
    if rel=='src/apps/android/app/src/main': lines.append("- `res/` contains Android packaged resources and is intentionally excluded from nested `.context` files to avoid AAPT/resource side effects.")

    lines += ["", "## Interfaces and dependencies"]
    meta=go_dirs.get(d)
    if meta:
        lines.append(f"- Go package: `{meta['package']}`.")
        if meta['exports']:
            shown=meta['exports'][:10]
            lines.append("- Notable exported surface: " + ", ".join(f"`{x}`" for x in shown) + (" …" if len(meta['exports'])>10 else "."))
        else: lines.append("- No exported Go declarations detected in direct files; treat this as implementation-only or namespace code.")
        local=[x for x in meta['deps'] if x.startswith(MODULE+'internal/')]
        external=[x for x in meta['deps'] if x not in local]
        lines.append("- Daemon-local dependencies: " + (", ".join(f"`{x[len(MODULE):]}`" for x in local) if local else "none") + ".")
        callers=sorted(reverse.get(d,set()))
        lines.append("- Direct daemon callers: " + (", ".join(f"`{c.relative_to(DAEMON).as_posix()}`" for c in callers) if callers else "none detected") + ".")
        if external: lines.append(f"- External/shared imports: {len(external)} distinct package(s); inspect source before changing dependency contracts.")
    elif rel.startswith('src/packages/lumicore/src'):
        lines.append("- Rust module membership is controlled by `mod.rs`/`lib.rs`; Cargo is compile authority.")
        lines.append("- Host-facing changes must preserve the versioned FFI envelope and private Go ABI declaration checks.")
    elif rel.startswith('src/packages/control-ui/src'):
        lines.append("- React/TypeScript source; imports flow through Vite/TypeScript module resolution and daemon calls go through the browser API adapter.")
    elif rel.startswith('src/apps/android'):
        lines.append("- Android/Gradle source or build metadata; runtime calls enter the generated Go mobile binding rather than a second native runtime.")
    else:
        lines.append("- See direct files and parent context for the interface consumed by sibling/parent modules.")

    lines += ["", "## Invariants"]
    inv=[]
    if pkg_name in SPECIAL_INVARIANTS: inv.extend(SPECIAL_INVARIANTS[pkg_name])
    if band:
        inv.append(f"`{band}` code must not import a higher-rank daemon band.")
    if rel.startswith('src/packages/lumicore'):
        inv.append("Do not advertise or promote dormant native surfaces without the Cargo/ABI/CGO verification gate.")
    if rel.startswith('src/packages/control-ui'):
        inv.append("This is the sole authored control UI; desktop/daemon hosts consume its canonical bundle rather than forking UI source.")
    if rel.startswith('src/apps/android'):
        inv.append("Android lifecycle authority remains VpnEngineService → generated Go mobile binding → canonical daemon/system owners.")
    if rel=='src':
        inv.extend(["All live product/application/shared-package source belongs under this root.","`docs/`, `governance/`, `labs/`, `scripts/`, `deploy/`, `tests/`, and `third_party/` remain outside because they are documentation/evidence/tooling/delivery/test/reference roots, not product source."])
    if not inv: inv.append("Keep behavior local to the named module; move cross-cutting policy to its canonical owner instead of duplicating it here.")
    for x in inv: lines.append(f"- {x}")
    lines += ["", "## Navigation", "- Read this file first, then direct child `.context` files before editing a deeper folder.", "- Update this context when ownership, supported interfaces, or child-folder meaning changes; do not use it as a changelog.", ""]
    (d/'.context').write_text('\n'.join(lines),encoding='utf-8')

print(f"generated {len(required)} .context files")
