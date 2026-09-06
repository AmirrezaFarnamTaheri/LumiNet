#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors = []

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

contract = text("src/apps/daemon/internal/runtime/proxy/evasion_contract.go")
manager = text("src/apps/daemon/internal/runtime/proxy/evasion_tunnel.go")
fragment = text("src/apps/daemon/internal/runtime/proxy/fragment_helper.go")
dial = text("src/apps/daemon/internal/runtime/proxy/evasion_tunnel_dial.go")
socks = text("src/apps/daemon/internal/runtime/proxy/evasion_tunnel_socks.go")
api = text("src/apps/daemon/internal/adapters/api/handlers_system_evasion.go")
cmd = text("src/apps/daemon/cmd/system.go")

for mode in ("dnstunnel", "gdocs", "gdrive"):
    if mode not in contract:
        errors.append(f"covert capability truth does not classify {mode}")
if "simulation-only" not in contract or "simulator mode is not a production transport" not in contract:
    errors.append("simulation-only covert transports are not fail-closed")
if (ROOT / "src/apps/daemon/internal/runtime/proxy/dns_tunnel.go").exists():
    errors.append("simulation-only DNS tunnel implementation returned to active source")
if 'case "dnstunnel":' not in dial or "no production DNS tunnel transport is implemented" not in dial:
    errors.append("internal DNS tunnel dial branch does not fail closed")
if "if err := validateEvasionConfig(newCfg); err != nil" not in manager:
    errors.append("evasion Start does not validate capability before listener ownership")
if "redactEvasionSecret(newCfg.CovertGsaKey)" not in manager:
    errors.append("startup log can expose the GSA credential")
if "GetRedactedConfig()" not in api:
    errors.append("HTTP status does not consume the module-owned redacted snapshot")
if "return nil" not in fragment.split("if err != nil", 1)[-1].split("}", 1)[0]:
    errors.append("fragment entropy failure is not fail-closed")
import re
if re.search(r"proxy\.DefaultEvasion(?!Config)", api) or re.search(r"proxy\.DefaultEvasion(?!Config)", cmd):
    errors.append("transport adapters still import individual evasion default constants")
if "proxy.EvasionConfig{" in api or "proxy.EvasionConfig{" in cmd:
    errors.append("transport adapters still construct the full evasion implementation config from zero values")
if "proxy.DefaultEvasionConfig()" not in api or "proxy.DefaultEvasionConfig()" not in cmd:
    errors.append("transport adapters do not start from the canonical evasion default snapshot")
for legacy in ("SetCovertConfig(", "GetCovertConfig(", "GetCovertGsaKey(", "GetCovertGdocsAccessToken("):
    if legacy in api or legacy in manager:
        errors.append(f"split evasion configuration seam remains active: {legacy[:-1]}")
if "RestoreRedactedSecrets" not in contract or "RestoreRedactedSecrets" not in api:
    errors.append("evasion owner does not restore redacted secret round-trips before Start")
for rel in ("covert_gdocs.go", "gdrive_transport.go"):
    covert = text("src/apps/daemon/internal/runtime/proxy/" + rel)
    if "UseSimulator" in covert or "Simulation Mode" in covert:
        errors.append(f"{rel}: simulator mode returned to product transport")
    if "context.Background()" in covert:
        errors.append(f"{rel}: virtual connection detached from evasion/request lifetime")

# Every canonical field must either be mapped by an adapter or have one explicit
# defaulted/unsupported disposition. This prevents silent field drift as the
# canonical config evolves.
config_body = re.search(r"type EvasionConfig struct \{(.*?)\n\}", manager, re.S)
if not config_body:
    errors.append("cannot enumerate canonical evasion fields")
else:
    fields = {
        match.group(1)
        for match in re.finditer(r"(?m)^\s*([A-Z]\w*)\s+", config_body.group(1))
    }
    cli_mapped = set(re.findall(r"\bevasionCfg\.([A-Z]\w*)\s*=", cmd))
    api_mapped = set(re.findall(r"\bevasionCfg\.([A-Z]\w*)\s*=", api))
    cli_defaulted = {
        "PrecisionSniSplits", "RandomMultiSplit", "NumFragments", "HostsOverride",
        "ShadowsocksPrefix", "AutoReconnectEnabled", "AutoReconnectMaxTries",
        "AutoReconnectDelayMs",
    }
    cli_unsupported = {"CovertCfg"}
    api_defaulted = {
        "RandomMultiSplit", "NumFragments", "HostsOverride", "ShadowsocksPrefix",
        "AutoReconnectEnabled", "AutoReconnectMaxTries", "AutoReconnectDelayMs",
    }
    if fields != cli_mapped | cli_defaulted | cli_unsupported:
        errors.append(
            "CLI evasion field dispositions drifted: "
            f"missing={sorted(fields - cli_mapped - cli_defaulted - cli_unsupported)} "
            f"unexpected={sorted((cli_mapped | cli_defaulted | cli_unsupported) - fields)}"
        )
    if fields != api_mapped | api_defaulted:
        errors.append(
            "HTTP evasion field dispositions drifted: "
            f"missing={sorted(fields - api_mapped - api_defaulted)} "
            f"unexpected={sorted((api_mapped | api_defaulted) - fields)}"
        )
if "DefaultEvasionConfig() EvasionConfig" not in manager:
    errors.append("canonical evasion default snapshot is missing")
if "DefaultEvasionUpgenQuicExhaustionRate = 0" not in manager:
    errors.append("retired UPGen QUIC exhaustion rate is not defaulted off")
if "UPGen QUIC exhaustion is not a production-supported capability" not in contract:
    errors.append("retired UPGen QUIC exhaustion compatibility field can still activate behavior")
crypto_cfg = text("src/apps/daemon/internal/foundation/crypto/cfg_compiler.go")
for retired in ("GenerateQUICClientInitial", "StartQUICExhaustionLoop"):
    if retired in crypto_cfg or retired in manager:
        errors.append(f"retired pseudo-QUIC exhaustion implementation returned: {retired}")
if "handleSocksConnection(ctx context.Context, client net.Conn, cfg EvasionConfig)" not in socks:
    errors.append("SOCKS session still exposes the evasion implementation as a long argument train")
if "dialWithEvasion(ctx context.Context, host string, port uint16, cfg EvasionConfig)" not in dial:
    errors.append("outbound dial still exposes the evasion implementation as a long argument train")
for marker in ("lifecycleMu", "acceptWG", "sessionWG", "backgroundWG", "activeSessions", "stopAndWait"):
    if marker not in manager:
        errors.append(f"evasion runtime does not own quiescent session lifetime: missing {marker}")
if "m.acceptWG.Wait()" not in manager or "m.closeActiveSessions()" not in manager or "m.sessionWG.Wait()" not in manager:
    errors.append("evasion Stop does not join accept/session ownership in order")

# Windows raw packet injection is an optional external-runtime seam. The source
# distribution does not own a WinDivert binary supply chain; stale fetch or
# installer helpers must not imply otherwise.
for retired in (
    "scripts/fetch_windivert.json",
    "scripts/fetch_windivert.ps1",
    "scripts/install/luminet.json",
):
    if (ROOT / retired).exists():
        errors.append(f"unsupported Windows dependency/install surface returned: {retired}")

release = text(".github/workflows/release.yml")
if "WinDivert.dll" in release or "WinDivert64.sys" in release:
    errors.append("release workflow unexpectedly bundles WinDivert without a governed supply-chain contract")

evasion_doc = text("docs/architecture/evasion-protocols.md")
if "WinDivert is not bundled" not in evasion_doc or "operator-supplied" not in evasion_doc:
    errors.append("evasion architecture does not state the external WinDivert runtime dependency")

divert_stub = text("src/apps/daemon/internal/runtime/proxy/evasion_divert_stub.go")
divert_common = text("src/apps/daemon/internal/runtime/proxy/evasion_divert.go")
linux_divert = text("src/apps/daemon/internal/runtime/proxy/evasion_divert_linux.go")
if 'return errors.New("packet injection not supported on this platform")' not in divert_stub:
    errors.append("unsupported packet-injector stub still reports success")
if 'return errors.New("raw bypass not supported on this platform")' not in divert_stub:
    errors.append("unsupported raw-bypass stub still reports success")
if 'if err := InstallRstDropRule' not in divert_common or 'if err := StartBypassSniffer' not in divert_common:
    errors.append("Paqet raw-bypass setup still discards platform setup failures")
if 'open packet capture socket' not in linux_divert:
    errors.append("Linux packet injector does not acquire raw capture resource before reporting success")
if 'start requested packet injector' not in manager:
    errors.append("evasion Start does not fail when a requested packet injector cannot start")
conn = text("src/apps/daemon/internal/runtime/proxy/evasion_tunnel_conn.go")
if "_ = bridge.InjectFakePacket" in conn:
    errors.append("evasion fake-packet injection still discards native/degraded bridge failures")
if "fake packet injection unavailable" not in conn:
    errors.append("evasion fake-packet injection does not fail closed when requested technique is unavailable")

print(f"evasion-truth errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
