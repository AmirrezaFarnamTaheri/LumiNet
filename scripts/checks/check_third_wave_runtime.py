#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SUCCESSOR_226 = (ROOT / "governance/convergence/post-refactor-226-baseline-files.csv").is_file()


def text(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        raise AssertionError(f"missing required file: {rel}")
    return p.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *tokens: str) -> None:
    body = text(rel)
    for token in tokens:
        if token not in body:
            raise AssertionError(f"{rel}: missing {token!r}")


def check_runtime() -> None:
    require(
        "src/apps/daemon/internal/networking/proxyconfig/types.go",
        "CipherSuites string",
        "ECHConfigList string",
        "VerifyPeerCertByName string",
        "PinnedPeerCertSHA256 string",
        "FinalMask string",
        "XHTTPMode  string",
        "XHTTPExtra string",
        "SpiderX string",
        "Hysteria2PortHopping string",
        'strings.HasPrefix(lowered, "purguard://")',
    )
    require(
        "src/apps/daemon/internal/networking/proxyconfig/finalmask.go",
        "MaxFinalMaskBytes = 16 * 1024",
        "func DecodeFinalMask",
        "json.Unmarshal",
    )
    require(
        "src/apps/daemon/internal/networking/proxyconfig/xhttp.go",
        "MaxXHTTPExtraBytes = 16 * 1024",
        "func CanonicalXHTTPTransport",
        'case "xhttp", "splithttp"',
        "func BuildXrayXHTTPSettings",
    )
    require(
        "src/apps/daemon/internal/networking/proxyconfig/xray_tls.go",
        "func BuildXrayTLSSettings",
        'out["cipherSuites"]',
        'out["echConfigList"]',
        'out["verifyPeerCertByName"]',
        'out["pinnedPeerCertSha256"]',
    )
    if re.search(r'out\s*\[\s*["\']allowInsecure["\']\s*\]', text("src/apps/daemon/internal/networking/proxyconfig/xray_tls.go")):
        raise AssertionError("Xray TLS builder must not emit allowInsecure")
    require(
        "src/apps/daemon/internal/networking/proxyconfig/hysteria2_fields.go",
        "maxHysteria2PortHoppingEntries = 32",
        "func ParseHysteria2PortHopping",
        "func BuildXrayHysteria2Settings",
        "requires an explicit Xray FinalMask udpHop policy",
    )
    require(
        "src/apps/daemon/internal/networking/proxyconfig/core_compat.go",
        "func ValidateSingBoxCompatibility",
        "Xray-specific",
    )
    require(
        "src/apps/daemon/internal/networking/proxyconfig/parser_hy2.go",
        'q.Get("mport")',
        'q.Get("pinSHA256")',
        'q.Get("fm")',
    )
    require(
        "src/apps/daemon/internal/networking/proxyconfig/parser_vless.go",
        'q.Get("spx")',
        'q.Get("fm")',
        'q.Get("extra")',
    )
    require(
        "src/apps/daemon/internal/networking/proxyconfig/parser_wg.go",
        "purguard://",
        "presharedkey",
    )
    require(
        "src/apps/daemon/internal/runtime/proxy/proxyconfig_internal.go",
        "buildXrayTLSSettings",
        "buildXrayXHTTPSettings",
        "parseHysteria2PortHopping",
        "buildXrayHysteria2Settings",
        "validateSingBoxCompatibility",
    )
    core = text("src/apps/daemon/internal/runtime/proxy/core_manager.go")
    for token in (
        "validateSingBoxCompatibility(proxy)",
        'wgOutbound["pre_shared_key"] = proxy.PreSharedKey',
        'peer["preSharedKey"] = proxy.PreSharedKey',
        "case protocolHysteria2:",
        'streamSettings["xhttpSettings"] = xhttpSettings',
        'streamSettings["hysteriaSettings"] = hysteriaSettings',
        'realitySettings["spiderX"] = proxy.SpiderX',
        'streamSettings["finalmask"] = finalMask',
        "buildXrayTLSSettings(proxy)",
        'proxy.Protocol != protocolHysteria2',
    ):
        if token not in core:
            raise AssertionError(f"core_manager.go: missing {token!r}")
    require(
        "src/apps/daemon/internal/runtime/proxy/hysteria2_obfs.go",
        'ServerPorts []string `json:"server_ports,omitempty"`',
        'out["server_ports"] = cfg.ServerPorts',
    )

    validation = text("src/apps/daemon/internal/analysis/diagnostics/sni_validation.go")
    if "maxSniSpoofLength = 219" in validation:
        for token in ("func validSNI", "len(s) > maxSniSpoofLength"):
            if token not in validation:
                raise AssertionError(f"sni_validation.go: missing {token!r}")
    else:
        # post-refactor-227 successor: SNI length/shape validation was moved to
        # the single lower networking/tlsdecoy owner used by diagnostics and
        # the live tunnel. Preserve the original third-wave contract without
        # requiring a duplicate local validator.
        for token in ("maxSniSpoofLength = tlsdecoy.MaxSNIBytes", "func validSNI", "tlsdecoy.ValidSNI"):
            if token not in validation:
                raise AssertionError(f"sni_validation.go successor: missing {token!r}")
        require(
            "src/apps/daemon/internal/networking/tlsdecoy/decoy.go",
            "MaxSNIBytes",
            "= 219",
            "func ValidSNI",
        )
    sni = text("src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go")
    for token in (
        "maxSniSpoofCandidates  = 4096",
        "maxSniSpoofConcurrency = 64",
        "io.ReadFull(conn, header)",
        "validSNI(fakeSni)",
        "SniSpoofInvalidSNI",
        "SniSpoofCancelled",
        "SniSpoofBudgetExceeded",
    ):
        if token not in sni:
            raise AssertionError(f"sni_spoof_scan.go: missing {token!r}")
    # Budget must be checked before the per-candidate result allocation.
    budget_pos = sni.index("len(snis) > maxSniSpoofCandidates")
    alloc_pos = sni.index("make([]SniSpoofResult")
    if budget_pos > alloc_pos:
        raise AssertionError("SNI candidate budget is enforced after result allocation")

    require(
        "src/apps/daemon/internal/runtime/proxy/accept_backoff.go",
        "func acceptBackoffForError",
        "syscall.EMFILE",
        "syscall.ENFILE",
        "acceptFDExhaustBackoff",
    )
    # The third-wave local Shadowsocks listener was a valid historical owner at
    # that release boundary. Post-refactor-226 deliberately retires it after
    # proving it had no consumers and consolidates Shadowsocks execution in the
    # maintained external core-manager path. Preserve the historical assertion
    # on original/pre-226 trees, but verify the explicit successor contract on
    # 226+ instead of requiring dead duplicate authority to be resurrected.
    if SUCCESSOR_226:
        retired = ROOT / "src/apps/daemon/internal/runtime/proxy/ss_server.go"
        if retired.exists():
            raise AssertionError("post-226 successor must keep retired ss_server.go absent")
        for token in (
            "case protocolShadowsocks:",
            "case protocolSOCKS5:",
            "case protocolHTTP:",
            'fmt.Errorf("unsupported protocol %q for sing-box outbound", proxy.Protocol)',
            'fmt.Errorf("unsupported protocol %q for Xray outbound", proxy.Protocol)',
        ):
            if token not in core:
                raise AssertionError(f"core_manager.go: missing post-226 Shadowsocks successor token {token!r}")
        require(
            "src/apps/daemon/internal/networking/proxyconfig/parser_ss.go",
            "validateShadowsocks2022Key",
        )
    else:
        require("src/apps/daemon/internal/runtime/proxy/ss_server.go", "waitAfterAcceptError")
    require("src/apps/daemon/internal/runtime/proxy/gfwknocker.go", "waitAfterAcceptError")

    # Protect the already-promoted second-order source-health authority.
    require(
        "src/apps/daemon/internal/integrations/sub/profile_service.go",
        "AutoRefresh",
        "SourceHealth",
        "func (s *ProfileService) QueueDueRefreshes",
        "func (s *ProfileService) StartAutoRefresh",
    )


def check_corpus_sanitization() -> None:
    rel = "governance/convergence/third-wave-corpora.json"
    raw = text(rel)
    doc = json.loads(raw)
    pur = doc.get("purvpn", {})
    if pur.get("unique_share_uris_classified") != 2827:
        raise AssertionError("sanitized PurVPN corpus denominator must be 2827")
    if sum(pur.get("schemes", {}).values()) != 2827:
        raise AssertionError("PurVPN scheme counts must sum to 2827")
    # Aggregates may name schemes but must not contain live URI payloads.
    if re.search(r"(?i)(?:vless|vmess|trojan|ss|hysteria2|wireguard|purguard)://", raw):
        raise AssertionError("sanitized corpus contains a raw proxy/share URI")
    if "@" in raw:
        raise AssertionError("sanitized corpus unexpectedly contains endpoint-like '@' data")


def main() -> int:
    try:
        check_runtime()
        check_corpus_sanitization()
    except AssertionError as exc:
        print(f"third-wave runtime: FAIL: {exc}", file=sys.stderr)
        return 1
    print("third-wave runtime: proxy/core=ok sni=ok accept=ok source-health=ok corpus-sanitized=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
