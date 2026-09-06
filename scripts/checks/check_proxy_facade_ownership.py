#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
PROXY = ROOT / 'src/apps/daemon/internal/runtime/proxy'

# These files are compatibility-only facades over canonical owners. Keeping
# them active makes callers learn proxy plus the real module and defeats
# locality. Historical source belongs under labs once consumers migrate.
FACADES = {
    'async_reactor.go': 'asyncreactor',
    'captcha_solver.go': 'captchaclient',
    'censorship_doctor.go': 'censorshipdoctor',
    'clean_ip_prober.go': 'cleanipprobe',
    'fallback_router.go': 'relayserver',
    'geosite_routing_matcher.go': 'domainrouting',
    'gsa_relay.go': 'relayclient/gsa',
    'ip_security_analyzer.go': 'ipsecurity',
    'presets.go': 'presets',
    'provider_corpus.go': 'provider',
    'psiphon_parser.go': 'scanner',
    'reality_detector.go': 'relayserver',
    'relay_coalescer.go': 'relayclient/appsscript',
    'relay_server.go': 'relayserver',
    'serverless_dialer.go': 'relayclient/serverless',
    'smart_dns.go': 'smartdns',
    'tarpit.go': 'tarpit',
    'traffic_accounting.go': 'trafficstats',
    'utls_fragment.go': 'tlsfragment',
    'vpn_service_bridge.go': 'vpnstate',
    'warp_noise.go': 'warpnoise',
}

errors = []
for name, owner in FACADES.items():
    path = PROXY / name
    if path.exists():
        errors.append(f'src/apps/daemon/internal/runtime/proxy/{name}: shallow facade remains active; canonical owner is internal/{owner}')

print(f'proxy-facade-ownership facades={len(FACADES)} errors={len(errors)}')
for error in errors:
    print('ERROR:', error)
sys.exit(bool(errors))
