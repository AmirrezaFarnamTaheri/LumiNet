#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
router = (root / 'src/apps/daemon/internal/adapters/api/router.go').read_text(encoding='utf-8')
errors = []
if 'r.SetTrustedProxies(nil)' not in router:
    errors.append('API router does not disable implicit trust of forwarded client-IP headers')
if 'failed to disable API trusted proxies' not in router:
    errors.append('API trusted-proxy configuration failure is not fail-closed')
if errors:
    print(f'api direct-client-ip trust: errors={len(errors)}')
    for error in errors:
        print('ERROR:', error)
    raise SystemExit(1)
print('api direct-client-ip trust: errors=0')
