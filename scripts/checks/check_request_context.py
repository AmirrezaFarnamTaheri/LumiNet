#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / 'src/apps/daemon/internal/adapters/api'
errors = []

# HTTP handlers are request-owned: they must not detach work onto Background.
for path in sorted(API.glob('handlers_*.go')):
    if path.name.endswith('_test.go'):
        continue
    text = path.read_text(errors='replace')
    if 'context.Background()' in text:
        errors.append(f'{path.relative_to(ROOT)}: request handler uses context.Background()')
    if re.search(r'\bgo\s+(?:func\s*\(|[A-Za-z_][A-Za-z0-9_.]*\s*\()', text):
        errors.append(f'{path.relative_to(ROOT)}: request handler starts detached goroutine')

# Readiness checks invoked over HTTP must observe request cancellation too.
doctor = (API / 'doctor.go').read_text(errors='replace')
required = [
    'Check(ctx context.Context) CheckResult',
    'func (h *DoctorHandler) Run(ctx context.Context) DoctorReport',
    'report := h.Run(r.Context())',
    'func (c CheckerFunc) Check(ctx context.Context) CheckResult { return c.fn(ctx) }',
]
for token in required:
    if token not in doctor:
        errors.append(f'src/apps/daemon/internal/adapters/api/doctor.go: missing request-context contract: {token}')

routes = (API / 'routes_system.go').read_text(errors='replace')
if 'context.Background()' in routes:
    errors.append('src/apps/daemon/internal/adapters/api/routes_system.go: readiness checker detaches from HTTP request context')

# These are caller/daemon-lifetime fallbacks, not request handlers. Keep the allowlist explicit.
allowed_background = {
    'router.go': 1,
    'mcp_engine.go': 1,
}
for path in sorted(API.glob('*.go')):
    if path.name.endswith('_test.go') or path.name.startswith('handlers_') or path.name in {'routes_system.go'}:
        continue
    count = path.read_text(errors='replace').count('context.Background()')
    allowed = allowed_background.get(path.name, 0)
    if count > allowed:
        errors.append(f'{path.relative_to(ROOT)}: unexpected context.Background() count={count} allowed={allowed}')

print(f'request-context errors={len(errors)}')
for error in errors:
    print(f'ERROR: {error}')
raise SystemExit(1 if errors else 0)
