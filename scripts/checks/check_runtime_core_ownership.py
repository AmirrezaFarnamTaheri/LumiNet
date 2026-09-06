#!/usr/bin/env python3
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[2]
errors=[]
prod=ROOT/'src/apps/daemon'
manager=prod/'internal/runtime/runtimecore/manager.go'
if not manager.is_file(): errors.append('src/apps/daemon/internal/runtime/runtimecore/manager.go: canonical runtime-core module is missing')
for rel in ['src/apps/daemon/internal/runtime/runtimecore/tor_engine.go','src/apps/daemon/internal/runtime/runtimecore/psiphon_engine.go']:
    if not (ROOT/rel).is_file(): errors.append(f'{rel}: long-lived runtime implementation is missing from runtimecore')
for rel in ['src/apps/daemon/internal/runtime/proxy/tor_engine.go','src/apps/daemon/internal/runtime/proxy/psiphon_engine.go']:
    if (ROOT/rel).exists(): errors.append(f'{rel}: long-lived runtime implementation leaked back into proxy')
adapters=(prod/'internal/runtime/runtimecore/adapters.go').read_text(errors='ignore') if (prod/'internal/runtime/runtimecore/adapters.go').exists() else ''
if 'internal/runtime/proxy' in adapters or 'proxy.' in adapters: errors.append('src/apps/daemon/internal/runtime/runtimecore/adapters.go: runtimecore still depends on proxy implementation')
for rel in ['src/apps/daemon/internal/runtime/proxy/multi_core.go']:
    if (ROOT/rel).exists(): errors.append(f'{rel}: generic compatibility runtime factory remains active')
for rel in ['src/apps/daemon/internal/adapters/api/handlers_system_engines.go','src/apps/daemon/internal/adapters/mobilebind/mobilebind.go']:
    p=ROOT/rel; text=p.read_text() if p.exists() else ''
    if 'runtimecore' not in text: errors.append(f'{rel}: does not delegate lifecycle/state to runtimecore')
    if re.search(r'(?:runningEngines|activeEngines)\s*=\s*make\(', text): errors.append(f'{rel}: owns a competing runtime engine map')
for p in prod.rglob('*.go'):
    if '_test.go' in p.name: continue
    if 'internal/runtimecore' in p.as_posix(): continue
    text=p.read_text(errors='ignore')
    if re.search(r'\bproxy\.GetProxyEngine\s*\(', text): errors.append(f'{p.relative_to(ROOT)}: constructs engine through retired generic factory')
    if re.search(r'\bproxy\.New(?:TorEngine|PsiphonEngine(?:Wrapper)?)\s*\(', text): errors.append(f'{p.relative_to(ROOT)}: constructs long-lived engine outside runtimecore')
# Generic tailscale/sing-box runtime must not claim success through the retired factory.
if (prod/'internal/runtime/proxy/multi_core.go').exists():
    text=(prod/'internal/runtime/proxy/multi_core.go').read_text()
    if 'EngineSingBox' in text: errors.append('src/apps/daemon/internal/runtime/proxy/multi_core.go: generic sing-box capability fiction remains')
    if 'EngineTailscale' in text: errors.append('src/apps/daemon/internal/runtime/proxy/multi_core.go: generic Tailscale capability fiction remains')
# The dedicated Tailscale route is preserved for compatibility, but embedded runtime support is not shipped.
tailscale_handler = prod/'internal/adapters/api/handlers_tailscale.go'
text = tailscale_handler.read_text(errors='ignore') if tailscale_handler.exists() else ''
if re.search(r'\bproxy\.(?:GetTailscaleAdapter|ConfigureTailscaleAdapter)\s*\(', text):
    errors.append('src/apps/daemon/internal/adapters/api/handlers_tailscale.go: dedicated route still starts the mock Tailscale adapter')
if '"supported"' not in text:
    errors.append('src/apps/daemon/internal/adapters/api/handlers_tailscale.go: route does not report explicit runtime support status')

# Temporary proxy-test cores are separate from runtimecore, but discovery must be portable.
core_manager = prod/'internal/runtime/proxy/core_manager.go'
text = core_manager.read_text(errors='ignore') if core_manager.exists() else ''
if re.search(r'(?:Users[\\/]+ACER|quranips)', text, re.IGNORECASE):
    errors.append('src/apps/daemon/internal/runtime/proxy/core_manager.go: developer-specific binary discovery path remains')

print(f'runtime-core-ownership errors={len(errors)}')
for e in errors: print('ERROR:',e)
sys.exit(bool(errors))
