#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
base=ROOT/'src/apps/android/app/src/main'
service=(base/'java/com/luminet/android/VpnEngineService.kt').read_text()
activity=(base/'java/com/luminet/android/LumiNetActivity.kt').read_text()
state=(base/'java/com/luminet/android/VpnRuntimeState.kt').read_text() if (base/'java/com/luminet/android/VpnRuntimeState.kt').is_file() else ''
tile=(base/'java/com/luminet/android/LumiNetTileService.kt').read_text() if (base/'java/com/luminet/android/LumiNetTileService.kt').is_file() else ''
manifest=(base/'AndroidManifest.xml').read_text()
strings=(base/'res/values/strings.xml').read_text()
gradle=(ROOT/'src/apps/android/app/build.gradle.kts').read_text()
errors=[]
def req(c,m):
    if not c: errors.append(m)
for name in ['IDLE','STARTING','CONNECTED','STOPPING','ERROR']:
    req(name in state, f'missing runtime stage {name}')
req('failureCode' in state and 'message' not in state.lower(), 'runtime failure state must expose bounded code, not free-form exception text')
req('MutableStateFlow(VpnRuntimeState())' in service, 'service does not own runtime state')
req('_runtimeState.update' in service, 'service state transitions are not atomic updates')
req('classifyFailureCode' in service and 'ex.message' not in service, 'service exposes raw failure text or lacks sanitized classifier')
req('collectAsStateWithLifecycle' in activity, 'activity does not collect VPN state lifecycle-aware')
req('VpnRuntimeStage.STARTING' in activity and 'VpnRuntimeStage.STOPPING' in activity and 'VpnRuntimeStage.ERROR' in activity, 'activity collapses transitional/error states')
req('class LumiNetTileService : TileService()' in tile, 'Quick Settings tile missing')
req('VpnEngineService.runtimeState.value' in tile, 'tile does not observe canonical service state')
req('VpnService.prepare(this)' in tile, 'tile does not respect VPN permission flow')
req('Builder()' not in tile and 'establish()' not in tile and 'VPNEngine()' not in tile, 'tile gained VPN/TUN authority')
req(manifest.count('android.permission.BIND_VPN_SERVICE') == 1, 'there must remain exactly one BIND_VPN_SERVICE authority')
req('android.service.quicksettings.action.QS_TILE' in manifest, 'Quick Settings tile intent missing')
req('android.permission.BIND_QUICK_SETTINGS_TILE' in manifest, 'Quick Settings service permission missing')
req('lifecycle-runtime-compose' in gradle, 'lifecycle-aware Compose dependency missing')
for key in ['vpn_status_idle','vpn_status_starting','vpn_status_connected','vpn_status_stopping','vpn_status_error','vpn_tile_label']:
    req(f'name="{key}"' in strings, f'missing localized string {key}')
if errors:
    print(f'post-refactor-223 android: FAIL ({len(errors)} errors)')
    for e in errors: print('ERROR:',e)
    raise SystemExit(1)
print('post-refactor-223 android: PASS')
