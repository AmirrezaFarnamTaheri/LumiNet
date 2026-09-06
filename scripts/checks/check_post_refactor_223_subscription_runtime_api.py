#!/usr/bin/env python3
from pathlib import Path
import sys,re
root=Path(__file__).resolve().parents[2]
router=(root/'src/apps/daemon/internal/adapters/api/router.go').read_text()
routes=(root/'src/apps/daemon/internal/adapters/api/routes_misc.go').read_text()
handlers=(root/'src/apps/daemon/internal/adapters/api/handlers_subscription_nodes.go')
htext=handlers.read_text() if handlers.exists() else ''
profiles=(root/'src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go').read_text()
errors=[]
def need(name,cond):
    if not cond: errors.append(name)
need('server owns subscription runtime','subscriptionRuntime *proxy.SubscriptionRuntime' in router)
need('server initializes runtime','NewSubscriptionRuntime' in router)
need('shutdown closes runtime','subscriptionRuntime.Close()' in router)
for frag in [
 'profiles/:id/nodes', 'profiles/:id/nodes/visibility', 'profiles/:id/nodes/:node_id/activate', '/runtime', '/runtime/stop']:
    need('route '+frag, frag in routes)
need('list is redacted service view','ListNodes(' in htext and 'ResolveNode(' not in htext.split('func (s *Server) ListSubscriptionNodes',1)[-1].split('func ',1)[0])
need('activate resolves visible node','ResolveNode(' in htext and 'subscriptionRuntime.Activate' in htext)
need('hide active blocked','cannot hide the active subscription node' in htext)
need('source change active blocked','cannot change subscription source while its node is active' in profiles)
need('delete exact stops active runtime','subscriptionRuntime.Stop' in profiles)
need('api states system proxy unchanged','does_not_modify_system_proxy' in htext)
need('no credential fields in node handler', not re.search(r'\.UUID|\.Password|\.PrivateKey|\.RawURI', htext))
if errors:
 print('post-refactor-223 subscription runtime API: FAIL')
 for e in errors: print(' -',e)
 sys.exit(1)
print('post-refactor-223 subscription runtime API: PASS')
