#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
core=(ROOT/'src/apps/daemon/internal/native/bridge/core.go').read_text()
policy=(ROOT/'src/apps/daemon/internal/native/bridge/async_policy.go').read_text() if (ROOT/'src/apps/daemon/internal/native/bridge/async_policy.go').is_file() else ''
errors=[]
def req(cond,msg):
    if not cond: errors.append(msg)
req('select {' in core and 'case ch.(chan string) <- payload:' in core and 'default:' in core, 'native callback delivery is still blocking')
req(('case res := <-ch:' in core or 'case res = <-ch:' in core) and 'case <-timer.C:' in core, 'async wait is still unbounded')
req('asyncWaitDuration(timeout)' in core or 'asyncWaitDuration(timeoutMs)' in core, 'caller timeout is not propagated to host callback wait')
req('maxAsyncCallbackWait' in policy and 'asyncCallbackGrace' in policy and 'const (' in policy, 'async callback wait lacks explicit grace/ceiling')
req('func asyncWaitDuration' in policy, 'async wait policy helper missing')
req('callbackMap.Delete(reqId)' in core, 'callback registry cleanup missing')
if errors:
    print(f'post-refactor-223 native async: FAIL ({len(errors)} errors)')
    for e in errors: print('ERROR:',e)
    raise SystemExit(1)
print('post-refactor-223 native async: PASS')
