#!/usr/bin/env python3
from pathlib import Path
import re, sys
root = Path(__file__).resolve().parents[2]
errors=[]
def need(path, pattern, message):
    text=(root/path).read_text()
    if not re.search(pattern,text,re.S): errors.append(f"{path}: {message}")
def forbid(path, pattern, message):
    text=(root/path).read_text()
    if re.search(pattern,text,re.S): errors.append(f"{path}: {message}")
need(Path('src/apps/daemon/cmd/serve.go'), r'signal\.NotifyContext\(cmd\.Context\(\)', 'serve must derive daemon lifetime from command context')
need(Path('src/apps/daemon/cmd/serve.go'), r'jobs\.NewJobManager\(ctx, db\)', 'job manager must receive daemon context')
need(Path('src/apps/daemon/cmd/serve.go'), r'runner\.Start\(ctx\)', 'cron runner must receive daemon context')
need(Path('src/apps/daemon/internal/adapters/api/router.go'), r'NewServer\(ctx context\.Context', 'API server must receive caller context')
need(Path('src/apps/daemon/internal/adapters/api/router.go'), r'profileService\s+\*sub\.ProfileService', 'API server must hold the daemon-owned subscription profile service')
forbid(Path('src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go'), r'\bgo\s+s\.refreshProfileAsync|context\.Background\(', 'subscription handlers must not create detached refresh lifetime')
forbid(Path('src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go'), r'globalProfileStore|refreshProfileAsync', 'subscription profile ownership must not live in package-global handler state')
for handler in sorted((root / 'src/apps/daemon/internal/adapters/api').glob('handlers_*.go')):
    if handler.name.endswith('_test.go'):
        continue
    text = handler.read_text(errors='replace')
    if 'context.Background()' in text:
        errors.append(f"{handler.relative_to(root)}: request handler must not detach work onto context.Background()")
    if re.search(r'\bgo\s+(?:func\s*\(|[A-Za-z_][A-Za-z0-9_.]*\s*\()', text):
        errors.append(f"{handler.relative_to(root)}: request handler must not create detached goroutine lifetime")
need(Path('src/apps/daemon/internal/adapters/api/websocket.go'), r'func \(h \*Hub\) Run\(ctx context\.Context\)', 'Hub Run must be context-owned')
forbid(Path('src/apps/daemon/internal/adapters/api/websocket.go'), r'func \(h \*Hub\) ListenToJobs', 'job subscription must be internal to Hub lifetime')
forbid(Path('src/apps/daemon/internal/adapters/api/middleware.go'), r'go func\(\)\s*\{\s*ticker := time\.NewTicker\(10 \* time\.Minute\)', 'rate limiter must not start an immortal sweeper')
need(Path('src/apps/daemon/internal/adapters/api/mcp_engine.go'), r'func StdioRun\(ctx context\.Context', 'stdio MCP must receive daemon context')
if errors:
    for e in errors: print('ERROR', e)
print(f"daemon-lifecycle errors={len(errors)}")
sys.exit(bool(errors))
