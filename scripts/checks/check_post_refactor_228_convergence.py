#!/usr/bin/env python3
"""Verify post-refactor-228 second-order peer convergence and source delta."""
from __future__ import annotations
import csv, hashlib, json, os, re, stat, sys, zipfile
from pathlib import Path, PurePosixPath

ROOT=Path(os.environ.get('LUMINET_228_TARGET_ROOT',Path(__file__).resolve().parents[2]))
E=ROOT/'governance/convergence'
DONOR_BASE=Path(os.environ.get('LUMINET_228_DONOR_ROOT','/mnt/data/luminet228_work/donors'))
INPUT226=Path(os.environ.get('LUMINET_228_INPUT226','/mnt/data/luminet226_inputs'))
SNI_ARCHIVE=Path(os.environ.get('LUMINET_228_SNI_ARCHIVE','/mnt/data/sni-spoofing-rust-main.zip'))
DONORS={
 'shadowsocks-crypto':('shadowsocks-crypto-main.zip',DONOR_BASE/'shadowsocks-crypto-main'/'shadowsocks-crypto-main'),
 'shadowsocksr':('shadowsocksR-master.zip',DONOR_BASE/'shadowsocksR-master'/'shadowsocksR-master'),
 'shadowsocks-rust':('shadowsocks-rust-master.zip',DONOR_BASE/'shadowsocks-rust-master'/'shadowsocks-rust-master'),
 'srsc':('srsc-dev.zip',DONOR_BASE/'srsc-dev'/'srsc-dev'),
 'ssh':('ssh-master.zip',DONOR_BASE/'ssh-master'/'ssh-master'),
 'subconverter':('subconverter-master(1).zip',DONOR_BASE/'subconverter-master(1)'/'subconverter-master'),
 'tailscale-client':('tailscale-client-go-main(3).zip',DONOR_BASE/'tailscale-client-go-main(3)'/'tailscale-client-go-main'),
 'tinytun':('TinyTun-master(3).zip',DONOR_BASE/'TinyTun-master(3)'/'TinyTun-master'),
 'tools':('Tools-main(3).zip',DONOR_BASE/'Tools-main(3)'/'Tools-main'),
 'browser-ext':('ts-browser-ext-main(3).zip',DONOR_BASE/'ts-browser-ext-main(3)'/'ts-browser-ext-main'),
 'tsheadroom':('tsheadroom-main(3).zip',DONOR_BASE/'tsheadroom-main(3)'/'tsheadroom-main'),
 'mwgp':('mwgp-2.zip',DONOR_BASE/'mwgp-2'/'mwgp-2'),
 'paas-gateway':('PaaS-vmess-trojan-argo-main.zip',DONOR_BASE/'PaaS-vmess-trojan-argo-main'/'PaaS-vmess-trojan-argo-main'),
 'reverse-tls':('Reverse_tls-main.zip',DONOR_BASE/'Reverse_tls-main'/'Reverse_tls-main'),
 'sni-spoofing-rust':('sni-spoofing-rust-main.zip',DONOR_BASE/'sni-spoofing-rust-main'/'sni-spoofing-rust-main'),
}
ARCHIVES={d:(SNI_ARCHIVE if d=='sni-spoofing-rust' else INPUT226/name) for d,(name,_) in DONORS.items()}
errors=[]; assertions=0

def check(cond,msg):
 global assertions
 assertions+=1
 if not cond:errors.append(msg)

def sha_file(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()

def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()

def read_csv(name):
 p=E/name if isinstance(name,str) else name
 with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))

def text(rel):return (ROOT/rel).read_text(encoding='utf-8',errors='replace')

def norm(name:str):
 p=PurePosixPath(name.replace('\\','/'))
 return p, (not ('\x00' in name or p.is_absolute() or any(x in ('','.','..') for x in p.parts) or (p.parts and ':' in p.parts[0])))

# Successor releases freeze the exact 228 source inventory and preserve all
# post-refactor-228 governance evidence byte-for-byte. A 229 successor must not
# require historical 228 donor mounts or the 227->228 live delta to remain the
# current tree. The original 228 release has no 229 baseline, so it continues
# through the native verification path below.
SUCCESSOR_BASELINE=E/'post-refactor-229-baseline-files.csv'
if SUCCESSOR_BASELINE.is_file():
 frozen={r['path']:r for r in read_csv(SUCCESSOR_BASELINE)}
 check(sha_file(SUCCESSOR_BASELINE)=='4cf881c8764d47cfbd7cbfa816f424fee889878b75f11a6109d29ed807ff1dbd','228 frozen source inventory identity in 229 successor')
 for evidence in sorted(E.glob('post-refactor-228-*')):
  if not evidence.is_file(): continue
  rel=evidence.relative_to(ROOT).as_posix();row=frozen.get(rel)
  check(row is not None,f'228 frozen evidence listed in 229 baseline: {rel}')
  if row: check(sha_file(evidence)==row['sha256'],f'228 frozen evidence byte-identical in 229 successor: {rel}')
 if errors:
  print('\n'.join(errors));sys.exit(1)
 print(f'post-refactor-228 convergence: successor-frozen assertions={assertions} errors=0')
 sys.exit(0)

# Frozen predecessor identity and exact current-wave denominators.
check(sha_file(E/'post-refactor-228-baseline-files.csv')=='13a74243d0968da3c45867ecab4cf69a406ec9ea4d24298817ed83b5533bd9ef','228 baseline must be exact frozen 227 source inventory')
summary=json.loads((E/'post-refactor-228-evidence-summary.json').read_text())
expected_summary={
 'donor_archives_reaudited':15,'archive_members':1617,'files':1349,'surfaces':1349,'symlinks':0,
 'directory_merkle_records':268,'definitions_reverified':16310,'predecessor_semantic_records_reaudited':949,
 'refined_second_order_records':27,'high_signal_surfaces':788,'high_signal_unaccounted':0,
 'unresolved_high_signal_surfaces':0,'automatic_mutation_retry_owner_count':1,
 'fresh_226_evidence_identity_confirmed':True,'fresh_227_evidence_identity_confirmed':True,
}
for k,v in expected_summary.items():check(summary.get(k)==v,f'evidence summary {k}={v!r}')

archive_rows=read_csv('post-refactor-228-archive-accountability.csv'); check(len(archive_rows)==15,'15 archive-accountability rows')
archive_by={r['donor']:r for r in archive_rows};check(set(archive_by)==set(DONORS),'archive donor set exact')
# Re-admit every raw ZIP and compare every file byte to evidence and extracted donor.
surfaces=read_csv('post-refactor-228-surface-accountability.csv');check(len(surfaces)==1349,'1349 surface rows')
by_surface={(r['donor'],r['path']):r for r in surfaces};check(len(by_surface)==1349,'surface donor/path keys unique')
for donor,(archive_name,root) in DONORS.items():
 archive=ARCHIVES[donor]; row=archive_by[donor]
 check(archive.is_file(),f'archive exists {donor}');check(root.is_dir(),f'extracted root exists {donor}')
 if not archive.is_file() or not root.is_dir():continue
 check(sha_file(archive)==row['archive_sha256'],f'archive hash {donor}')
 with zipfile.ZipFile(archive) as z:
  check(z.testzip() is None,f'archive CRC {donor}')
  infos=z.infolist();check(len(infos)==int(row['members']),f'archive member count {donor}')
  seen=set();folded=set();files=dirs=syms=total=0;roots=set()
  for info in infos:
   p,safe=norm(info.filename);check(safe,f'safe archive path {donor}:{info.filename}')
   if not safe:continue
   key=p.as_posix().rstrip('/');check(key not in seen,f'no duplicate member {donor}:{key}');check(key.casefold() not in folded,f'no case collision {donor}:{key}');seen.add(key);folded.add(key.casefold());roots.add(p.parts[0]);total+=info.file_size
   mode=info.external_attr>>16;kind=stat.S_IFMT(mode);check(kind in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK),f'no special archive member {donor}:{key}');check(not(info.flag_bits&1),f'not encrypted {donor}:{key}')
   if info.is_dir():dirs+=1;continue
   if kind==stat.S_IFLNK:syms+=1;continue
   files+=1;rel=PurePosixPath(*p.parts[1:]).as_posix();sr=by_surface.get((donor,rel));check(sr is not None,f'archive surface exists {donor}:{rel}')
   if sr is None:continue
   data=z.read(info);check(sha_bytes(data)==sr['sha256'],f'archive file hash {donor}:{rel}');ep=root/rel;check(ep.is_file(),f'extracted donor file {donor}:{rel}');
   if ep.is_file():check(sha_file(ep)==sr['sha256'],f'extracted donor hash {donor}:{rel}')
  check(len(roots)==1,f'single archive root {donor}');check(files==int(row['files']),f'archive file count {donor}');check(dirs==int(row['directories']),f'archive directory count {donor}');check(syms==int(row['symlinks'])==0,f'archive symlink count {donor}');check(total==int(row['uncompressed_bytes']),f'archive expanded bytes {donor}');check(total<=1<<30,f'archive expansion bound {donor}')

# Surface backlinks/classification and exact extracted bytes.
new_ledger=read_csv('post-refactor-228-adoption-ledger.csv');check(len(new_ledger)==27,'27 refined records')
new_ids={r['record_id'] for r in new_ledger};check(len(new_ids)==27,'refined IDs unique')
high_signal=0
for r in surfaces:
 key=(r['donor'],r['path']);check(r['donor'] in DONORS,f'surface donor {key}');p=DONORS[r['donor']][1]/r['path'];check(p.is_file(),f'surface file exists {key}')
 if p.is_file():check(sha_file(p)==r['sha256'],f'surface hash {key}');check(str(p.stat().st_size)==r['size_bytes'],f'surface size {key}')
 check(r['predecessor_wave'] in {'226','227'},f'surface predecessor wave {key}');check(r['post_refactor_228_review']=='fresh-byte-reverified-and-semantic-row-revisited',f'surface 228 review {key}');check(bool(r['semantic_record_ids']),f'surface predecessor backlink {key}')
 if r['classification'] in {'implementation','test','configuration','script','deployment','ui-or-product'}:high_signal+=1
 refs=r.get('post_refactor_228_record_ids','n/a')
 if refs and refs!='n/a':
  for rid in refs.split(';'):check(rid in new_ids,f'surface refined backlink {key}->{rid}')
check(high_signal==788,'788 high-signal surfaces recomputed')

# Recompute all donor directory/root Merkle records.
dirs=read_csv('post-refactor-228-directories.csv');check(len(dirs)==268,'268 directory/root Merkle rows');dir_keys={(r['donor'],r['path']) for r in dirs};check(len(dir_keys)==268,'directory keys unique')
for r in dirs:
 root=DONORS[r['donor']][1];d=root if r['path']=='.' else root/r['path'];check(d.is_dir(),f'directory exists {r["donor"]}:{r["path"]}')
 if not d.is_dir():continue
 entries=[]
 for p in sorted(root.rglob('*'),key=lambda p:p.relative_to(root).as_posix()):
  if not p.is_file():continue
  try:rel=p.relative_to(d).as_posix()
  except ValueError:continue
  entries.append((rel,sha_file(p)))
 payload=''.join(f'{h}  {rel}\n' for rel,h in entries).encode();check(len(entries)==int(r['descendant_files']),f'directory descendant count {r["donor"]}:{r["path"]}');check(sha_bytes(payload)==r['tree_sha256'],f'directory Merkle {r["donor"]}:{r["path"]}')

# Revalidated definition index.
symbols=read_csv('post-refactor-228-symbols.csv');check(len(symbols)==16310,'16310 definition rows')
for r in symbols:
 sr=by_surface.get((r['donor'],r['path']));check(sr is not None,f'definition surface {r["donor"]}:{r["path"]}:{r["line"]}')
 if sr is None:continue
 check(r['sha256']==sr['sha256'],f'definition source hash {r["donor"]}:{r["path"]}:{r["line"]}');check(r['predecessor_wave'] in {'226','227'},f'definition predecessor wave {r["line"]}');check(r['post_refactor_228_review']=='definition-index-reverified-on-identical-bytes',f'definition 228 review {r["line"]}')
 try:line=int(r['line'])
 except ValueError:line=0
 check(line>=1,f'definition line positive {r["donor"]}:{r["path"]}:{r["line"]}')

# Every predecessor semantic decision is re-reviewed exactly once.
reviews=read_csv('post-refactor-228-second-order-review.csv');check(len(reviews)==949,'949 predecessor semantic review rows')
review_keys={(r['predecessor_wave'],r['predecessor_record_id']) for r in reviews};check(len(review_keys)==949,'predecessor semantic review keys unique')
pre_ids=set()
for wave in ('226','227'):
 rows=read_csv(f'post-refactor-{wave}-adoption-ledger.csv');pre_ids|={(wave,r['record_id']) for r in rows}
check(review_keys==pre_ids,'second-order review exactly covers 226+227 semantic ledgers')
for r in reviews:
 check(r['fresh_source_hash_verified']=='true',f'fresh semantic source verified {r["predecessor_record_id"]}');check(bool(r['post_refactor_228_status']),f'228 semantic status {r["predecessor_record_id"]}');check(bool(r['post_refactor_228_rationale']),f'228 semantic rationale {r["predecessor_record_id"]}')
 refs=r['post_refactor_228_record_ids']
 if refs!='n/a':
  for rid in refs.split(';'):check(rid in new_ids,f'review refinement exists {r["predecessor_record_id"]}->{rid}')

# Refined decision graph and evidence links.
for r in new_ledger:
 rid=r['record_id'];check(rid.startswith('PR228-'),f'228 record ID namespace {rid}');check(r['validation_status'] in {'verified','reviewed','statically-validated','inferred','unverified','pending'},f'validation status vocabulary {rid}');check(bool(r['decision_rationale']),f'decision rationale {rid}');check(bool(r['invariant']),f'invariant {rid}');check(bool(r['negative_invariant']),f'negative invariant {rid}');check(bool(r['target_nodes']),f'target ownership {rid}')
 if r['parent_record_id']!='n/a':check(r['parent_record_id'] in new_ids,f'parent exists {rid}')
 if r['dependency_record_ids']!='n/a':
  for dep in r['dependency_record_ids'].split(';'):check(dep in new_ids,f'dependency exists {rid}->{dep}')
 if r['donor']=='target-requirement':check(r['donor_path']=='n/a' and r['donor_sha256']=='n/a',f'target requirement evidence shape {rid}')
 else:
  sr=by_surface.get((r['donor'],r['donor_path']));check(sr is not None,f'refined donor evidence path {rid}')
  if sr is not None:check(sr['sha256']==r['donor_sha256'],f'refined donor evidence hash {rid}')
 if r['test_node']!='n/a':
  test_path=r['test_node'].split('#',1)[0];check((ROOT/test_path).is_file(),f'acceptance evidence path exists {rid}:{test_path}')

# Supersession map only references refined records and one target owner per row.
smap=read_csv('post-refactor-228-supersession-map.csv');check(len(smap)>=20,'second-order supersession map is granular')
for r in smap:
 for rid in r['contributing_records'].split(';'):check(rid in new_ids,f'supersession contributing record {rid}');check(bool(r['target_nodes']),f'supersession target node {r["target_capability"]}');check('target-native convergence' in r['second_order_result'],f'supersession second-order result {r["target_capability"]}')

# Historical overlay is intentionally unchanged: 228 is a re-audit, not fake donor growth.
all_summary=json.loads((E/'post-refactor-228-all-history-summary.json').read_text())
expected_history={'donors':53,'unique_donor_names':53,'surfaces':3810,'symbols':25821,'modules':297,'high_signal_surfaces':2360,'ui_product_surfaces':162,'history_inflation_from_228':0,'post_refactor_228_second_order_reaudited_archives':15,'post_refactor_228_second_order_reaudited_surfaces':1349,'post_refactor_228_second_order_reaudited_symbols':16310,'post_refactor_228_second_order_reaudited_semantic_records':949,'post_refactor_228_refined_records':27}
for k,v in expected_history.items():check(all_summary.get(k)==v,f'all-history {k}={v}')
for src,dst in [('post-refactor-227-all-history-surface-audit.csv','post-refactor-228-all-history-surface-audit.csv'),('post-refactor-227-all-history-symbol-index.csv','post-refactor-228-all-history-symbol-index.csv'),('post-refactor-227-all-history-module-audit.csv','post-refactor-228-all-history-module-audit.csv')]:check((E/src).read_bytes()==(E/dst).read_bytes(),f'all-history carried without duplication {dst}')

# Exact 227->228 live source delta, including size/mode/hash, excluding only its own generated delta and transient caches.
base={r['path']:r for r in read_csv('post-refactor-228-baseline-files.csv')};delta=read_csv('post-refactor-228-target-delta.csv');actual={r['path']:r for r in delta};check(len(actual)==len(delta),'delta paths unique');cur={}
for p in ROOT.rglob('*'):
 if not p.is_file() or p.is_symlink():continue
 rel=p.relative_to(ROOT).as_posix()
 if rel=='governance/convergence/post-refactor-228-target-delta.csv' or rel.startswith('.git/') or '/node_modules/' in '/'+rel or '__pycache__' in rel:continue
 cur[rel]={'sha256':sha_file(p),'size_bytes':str(p.stat().st_size),'mode':oct(stat.S_IMODE(p.stat().st_mode))}
expected_delta={}
for path in set(base)|set(cur):
 b=base.get(path);c=cur.get(path)
 if b is None:typ='added'
 elif c is None:typ='deleted'
 elif (b['sha256'],b['size_bytes'],b['mode'])!=(c['sha256'],c['size_bytes'],c['mode']):typ='modified'
 else:continue
 expected_delta[path]=(typ,b['sha256'] if b else 'n/a',c['sha256'] if c else 'n/a',b['size_bytes'] if b else 'n/a',c['size_bytes'] if c else 'n/a',b['mode'] if b else 'n/a',c['mode'] if c else 'n/a')
actual_delta={p:(r['change_type'],r['baseline_sha256'],r['current_sha256'],r['baseline_size_bytes'],r['current_size_bytes'],r['baseline_mode'],r['current_mode']) for p,r in actual.items()}
check(actual_delta==expected_delta,'227→228 delta exactly matches frozen baseline and live source bytes/modes')

# Implementation: SSH passphrase participates in existing pre-network auth/secret boundaries.
ssh=text('src/apps/daemon/internal/runtime/proxy/ssh_tunnel.go')
for needle in ['PrivateKeyPassphrase string','SetPrivateKeyPassphrase','ssh.ParsePrivateKeyWithPassphrase','SSH private-key passphrase requires private key material','SSH authentication requires a valid private key or password']:check(needle in ssh,f'SSH passphrase/auth invariant {needle}')
ev_contract=text('src/apps/daemon/internal/runtime/proxy/evasion_contract.go');check('SshKeyPassphrase' in ev_contract,'SSH passphrase is included in secret redaction contract')

# Extended local rules and read-only policy-group semantics.
rules=text('src/apps/daemon/internal/analysis/diagnostics/local_ruleset_plan.go')
for needle in ['DOMAIN-KEYWORD','SRC-IP-CIDR','SRC-PORT','DST-PORT','PROCESS-NAME','SRC-GEOIP','RULE-SET','no-resolve']:check(needle in rules,f'extended local rule support {needle}')
policy=text('src/apps/daemon/internal/analysis/diagnostics/routing_policy_group_plan.go')
for needle in ['manual-select','latency-auto','fallback','load-balance','maxRoutingPolicyCandidates = 128','performs no remote probe','unhealthy candidates never gain automatic dispatch authority']:check(needle in policy,f'policy-group invariant {needle}')
for bad in ['http.Get(','http.Post(','net.Dial(','exec.Command(']:check(bad not in policy,f'policy planner no authority {bad}')

# Browser/native-host, gateway presets, WireGuard recovery, and worker protocol details.
browser=text('src/apps/daemon/internal/analysis/diagnostics/browser_proxy_handoff_plan.go')
for needle in ['com.luminet.browser','maxNativeMessageBytes = 1 << 20','chromeExtensionIDPattern','[]int{1000, 2000, 4000, 8000}','the planner registers no native host and changes no browser proxy setting']:check(needle in browser,f'browser contract {needle}')
gateway=text('src/apps/daemon/internal/analysis/diagnostics/gateway_composition_plan.go')
for needle in ['reverse-tls-relay','websocket-edge','managed-edge-tunnel','gateway preset and explicit services are mutually exclusive','the planner downloads nothing and writes no systemd, cron, runit, Caddy, or other service configuration']:check(needle in gateway,f'gateway preset contract {needle}')
wg=text('src/apps/daemon/internal/analysis/diagnostics/wireguard_index_translation_plan.go')
for needle in ['len(req.Entries) == 0 || len(req.Entries) > 1024','24*time.Hour','persisted mappings are recovery hints only','any live receiver-index rewrite must recompute the affected WireGuard packet authentication fields before transmission','this planner rewrites no packet and restores no mapping into a live WireGuard owner']:check(needle in wg,f'WireGuard translation invariant {needle}')
workers=text('src/apps/daemon/internal/analysis/diagnostics/worker_affinity_plan.go')
for needle in ['ProtocolFraming: "ndjson"','ReadyHandshake: `{"ready":true}`','AffinityQueueDepth: 1','SharedQueueDepth: 0','RecycleOnProtocolError: true','ColdFirstCallTelemetry: true','max_protocol_frame_bytes must be 1024..67108864']:check(needle in workers,f'worker protocol contract {needle}')

# Shadowsocks extension intent and product runtime truth share one compatibility owner.
compat=text('src/apps/daemon/internal/networking/proxyconfig/core_compat.go')
for needle in ['func EvaluateExternalCoreCompatibility','case "", "obfs-local", "v2ray-plugin"','unsupported sing-box Shadowsocks SIP003 plugin','Shadowsocks SIP003 plugins are unsupported by Xray outbound','Shadowsocks packet prefix is unsupported by sing-box outbound','Shadowsocks packet prefix is unsupported by Xray outbound']:check(needle in compat,f'external-core compatibility {needle}')
core=text('src/apps/daemon/internal/runtime/proxy/core_manager.go');check('outbound["plugin"] = proxy.Plugin' in core and 'outbound["plugin_opts"] = proxy.PluginOpts' in core,'sing-box core builder retains supported SIP003 plugin intent')
catalogue=text('src/apps/daemon/internal/integrations/sub/node_catalogue.go');check('proxyconfig.EvaluateExternalCoreCompatibility(cfg)' in catalogue,'catalogue consumes compatibility owner');check('RuntimeActivatable bool' in catalogue and 'RuntimeCores' in catalogue and 'RuntimeReason' in catalogue,'catalogue exposes runtime truth')
profiles=text('src/packages/control-ui/src/pages/Profiles.tsx');check('planning/import only' in profiles,'Profiles shows planning/import-only state');check('!node.runtimeActivatable' in profiles,'Profiles disables impossible activation');check('External-core candidates:' in profiles,'Profiles shows compatible core candidates')

# SNI literal self-loop guard is offline and platform-support claim remains bounded.
sni=text('src/apps/daemon/internal/analysis/diagnostics/sni_gateway_plan.go')
for needle in ['ListenerEndpoint','UpstreamEndpoint','SelfLoop','SNI upstream would loop back into the local listener','net.ParseIP']:check(needle in sni,f'SNI self-loop guard {needle}')
for bad in ['net.Lookup','http.Get(','net.Dial(']:check(bad not in sni,f'SNI self-loop guard offline {bad}')
stub=text('src/apps/daemon/internal/runtime/proxy/evasion_divert_stub.go');check('//go:build !windows && !linux' in stub[:120],'macOS remains explicit unsupported raw-injector stub')
supervision=text('src/packages/lumicore/src/netutil/supervision.rs');check('#[cfg(not(target_os = "windows"))]' in supervision and 'Ok(Vec::new())' in supervision,'Linux process attribution residual gap remains explicit in source')

# Automatic mutation retry has exactly one config owner and bounded remote safety classes.
retry=text('src/apps/daemon/internal/foundation/config/config.go')
for needle in ['DefaultMutationAttempts = 3','MaxMutationAttempts     = 8','func (m *Manager) Mutate(options MutationOptions','maxAttempts = 1','cfg, revision := m.GetWithRevision()','if !errors.Is(err, ErrRevisionConflict)']:check(needle in retry,f'config retry invariant {needle}')
owner_count=sum(p.read_text(errors='replace').count('func (m *Manager) Mutate(options MutationOptions') for p in ROOT.glob('src/apps/daemon/internal/**/*.go'));check(owner_count==1,'exactly one automatic config mutation owner')
remote=text('src/apps/daemon/internal/foundation/remoteaction/remoteaction.go')
for needle in ['Idempotent SafetyClass = "idempotent"','ReconcileBeforeRetry SafetyClass = "reconcile-before-retry"','SingleAttempt SafetyClass = "single-attempt"','maxAutomaticAttempts = 8']:check(needle in remote,f'remote retry safety class {needle}')

# Planner HTTP adapters stay thin/non-authoritative.
handler=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_228_planners.go')
for needle in ['PlanRoutingPolicyGroup','BuildRoutingPolicyGroupPlan','PlanWireGuardIndexTranslation','BuildWireGuardIndexTranslationPlan']:check(needle in handler,f'228 handler delegates {needle}')
for bad in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(']:check(bad not in handler,f'228 handler no hidden authority {bad}')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go');check('POST("/routing-policy-group-plan"' in routes,'routing policy route registered');check('POST("/wireguard-index-translation-plan"' in routes,'WireGuard translation route registered')

# Product characterization and package wiring.
ui_test=text('src/packages/control-ui/scripts/test-post-refactor-228.mjs');check('checks !== 82' in ui_test,'228 UI characterization denominator locked');check('post-refactor-228 second-order product convergence characterization passed' in ui_test,'228 UI characterization success marker')
pkg=json.loads(text('src/packages/control-ui/package.json'));check(pkg['scripts'].get('test:228')=='node scripts/test-post-refactor-228.mjs','package owns test:228');check('test:228' in pkg['scripts'].get('test',''),'aggregate UI test includes 228')

# Makefile owns deterministic generation/checking and canonical verify-repo admission.
mk=text('Makefile')
for needle in ['post-refactor-228-evidence','generate_post_refactor_228_evidence.py','generate_post_refactor_228_delta.py','check_mutation_retry_authority.py','check_post_refactor_228_convergence.py']:check(needle in mk,f'Makefile owns {needle}')

# Durable reports carry the load-bearing second-order outcomes and limitations.
REPORTS={
 'post-refactor-228-architecture.md':('15 raw donor archives','Single owners retained','Configuration mutation retry'),
 'post-refactor-228-security-model.md':('SSH encrypted-key passphrases','Shadowsocks SIP003','Automatic config retry'),
 'post-refactor-228-state-machines.md':('fresh snapshot','needs-revalidation','planning/import-only'),
 'post-refactor-228-peer-synthesis.md':('TinyTun Linux process lookup','superseded does not mean ignored','SIP003'),
 'post-refactor-228-omission-audit.md':('15/15','16,310','949/949'),
 'post-refactor-228-operator-runbook.md':('Planning/import-only','retries are automatic only for revision conflicts','Known gap'),
 'post-refactor-228-validation.md':('1,847 assertions','Cargo/rustc','Rust/macOS-BPF and Android native production-build parity are not claimed'),
 'post-refactor-228-all-history-second-order-audit.md':('53 unique donors','zero','Linux process attribution'),
}
for name,tokens in REPORTS.items():
 p=E/name;check(p.is_file(),f'durable report exists {name}')
 if p.is_file():
  body=p.read_text(errors='replace')
  for token in tokens:check(token in body,f'durable report token {name}:{token}')

print(f'post-refactor-228 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:200]:print('ERROR:',e)
 sys.exit(1)
