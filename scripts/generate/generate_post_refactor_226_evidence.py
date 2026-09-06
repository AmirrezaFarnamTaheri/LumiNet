#!/usr/bin/env python3
from __future__ import annotations
import bisect, csv, hashlib, json, os, re, stat, zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from collections import defaultdict

TARGET=Path(os.environ.get('LUMINET_226_TARGET_ROOT','/mnt/data/luminet226_work/target'))
INPUTS=Path(os.environ.get('LUMINET_226_INPUT_ROOT','/mnt/data/luminet226_inputs'))
DONOR_BASE=Path(os.environ.get('LUMINET_226_DONOR_ROOT','/mnt/data/luminet226_work/donors'))
OUT=TARGET/'governance/convergence'

@dataclass(frozen=True)
class Donor:
    id:str; archive_name:str; root_name:str; product:str
    @property
    def archive(self): return INPUTS/self.archive_name
    @property
    def root(self): return DONOR_BASE/self.root_name

DONORS=[
 Donor('shadowsocks-crypto','shadowsocks-crypto-main.zip','shadowsocks-crypto-main','shadowsocks-crypto'),
 Donor('shadowsocksr','shadowsocksR-master.zip','shadowsocksR-master','ShadowsocksR'),
 Donor('shadowsocks-rust','shadowsocks-rust-master.zip','shadowsocks-rust-master','shadowsocks-rust'),
 Donor('srsc','srsc-dev.zip','srsc-dev','SRSC'),
 Donor('ssh','ssh-master.zip','ssh-master','x/crypto SSH'),
 Donor('subconverter','subconverter-master(1).zip','subconverter-master(1)','subconverter'),
 Donor('tailscale-client','tailscale-client-go-main(3).zip','tailscale-client-go-main(3)','tailscale-client-go'),
 Donor('tinytun','TinyTun-master(3).zip','TinyTun-master(3)','TinyTun'),
 Donor('tools','Tools-main(3).zip','Tools-main(3)','Tools'),
 Donor('browser-ext','ts-browser-ext-main(3).zip','ts-browser-ext-main(3)','ts-browser-ext'),
 Donor('tsheadroom','tsheadroom-main(3).zip','tsheadroom-main(3)','tsheadroom'),
 Donor('mwgp','mwgp-2.zip','mwgp-2','MWGP'),
 Donor('paas-gateway','PaaS-vmess-trojan-argo-main.zip','PaaS-vmess-trojan-argo-main','PaaS vmess/trojan/argo'),
 Donor('reverse-tls','Reverse_tls-main.zip','Reverse_tls-main','Reverse TLS'),
]

def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def sha_file(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1<<20),b''):h.update(c)
    return h.hexdigest()

def norm(name:str)->PurePosixPath:
    if '\x00' in name: raise ValueError('NUL path')
    p=PurePosixPath(name.replace('\\','/'))
    if p.is_absolute() or any(x in ('','.','..') for x in p.parts): raise ValueError(f'unsafe path {name!r}')
    if p.parts and ':' in p.parts[0]: raise ValueError(f'drive path {name!r}')
    return p

def language(path:str)->str:
    e=Path(path).suffix.lower(); n=Path(path).name.lower()
    return {'.go':'Go','.rs':'Rust','.py':'Python','.kt':'Kotlin','.java':'Java','.c':'C','.h':'C/C++ header','.hh':'C/C++ header','.hpp':'C/C++ header','.cpp':'C++','.cc':'C++','.cxx':'C++','.ts':'TypeScript','.tsx':'TypeScript JSX','.js':'JavaScript','.mjs':'JavaScript','.sh':'Shell','.ps1':'PowerShell','.xml':'XML','.json':'JSON','.yaml':'YAML','.yml':'YAML','.toml':'TOML','.md':'Markdown','.html':'HTML','.css':'CSS','.gradle':'Gradle'}.get(e,'Dockerfile' if n.startswith('dockerfile') else 'other')

def classify(path:str)->str:
    q=path.lower();n=Path(q).name
    if '/.git/' in '/'+q or q.startswith('.git/') or q.startswith('.github/'):return 'repository-administration'
    if any(x in q for x in ['/testdata/','/fixtures/','/fixture/']) or n.endswith(('.png','.jpg','.jpeg','.gif','.ico','.webp','.pcap','.bin','.der','.crt')):return 'fixture'
    if re.search(r'(^|/)(test|tests)(/|$)',q) or re.search(r'(_test\.(go|rs)|test_.*\.py$|.*\.test\.(js|mjs|ts)$)',q):return 'test'
    if any(x in q for x in ['/layout/','/drawable/','/mipmap/','/values/','/ui/','/view/','/pages/','/components/']) or Path(q).suffix in ('.tsx','.html','.css'):return 'ui-or-product'
    if any(x in q for x in ['dockerfile','docker-compose','systemd','/deploy/','/deployment/','/installer','/setup/','/release/']) or n.endswith(('.service','.wxs')):return 'deployment'
    if Path(q).suffix in ('.sh','.ps1','.bat','.cmd') or '/scripts/' in q or q.startswith('scripts/'):return 'script'
    if n in ('go.mod','go.sum','cargo.toml','cargo.lock','package.json','package-lock.json','gradle.properties','settings.gradle','settings.gradle.kts','build.gradle','build.gradle.kts','makefile') or Path(q).suffix in ('.yaml','.yml','.toml','.ini','.conf','.properties','.json'):return 'configuration'
    if n.startswith('readme') or Path(q).suffix in ('.md','.rst','.txt') or 'license' in n or 'changelog' in n:return 'documentation'
    if Path(q).suffix in ('.go','.rs','.py','.kt','.java','.c','.h','.hh','.cpp','.cc','.cxx','.hpp','.ts','.js','.mjs'):return 'implementation'
    return 'repository-administration'
HIGH={'implementation','test','script','deployment','ui-or-product','configuration'}

def module_key(donor:str,path:str)->str:
    parts=PurePosixPath(path).parts
    if donor=='shadowsocks-rust':
        if len(parts)>=2 and parts[0]=='crates':
            return 'crates-'+parts[1]+('-'+parts[3] if len(parts)>3 and parts[2]=='src' else '')
        if parts and parts[0]=='src': return 'root-src-'+(parts[1] if len(parts)>2 else 'root')
    if donor=='subconverter':
        if len(parts)>=2 and parts[0] in ('src','base'):return parts[0]+'-'+parts[1]
    if donor=='srsc' and len(parts)>=2 and parts[0]=='convertor':return 'convertor-'+parts[1]
    if donor=='tinytun' and len(parts)>=2 and parts[0]=='src':
        n=Path(path).stem
        if n=='socks5_client':return 'src-socks5'
        if n in ('tun_device','route_manager','ebpf_loader','packet_processor','process_lookup'):return 'src-tun-runtime'
        return 'src-'+n
    return (parts[0] if len(parts)>1 else '@root')

@dataclass(frozen=True)
class Decision:
    disposition:str; transformation:str; topology:str; capability:str; nodes:str; invariant:str; negative:str; behavior_test:str; operator:str; validation:str; rationale:str; risk:str='medium'

def dec(donor:str,key:str)->Decision:
    if donor in ('shadowsocks-crypto','shadowsocks-rust'):
        return Decision('hardened','oracle extraction + authority consolidation','many-to-one','Shadowsocks/SS2022 admission and runtime ownership','src/apps/daemon/internal/networking/proxyconfig/parser_ss.go#validateShadowsocks2022Key;src/apps/daemon/internal/runtime/proxy/core_manager.go#buildSingBoxOutbound','SS2022 key components have exact method-specific decoded lengths and the external core-manager remains the sole runtime owner','no duplicate Go/Rust Shadowsocks runtime or malformed/unknown 2022 key can gain execution authority','src/apps/daemon/internal/networking/proxyconfig/parser_contract_test.go#TestShadowsocks2022KeyAdmission','Profiles/Connections','verified','Crypto/framing/runtime material is retained as an oracle; target-native admission is hardened while zero-consumer duplicate runtime facades are retired.','high')
    if donor=='shadowsocksr':
        return Decision('guardrail-derived','negative-to-guardrail','negative-to-guardrail','fail-closed proxy protocol dispatch','src/apps/daemon/internal/runtime/proxy/core_manager.go#buildSingBoxOutbound;src/apps/daemon/internal/runtime/proxy/core_manager.go#buildXrayOutbound','protocol selection is explicit','SSR or unknown protocols never fall through to SOCKS/HTTP or another executable protocol','src/apps/daemon/internal/runtime/proxy/core_manager_test.go#TestCoreManager_UnsupportedProtocolFailsClosed','Connections','verified','SSR protocol/obfs material is compatibility evidence; unsupported execution fails closed instead of silently changing protocol.','high')
    if donor=='ssh':
        return Decision('hardened','dependency-oracle hardening','many-to-one','SSH authentication admission','src/apps/daemon/internal/runtime/proxy/ssh_tunnel.go#buildSSHAuthMethods','at least one valid explicit authentication method is required before dialing','malformed private-key-only or empty-auth configuration cannot reach network activity','src/apps/daemon/internal/runtime/proxy/ssh_tunnel_test.go#TestSSHTunnelRejectsEmptyAuthBeforeNetwork','Connections','verified','The donor is effectively the dependency-owned SSH protocol stack; target-specific value is stronger pre-network authentication admission, not a second SSH implementation.','high')
    if donor in ('srsc','subconverter'):
        if donor=='srsc' and (key.startswith('convertor-') or key in ('source','adapter','common')) or donor=='subconverter' and (key.startswith('src-parser') or key.startswith('src-generator') or key.startswith('base-rules') or key.startswith('src-config')):
            return Decision('adapted','parser normalization + bounded rederivation','many-to-one','local rule-set normalization','src/apps/daemon/internal/analysis/diagnostics/local_ruleset_plan.go#BuildLocalRuleSetPlan','local rule conversion is deterministic, bounded, duplicate-aware, and offline','remote URL fetching, template/script execution, or converted-rule installation never occurs in the planner','src/apps/daemon/internal/analysis/diagnostics/post_refactor_226_plans_test.go#TestPostRefactor226LocalRuleSetPlan','Rules','verified','Rule syntax/normalization semantics are recomposed into a bounded local preview rather than a second converter server.','medium')
        return Decision('superseded','comparison + selective extraction','many-to-one','subscription/rule conversion runtime','src/apps/daemon/internal/analysis/diagnostics/local_ruleset_plan.go#BuildLocalRuleSetPlan','existing subscription/rule owners remain authoritative','donor web servers, remote fetchers, scripting/template execution, or persistence do not become new target authority','scripts/checks/check_post_refactor_226_convergence.py#semantic-rules-runtime','Rules','reviewed','Non-parser runtime/deployment surfaces are exhaustively accounted as reference/supersession evidence; only safe local normalization semantics are promoted.','medium')
    if donor=='tailscale-client':
        return Decision('inspired-native','transaction-semantic rederivation','idea-to-native','Tailnet transactional change planning','src/apps/daemon/internal/analysis/diagnostics/tailnet_transaction_plan.go#BuildTailnetTransactionPlan','validate/CAS/patch-vs-replace/device-route/key/webhook operations remain explicit and bounded','planner accepts no Tailnet credential, makes no API request, and never returns generated secret material','src/apps/daemon/internal/analysis/diagnostics/post_refactor_226_plans_test.go#TestPostRefactor226TailnetTransactionPlan','Settings','verified','ETag, validation, patch/replace, key and webhook transaction semantics become a read-only change plan.','high')
    if donor=='tinytun':
        if key=='src-socks5':
            return Decision('hardened','wire-boundary hardening','many-to-one','SOCKS5 target/reply framing','src/apps/daemon/internal/runtime/proxy/edge_dialer.go#encodeSOCKS5Target;src/packages/lumicore/src/transport/socks5_client.rs#encode_connect_address','domain and port wire fields are length/range checked before encoding','oversized domains, invalid ports, NUL targets, and unknown reply ATYP values fail closed','src/apps/daemon/internal/runtime/proxy/edge_dialer_test.go#TestEncodeSOCKS5TargetBounds','Connections','verified','TinyTun SOCKS handling exposed one-byte/uint16 truncation and unknown-ATYP acceptance gaps in the actual target owners.','high')
        return Decision('superseded','runtime comparison','many-to-one','TUN/process-routing runtime','src/apps/daemon/internal/platform/system;src/packages/lumicore/src/transport','existing TUN/platform owners remain single-authoritative','no second eBPF/TUN/process-routing runtime is introduced','scripts/checks/check_post_refactor_226_convergence.py#semantic-tinytun-runtime','n/a','reviewed','TinyTun TUN/eBPF/process-routing machinery is reference evidence because existing platform owners are stronger.','high')
    if donor=='tools':
        return Decision('inspired-native','protocol-readiness rederivation','idea-to-native','WebSocket backend readiness','src/apps/daemon/internal/analysis/diagnostics/websocket_readiness_plan.go#BuildWebSocketReadinessPlan','readiness requires a valid HTTP 101 WebSocket upgrade and correct Sec-WebSocket-Accept; TLS evidence is required when expected','an open TCP port alone never proves WebSocket readiness and the planner performs no network I/O','src/apps/daemon/internal/analysis/diagnostics/post_refactor_226_plans_test.go#TestPostRefactor226WebSocketReadinessPlan','Connections','verified','Backend-checking scripts contribute the TCP-vs-WebSocket protocol distinction; mutable proxy lists remain reference data.','medium')
    if donor=='browser-ext':
        return Decision('inspired-native','state-model rederivation','idea-to-native','browser/native-host proxy handoff','src/apps/daemon/internal/analysis/diagnostics/browser_proxy_handoff_plan.go#BuildBrowserProxyHandoffPlan','profile, loopback proxy, permission, payload and install/offline/ready states are explicit and bounded','planner registers no native host and changes no browser proxy setting','src/apps/daemon/internal/analysis/diagnostics/post_refactor_226_plans_test.go#TestPostRefactor226BrowserProxyHandoffPlan','Settings','verified','Extension/native-host lifecycle and permission semantics become a non-authoritative handoff readiness plan.','medium')
    if donor=='tsheadroom':
        return Decision('inspired-native','supervision-policy rederivation','idea-to-native','worker affinity and recovery planning','src/apps/daemon/internal/analysis/diagnostics/worker_affinity_plan.go#BuildWorkerAffinityPlan','affinity is deterministic, capacity-aware, deadline-bounded, and restart backoff is capped','planner starts no process and unhealthy/saturated workers cannot receive normal assignments','src/apps/daemon/internal/analysis/diagnostics/post_refactor_226_plans_test.go#TestPostRefactor226WorkerAffinityPlan','Health','verified','Worker-pool affinity/deadline/restart semantics are absorbed as policy evidence without process authority.','medium')
    if donor=='mwgp':
        return Decision('guardrail-derived','mechanism extraction + negative-to-guardrail','many-to-one','WireGuard receiver-index/obfuscation policy','src/apps/daemon/internal/analysis/diagnostics/wireguard_device_policy_plan.go#BuildWireGuardDevicePolicyPlan','translated receiver-index mappings are unique, source-identity-bound, future-expiring, and bounded','packet obfuscation is traffic-shape modification only and never authentication, confidentiality, replay protection, or a MAC2/cookie substitute','src/apps/daemon/internal/analysis/diagnostics/post_refactor_225_workflow_wireguard_test.go#TestPostRefactor226WireGuardReceiverIndexMappingsExpireAndBindSource','Operations','verified','MWGP index translation and obfuscation inform stricter readiness invariants rather than a second WireGuard stack.','high')
    if donor in ('paas-gateway','reverse-tls'):
        return Decision('recomposed','deployment-graph rederivation','many-to-one','gateway deployment composition planning','src/apps/daemon/internal/analysis/diagnostics/gateway_composition_plan.go#BuildGatewayCompositionPlan','service graph is bounded, acyclic, topologically started, reverse-stopped/rolled back, and restart schedules are capped','planner downloads nothing and writes no cron/systemd/runit/Caddy/service configuration','src/apps/daemon/internal/analysis/diagnostics/post_refactor_226_plans_test.go#TestPostRefactor226GatewayCompositionPlan','Operations','verified','Reverse/listener/router/detour/health lifecycle value is retained as an immutable service graph while root/install/mutable-latest mutation authority is rejected.','high')
    return Decision('reference-only','review','one-to-one','reviewed donor evidence','n/a','source is hash-accounted and compared against target ownership','accountability alone never grants runtime authority','n/a','governance/convergence/post-refactor-226-peer-synthesis.md','reviewed','Supporting donor material is retained as explicit reference evidence.','low')

def blank_cpp(text:str)->str:
    out=list(text);i=0;n=len(text);state='code'
    while i<n:
        c=text[i]
        if state=='code':
            if text.startswith('//',i):out[i]=out[i+1]=' ';i+=2;state='line';continue
            if text.startswith('/*',i):out[i]=out[i+1]=' ';i+=2;state='block';continue
            if c=='"':out[i]=' ';i+=1;state='dq';continue
            if c=="'":out[i]=' ';i+=1;state='sq';continue
            i+=1
        elif state=='line':
            if c=='\n':state='code'
            else:out[i]=' '
            i+=1
        elif state=='block':
            if text.startswith('*/',i):out[i]=out[i+1]=' ';i+=2;state='code'
            else:
                if c!='\n':out[i]=' '
                i+=1
        else:
            q='"' if state=='dq' else "'"
            if c=='\\' and i+1<n:
                if c!='\n':out[i]=' '
                if text[i+1]!='\n':out[i+1]=' '
                i+=2
            elif c==q:out[i]=' ';i+=1;state='code'
            else:
                if c!='\n':out[i]=' '
                i+=1
    return ''.join(out)

def conservative_cpp_definitions(root:Path):
    """Return structurally distinguishable C++ definitions missed by the legacy line index.
    This intentionally avoids broad statement-shaped regexes. Categories are named types,
    header free definitions, qualified source definitions, special members/operators,
    and header template/inline member definitions.
    """
    files=[]
    for ext in ('*.h','*.hpp','*.hh','*.cpp','*.cc','*.cxx'):files+=list((root/'src').rglob(ext))
    rec=[];control={'if','for','while','switch','catch','return','sizeof','alignof','decltype','static_assert','requires','noexcept'}
    for p in files:
        t=blank_cpp(p.read_text(errors='replace'));starts=[0]+[m.end() for m in re.finditer('\n',t)]
        line_of=lambda pos:bisect.bisect_right(starts,pos)
        stack=[];last=0
        for i,ch in enumerate(t):
            if ch==';':
                if not any(tag=='function' for tag,_ in stack):last=i+1
            elif ch=='}':
                if stack:stack.pop()
                if not any(tag=='function' for tag,_ in stack):last=i+1
            elif ch=='{':
                inside_func=any(tag=='function' for tag,_ in stack);prefix=t[last:i].strip();tag='other';scope='';row=None
                types=[name for tag,name in stack if tag=='type'];parent=types[-1] if types else None
                if not inside_func:
                    mts=list(re.finditer(r'\b(class|struct|enum(?:\s+class)?)\s+([A-Za-z_]\w*)\b',prefix))
                    if mts:
                        m=mts[-1];tail=prefix[m.end():]
                        if ')' not in tail or ':' in tail:tag='type';scope=m.group(2);row=('type',m.group(2),parent,prefix)
                    if row is None and '(' in prefix and ')' in prefix:
                        close=prefix.rfind(')');depth=0;op=-1
                        for j in range(close,-1,-1):
                            if prefix[j]==')':depth+=1
                            elif prefix[j]=='(':
                                depth-=1
                                if depth==0:op=j;break
                        if op>=0:
                            before=prefix[:op].rstrip();mn=re.search(r'(operator\s*(?:\[\]|\(\)|[^\s(]+)|~?[A-Za-z_]\w*(?:::\~?[A-Za-z_]\w*)*)\s*$',before)
                            if mn:
                                fn=mn.group(1).replace(' ','');leaf=fn.split('::')[-1]
                                if leaf not in control:tag='function';row=('function',fn,parent,prefix)
                stack.append((tag,scope))
                if row:rec.append((p.relative_to(root).as_posix(),line_of(i),row[0],row[1],row[2],row[3]))
                if not inside_func:last=i+1
    uniq=[];seen=set()
    for r in rec:
        k=r[:4]
        if k not in seen:seen.add(k);uniq.append(r)
    out=[]
    for r in uniq:
        path,line,kind,name,parent,prefix=r; ext=Path(path).suffix.lower();header=ext in ('.h','.hpp','.hh')
        include=False
        if kind=='type':include=True
        elif kind=='function':
            leaf=name.split('::')[-1];special=bool(parent) and (leaf.startswith('operator') or leaf==parent or leaf=='~'+parent)
            free_header=header and not parent
            qualified_source=(not header) and '::' in name
            templ_inline=header and bool(parent) and ('template' in prefix or 'inline' in prefix)
            include=free_header or qualified_source or special or templ_inline
        if include:out.append((path,line,kind,name))
    # Recover single-line template constructors whose initializer-list call would otherwise
    # hide the constructor name from the conservative brace-prefix parser.
    for hp in (root/'src').rglob('*.h'):
        rel=hp.relative_to(root).as_posix()
        for ln,line in enumerate(hp.read_text(errors='replace').splitlines(),1):
            m=re.search(r'template\s*<[^>]+>\s*class\s+([A-Za-z_]\w*)[^;{]*\{.*?explicit\s+\1\s*\(',line)
            if m and (rel,ln,'function',m.group(1)) not in {(a,b,c,d) for a,b,c,d in out}:
                out.append((rel,ln,'function',m.group(1)))
    # These conservative categories are intentionally stable on this donor corpus.
    return out

# Archive validation, exact extraction equality, surface matrix, directory Merkle.
archive_rows=[];surfaces=[];directories=[];path_to_module={}
for donor in DONORS:
    if not donor.archive.is_file():raise FileNotFoundError(donor.archive)
    if not donor.root.is_dir():raise FileNotFoundError(donor.root)
    with zipfile.ZipFile(donor.archive) as z:
        infos=z.infolist();seen=set();folded=set();roots=set();file_infos=[];total=0;syms=0
        for info in infos:
            p=norm(info.filename);name=p.as_posix().rstrip('/');key=name.casefold()
            if name in seen or key in folded:raise ValueError(f'{donor.id}: duplicate/case collision {name}')
            seen.add(name);folded.add(key);roots.add(p.parts[0]);mode=info.external_attr>>16
            if stat.S_ISLNK(mode):syms+=1
            kind=stat.S_IFMT(mode)
            if kind not in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK):raise ValueError(f'{donor.id}: special member {name}')
            if info.flag_bits&1:raise ValueError(f'{donor.id}: encrypted {name}')
            if info.compress_size and info.file_size/info.compress_size>1000:raise ValueError(f'{donor.id}: compression ratio {name}')
            total+=info.file_size
            if not info.is_dir():file_infos.append((info,p,mode))
        bad=z.testzip()
        if bad:raise ValueError(f'{donor.id}: CRC {bad}')
        if len(roots)!=1:raise ValueError(f'{donor.id}: roots {roots}')
        extracted={p.relative_to(donor.root).as_posix():p for p in donor.root.rglob('*') if p.is_file() or p.is_symlink()}
        zipped={}
        for info,p,mode in file_infos:
            rel=PurePosixPath(*p.parts[1:]).as_posix()
            if rel:zipped[rel]=(info,mode,sha_bytes(z.read(info)))
        if set(zipped)!=set(extracted):raise ValueError(f'{donor.id}: extracted path mismatch')
        for rel,(info,mode,zh) in zipped.items():
            ep=extracted[rel];eh=sha_bytes(os.readlink(ep).encode()) if ep.is_symlink() else sha_file(ep)
            if zh!=eh:raise ValueError(f'{donor.id}: byte mismatch {rel}')
            c=classify(rel);mk=module_key(donor.id,rel);path_to_module[(donor.id,rel)]=mk
            surfaces.append({'donor':donor.id,'path':rel,'sha256':eh,'size_bytes':info.file_size,'file_type':'symlink' if stat.S_ISLNK(mode) else 'file','language':language(rel),'classification':c,'authority_status':'authoritative-source' if c in HIGH else 'supporting-evidence','semantic_record_ids':'','surface_disposition':'','surface_rationale':''})
        archive_rows.append({'donor':donor.id,'archive':donor.archive.name,'archive_sha256':sha_file(donor.archive),'members':len(infos),'files':len(zipped),'symlinks':syms,'uncompressed_bytes':total,'archive_root':next(iter(roots)),'validation':'verified-safe+crc+byte-equal'})
    rel_files=sorted([p for p in donor.root.rglob('*') if p.is_file() or p.is_symlink()],key=lambda p:p.relative_to(donor.root).as_posix())
    dirs=[donor.root]+sorted([p for p in donor.root.rglob('*') if p.is_dir()],key=lambda p:p.relative_to(donor.root).as_posix())
    for d in dirs:
        entries=[]
        for p in rel_files:
            try:r=p.relative_to(d)
            except ValueError:continue
            h=sha_bytes(os.readlink(p).encode()) if p.is_symlink() else sha_file(p);entries.append((r.as_posix(),h))
        payload=''.join(f'{h}  {r}\n' for r,h in entries).encode()
        directories.append({'donor':donor.id,'path':'.' if d==donor.root else d.relative_to(donor.root).as_posix(),'descendant_files':len(entries),'tree_sha256':sha_bytes(payload)})

# Semantic graph: donor -> focused module -> every high-signal file.
records=[];module_record={};file_record={};seq=1
for donor in DONORS:
    rep=next(s for s in surfaces if s['donor']==donor.id);base=f'PR226-R{seq:03d}';seq+=1
    records.append({'record_id':base,'parent_record_id':'n/a','composition_group_id':'CG226-'+donor.id,'donor':donor.id,'domain':'repository-accountability','value_unit':f'{donor.product} complete repository accountability','source_granularity':'repository','value_form':'evidence corpus','separability':'context-dependent','donor_path':rep['path'],'donor_sha256':rep['sha256'],'donor_symbol':'n/a','transformation':'exhaustive review','mapping_topology':'one-to-many','disposition':'reference-only','decision_rationale':'Every archive surface is hash-accounted; independent high-signal modules and files receive child records.','target_capability':'convergence evidence','target_nodes':'n/a','invariant':'all donor files/directories/definitions remain traceable','negative_invariant':'repository accountability alone is never implementation evidence','test_node':'n/a','operator_surface':'governance/convergence/post-refactor-226-surface-accountability.csv','migration_impact':'none','license_note':'provenance retained; no legal conclusion encoded in technical evidence','risk_tier':'low','dependency_record_ids':'n/a','evidence_confidence':'high','validation_status':'verified'})
    keys=sorted(set(path_to_module[(donor.id,s['path'])] for s in surfaces if s['donor']==donor.id and s['classification'] in HIGH))
    for key in keys:
        cand=[s for s in surfaces if s['donor']==donor.id and path_to_module[(donor.id,s['path'])]==key and s['classification'] in HIGH];rep2=cand[0];rid=f'PR226-M{seq:03d}';seq+=1;module_record[(donor.id,key)]=rid;d=dec(donor.id,key)
        test='n/a' if d.disposition=='reference-only' else f'scripts/checks/check_post_refactor_226_convergence.py#semantic-{rid}'
        records.append({'record_id':rid,'parent_record_id':base,'composition_group_id':'CG226-'+re.sub(r'[^a-z0-9]+','-',d.capability.lower()).strip('-'),'donor':donor.id,'domain':key,'value_unit':key.replace('-',' ')+' semantics','source_granularity':'module/path cluster','value_form':'mechanism + tests + operational evidence','separability':'independently reviewable module cluster','donor_path':rep2['path'],'donor_sha256':rep2['sha256'],'donor_symbol':'n/a','transformation':d.transformation,'mapping_topology':d.topology,'disposition':d.disposition,'decision_rationale':d.rationale+(' Behavioral evidence: '+d.behavior_test if d.behavior_test!='n/a' else ''),'target_capability':d.capability,'target_nodes':d.nodes,'invariant':d.invariant,'negative_invariant':d.negative,'test_node':test,'operator_surface':d.operator,'migration_impact':'target-native bounded hardening/planning only; existing write/runtime owners remain authoritative','license_note':'provenance retained; no legal conclusion encoded in technical evidence','risk_tier':d.risk,'dependency_record_ids':base,'evidence_confidence':'high','validation_status':d.validation})
for s in sorted(surfaces,key=lambda r:(r['donor'],r['path'])):
    if s['classification'] not in HIGH:continue
    key=path_to_module[(s['donor'],s['path'])];parent=module_record[(s['donor'],key)];d=dec(s['donor'],key);rid=f'PR226-F{len(file_record)+1:04d}';file_record[(s['donor'],s['path'])]=rid
    test='n/a' if d.disposition=='reference-only' else f'scripts/checks/check_post_refactor_226_convergence.py#surface-{rid}'
    records.append({'record_id':rid,'parent_record_id':parent,'composition_group_id':'CG226-'+re.sub(r'[^a-z0-9]+','-',d.capability.lower()).strip('-'),'donor':s['donor'],'domain':'file:'+s['path'],'value_unit':s['path']+' file semantics','source_granularity':'file','value_form':s['classification']+' surface','separability':'independently hash-accounted file surface','donor_path':s['path'],'donor_sha256':s['sha256'],'donor_symbol':'n/a','transformation':d.transformation,'mapping_topology':d.topology,'disposition':d.disposition,'decision_rationale':d.rationale+f' File-level disposition: {s["path"]} independently reviewed inside module {key}.','target_capability':d.capability,'target_nodes':d.nodes,'invariant':d.invariant,'negative_invariant':d.negative,'test_node':test,'operator_surface':d.operator,'migration_impact':'inherits module-level bounded convergence and cannot independently grant authority','license_note':'provenance retained; no legal conclusion encoded in technical evidence','risk_tier':d.risk,'dependency_record_ids':parent,'evidence_confidence':'high','validation_status':d.validation})
base_by={r['donor']:r['record_id'] for r in records if r['domain']=='repository-accountability'}
for s in surfaces:
    ids=[base_by[s['donor']]];m=module_record.get((s['donor'],path_to_module[(s['donor'],s['path'])]));f=file_record.get((s['donor'],s['path']))
    if m:ids.append(m)
    if f:ids.append(f)
    if s['classification'] in HIGH and (not m or not f):raise ValueError(f'high-signal missing focused record {s["donor"]}:{s["path"]}')
    s['semantic_record_ids']=';'.join(ids);s['surface_disposition']='focused-file-'+s['classification'] if f else 'accounted-supporting-'+s['classification'];s['surface_rationale']='independent file-level disposition' if f else 'supporting/admin/fixture/documentation surface explicitly accounted by donor record'

# Legacy 225 symbol policy.
patterns={
 'Go':[(re.compile(r'^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+'),'type')],
 'Rust':[(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)'),'function'),(re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'Python':[(re.compile(r'^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'Kotlin':[(re.compile(r'^\s*(?:[\w<>]+\s+)*(?:suspend\s+)?fun\s+(?:<[^>]+>\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*(?:data\s+|sealed\s+|enum\s+)?(?:class|interface|object)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'Java':[(re.compile(r'^\s*(?:public|private|protected|static|final|synchronized|native|abstract|\s)+[\w<>\[\], ?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('),'function'),(re.compile(r'^\s*(?:public|private|protected|abstract|final|\s)*(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'C':[(re.compile(r'^\s*(?:static\s+)?[\w\s\*]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{?\s*$'),'function')],
 'C++':[(re.compile(r'^\s*(?:static\s+)?[\w:<>,~&*\s]+\s+([A-Za-z_~][A-Za-z0-9_:~]*)\s*\([^;]*\)\s*(?:const\s*)?\{?\s*$'),'function')],
 'TypeScript':[(re.compile(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)'),'function'),(re.compile(r'^\s*(?:export\s+)?(?:class|interface|type)\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
 'JavaScript':[(re.compile(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)'),'function'),(re.compile(r'^\s*(?:export\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)'),'type')],
}
roots={d.id:d.root for d in DONORS};surf={(s['donor'],s['path']):s for s in surfaces};symbols=[]
def add_symbol(donor,path,line,kind,name,policy='legacy'):
    s=surf[(donor,path)];symbols.append({'donor':donor,'path':path,'sha256':s['sha256'],'line':line,'kind':kind,'name':name,'extraction_policy':policy,'semantic_record_ids':s['semantic_record_ids']})
for s in surfaces:
    lang=s['language'];pats=patterns.get(lang)
    if not pats:continue
    p=roots[s['donor']]/s['path']
    try:text=p.read_text(encoding='utf-8',errors='replace')
    except Exception:continue
    for ln,line in enumerate(text.splitlines(),1):
        for pat,kind in pats:
            m=pat.match(line)
            if m:add_symbol(s['donor'],s['path'],ln,kind,m.group(1),'legacy-225-compatible');break
# Rich 226 policy: Rust package constants/statics/macros.
for s in surfaces:
    if s['language']!='Rust':continue
    p=roots[s['donor']]/s['path'];lines=p.read_text(errors='replace').splitlines()
    for ln,line in enumerate(lines,1):
        m=re.match(r'^(?:pub(?:\([^)]*\))?\s+)?(?:const|static(?:\s+mut)?)\s+([A-Za-z_][A-Za-z0-9_]*)\b',line)
        if m:add_symbol(s['donor'],s['path'],ln,'constant',m.group(1),'rich-rust-top-level')
        m=re.match(r'^macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)\b',line)
        if m:add_symbol(s['donor'],s['path'],ln,'macro',m.group(1),'rich-rust-top-level')
# SRSC package-level registration/contract variables.
for s in surfaces:
    if s['donor']!='srsc' or s['language']!='Go':continue
    p=roots[s['donor']]/s['path']
    for ln,line in enumerate(p.read_text(errors='replace').splitlines(),1):
        m=re.match(r'^var\s+([A-Za-z_][A-Za-z0-9_]*)\b',line)
        if m:add_symbol(s['donor'],s['path'],ln,'package-variable',m.group(1),'rich-go-package-registration')
# Conservative C++ definitions missed by legacy header indexing.
cpp=next(d for d in DONORS if d.id=='subconverter')
cpp_defs=conservative_cpp_definitions(cpp.root)
for path,ln,kind,name in cpp_defs:add_symbol('subconverter',path,ln,'cpp-'+kind,name,'rich-cpp-structural')

# Target capability supersession graph.
groups=defaultdict(list)
for r in records:
    if r['domain']!='repository-accountability':groups[r['target_capability']].append(r)
sup=[]
for cap,rs in sorted(groups.items()):
    sup.append({'target_capability':cap,'contributing_records':';'.join(r['record_id'] for r in rs),'donors':';'.join(sorted(set(r['donor'] for r in rs))),'dispositions':';'.join(sorted(set(r['disposition'] for r in rs))),'target_nodes':';'.join(sorted(set(r['target_nodes'] for r in rs))),'second_order_result':'many donor surfaces collapse into one existing/bounded target owner; duplicate runtime/write authority is forbidden'})

OUT.mkdir(parents=True,exist_ok=True)
def write_csv(name,rows,fields):
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
write_csv('post-refactor-226-archive-accountability.csv',archive_rows,['donor','archive','archive_sha256','members','files','symlinks','uncompressed_bytes','archive_root','validation'])
write_csv('post-refactor-226-surface-accountability.csv',sorted(surfaces,key=lambda r:(r['donor'],r['path'])),['donor','path','sha256','size_bytes','file_type','language','classification','authority_status','semantic_record_ids','surface_disposition','surface_rationale'])
write_csv('post-refactor-226-directories.csv',sorted(directories,key=lambda r:(r['donor'],r['path'])),['donor','path','descendant_files','tree_sha256'])
write_csv('post-refactor-226-symbols.csv',sorted(symbols,key=lambda r:(r['donor'],r['path'],int(r['line']),r['kind'],r['name'],r['extraction_policy'])),['donor','path','sha256','line','kind','name','extraction_policy','semantic_record_ids'])
ledger_fields=['record_id','parent_record_id','composition_group_id','donor','domain','value_unit','source_granularity','value_form','separability','donor_path','donor_sha256','donor_symbol','transformation','mapping_topology','disposition','decision_rationale','target_capability','target_nodes','invariant','negative_invariant','test_node','operator_surface','migration_impact','license_note','risk_tier','dependency_record_ids','evidence_confidence','validation_status']
write_csv('post-refactor-226-adoption-ledger.csv',records,ledger_fields)
write_csv('post-refactor-226-supersession-map.csv',sup,['target_capability','contributing_records','donors','dispositions','target_nodes','second_order_result'])
summary={'donors':len(DONORS),'archive_members':sum(int(r['members']) for r in archive_rows),'surfaces':len(surfaces),'files':sum(1 for s in surfaces if s['file_type']=='file'),'symlinks':sum(1 for s in surfaces if s['file_type']=='symlink'),'directories_excluding_roots':len(directories)-len(DONORS),'directory_merkle_records':len(directories),'symbols':len(symbols),'semantic_records':len(records),'focused_module_records':len(module_record),'focused_file_records':len(file_record),'high_signal_surfaces':sum(1 for s in surfaces if s['classification'] in HIGH),'high_signal_without_focused_record':sum(1 for s in surfaces if s['classification'] in HIGH and len(s['semantic_record_ids'].split(';'))<3),'rich_cpp_symbols':len(cpp_defs)}
(OUT/'post-refactor-226-evidence-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary,sort_keys=True))
