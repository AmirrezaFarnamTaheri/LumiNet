#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
G=ROOT/'governance/convergence'
FOURTH_BASELINE=G/'fourth-order-baseline-files.csv'
EXPECTED={'donors':8,'archive_members':3320,'directories':341,'surfaces':2979,'modules':109,'symbols':7351,'semantic':110,'ledger':3089,'symlinks':15,'repairs':4,'high_signal':2094,'unresolved_high_signal':0,'target_delta':100}
IMPLEMENTED={'adopted','adapted','hardened','extracted','recomposed','synthesized','inspired-native','guardrail-derived','superseded'}
HEX64=re.compile(r'^[0-9a-f]{64}$')

def read(name):
    p=G/name
    if not p.exists(): raise RuntimeError(f'missing peer convergence artifact: {p.relative_to(ROOT)}')
    with p.open(newline='',encoding='utf-8-sig') as f: return list(csv.DictReader(f))

def aggregate_hash(values):
    h=hashlib.sha256()
    for v in sorted(values): h.update((v+'\n').encode())
    return h.hexdigest()

def main():
    errors=[]
    donors=read('peer-donors.csv'); surfaces=read('peer-surfaces.csv'); dirs=read('peer-directories.csv'); modules=read('peer-modules.csv'); symbols=read('peer-symbols.csv'); corpora=read('peer-corpora.csv'); ledger=read('peer-adoption-ledger.csv'); repairs=read('peer-target-repairs.csv'); reversal=read('peer-reference-reversal.csv'); target_delta=read('peer-target-delta.csv'); second_order_delta=read('second-order-target-delta.csv'); third_wave_delta=read('third-wave-target-delta.csv') if (G/'third-wave-target-delta.csv').is_file() else []
    successor_226_delta=read('post-refactor-226-target-delta.csv') if (G/'post-refactor-226-target-delta.csv').is_file() else []
    successor_226_baseline=read('post-refactor-226-baseline-files.csv') if (G/'post-refactor-226-baseline-files.csv').is_file() else []
    validation=(G/'peer-validation.md').read_text(encoding='utf-8')
    fourth_baseline={}
    if FOURTH_BASELINE.is_file():
        for row in read('fourth-order-baseline-files.csv'):
            fourth_baseline[row['path'].strip()]=row
    counts={'donors':len(donors),'directories':len(dirs),'surfaces':len(surfaces),'modules':len(modules),'symbols':len(symbols),'ledger':len(ledger),'symlinks':sum(r['file_type']=='symlink' for r in surfaces),'repairs':len(repairs),'high_signal':sum(r.get('high_signal')=='yes' for r in symbols),'unresolved_high_signal':sum(r.get('high_signal')=='yes' and r.get('needs_semantic_review')!='no' for r in symbols)}
    semantic=[r for r in ledger if r['record_id'].startswith('SEM')]; counts['semantic']=len(semantic); counts['target_delta']=len(target_delta)
    try: counts['archive_members']=sum(int(r['archive_members']) for r in donors)
    except Exception: counts['archive_members']=-1
    for k,v in EXPECTED.items():
        if counts.get(k)!=v: errors.append(f'{k}: got {counts.get(k)} expected {v}')
    if counts['archive_members'] != counts['directories']+counts['surfaces']:
        errors.append(f"archive equation broken: {counts['archive_members']} != {counts['directories']} + {counts['surfaces']}")
    donor_names={r['donor'] for r in donors}
    for name,rs in [('surfaces',surfaces),('directories',dirs),('modules',modules),('symbols',symbols),('ledger',ledger),('corpora',corpora)]:
        unknown=sorted({r['donor'] for r in rs}-donor_names)
        if unknown: errors.append(f'{name}: unknown donors {unknown}')
    # donors and aggregate hashes
    surf_by_donor=defaultdict(list)
    for r in surfaces:
        if not HEX64.fullmatch(r['sha256']): errors.append(f"bad surface hash {r['donor']}:{r['path']}")
        surf_by_donor[r['donor']].append(r)
    for d in donors:
        rs=surf_by_donor[d['donor']]
        if int(d['surfaces'])!=len(rs): errors.append(f"{d['donor']}: donor surface count mismatch")
        if int(d['safe_symlinks'])!=sum(r['file_type']=='symlink' for r in rs): errors.append(f"{d['donor']}: symlink count mismatch")
        if d['surface_hash']!=aggregate_hash(r['sha256'] for r in rs): errors.append(f"{d['donor']}: surface aggregate hash mismatch")
        if not HEX64.fullmatch(d['archive_sha256']): errors.append(f"{d['donor']}: invalid archive hash")
    # unique surfaces/modules/symbol links
    surf_key={(r['donor'],r['path']):r for r in surfaces}
    if len(surf_key)!=len(surfaces): errors.append('duplicate donor/path in peer-surfaces')
    mod_key={(r['donor'],r['module_id']):r for r in modules}
    if len(mod_key)!=len(modules): errors.append('duplicate donor/module in peer-modules')
    files_by_mod=Counter()
    semantic_by_mod=defaultdict(set)
    for r in surfaces:
        key=(r['donor'],r['module_id'])
        if key not in mod_key: errors.append(f"surface unknown module {r['donor']}:{r['path']} -> {r['module_id']}")
        files_by_mod[key]+=1
        for rid in r['semantic_record_ids'].split(';'):
            if rid.startswith('SEM'): semantic_by_mod[key].add(rid)
    for key,m in mod_key.items():
        if int(m['file_count'])!=files_by_mod[key]: errors.append(f"module {key} file_count {m['file_count']} != {files_by_mod[key]}")
        declared={x for x in m['semantic_record_ids'].split(';') if x!='n/a'}
        if declared!=semantic_by_mod[key]: errors.append(f"module {key} semantic links disagree")
        if m['module_disposition']=='decomposed': errors.append(f"module {key} remains unresolved decomposed")
        if m['module_disposition']=='resolved-by-semantic-ledger' and not semantic_by_mod[key]: errors.append(f"module {key} resolved-by-semantic-ledger without semantic child")
    sem_ids={r['record_id'] for r in semantic}
    for s in symbols:
        key=(s['donor'],s['path'])
        if key not in surf_key: errors.append(f"symbol unknown surface {key}:{s['symbol']}")
        if (s['donor'],s['module_id']) not in mod_key: errors.append(f"symbol unknown module {s['donor']}:{s['module_id']}")
        if s.get('high_signal') not in {'yes','no'}:
            errors.append(f"symbol missing high-signal classification {key}:{s['symbol']}")
        if s.get('high_signal')=='yes':
            if s.get('needs_semantic_review')!='no': errors.append(f"unresolved high-signal symbol {key}:{s['symbol']}")
            if not s.get('high_signal_keywords') or s.get('high_signal_keywords')=='n/a': errors.append(f"high-signal symbol lacks trigger keywords {key}:{s['symbol']}")
        if s['resolution']=='semantic-child':
            ids=[x for x in s['semantic_record_ids'].split(';') if x and x!='n/a']
            if not ids: errors.append(f"semantic-child symbol missing semantic id {key}:{s['symbol']}")
            for rid in ids:
                if rid not in sem_ids: errors.append(f"semantic-child symbol references unknown semantic id {rid}: {key}:{s['symbol']}")
    # adoption graph and bidirectional links
    idmap={r['record_id']:r for r in ledger}
    if len(idmap)!=len(ledger): errors.append('duplicate record_id in peer adoption ledger')
    parent_ids={r['record_id'] for r in ledger if r['record_id'].startswith('SURF-')}
    if len(parent_ids)!=len(surfaces): errors.append('surface-parent adoption count mismatch')
    nonlive_ids={r['record_id'] for r in semantic if r['disposition'] in {'reference-only','rejected-with-reason','superseded'}}
    reversal_ids={r['record_id'] for r in reversal}
    if reversal_ids!=nonlive_ids:
        errors.append(f'reference reversal coverage mismatch: got={len(reversal_ids)} expected={len(nonlive_ids)} missing={sorted(nonlive_ids-reversal_ids)} extra={sorted(reversal_ids-nonlive_ids)}')
    for r in surfaces:
        refs={x for x in r['semantic_record_ids'].split(';') if x}
        parent=[x for x in refs if x.startswith('SURF-')]
        if len(parent)!=1: errors.append(f"surface {r['donor']}:{r['path']} must link exactly one SURF parent")
        for rid in refs:
            if rid not in idmap: errors.append(f"surface {r['donor']}:{r['path']} references unknown {rid}")
            elif idmap[rid]['donor']!=r['donor'] or idmap[rid]['donor_path']!=r['path']:
                errors.append(f"surface link mismatch {r['donor']}:{r['path']} -> {rid}")
    # Every non-live decision is challenged against the current target, not
    # inherited from the first comparison pass. Evidence anchors must remain
    # literal and the reversal result must explicitly state that the donor still
    # loses after target re-check.
    for r in reversal:
        rid=r['record_id']
        if r['reversal_result']!='stays-non-live-after-target-recheck':
            errors.append(f"{rid}: unresolved/non-final reversal result {r['reversal_result']!r}")
        if r['validation_status'] not in {'reviewed','statically-validated','verified'}:
            errors.append(f"{rid}: invalid reversal validation status {r['validation_status']!r}")
        if not r['reversal_rationale'].strip():
            errors.append(f"{rid}: missing reversal rationale")
        evidence=r['target_evidence'].strip()
        for node in [x.strip() for x in evidence.split(';') if x.strip()]:
            if '#' not in node:
                errors.append(f"{rid}: reversal target evidence must use path#anchor: {node!r}")
                continue
            path,anchor=node.split('#',1)
            ep=ROOT/path
            if not ep.is_file():
                errors.append(f"{rid}: reversal evidence file missing: {path}")
                continue
            text=ep.read_text(encoding='utf-8',errors='ignore')
            candidates={anchor,anchor.split('.')[-1],anchor.replace('-', ' '),anchor.replace('-', '_')}
            if not any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])', text, re.I) for c in candidates):
                errors.append(f"{rid}: reversal evidence anchor missing: {node}")

    for r in semantic:
        parent=r['parent_record_id']
        if parent not in parent_ids: errors.append(f"{r['record_id']}: unknown parent {parent}")
        key=(r['donor'],r['donor_path'])
        s=surf_key.get(key)
        if not s: errors.append(f"{r['record_id']}: donor path absent from surfaces")
        else:
            if r['donor_sha256']!=s['sha256']: errors.append(f"{r['record_id']}: donor hash disagrees with surface")
            if r['record_id'] not in s['semantic_record_ids'].split(';'): errors.append(f"{r['record_id']}: surface does not link back")
        anchor='#'+r['record_id'].lower()
        heading='### '+r['record_id'].lower()
        if heading not in validation: errors.append(f"{r['record_id']}: missing validation heading {heading}")
        if r['test_node']!='n/a' and not r['test_node'].endswith(anchor): errors.append(f"{r['record_id']}: test_node must use unique validation anchor")
        if r['disposition'] in IMPLEMENTED:
            if r['target_nodes']=='n/a': errors.append(f"{r['record_id']}: implemented/superseded decision missing target_nodes")
            for node in r['target_nodes'].split(';'):
                if '#' not in node:
                    errors.append(f"{r['record_id']}: target node must use path#anchor: {node}")
                    continue
                path, anchor = node.split('#', 1)
                target_path = ROOT/path
                if not target_path.is_file():
                    errors.append(f"{r['record_id']}: target node file missing: {path}")
                    continue
                text = target_path.read_text(encoding='utf-8', errors='ignore')
                candidates = {anchor, anchor.split('.')[-1], anchor.replace('-', ' '), anchor.replace('-', '_')}
                if not any(c and re.search(r'(?<![A-Za-z0-9_])'+re.escape(c)+r'(?![A-Za-z0-9_])', text, re.I) for c in candidates):
                    errors.append(f"{r['record_id']}: target node anchor missing: {path}#{anchor}")
            if r['invariant']=='n/a' or r['negative_invariant']=='n/a': errors.append(f"{r['record_id']}: implemented/superseded decision missing invariants")
        if r['disposition']=='rejected-with-reason' and r['negative_invariant']=='n/a': errors.append(f"{r['record_id']}: rejected decision lacks negative invariant")
    # module/symbol counts per donor in donor summary
    for d in donors:
        donor=d['donor']
        if int(d['directories'])!=sum(x['donor']==donor for x in dirs): errors.append(f'{donor}: directory count mismatch')
        if int(d['modules'])!=sum(x['donor']==donor for x in modules): errors.append(f'{donor}: module count mismatch')
        if int(d['symbols'])!=sum(x['donor']==donor for x in symbols): errors.append(f'{donor}: symbol count mismatch')
    # corpora evidence hashes must be valid and non-empty.
    for c in corpora:
        if not HEX64.fullmatch(c['aggregate_sha256']): errors.append(f"corpus {c['corpus_id']}: bad aggregate hash")
        if int(c['surface_count'])<1: errors.append(f"corpus {c['corpus_id']}: empty corpus")
    # The original peer-convergence target delta remains immutable evidence.
    # A later second-order convergence may legitimately change one of those
    # paths, but only through an explicit hash chain from the peer-converged
    # hash to the current hash. This preserves the original 100-row denominator
    # instead of silently rewriting historical evidence.
    second_order_by_path={r['path'].strip():r for r in second_order_delta}
    if len(second_order_by_path)!=len(second_order_delta):
        errors.append('duplicate path in second-order target delta')
    third_wave_by_path={r['path'].strip():r for r in third_wave_delta}
    if len(third_wave_by_path)!=len(third_wave_delta):
        errors.append('duplicate path in third-wave target delta')
    successor_226_by_path={r['path'].strip():r for r in successor_226_delta}
    successor_226_baseline_by_path={r['path'].strip():r for r in successor_226_baseline}
    if len(successor_226_by_path)!=len(successor_226_delta):
        errors.append('duplicate path in post-refactor-226 target delta')
    if len(successor_226_baseline_by_path)!=len(successor_226_baseline):
        errors.append('duplicate path in post-refactor-226 frozen baseline')

    # The target-side change denominator is explicit too. This matrix excludes
    # itself (a manifest cannot include a stable hash of its own bytes), but every
    # other convergence-changed path is classified, hash-pinned, and linked to
    # semantic or repair/governance evidence.
    delta_paths=set()
    for r in target_delta:
        path=r['path'].strip()
        if not path or path in delta_paths:
            errors.append(f"duplicate/empty peer target-delta path: {path!r}")
            continue
        delta_paths.add(path)
        if r['change_type'] not in {'added','modified','deleted'}:
            errors.append(f"target-delta {path}: invalid change_type {r['change_type']!r}")
        if not r['accountability_class'].strip() or not r['reason'].strip() or not r['verification_node'].strip():
            errors.append(f"target-delta {path}: incomplete accountability fields")
        for rid in [x for x in r['semantic_record_ids'].split(';') if x and x!='n/a']:
            if rid not in sem_ids:
                errors.append(f"target-delta {path}: unknown semantic record {rid}")
        if r['change_type'] != 'deleted':
            target_path=ROOT/path
            if not target_path.is_file():
                # A later immutable successor may explicitly retire a historical
                # target path. Accept that only through the frozen 225 -> 226
                # deletion receipt: the 226 delta must classify the path as
                # deleted, its baseline hash must equal the exact frozen 225
                # inventory hash, and its current hash must be n/a. This keeps
                # the old peer-convergence evidence immutable without requiring
                # deliberately retired duplicate authority to remain live.
                successor=successor_226_by_path.get(path)
                frozen=successor_226_baseline_by_path.get(path)
                valid_retirement=(
                    successor is not None
                    and successor.get('change_type')=='deleted'
                    and successor.get('current_sha256')=='n/a'
                    and frozen is not None
                    and HEX64.fullmatch(frozen.get('sha256','')) is not None
                    and successor.get('baseline_sha256')==frozen.get('sha256')
                )
                if not valid_retirement:
                    errors.append(f"target-delta {path}: current target file missing without valid post-226 retirement receipt")
            elif r['accountability_class']=='generated-inventory':
                if r['current_sha256']!='n/a':
                    errors.append(f"target-delta {path}: generated inventory row must use current_sha256=n/a")
            elif not HEX64.fullmatch(r['current_sha256']):
                errors.append(f"target-delta {path}: invalid current SHA-256")
            else:
                # When a successor convergence exists, historical peer hashes are
                # validated through the immutable predecessor snapshot rather than
                # treating legitimate fourth-order edits as corruption of the old receipt.
                snapshot=fourth_baseline.get(path)
                actual_hash=(snapshot.get('sha256') if snapshot and snapshot.get('file_type')=='file' else hashlib.sha256(target_path.read_bytes()).hexdigest())
                if actual_hash!=r['current_sha256']:
                    successor=second_order_by_path.get(path)
                    third=third_wave_by_path.get(path)
                    if successor and successor.get('peer_converged_sha256')==r['current_sha256']:
                        second_hash=successor.get('current_sha256')
                        if actual_hash!=second_hash:
                            if not third or third.get('second_order_sha256')!=second_hash or third.get('current_sha256')!=actual_hash:
                                errors.append(f"target-delta {path}: current SHA-256 mismatch without valid third-wave successor")
                    elif third and third.get('second_order_sha256')==r['current_sha256'] and third.get('current_sha256')==actual_hash:
                        # This path was unchanged in second order and changed directly
                        # in third wave; the third-wave baseline hash is therefore the
                        # original peer-converged delivered hash.
                        pass
                    else:
                        errors.append(f"target-delta {path}: current SHA-256 mismatch without valid successor hash chain")
        elif r['current_sha256']!='n/a':
            errors.append(f"target-delta {path}: deleted row must use current_sha256=n/a")
        if r['baseline_sha256']!='n/a' and not HEX64.fullmatch(r['baseline_sha256']):
            errors.append(f"target-delta {path}: invalid baseline SHA-256")
        evidence_path=r['verification_node'].split('#',1)[0]
        if evidence_path and not (ROOT/evidence_path).exists():
            errors.append(f"target-delta {path}: verification path missing: {evidence_path}")

    # Target-local repairs discovered during convergence must remain explicit,
    # evidence-backed, and attached to a live target path. They are deliberately
    # separate from donor semantic records so target defects are not laundered
    # into peer provenance.
    repair_ids=set()
    for r in repairs:
        rid=r['repair_id'].strip()
        if not rid or rid in repair_ids: errors.append(f"duplicate/empty peer target repair id: {rid!r}")
        repair_ids.add(rid)
        if not r['reason'].strip() or not r['trigger'].strip() or not r['evidence'].strip():
            errors.append(f"{rid or '<missing>'}: incomplete target-repair rationale/evidence")
        if r['status'] not in {'verified','statically-validated','reviewed'}:
            errors.append(f"{rid}: invalid target-repair status {r['status']!r}")
        path=ROOT/r['path']
        if not path.exists(): errors.append(f"{rid}: target repair path missing: {r['path']}")
        evidence_path=r['evidence'].split('#',1)[0]
        if evidence_path and not (ROOT/evidence_path).exists():
            errors.append(f"{rid}: target repair evidence path missing: {evidence_path}")
    if errors:
        print(f'peer convergence: errors={len(errors)}')
        for e in errors[:120]: print('ERROR:',e)
        return 1
    print('peer convergence:', ' '.join(f'{k}={counts[k]}' for k in ['donors','archive_members','directories','surfaces','modules','symbols','high_signal','unresolved_high_signal','semantic','ledger','symlinks','repairs','target_delta']), f'corpora={len(corpora)} reversal={len(reversal)} errors=0')
    return 0
if __name__=='__main__': sys.exit(main())
