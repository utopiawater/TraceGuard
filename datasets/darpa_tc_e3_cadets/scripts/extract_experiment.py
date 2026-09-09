"""Small single-topic experiment selected by official scenario indicators.

Uses the completed temporary raw index, writes exactly five dataset files.
Never infers a report timezone: observed IoC event times define the windows.
"""
import argparse, bisect, collections, functools, hashlib, json, re, sqlite3
from pathlib import Path
from common import ROOT, array, datum, dump, timestamp
from preprocess import normalize, uid

SCENARIO={
 'id':'E3-CADETS-20180412-nginx',
 'source':'TC_Ground_Truth_Report_E3_Update.pdf section 3.13, PDF pages 26-29 (printed 23-26)',
 'date':'2018-04-12',
 'ips':['25.159.96.207','76.56.184.25','155.162.39.48','198.115.236.119','53.158.101.118','98.15.44.232','192.113.144.28'],
 'paths':['/tmp/XIM','/tmp/tmux-1002','/tmp/minions','/tmp/font','/var/log/netlog','/var/log/sendmail','/tmp/main','/tmp/test'],
 'context_padding_seconds':120,
 'timezone_policy':'Report clock timezone not assumed; match indicators on UTC date, use observed event nanoseconds as anchors.'
}

def write_products(events,lookup,out):
    needed={e[key] for e in events for key in ('host','subject_id','parent_subject_id','object_id','object2_id') if e[key]}
    events.sort(key=lambda e:(e['timestamp_ns'],e['event_id']))
    nodes={}; edges=[]
    def node(ident,kind,**props): nodes.setdefault(ident,dict(id=ident,type=kind,**props)); return ident
    def ent(ident): return 'cadets:entity:'+ident
    for ident in needed:
        d=lookup('cadets',ident); kind={'Host':'host','Subject':'process','NetFlowObject':'network_flow','FileObject':'file','Principal':'user'}.get(d.get('_kind'),'entity')
        node(ent(ident),kind,uuid=ident,details=d or None)
    def edge(a,b,rel,e): edges.append(dict(source=a,target=b,relation=rel,time=e['timestamp'],event_id=e['event_id'],evidence_type='temporal_association' if rel=='temporal_next' else 'observed_reference'))
    previous={}; parent_edges=set()
    for e in events:
        eid=node(e['event_id'],'event',event_type=e['event_type'],attack_label=e['attack_label'])
        for key,rel,reverse in [('host','observed_on_host',True),('subject_id','performed',True),('object_id','target',False),('object2_id','secondary_target',False)]:
            if e[key]: edge(ent(e[key]) if reverse else eid,eid if reverse else ent(e[key]),rel,e)
        pair=(e['parent_subject_id'],e['subject_id'])
        if all(pair) and pair not in parent_edges: edge(ent(pair[0]),ent(pair[1]),'parent_process',e); parent_edges.add(pair)
        if e['category']=='network':
            ends=[]
            for side in ('source','destination'):
                ep=e[side]
                if ep and ep.get('ip'):
                    ends.append(node(f'cadets:endpoint:{e["host"]}:{ep["ip"]}:{ep["port"]}','endpoint',**ep))
                else: ends.append(None)
            if all(ends): edge(*ends,'network_connection',e)
        if e['host'] in previous: edge(previous[e['host']],eid,'temporal_next',e)
        previous[e['host']]=eid
    out.mkdir(parents=True,exist_ok=True)
    # Exhaustive non-overlapping partition: host behaviors other than files/network
    # are kept with process events, including unknown types, never silently dropped.
    partitions={'process_events.json':[e for e in events if e['category'] not in ('file','network')], 'network_events.json':[e for e in events if e['category']=='network'],'file_events.json':[e for e in events if e['category']=='file']}
    for name,values in partitions.items(): array(out/name,values)
    array(out/'attack_timeline.json',(dict(time=e['timestamp'],host=e['host'],event=e['event_type'],description=' '.join(str(v) for v in (e['process'],e['action'],e['object_path']) if v),related_node=e['event_id'],attack_label=e['attack_label']) for e in events))
    dump(out/'attack_graph.json',dict(scenario=SCENARIO['id'],nodes=list(nodes.values()),edges=edges,temporal_edges_are_causal=False,labels_are_verified_malicious=False))
    size=sum(p.stat().st_size for p in out.iterdir() if p.is_file())
    if size>=500_000_000: raise RuntimeError('Output exceeds 500 MB; reduce context_limit. Direct indicator matches must not be silently truncated.')
    assert len(events)==sum(len(v) for v in partitions.values())
    assert all(x['source'] in nodes and x['target'] in nodes for x in edges)
    return partitions,nodes,edges,size

def extract(db,out,metadata,context_limit=20000):
    con=sqlite3.connect(Path(db).resolve().as_uri()+'?mode=ro',uri=True)
    @functools.lru_cache(maxsize=50000)
    def lookup(prov,ident):
        if not ident: return {}
        row=con.execute('SELECT r.kind,r.data FROM entities e JOIN records r ON r.id=e.record_id WHERE e.provider=? AND e.uuid=?',(prov,ident)).fetchone()
        if row:
            kind,data=datum(json.loads(row[1])); return dict(data,_kind=kind)
        return {}
    badflows=set()
    for uuid,data in con.execute("SELECT r.uuid,r.data FROM records r JOIN entities e ON e.record_id=r.id WHERE r.provider='cadets' AND r.kind='NetFlowObject'"):
        _,d=datum(json.loads(data))
        if d.get('localAddress') in SCENARIO['ips'] or d.get('remoteAddress') in SCENARIO['ips']: badflows.add(uuid)
    print('Indicator network objects',len(badflows),flush=True)
    indicator_pattern=re.compile('|'.join(re.escape(x) for x in badflows)) if badflows else None
    start=timestamp(SCENARIO['date']+'T00:00:00Z')[1]; end=start+86400*10**9
    time_pattern=re.compile(r'"timestampNanos"\s*:\s*(\d+)')
    def rows():
        for rid,source,pos,data in con.execute("SELECT id,file,position,data FROM records WHERE provider='cadets' AND kind='Event' ORDER BY id"):
            match=time_pattern.search(data)
            if not match or not start<=int(match[1])<end: continue
            yield rid,source,pos,data,int(match[1])
    seeds={}; subjects=set(); anchors=[]; scanned=0
    for rid,source,pos,data,ns in rows():
        scanned+=1
        if not (indicator_pattern and indicator_pattern.search(data)) and not any(x in data for x in SCENARIO['paths']): continue
        _,d=datum(json.loads(data)); reasons=[]
        if uid(d.get('predicateObject')) in badflows or uid(d.get('predicateObject2')) in badflows: reasons.append('official_network_ioc')
        if any(d.get(k) in SCENARIO['paths'] for k in ('predicateObjectPath','predicateObject2Path')): reasons.append('official_file_ioc')
        if not reasons: continue
        seeds[rid]=(source,pos,data,ns,reasons); anchors.append(ns)
        if uid(d.get('subject')): subjects.add(uid(d['subject']))
    if not seeds: raise RuntimeError('No official indicator hits; no artificial attack data emitted')
    print('Direct indicator matches',len(seeds),'subjects',len(subjects),flush=True)
    # Two descendant generations and one parent generation, scoped to CDM UUID.
    links=[]
    for uuid,data in con.execute("SELECT r.uuid,r.data FROM records r JOIN entities e ON e.record_id=r.id WHERE r.provider='cadets' AND r.kind='Subject'"):
        _,d=datum(json.loads(data)); links.append((uuid,uid(d.get('parentSubject'))))
    for _ in range(2): subjects.update(child for child,parent in links if parent in subjects)
    subjects.update(parent for child,parent in links if child in subjects and parent)
    padding=SCENARIO['context_padding_seconds']*10**9; intervals=[]
    for ns in sorted(anchors):
        lo,hi=ns-padding,ns+padding
        if intervals and lo<=intervals[-1][1]: intervals[-1][1]=max(hi,intervals[-1][1])
        else: intervals.append([lo,hi])
    starts=[p[0] for p in intervals]
    def in_window(ns):
        i=bisect.bisect_right(starts,ns)-1; return i>=0 and ns<=intervals[i][1]
    # Keep closest context using a bounded heap, without capping direct IoC matches.
    import heapq
    anchors.sort(); heap=[]; candidates=0
    for rid,source,pos,data,ns in rows():
        if rid in seeds or not in_window(ns): continue
        _,d=datum(json.loads(data))
        if uid(d.get('subject')) not in subjects: continue
        candidates+=1; i=bisect.bisect_left(anchors,ns)
        distance=min(abs(ns-anchors[j]) for j in (max(0,i-1),min(len(anchors)-1,i)))
        value=(-distance,-rid,source,pos,data,ns)
        if len(heap)<context_limit: heapq.heappush(heap,value)
        elif value>heap[0]: heapq.heapreplace(heap,value)
    selected=dict(seeds)
    for _,negid,source,pos,data,ns in heap: selected[-negid]=(source,pos,data,ns,['same_process_or_family_near_ioc'])
    events=[]; needed=set(); process_ids=set()
    for rid,(source,pos,data,ns,reasons) in sorted(selected.items()):
        original=json.loads(data); _,d=datum(original); e=normalize(d,'Event','cadets',f'cadets:record:{rid}',lookup)
        e.update(selection_reason=reasons,attack_label='ioc_match' if rid in seeds else 'context',raw_location={'file':source,'record':pos},evidence=d)
        events.append(e)
        for key in ('host','subject_id','parent_subject_id','object_id','object2_id'):
            if e[key]: needed.add(e[key])
        if e['subject_id']: process_ids.add(e['subject_id'])
    partitions,nodes,edges,size=write_products(events,lookup,out)
    summary={'scenario':SCENARIO,'topic':'ta1-cadets-e3-official-2','status':'complete','events':len(events),'direct_ioc_events':len(seeds),'context_events':len(heap),'excluded_context_candidates':candidates-len(heap),'day_events_scanned':scanned,'counts':{k:len(v) for k,v in partitions.items()},'graph_nodes':len(nodes),'graph_edges':len(edges),'bytes':size,'limit_bytes':500_000_000,'windows_utc':[[timestamp(x,'ns')[0] for x in pair] for pair in intervals],'time_min':events[0]['timestamp'],'time_max':events[-1]['timestamp'],'raw_retention':'delete downloaded event archives and full temporary index after verification','selection_limitations':'Indicator-based experiment, not all malicious events in E3; context capped by nearest anchor; ioc_match is not a manually verified malicious label'}
    dump(metadata/'selection_manifest.json',summary)
    dump(metadata/'output_checksums.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()})
    print(json.dumps(summary,ensure_ascii=False,indent=2)); con.close()

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--db',type=Path,default=ROOT/'processed_dataset/metadata/dataset.sqlite'); p.add_argument('--out',type=Path,default=ROOT/'experiment_dataset'); p.add_argument('--metadata',type=Path,default=ROOT/'source_metadata'); p.add_argument('--context-limit',type=int,default=20000); a=p.parse_args(); extract(a.db,a.out,a.metadata,a.context_limit)
