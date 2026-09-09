import argparse, hashlib, json
from pathlib import Path
from common import ROOT, FIELDS, dump

def verify(out):
    names={'process_events.json','file_events.json','network_events.json','attack_graph.json','attack_timeline.json'}
    assert {p.name for p in out.iterdir()}==names,'Exactly five dataset files required'
    size=sum(p.stat().st_size for p in out.iterdir()); assert size<500_000_000
    events=[]
    for name in ('process_events.json','file_events.json','network_events.json'): events.extend(json.loads((out/name).read_text(encoding='utf-8')))
    ids={e['event_id'] for e in events}; assert len(ids)==len(events)
    assert all(set(FIELDS)<=set(e) and e['provider']=='cadets' and 'cadets-e3-official-2' in e['raw_location']['file'] for e in events)
    timeline=json.loads((out/'attack_timeline.json').read_text(encoding='utf-8'))
    assert len(timeline)==len(events) and {e['related_node'] for e in timeline}==ids
    assert [e['time'] for e in timeline]==sorted(e['time'] for e in timeline)
    graph=json.loads((out/'attack_graph.json').read_text(encoding='utf-8')); nodes={n['id'] for n in graph['nodes']}
    assert ids<=nodes and all(e['source'] in nodes and e['target'] in nodes for e in graph['edges'])
    manifest=json.loads((ROOT/'source_metadata/selection_manifest.json').read_text(encoding='utf-8'))
    assert sum(e['attack_label']=='ioc_match' for e in events)==manifest['direct_ioc_events']
    summary={'passed':True,'events':len(events),'bytes':size,'megabytes':round(size/1_000_000,3),'checks':['five files','below 500 MB','single CADets topic','required fields','unique event IDs','event conservation','timeline sorted and complete','graph endpoint integrity','direct IoC events preserved']}
    dump(ROOT/'source_metadata/verification.json',summary); print(json.dumps(summary,indent=2)); return summary

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--out',type=Path,default=ROOT/'processed_dataset'); a=p.parse_args(); verify(a.out)
